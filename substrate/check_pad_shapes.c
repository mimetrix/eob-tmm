/* Both pad shapes, arm and disarm --- the byte-level decision, on any arch.
 *
 * check_arm.c executes a real patch and is therefore x86_64-only, so on any other
 * host the shape logic went untested entirely. That is the wrong thing to skip:
 * deciding WHERE the five patchable bytes are is pure byte matching, it is
 * arch-independent, and getting it wrong writes a call over a real instruction.
 *
 * Handling only endbr64+5nop refused 4,611 functions, and they are not a random
 * slice --- -fcf-protection emits endbr64 only for indirect-branch targets, so
 * file-scope statics and .isra/.constprop clones get the pad at +0. Measured on
 * the shipped binary: http_ingress_initialize, http_process_client_headers and
 * format_via_info all carry +0 pads and were unreachable, while
 * http_parse_client_headers carries +4 and was not. Three of four candidates for
 * a developer probe were refused for a reason unrelated to their usefulness.
 *
 * The negative cases matter as much as the positive ones. A REFUSAL is the
 * correct answer for anything that is not a recognised pad, because the
 * alternative is corrupting a live instruction stream.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define LS_ENDBR   "\xf3\x0f\x1e\xfa"
#define LS_ENDBR_LEN 4
#define LS_PAD_LEN 5
static const uint8_t LS_NOPS[LS_PAD_LEN] = { 0x90, 0x90, 0x90, 0x90, 0x90 };

/* Mirrors of the functions in ls_arm.c. Kept in step by check-arm-shapes below,
 * which greps the real source so a divergence fails rather than drifts. */
static uint8_t *
ls_find_pad(void *fn)
{
    uint8_t *p = (uint8_t *)fn;
    if (memcmp(p, LS_ENDBR, LS_ENDBR_LEN) == 0) {
        if (memcmp(p + LS_ENDBR_LEN, LS_NOPS, LS_PAD_LEN) != 0)
            return NULL;
        return p + LS_ENDBR_LEN;
    }
    if (memcmp(p, LS_NOPS, LS_PAD_LEN) == 0)
        return p;
    return NULL;
}

static uint8_t *
ls_find_armed(void *fn)
{
    uint8_t *p = (uint8_t *)fn;
    if (memcmp(p, LS_ENDBR, LS_ENDBR_LEN) == 0)
        return p[LS_ENDBR_LEN] == 0xe8 ? p + LS_ENDBR_LEN : NULL;
    return p[0] == 0xe8 ? p : NULL;
}

int
main(void)
{
    int n = 0;

    /* Real entry bytes, copied from the shipped tmm64.no_pgo. */
    uint8_t pad4[16] = { 0xf3,0x0f,0x1e,0xfa, 0x90,0x90,0x90,0x90,0x90,
                         0x41,0x54,0x49 };                  /* http_parse_client_headers */
    uint8_t pad0[16] = { 0x90,0x90,0x90,0x90,0x90,
                         0x41,0x55,0x41,0x54,0x55,0x48,0x89 }; /* http_ingress_initialize */

    /* 1. both shapes are FOUND, at the right offset */
    assert(ls_find_pad(pad4) == pad4 + 4);                                  n++;
    assert(ls_find_pad(pad0) == pad0 + 0);                                  n++;

    /* 2. a function with neither shape is REFUSED --- the important direction,
     *    because a guess here writes a call over a real instruction */
    {
        uint8_t none[16] = { 0x55,0x48,0x89,0xe5,0x41,0x57 };  /* push rbp; mov */
        assert(ls_find_pad(none) == NULL);                                  n++;
    }

    /* 3. endbr64 followed by NON-nops is refused, not treated as a +0 pad.
     *    This is the ordering trap: falling through to the +0 test after the
     *    endbr64 branch fails would compare the endbr64 bytes to nops. */
    {
        uint8_t armed4[16] = { 0xf3,0x0f,0x1e,0xfa, 0xe8,0x11,0x22,0x33,0x44 };
        assert(ls_find_pad(armed4) == NULL);                                n++;
        assert(ls_find_armed(armed4) == armed4 + 4);                        n++;
    }

    /* 4. four nops is NOT a pad --- five is the whole requirement */
    {
        uint8_t four[16] = { 0x90,0x90,0x90,0x90, 0x55,0x48 };
        assert(ls_find_pad(four) == NULL);                                  n++;
    }

    /* 5. arm then disarm, round trip, BOTH shapes. This is the property that
     *    matters: whatever offset arming chose, disarming must restore the same
     *    five bytes and nothing else. */
    {
        uint8_t *p;
        uint8_t call[LS_PAD_LEN] = { 0xe8, 0x44, 0x33, 0x22, 0x11 };
        uint8_t save4[16], save0[16];
        memcpy(save4, pad4, 16); memcpy(save0, pad0, 16);

        p = ls_find_pad(pad4); assert(p);  memcpy(p, call, LS_PAD_LEN);
        assert(ls_find_pad(pad4) == NULL);          /* armed: no longer a pad */ n++;
        assert(ls_find_armed(pad4) == pad4 + 4);                            n++;
        memcpy(ls_find_armed(pad4), LS_NOPS, LS_PAD_LEN);
        assert(memcmp(pad4, save4, 16) == 0);       /* byte-identical again */ n++;

        p = ls_find_pad(pad0); assert(p);  memcpy(p, call, LS_PAD_LEN);
        assert(ls_find_pad(pad0) == NULL);                                  n++;
        assert(ls_find_armed(pad0) == pad0 + 0);                            n++;
        memcpy(ls_find_armed(pad0), LS_NOPS, LS_PAD_LEN);
        assert(memcmp(pad0, save0, 16) == 0);                               n++;
    }

    /* 6. THE KNOWN WEAKNESS, asserted so it is recorded rather than discovered.
     *    At +0 there is no endbr64 in front, so a function whose genuine first
     *    instruction is `call rel32` reads as armed. Disarming it would write
     *    nops over a real instruction. Bounded by the address coming from the
     *    hook map and by arming having required a nop pad; the real fix is
     *    verifying the displacement points at the trampoline, which needs
     *    per-site arm state that does not exist yet. */
    {
        uint8_t real_call[16] = { 0xe8, 0x00,0x01,0x00,0x00, 0x5d,0xc3 };
        assert(ls_find_armed(real_call) == real_call);   /* misread --- known */ n++;
        assert(ls_find_pad(real_call) == NULL);          /* but never armable */ n++;
    }

    printf("ok    ls_arm pad shapes  (%d assertions: +4 and +0 found, round-trip "
           "byte-identical, non-pads refused)\n", n);
    return 0;
}
