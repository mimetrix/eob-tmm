/*
 * ls_arm.c --- write the patch into live code, and take it back out. Item 2.
 *
 * The trampoline (trampoline_x86_64.S) is the TARGET of the patch; this is the
 * act of installing it. Given a function whose entry carries the
 * -fpatchable-function-entry pad, arming rewrites the five nop bytes into a
 * `call rel32` to the trampoline, and disarming restores the nops.
 *
 * ===================================================================
 *  WHAT THIS DOES, AND WHAT IT DELIBERATELY DOES NOT
 * ===================================================================
 *
 * DOES: locate the pad, compute the rel32, write the five bytes through
 * /proc/self/mem (opcode byte last) atomically enough for the single-writer case,
 * flush the i-cache. Reversibly. Verified by arming a live function and calling it.
 *
 * DOES NOT: coordinate with other cores. On x86 a `call` opcode is written by a
 * single aligned store of its first byte last, so a core fetching mid-write sees
 * either all-nops or the whole call --- never a torn instruction --- which is why
 * ftrace patches live kernel text this way. But that is safety against a TORN
 * READ, not against a core standing INSIDE the pad at the instant of the write,
 * nor against the cross-modifying-code rule that every other core must serialise
 * before trusting the new bytes. Closing those is the safe point (item 0), and
 * it is not here. This is correct for a single thread and for the demonstration;
 * it is NOT correct to run against a live multi-core TMM without item 0.
 *
 * Writes go through /proc/self/mem, the debugger's path into r-xp text --- no
 * mprotect, no W^X relaxation, no writable alias. Proven to reach the *executed*
 * bytes on real private .text (it was long assumed impossible here; that was a
 * flawed readback test --- see ls_write_text). What remains TMM-specific: whether
 * tmm64's text is hugepage-backed (this is proven on 4 KB pages) and whatever
 * code-integrity policy the production node enforces.
 *
 * Status: candidate artifact. It runs (see check_arm.c). Nothing in TMM calls it.
 */

#include <stdint.h>
#include <fcntl.h>
#include "ls_arm.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

/* TWO PAD SHAPES, and the second one is not an edge case.
 *
 *   endbr64 + 5 nops   pad at +4   --- indirect-call targets
 *   5 nops             pad at +0   --- direct-call-only functions
 *
 * -fcf-protection emits endbr64 only where an indirect branch can land. A
 * function reached solely by direct calls needs no landing pad, so
 * -fpatchable-function-entry=5,0 puts its five bytes at offset 0 with nothing in
 * front. That is most file-scope statics and every .isra/.constprop clone.
 *
 * Handling only the +4 shape refused 4,611 functions, and they are NOT a random
 * slice: they are disproportionately the internal, file-local logic worth
 * probing. Measured on the shipped binary, http_ingress_initialize,
 * http_process_client_headers and format_via_info all carry a +0 pad and were
 * unreachable; http_parse_client_headers carries +4 and was not. Three of four
 * candidates for a developer probe were refused for a reason that has nothing to
 * do with whether the function is interesting. */
#define LS_ENDBR   "\xf3\x0f\x1e\xfa"
#define LS_ENDBR_LEN 4
#define LS_PAD_LEN 5
static const uint8_t LS_NOPS[LS_PAD_LEN] = { 0x90, 0x90, 0x90, 0x90, 0x90 };

/*
 * Find the five patchable bytes at a function's entry.
 *
 * Returns a pointer to the first pad byte, or NULL if the entry is not the shape
 * arming requires --- which is a REFUSAL, not a guess. A function without the pad
 * cannot be armed, and pretending otherwise would corrupt a real instruction.
 * The endbr64 is required too: without it the function was not built for IBT and
 * this whole mechanism's assumptions do not hold.
 */
static uint8_t *
ls_find_pad(void *fn)
{
    uint8_t *p = (uint8_t *)fn;

    /* Order matters. Test endbr64 FIRST and do not fall through on failure: if
     * the entry has an endbr64 whose following bytes are not nops it is already
     * armed (or not padded), and checking +0 next would compare the endbr64
     * bytes themselves against nops --- which cannot match, but the reasoning
     * should not depend on that accident. */
    if (memcmp(p, LS_ENDBR, LS_ENDBR_LEN) == 0) {
        if (memcmp(p + LS_ENDBR_LEN, LS_NOPS, LS_PAD_LEN) != 0)
            return NULL;                   /* already armed, or no pad          */
        return p + LS_ENDBR_LEN;           /* +4 shape                          */
    }

    /* No endbr64: a direct-call-only function, pad at +0. Five nops as the first
     * instruction of a function is the pad --- the flag is applied to every
     * translation unit, so an unpadded function does not begin this way. Arming
     * an address that is not a function entry remains the caller's error, and is
     * what the hook map exists to prevent. */
    if (memcmp(p, LS_NOPS, LS_PAD_LEN) == 0)
        return p;                          /* +0 shape                          */

    return NULL;
}

/*
 * The armed counterpart: find the `call rel32` a previous arm wrote, in whichever
 * shape this entry uses. Returns NULL unless the entry really looks armed.
 *
 * The +0 case is weaker evidence than the +4 case and it is worth saying so. At
 * +4 the endbr64 confirms a function entry before we look at the call. At +0
 * there is nothing in front, so a function whose genuine first instruction is
 * `call rel32` would be misread as armed, and disarming it would write nops over
 * a real instruction. Two things bound that: the address must have come from the
 * hook map, and you cannot reach the armed state without a successful arm, which
 * required a nop pad. Verifying the displacement points at the trampoline is the
 * real fix and belongs with per-site arm state, which does not exist yet.
 */
static uint8_t *
ls_find_armed(void *fn)
{
    uint8_t *p = (uint8_t *)fn;

    if (memcmp(p, LS_ENDBR, LS_ENDBR_LEN) == 0)
        return p[LS_ENDBR_LEN] == 0xe8 ? p + LS_ENDBR_LEN : NULL;
    return p[0] == 0xe8 ? p : NULL;
}

/*
 * Arm: write `call rel32` over the pad so entering the function calls the
 * trampoline. Returns 0 on success, -1 on refusal.
 *
 * rel32 is relative to the END of the call (pad + 5), and must fit in a signed
 * 32-bit displacement --- checked, because a trampoline out of ±2GB range cannot
 * be reached by five bytes and the alternative is a torn indirect jump. Fail
 * closed rather than emit a call to the wrong place.
 */
/*
 * Write `len` bytes to executed code at `dst`, opcode byte LAST so the 5-byte
 * window is never a call-with-garbage-target.
 *
 * The write goes through /proc/self/mem --- the path a debugger uses to set a
 * breakpoint in its target's r-xp text. A process's own .text is mapped private
 * (r-xp), so a plain store faults (not writable) and mprotect-then-store depends
 * on a W^X policy that may deny PROT_EXEC|PROT_WRITE on the production node.
 * /proc/self/mem needs neither: the kernel writes through to the page the CPU
 * actually fetches.
 *
 * This CORRECTS an earlier finding here that claimed the opposite. That test read
 * the bytes back with a normal load and saw them "stale" --- but a load and an
 * instruction fetch can see different pages mid copy-on-write, so the readback
 * lied. Testing EXECUTION instead (write INT3 to a real function's pad, then CALL
 * it) shows the write IS fetched: it traps. Proven on real private .text by
 * patchtext2 (control clean, pad INT3 traps SIGTRAP, restore reversible) and by
 * the full multi-core swap in check_swap_realtext.c (clean under contention).
 *
 * Single-writer primitive. The cross-core coordination --- INT3 dance plus
 * membarrier so no other core runs a torn or stale instruction --- is the safe
 * point (item 0, built in check_swap.c), not here.
 */
static int
ls_write_text(void *dst, const uint8_t *bytes, size_t len)
{
    int fd = open("/proc/self/mem", O_RDWR);
    if (fd < 0)
        return -1;
    off_t at = (off_t)(uintptr_t)dst;
    int rc = -1;
    /* displacement first (bytes 1..len-1), then the opcode byte (0) last */
    if (len > 1 && pwrite(fd, bytes + 1, len - 1, at + 1) != (ssize_t)(len - 1))
        goto out;
    if (pwrite(fd, bytes, 1, at) != 1)
        goto out;
    rc = 0;
out:
    close(fd);
    return rc;
}

int
ls_arm(void *fn, void *trampoline)
{
    uint8_t *pad = ls_find_pad(fn);
    if (pad == NULL)
        return -1;

    int64_t disp = (int64_t)((uint8_t *)trampoline - (pad + LS_PAD_LEN));
    if (disp < INT32_MIN || disp > INT32_MAX) {
        fprintf(stderr, "ls_arm: trampoline out of rel32 range (%lld) --- refusing\n",
                (long long)disp);
        return -1;
    }

    uint8_t patch[LS_PAD_LEN];
    patch[0] = 0xe8;                        /* call rel32                       */
    int32_t d32 = (int32_t)disp;
    memcpy(patch + 1, &d32, 4);

    /*
     * Order: write the four displacement bytes, THEN the 0xe8 opcode, so a
     * concurrent fetch never sees a call with a garbage target. Single-writer
     * ordering only; the cross-core serialisation is item 0.
     *
     * ls_write_text reaches executed memory through /proc/self/mem --- the path
     * live patchers and debuggers use --- so no writable alias and no mprotect are
     * needed on the process's own r-xp text. (Proven; see ls_write_text.)
     */
    uint8_t bytes[LS_PAD_LEN];
    bytes[0] = patch[0];
    memcpy(bytes + 1, patch + 1, 4);
    if (ls_write_text(pad, bytes, LS_PAD_LEN) != 0)
        return -1;

    __builtin___clear_cache((char *)pad, (char *)pad + LS_PAD_LEN);

    if (pad[0] != 0xe8) {
        fprintf(stderr, "ls_arm: write did not take (pad[0]=0x%02x)\n", pad[0]);
        return -1;
    }
    return 0;
}

/*
 * Disarm: restore the five nops. Refuses unless the entry currently holds a
 * `call` over an endbr64 --- disarming something that is not armed would write
 * nops over whatever is actually there.
 */
int
ls_disarm(void *fn)
{
    uint8_t *pad = ls_find_armed(fn);
    if (pad == NULL)
        return -1;                          /* not armed --- refuse             */

    /* Nop the opcode first (0x90) so no core enters a half-restored call, then
     * the rest. Same /proc/self/mem path as arming. */
    uint8_t restore[LS_PAD_LEN] = { 0x90, 0x90, 0x90, 0x90, 0x90 };
    if (ls_write_text(pad, restore, LS_PAD_LEN) != 0)
        return -1;
    __builtin___clear_cache((char *)pad, (char *)pad + LS_PAD_LEN);
    if (pad[0] != 0x90)
        return -1;
    return 0;
}


/* ---------------------------------------------------------------------------
 * LIVE arming --- the whole point of the mechanism.
 *
 * Called on a RUNNING TMM (from the load path) while the per-core poll threads
 * are executing. The five pad bytes are rewritten by ls_swap_write5(), so no
 * core can observe a torn or stale instruction. No rebuild, no restart.
 * ------------------------------------------------------------------------ */
extern void ls_trampoline_entry(void);
extern unsigned char ls_tramp_slot_insn[];

/* Which slot the single shared immediate currently holds, and how many hooks depend
 * on it. See the refusal in ls_arm_live. */
static int g_armed_slot  = -1;
static int g_armed_count;

int
ls_arm_live(void *fn, void *trampoline, int slot)
{
    uint8_t *pad = ls_find_pad(fn);
    if (pad == NULL) {
        fprintf(stderr, "ls_arm: 0x%llx has no patchable pad --- refusing\n",
                (unsigned long long)(uintptr_t)fn);
        return -1;
    }
    int64_t disp = (int64_t)((uint8_t *)trampoline - (pad + LS_PAD_LEN));
    if (disp < INT32_MIN || disp > INT32_MAX) {
        fprintf(stderr, "ls_arm: trampoline out of rel32 range --- refusing\n");
        return -1;
    }
    /* bake the slot into the trampoline immediate, then swap in the call */
    /* The slot immediate is 4 bytes, and nothing is calling the trampoline yet
     * (the target is still unarmed), so a plain write is correct. The INT3 swap
     * is only for the 5 bytes that ARE being executed. */
    /*
     * ONE TRAMPOLINE, ONE SLOT IMMEDIATE --- AND THAT IS A HARD CONSTRAINT.
     *
     * There is a single ls_trampoline_entry in .text with a single
     * ls_tramp_slot_insn. Writing the slot here rewrites it for EVERY hook already
     * armed, so arming a second hook with a DIFFERENT slot silently re-points all
     * of them at the new slot's ctx builder.
     *
     * That is not theoretical. On 2026-08-17 four reset functions were armed with
     * slots 5, 6, 3, 3 in that order. The immediate ended at 3, so every armed
     * site --- including rst_why --- dispatched through the rst_why_preserve
     * builder, which reads the cause from a4 instead of a5. a4 is `reason`, which
     * is 0, so every record came back with an empty cause. Nothing failed, nothing
     * logged, and the wrong field was blamed for an hour.
     *
     * The trampoline's own header anticipated this: it says "one trampoline per
     * armed hook, so the slot is known when the trampoline is created", and notes
     * that a SHARED trampoline "would have to recover the slot from the return
     * address". The code took the shared route without taking that consequence.
     *
     * Until it is per-hook, hooks armed together MUST share a slot. Refused rather
     * than warned: a warning on a data-plane path nobody is reading is the same as
     * silence, and the failure it prevents is silently-wrong records.
     */
    if (g_armed_count > 0 && g_armed_slot != slot) {
        fprintf(stderr,
                "ls_arm: REFUSING slot %d --- %d hook(s) already armed on slot %d, "
                "and there is ONE shared slot immediate. Arming this would re-point "
                "every armed hook at slot %d's ctx builder and silently corrupt their "
                "records. Disarm first, or arm both on the same slot (legal only if "
                "their argument shapes match).\n",
                slot, g_armed_count, g_armed_slot, slot);
        return -1;
    }

    int32_t imm = slot;
    if (ls_write_text(ls_tramp_slot_insn + 1, (const uint8_t *)&imm, 4) != 0) {
        fprintf(stderr, "ls_arm: could not set slot immediate --- refusing\n");
        return -1;
    }
    __builtin___clear_cache((char *)ls_tramp_slot_insn,
                            (char *)ls_tramp_slot_insn + 8);
    uint8_t patch[LS_PAD_LEN];
    patch[0] = 0xe8;
    int32_t d32 = (int32_t)disp;
    memcpy(patch + 1, &d32, 4);
    if (ls_swap_write5(pad, patch) != 0)
        return -1;

    /* Only now, after the patch actually landed. Counting an arm that failed would
     * make the guard refuse a slot nothing is using. */
    g_armed_slot = slot;
    g_armed_count++;

    fprintf(stderr, "ls_arm: ARMED LIVE entry=%p slot=%d tramp=%p (armed=%d)\n",
            fn, slot, trampoline, g_armed_count);
    return 0;
}

int
ls_disarm_live(void *fn)
{
    uint8_t *pad = ls_find_armed(fn);       /* +4 or +0, whichever this entry uses */
    if (pad == NULL)
        return -1;
    static const uint8_t nops[LS_PAD_LEN] = { 0x90,0x90,0x90,0x90,0x90 };
    if (ls_swap_write5(pad, nops) != 0)
        return -1;

    /* Release the shared slot once the last hook goes. Clamped at zero rather than
     * asserted: ls_find_armed already refused anything not actually armed, so a
     * negative count would mean this file's own bookkeeping drifted, and dropping to
     * a state where NO slot is reserved is the safe direction --- it permits the next
     * arm rather than locking the mechanism out. */
    if (g_armed_count > 0)
        g_armed_count--;
    if (g_armed_count == 0)
        g_armed_slot = -1;

    fprintf(stderr, "ls_arm: DISARMED LIVE entry=%p (armed=%d)\n", fn, g_armed_count);
    return 0;
}
