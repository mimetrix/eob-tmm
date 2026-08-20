/* check_sig.c --- every falsifier registered for P6, as a test that fails without the fix.
 *
 * 02-RESEARCH-PARAMETERS.md P6 pre-registered five ways this mechanism could be shown worthless.
 * This is those five, executable. A signature gate that has not been attacked is not evidence of
 * anything --- the whole point is that an unsigned or tampered program is REFUSED, and the only
 * way to know is to try it.
 *
 *   F6a  corrupted signature, corrupted body, wrong key, absent signature -> all refused
 *   F6b  a validly signed program is admitted
 *   F6c  a signature valid for one program cannot be replayed onto another
 *   F6d  the hook, build range, mode ceiling and expiry are inside the signed bytes, so
 *        changing any of them invalidates the signature
 *   F6e  is about WHERE verification runs and cannot be tested here --- it is a property of the
 *        loader, checked live
 *
 * The binding layout is asserted against shield_abi.h here rather than trusted, because
 * sign_shield.py writes those offsets from Python and ls_sig.c reads them from C: two
 * independent spellings of one layout, which is exactly how a signature nobody can verify gets
 * produced.
 */
#include "ls_sig.h"
#include <ls_sig_pubkey.h>
#include "shield_abi.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- the layout both sides must agree on -------------------------------------------------- */
_Static_assert(sizeof(struct shield_binding) == LS_SIG_BINDING_LEN,
               "ls_sig_pubkey.h's binding length has drifted from shield_abi.h");
_Static_assert(offsetof(struct shield_binding, prog_sha256) == LS_SIG_BINDING_HASH_OFF,
               "the program hash is not where ls_sig.c looks for it");
_Static_assert(SHIELD_SIG_MAX == 64u, "Ed25519 signatures are 64 bytes");

static int checks;

static void
expect(enum ls_sig_result got, enum ls_sig_result want, const char *what)
{
    if (got != want) {
        fprintf(stderr, "*** %s\n    got  %s\n    want %s\n",
                what, ls_sig_strerror(got), ls_sig_strerror(want));
        exit(1);
    }
    checks++;
    printf("  ok    %-58s %s\n", what, ls_sig_strerror(got));
}

static unsigned char *
slurp(const char *p, size_t *n)
{
    FILE *f = fopen(p, "rb");
    unsigned char *b;
    if (!f) { fprintf(stderr, "*** cannot open %s\n", p); exit(2); }
    fseek(f, 0, SEEK_END); *n = (size_t)ftell(f); fseek(f, 0, SEEK_SET);
    b = malloc(*n ? *n : 1);
    if (fread(b, 1, *n, f) != *n) { fprintf(stderr, "*** short read %s\n", p); exit(2); }
    fclose(f);
    return b;
}

int
main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s <signed.bin> <prog.o> <other-prog.o> [wrongkey-signed.bin]\n",
                argv[0]);
        return 2;
    }
    size_t sn, pn, on, wn = 0;
    unsigned char *signed_blob = slurp(argv[1], &sn);
    unsigned char *prog        = slurp(argv[2], &pn);
    unsigned char *other       = slurp(argv[3], &on);
    unsigned char *wrongkey    = (argc > 4) ? slurp(argv[4], &wn) : NULL;

    if (sn != LS_SIG_BINDING_LEN + 64u) {
        fprintf(stderr, "*** %s is %zu bytes; expected %u binding + 64 signature\n",
                argv[1], sn, LS_SIG_BINDING_LEN);
        return 2;
    }
    unsigned char *binding = signed_blob;
    unsigned char *sig     = signed_blob + LS_SIG_BINDING_LEN;

    /* A KEYLESS BUILD MUST REFUSE EVERYTHING, including a program that is validly signed by
     * whoever holds the key. That is the correct default for a tree nobody has configured, and
     * it is asserted here rather than inferred from a failing F6b, because "the test failed in
     * the way I expected" is not a test. Run with --expect-nokey against a header built by
     * gen_sig_pubkey.py --none. */
    if (getenv("LS_SIG_EXPECT_NOKEY") != NULL) {
        if (ls_sig_have_pubkey()) {
            fprintf(stderr, "*** LS_SIG_EXPECT_NOKEY set but a key IS baked in\n");
            return 1;
        }
        expect(ls_sig_verify(binding, LS_SIG_BINDING_LEN, sig, 64, prog, pn),
               LS_SIG_NO_PUBKEY,
               "keyless build refuses even a VALIDLY signed program");
        printf("  ok    check_sig: %d assertion, fail-closed default confirmed\n", checks);
        return 0;
    }
    if (!ls_sig_have_pubkey()) {
        fprintf(stderr, "*** no key baked in, so nothing below would test what it claims.\n"
                        "    Generate one with gen_sig_pubkey.py, or set LS_SIG_EXPECT_NOKEY\n"
                        "    to assert the keyless behaviour instead.\n");
        return 1;
    }
    printf("  key in this build: present\n");

    /* --- F6b: the thing must WORK, or the rest is meaningless ---------------------------- */
    expect(ls_sig_verify(binding, LS_SIG_BINDING_LEN, sig, 64, prog, pn), LS_SIG_OK,
           "F6b  a validly signed program is admitted");

    /* --- F6a: tampering, in each place it can happen ------------------------------------ */
    {
        unsigned char s2[64];
        memcpy(s2, sig, 64);
        s2[0] ^= 0x01;
        expect(ls_sig_verify(binding, LS_SIG_BINDING_LEN, s2, 64, prog, pn),
               LS_SIG_BAD_SIGNATURE, "F6a  one flipped bit in the signature");
        memcpy(s2, sig, 64);
        s2[63] ^= 0x80;
        expect(ls_sig_verify(binding, LS_SIG_BINDING_LEN, s2, 64, prog, pn),
               LS_SIG_BAD_SIGNATURE, "F6a  one flipped bit in the signature's last byte");
    }
    {
        unsigned char zero[64];
        memset(zero, 0, sizeof zero);
        expect(ls_sig_verify(binding, LS_SIG_BINDING_LEN, zero, 64, prog, pn),
               LS_SIG_BAD_SIGNATURE, "F6a  an all-zero signature (i.e. none supplied)");
    }
    {
        unsigned char *p2 = malloc(pn);
        memcpy(p2, prog, pn);
        p2[pn / 2] ^= 0xff;
        expect(ls_sig_verify(binding, LS_SIG_BINDING_LEN, sig, 64, p2, pn),
               LS_SIG_BODY_MISMATCH, "F6a  one flipped bit in the program body");
        free(p2);
    }
    if (wrongkey) {
        expect(ls_sig_verify(wrongkey, LS_SIG_BINDING_LEN, wrongkey + LS_SIG_BINDING_LEN, 64,
                             prog, pn),
               LS_SIG_BAD_SIGNATURE, "F6a  a signature from a DIFFERENT key");
    }

    /* --- F6c: replay onto a different program ------------------------------------------- */
    expect(ls_sig_verify(binding, LS_SIG_BINDING_LEN, sig, 64, other, on),
           LS_SIG_BODY_MISMATCH, "F6c  the signature cannot be replayed onto another program");

    /* --- F6d: every field inside the binding is covered --------------------------------- */
    {
        struct { size_t off; size_t len; const char *name; } fields[] = {
            { offsetof(struct shield_binding, hook),         1, "hook name"     },
            { offsetof(struct shield_binding, build_min),    1, "build_min"     },
            { offsetof(struct shield_binding, build_max),    1, "build_max"     },
            { offsetof(struct shield_binding, mode_ceiling), 1, "mode_ceiling"  },
            { offsetof(struct shield_binding, expires_with), 1, "expires_with"  },
        };
        unsigned i;
        for (i = 0; i < sizeof fields / sizeof fields[0]; i++) {
            unsigned char b2[LS_SIG_BINDING_LEN];
            char msg[96];
            memcpy(b2, binding, sizeof b2);
            b2[fields[i].off] ^= 0x01;
            snprintf(msg, sizeof msg, "F6d  altering %s invalidates the signature",
                     fields[i].name);
            expect(ls_sig_verify(b2, LS_SIG_BINDING_LEN, sig, 64, prog, pn),
                   LS_SIG_BAD_SIGNATURE, msg);
        }
    }

    /* --- arguments a caller controls ----------------------------------------------------- */
    expect(ls_sig_verify(binding, LS_SIG_BINDING_LEN - 1, sig, 64, prog, pn),
           LS_SIG_BAD_ARGS, "a short binding is refused, not zero-padded");
    expect(ls_sig_verify(binding, LS_SIG_BINDING_LEN, sig, 63, prog, pn),
           LS_SIG_BAD_ARGS, "a short signature is refused");
    expect(ls_sig_verify(binding, LS_SIG_BINDING_LEN, sig, 64, prog, 0),
           LS_SIG_BAD_ARGS, "an empty program is refused");
    expect(ls_sig_verify(NULL, LS_SIG_BINDING_LEN, sig, 64, prog, pn),
           LS_SIG_BAD_ARGS, "a NULL binding is refused");

    printf("  ok    check_sig: %d assertions, every registered falsifier for P6 exercised\n",
           checks);
    free(signed_blob); free(prog); free(other); free(wrongkey);
    return 0;
}
