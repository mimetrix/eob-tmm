/* check_sslerr.c --- the ssl__err record and its builder.
 *
 * WHY THE ASSERTIONS ARE MOSTLY BOUNDARIES. This builder runs on TLS error paths,
 * where state is already unusual and a faulting tracepoint does the most damage. The
 * cases that matter are the ones producing PLAUSIBLE WRONG OUTPUT rather than obvious
 * failure: an over-long name silently cut without the length saying so, one NULL
 * pointer costing us the other field, a string bleeding into its neighbour because the
 * previous record was longer.
 *
 * THE SIZE ASSERTION IS THE LOAD-BEARING ONE. PREVAIL refuses a ctx access past 96
 * bytes, so growing either array must fail HERE, at build time, rather than later at
 * verification with "Upper bound must be at most 96" --- which is a message about a
 * program, printed nowhere near the header that caused it.
 */
#include "ls_ctx_sslerr.h"

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* PREVAIL's ceiling, measured 2026-08-18 rather than assumed: a program reading byte
 * 95 of a 96-byte ctx verifies; byte 99 of a 100-byte ctx is refused. */
#define LS_PREVAIL_CTX_MAX 96u

_Static_assert(sizeof(struct ls_ctx_sslerr) == 96,
               "record must be exactly 96 bytes --- the measured PREVAIL ctx ceiling");
_Static_assert(sizeof(struct ls_ctx_sslerr) <= LS_PREVAIL_CTX_MAX,
               "record exceeds PREVAIL's fentry ctx ceiling; shrink func[] or msg[]");
_Static_assert(_Alignof(struct ls_ctx_sslerr) == 4,
               "alignment must stay 4 --- a 64-bit member rounds sizeof past the ceiling");

/* Field order is part of the wire contract with the program-side mirror and the drain.
 * Pin it, so a reordering edit fails the build instead of shifting every field. */
_Static_assert(offsetof(struct ls_ctx_sslerr, cookie_lo) == 0,  "cookie_lo at 0");
_Static_assert(offsetof(struct ls_ctx_sslerr, cookie_hi) == 4,  "cookie_hi at 4");
_Static_assert(offsetof(struct ls_ctx_sslerr, lineno)    == 8,  "lineno at 8");
_Static_assert(offsetof(struct ls_ctx_sslerr, alert)     == 12, "alert at 12");
_Static_assert(offsetof(struct ls_ctx_sslerr, func_len)  == 16, "func_len at 16");
_Static_assert(offsetof(struct ls_ctx_sslerr, msg_len)   == 20, "msg_len at 20");
_Static_assert(offsetof(struct ls_ctx_sslerr, func)      == 24, "func at 24");
_Static_assert(offsetof(struct ls_ctx_sslerr, msg)       == 56, "msg at 56");

static int n_assert;
#define CHECK(c) do { assert(c); n_assert++; } while (0)

/* Poison the record before every build, so a field the builder fails to write shows up
 * as garbage rather than as a plausible zero left by the previous test. */
static void
poison(struct ls_ctx_sslerr *c)
{
    memset(c, 0xA5, sizeof *c);
}

int
main(void)
{
    struct ls_ctx_sslerr c;

    /* --- 1. the ordinary case ------------------------------------------------ */
    poison(&c);
    ls_ctx_sslerr_build(&c, LS_SSL_A_HANDSHAKE_FAILURE,
                        "ssl_hs_process_client_hello", 3551,
                        "no shared cipher", 0x00003a0c137fafbaULL);
    CHECK(c.alert == LS_SSL_A_HANDSHAKE_FAILURE);
    CHECK(c.lineno == 3551);
    CHECK(strcmp(c.func, "ssl_hs_process_client_hello") == 0);
    CHECK(strcmp(c.msg, "no shared cipher") == 0);
    CHECK(c.func_len == strlen("ssl_hs_process_client_hello"));
    CHECK(c.msg_len == strlen("no shared cipher"));
    /* The cookie must survive the split and reassemble bit-exactly --- a consumer
     * correlating a TLS failure with the reset that followed compares these. */
    CHECK((((unsigned long long)c.cookie_hi << 32) | c.cookie_lo)
          == 0x00003a0c137fafbaULL);
    printf("ok    ordinary record: func, msg, alert, line, cookie round-trip\n");

    /* --- 2. TRUNCATION, and that the length says so -------------------------- */
    poison(&c);
    /* 40 chars, longer than func[32] can hold. Measured max in the tree is 36, so
     * this is the real case rather than a hypothetical. */
    ls_ctx_sslerr_build(&c, 0, "ssl_fwdp_lookup_result_check_and_then_some", 1,
                        "x", 0);
    CHECK(c.func_len == LS_SSLERR_FUNC_MAX - 1);
    CHECK(c.func[LS_SSLERR_FUNC_MAX - 1] == '\0');   /* still NUL-terminated */
    CHECK(strlen(c.func) == LS_SSLERR_FUNC_MAX - 1);
    poison(&c);
    ls_ctx_sslerr_build(&c, 0, "f", 1,
                        "attempt to send unsupported SSLv2 record and more text", 0);
    CHECK(c.msg_len == LS_SSLERR_MSG_MAX - 1);
    CHECK(c.msg[LS_SSLERR_MSG_MAX - 1] == '\0');
    CHECK(strlen(c.msg) == LS_SSLERR_MSG_MAX - 1);
    printf("ok    over-long func and msg truncate, stay NUL-terminated, and the "
           "length reports it\n");

    /* --- 3. EXACT FIT, the off-by-one either side of truncation --------------- */
    {
        char exact[LS_SSLERR_FUNC_MAX];      /* MAX-1 chars + NUL */
        unsigned i;
        for (i = 0; i < LS_SSLERR_FUNC_MAX - 1; i++)
            exact[i] = 'a';
        exact[LS_SSLERR_FUNC_MAX - 1] = '\0';
        poison(&c);
        ls_ctx_sslerr_build(&c, 0, exact, 1, "m", 0);
        CHECK(c.func_len == LS_SSLERR_FUNC_MAX - 1);
        CHECK(strcmp(c.func, exact) == 0);
        printf("ok    a name of exactly MAX-1 fits whole (not silently cut short)\n");
    }

    /* --- 4. NULL POINTERS, guarded INDEPENDENTLY ----------------------------- */
    /* Two unrelated pointers from an error path. One being NULL must not cost us the
     * other, which is the bug an early version of the reset builder had. */
    poison(&c);
    ls_ctx_sslerr_build(&c, 47, 0, 99, "message survives", 0x1122334455667788ULL);
    CHECK(c.func_len == 0);
    CHECK(c.func[0] == '\0');
    CHECK(strcmp(c.msg, "message survives") == 0);
    CHECK(c.msg_len == strlen("message survives"));
    CHECK(c.lineno == 99 && c.alert == 47);
    CHECK(c.cookie_lo == 0x55667788u && c.cookie_hi == 0x11223344u);

    poison(&c);
    ls_ctx_sslerr_build(&c, 47, "func_survives", 99, 0, 0);
    CHECK(c.msg_len == 0);
    CHECK(c.msg[0] == '\0');
    CHECK(strcmp(c.func, "func_survives") == 0);

    poison(&c);
    ls_ctx_sslerr_build(&c, 0, 0, 0, 0, 0);
    CHECK(c.func_len == 0 && c.msg_len == 0);
    CHECK(c.func[0] == '\0' && c.msg[0] == '\0');
    printf("ok    a NULL func does not cost msg, nor the reverse; both NULL is safe\n");

    /* --- 5. NO BLEED between records ----------------------------------------- */
    /* Build a long one, then a short one into the SAME struct. Every byte past the
     * short string must be zero --- otherwise a consumer reading msg[] as a buffer
     * sees the previous record's tail, which decodes as plausible text. */
    poison(&c);
    ls_ctx_sslerr_build(&c, 0, "a_very_long_function_name_here", 1,
                        "a considerably longer message than the next", 0);
    ls_ctx_sslerr_build(&c, 0, "f", 2, "m", 0);
    {
        unsigned i;
        for (i = 1; i < LS_SSLERR_FUNC_MAX; i++)
            CHECK(c.func[i] == '\0');
        for (i = 1; i < LS_SSLERR_MSG_MAX; i++)
            CHECK(c.msg[i] == '\0');
    }
    printf("ok    a shorter record leaves no tail of the previous one\n");

    /* --- 6. EMPTY STRINGS are not NULL -------------------------------------- */
    poison(&c);
    ls_ctx_sslerr_build(&c, 0, "", 1, "", 0);
    CHECK(c.func_len == 0 && c.msg_len == 0);
    CHECK(c.func[0] == '\0' && c.msg[0] == '\0');
    printf("ok    empty strings give len 0 and a terminated buffer\n");

    /* --- 7. a zero cookie is a legitimate value, not an error ---------------- */
    /* ssl__err can fire before a connflow is attached, so the builder must record 0
     * rather than the caller having to special-case it. */
    poison(&c);
    ls_ctx_sslerr_build(&c, 0, "f", 1, "m", 0);
    CHECK(c.cookie_lo == 0 && c.cookie_hi == 0);
    printf("ok    cookie 0 stored as 0 --- 'no flow' is a value, not a failure\n");

    printf("ok    ls_ctx_sslerr.h  (%d assertions, 96 bytes AT the measured "
           "PREVAIL ceiling)\n", n_assert);
    return 0;
}
