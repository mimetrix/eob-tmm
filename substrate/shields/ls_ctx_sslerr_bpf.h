/* The program's copy of the ssl__err record --- substrate/ls_ctx_sslerr.h.
 * Two definitions of one layout in two compilers (gcc for the host builder, clang
 * -target bpf for the program); the assertions are what make a divergence a build
 * failure rather than a program reading the wrong field at run time. */
#ifndef LS_CTX_SSLERR_BPF_H
#define LS_CTX_SSLERR_BPF_H

#define LS_SSLERR_FUNC_MAX 32u
#define LS_SSLERR_MSG_MAX  40u

struct ls_ctx_sslerr {
    unsigned int cookie_lo;   /* TMM's flow cookie, split to keep align 4        */
    unsigned int cookie_hi;   /* 0 = no flow, legitimate before a connflow exists */
    unsigned int lineno;      /* __LINE__ of the ssl_err that fired              */
    unsigned int alert;       /* enum ssl_alert --- the TLS AlertDescription      */
    unsigned int func_len;    /* bytes copied; MAX-1 means the name was truncated */
    unsigned int msg_len;     /* bytes copied; MAX-1 means the message was cut    */
    char         func[LS_SSLERR_FUNC_MAX];   /* __func__, NOT __FILE__           */
    char         msg[LS_SSLERR_MSG_MAX];     /* the first vararg                 */
};

/* 96 EXACTLY, which is AT the ceiling rather than under it. Measured 2026-08-18:
 * PREVAIL admits a ctx read at byte 95 of a 96-byte ctx and refuses byte 99 of a
 * 100-byte one with "Upper bound must be at most 96". So this must not grow by a
 * single byte, and the assertion is the only thing that says so at build time. */
_Static_assert(sizeof(struct ls_ctx_sslerr) == 96,
               "sslerr record must be 96 bytes --- host and program disagree");
_Static_assert(sizeof(struct ls_ctx_sslerr) <= 96,
               "PREVAIL's fentry ctx is 96 bytes; a larger struct cannot be read");

/* OFFSETS, not just the size --- because two headers can agree on 96 bytes and disagree
 * on where `alert` is, and then the program reads lineno as the alert code and produces
 * a record that is the right length and the wrong meaning. That exact class of bug (the
 * slot-keyed ctx builder) is what ls_slots.h exists for.
 *
 * __builtin_offsetof rather than offsetof: this header is compiled by clang -target bpf
 * with no libc headers available, so <stddef.h> is not there to include. Same values are
 * asserted host-side in check_sslerr.c. */
_Static_assert(__builtin_offsetof(struct ls_ctx_sslerr, cookie_lo) == 0,  "cookie_lo@0");
_Static_assert(__builtin_offsetof(struct ls_ctx_sslerr, cookie_hi) == 4,  "cookie_hi@4");
_Static_assert(__builtin_offsetof(struct ls_ctx_sslerr, lineno)    == 8,  "lineno@8");
_Static_assert(__builtin_offsetof(struct ls_ctx_sslerr, alert)     == 12, "alert@12");
_Static_assert(__builtin_offsetof(struct ls_ctx_sslerr, func_len)  == 16, "func_len@16");
_Static_assert(__builtin_offsetof(struct ls_ctx_sslerr, msg_len)   == 20, "msg_len@20");
_Static_assert(__builtin_offsetof(struct ls_ctx_sslerr, func)      == 24, "func@24");
_Static_assert(__builtin_offsetof(struct ls_ctx_sslerr, msg)       == 56, "msg@56");

/* The three alerts that account for 383 of the 475 call sites. Wire numbers. */
#define LS_SSL_A_HANDSHAKE_FAILURE 40u
#define LS_SSL_A_ILLEGAL_PARAM     47u
#define LS_SSL_A_INTERNAL_ERROR    80u

/* Verdicts the host applies. A tracepoint program always returns FALLTHROUGH. */
#define LS_FALLTHROUGH 0ull
#define LS_SAFE_RETURN 1ull

#endif /* LS_CTX_SSLERR_BPF_H */
