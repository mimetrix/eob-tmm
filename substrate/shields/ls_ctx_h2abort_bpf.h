/* The program's copy of the HTTP/2 stream-abort record --- substrate/ls_ctx_h2abort.h.
 * Two definitions of one layout in two compilers; the assertions make a divergence a
 * build failure rather than a program reading the wrong field at run time. */
#ifndef LS_CTX_H2ABORT_BPF_H
#define LS_CTX_H2ABORT_BPF_H

#define LS_H2ABORT_WHY_MAX 36u

struct ls_ctx_h2abort {
    unsigned int stream_id;   /* folded from the stream pointer --- identity, not address */
    unsigned int error;       /* enum http2_error                                         */
    unsigned int why_len;     /* bytes copied; MAX-1 means the reason was truncated        */
    char         why[LS_H2ABORT_WHY_MAX];
};

_Static_assert(sizeof(struct ls_ctx_h2abort) == 48,
               "h2abort record must be 48 bytes --- host and program disagree");
_Static_assert(__builtin_offsetof(struct ls_ctx_h2abort, stream_id) == 0, "stream_id@0");
_Static_assert(__builtin_offsetof(struct ls_ctx_h2abort, error)     == 4, "error@4");
_Static_assert(__builtin_offsetof(struct ls_ctx_h2abort, why_len)   == 8, "why_len@8");
_Static_assert(__builtin_offsetof(struct ls_ctx_h2abort, why)       == 12, "why@12");

#define LS_FALLTHROUGH 0ull
#define LS_SAFE_RETURN 1ull

#endif /* LS_CTX_H2ABORT_BPF_H */
