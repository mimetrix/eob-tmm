/* The program's copy of the reset record --- substrate/ls_ctx_rst.h.
 * Two definitions of one layout in two compilers; the assertion is what makes a
 * divergence a build failure rather than garbage at runtime. */
#ifndef LS_CTX_RST_BPF_H
#define LS_CTX_RST_BPF_H

#define LS_RST_FILE_MAX 48u

struct ls_ctx_rst {
    unsigned int lineno;
    unsigned int err;
    unsigned int reason;
    unsigned int file_len;
    char         file[LS_RST_FILE_MAX];
};

_Static_assert(sizeof(struct ls_ctx_rst) == 64,
               "reset record must be 64 bytes --- host and program disagree");
_Static_assert(sizeof(struct ls_ctx_rst) <= 96,
               "PREVAIL's fentry ctx is 96 bytes; a larger struct cannot be read");

#define LS_ERR_EXPIRED  15u
#define LS_ERR_REJECT   16u
#define LS_ERR_UNKNOWN  32u

#define LS_FALLTHROUGH 0u
#define LS_SAFE_RETURN 1u
#endif
