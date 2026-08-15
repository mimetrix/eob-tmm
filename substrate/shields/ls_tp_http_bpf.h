/* The program's copy of the tracepoint record --- substrate/ls_tp_http.h.
 *
 * Two definitions of one layout, in two compilers, and they must agree byte for
 * byte. `unsigned int` is 32 bits on both the TMM x86_64 target and the BPF
 * target, so the layouts match without attributes; the assertion below is what
 * makes a divergence a build failure rather than a field of garbage at runtime.
 *
 * Keeping a second copy is deliberate. The program is compiled by clang for the
 * BPF target with none of TMM's headers available, so it cannot include the
 * host's version. `make check` compiles both and compares sizes.
 */
#ifndef LS_TP_HTTP_BPF_H
#define LS_TP_HTTP_BPF_H

struct ls_tp_http_hdrs {
    unsigned int parse_err;      /* the PARSER's verdict --- classify with this */
    unsigned int err;            /* the filter's final disposition, not the parse */
    unsigned int reject_reason;
    unsigned int passthru;
    unsigned int version;
    unsigned int method;
    unsigned int header_count;
    unsigned int status_code;
    unsigned int invalid_flags;  /* HTTP/2+3 ONLY --- uninitialised on the 1.x path */
    unsigned int body_pos;
    unsigned int hdr_bytes;
};

_Static_assert(sizeof(struct ls_tp_http_hdrs) == 44,
               "tracepoint record must be 44 bytes --- host and program disagree");

/* ERR_MORE_DATA IS NOT A FAULT. It is 17, so `parse_err != 0` counts every
 * header block that spans two packets --- routine HTTP --- as a rejection.
 * Classify with these, never with a zero test. */
#define LS_ERR_OK          0u
#define LS_ERR_VAL         3u   /* CR/LF in a header       */
#define LS_ERR_BOUNDS      5u   /* header count exceeded   */
#define LS_ERR_REJECT     16u   /* unknown method          */
#define LS_ERR_MORE_DATA  17u   /* NORMAL                  */

/* malformed: the parser found a protocol violation. Written out rather than as a
 * range test because the values are not contiguous and a range would silently
 * swallow ERR_MORE_DATA. */
#define LS_TP_MALFORMED(c) \
    ((c)->parse_err == LS_ERR_VAL || (c)->parse_err == LS_ERR_BOUNDS || \
     (c)->parse_err == LS_ERR_REJECT)

/* Verdicts. The tracepoint call site discards these (ls_tp.h), so here they
 * select rather than decide: SAFE_RETURN means "this request is in the set I am
 * counting" and shows up as safe_returns, FALLTHROUGH means it is not. */
#define LS_FALLTHROUGH 0u
#define LS_SAFE_RETURN 1u

/* Mirrors LS_TP_INVALID_* in the host header. */
#define LS_TP_INVALID_METHOD    0x01u
#define LS_TP_INVALID_SCHEME    0x02u
#define LS_TP_INVALID_PATH      0x04u
#define LS_TP_INVALID_STATUS    0x08u
#define LS_TP_INVALID_AUTHORITY 0x10u

#endif /* LS_TP_HTTP_BPF_H */
