/* GENERATED for build 1778975c... --- offsets read from that build's DWARF.
 *
 * THE TRACEPOINT: tmm:l7:parse_error, at http_parse_client_headers.
 * Chosen because it is the ONE function on this traffic's path that provably
 * fires 1:1 with requests (env/scripts/bnk-survey-hooks.sh), and because
 * struct http_parse_info carries the five parse-violation bits that are the
 * signal this tracepoint exists to capture.
 *
 * WHY OFFSETS RATHER THAN FIELD ACCESS. ls_tramp.c is compiled STDINC; the
 * structs live in src/modules/hudfilter/http/http_parser.h, which is a
 * source-tree header, not an installed one. Reaching it means an include-path
 * change or a relative include with cascade risk. Byte offsets make this file
 * self-contained: no headers, no include world to satisfy.
 *
 * THE COST, STATED: these offsets are true for ONE build. That is already the
 * contract for a function-boundary probe -- build-specific, re-validated per
 * build -- but here it is silent if wrong, so the program checks a value it can
 * predict (see ls_ctx_parse_sane) rather than trusting the numbers.
 */
#ifndef LS_CTX_PARSE_H
#define LS_CTX_PARSE_H

typedef unsigned long long ls_u64;
typedef unsigned int       ls_u32;
typedef unsigned short     ls_u16;

/* struct http_parse_ctx  (size 64) */
#define LS_OFF_PC_STATE        10   /* enum parse_state : 8   */
#define LS_OFF_PC_OFFSET       20   /* UINT32                 */
/* struct http_parse_info (size 416) */
#define LS_OFF_PI_BITS0         0   /* is_trailer/is_request/is_crlf/lws_found/version/original_version */
#define LS_OFF_PI_METHOD        1   /* BYTE                   */
#define LS_OFF_PI_HDRCOUNT      2   /* UINT16                 */
#define LS_OFF_PI_STATUS        8   /* int                    */
#define LS_OFF_PI_INVALID      12   /* UINT32 holding 5 flag bits */
#define LS_INVALID_MASK    0x1fu    /* method|scheme|path|status|authority */

/* Flat, no pointers. This is the program's entire world. */
struct ls_ctx_parse {
    ls_u32 state;          /* parser state when headers were parsed  */
    ls_u32 offset;         /* parser offset                          */
    ls_u32 version;        /* HTTP version (2 bits)                  */
    ls_u32 method;         /* HTTP method                            */
    ls_u32 header_count;   /* headers seen                           */
    ls_u32 status_code;    /* status, when this is a response        */
    ls_u32 invalid_flags;  /* 5 parse-violation bits, packed         */
};

/* Runs in the trampoline, ahead of a function that has not executed. Every
 * dereference is guarded: a null here is one the original code was about to
 * check itself, and faulting would be a crash we introduced. */
static inline void
ls_ctx_build_parse(struct ls_ctx_parse *c, const void *a0, const void *a2)
{
    const unsigned char *p;
    unsigned i;
    for (i = 0; i < sizeof *c; i++)
        ((unsigned char *)c)[i] = 0;

    if (a0 != 0) {
        p = (const unsigned char *)a0;
        c->state  = p[LS_OFF_PC_STATE];
        c->offset = *(const ls_u32 *)(p + LS_OFF_PC_OFFSET);
    }
    if (a2 != 0) {
        p = (const unsigned char *)a2;
        /* little-endian: bitfields fill from the LSB, so version is bits 4-5 */
        c->version       = (p[LS_OFF_PI_BITS0] >> 4) & 0x3u;
        c->method        = p[LS_OFF_PI_METHOD];
        c->header_count  = *(const ls_u16 *)(p + LS_OFF_PI_HDRCOUNT);
        c->status_code   = *(const ls_u32 *)(p + LS_OFF_PI_STATUS);
        c->invalid_flags = (*(const ls_u32 *)(p + LS_OFF_PI_INVALID)) & LS_INVALID_MASK;
    }
}

#endif /* LS_CTX_PARSE_H */
