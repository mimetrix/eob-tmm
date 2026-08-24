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
 * build -- but here it is silent if wrong, so the builder checks values it can
 * predict (ls_ctx_parse_sane, below) rather than trusting the numbers.
 *
 * THAT SENTENCE WAS FALSE UNTIL 2026-08-24. It read "see ls_ctx_parse_sane" for
 * months while no such function existed anywhere in the tree -- the one design
 * that would have caught a wrong offset was described, and never written, in a
 * comment phrased as though it had been. It was found by trying to answer
 * "would this have mitigated a real CVE?", which needs exactly this check to
 * have been run. See CONTESTED-PREMISES.md 12.
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


/* ---------------------------------------------------------------------------
 * ls_ctx_parse_sane --- is this record worth handing to a program?
 *
 * TWO TIERS, because they cost different things to know.
 *
 * TIER 1 is build-independent and always compiled: if BOTH source pointers were
 * null, ls_ctx_build_parse read nothing and every field is a zero it wrote
 * itself. A program then decides on data that does not exist, and -- this is the
 * part that matters -- it returns a VERDICT, which the host counts, which a
 * reader takes for a measurement. Declining is not caution here; running is a
 * fabricated answer.
 *
 * TIER 2 is the predictable-value check, and it needs the build to state the
 * bound: `state` is an enum, so it has a greatest enumerator, and a byte read
 * from the WRONG offset lands above it most of the time. check_ctx_parse.py
 * reads that enumerator out of the shipped debug info and writes
 * ls_ctx_parse_bounds.h. Until it has run for a given build there is nothing
 * honest to compare against, so tier 2 compiles out -- and says so at startup
 * rather than passing quietly, because a check that silently degrades to "true"
 * is the failure this file already made once.
 *
 * ONLY `state`, deliberately. `header_count` looks like the better discriminator
 * -- it is a u16, so a wrong offset escapes a tight ceiling far more often than
 * a one-byte enum does. But no ceiling for it exists in the debug info: it would
 * have to be a number someone chose and wrote down as though the build had said
 * it. That is the same move as the comment this file used to carry. A weaker
 * check that is derived beats a stronger one that is invented.
 */
#if defined(__has_include)
#  if __has_include("ls_ctx_parse_bounds.h")
#    include "ls_ctx_parse_bounds.h"
#    define LS_CTX_PARSE_GATED 1
#  endif
#endif
#ifndef LS_CTX_PARSE_GATED
#  define LS_CTX_PARSE_GATED 0
#endif

static inline int
ls_ctx_parse_sane(const struct ls_ctx_parse *c, const void *a0, const void *a2)
{
    if (a0 == 0 && a2 == 0)
        return 0;                       /* tier 1: nothing was read */

#if LS_CTX_PARSE_GATED
    if (a0 != 0 && c->state > LS_PARSE_STATE_MAX)
        return 0;                       /* tier 2: not a parser state */
#else
    (void)c;
#endif
    return 1;
}

#endif /* LS_CTX_PARSE_H */
