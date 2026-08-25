/* Flat record for http_parse_client_headers, and the host-side builder that fills it.
 *
 * NO NUMBER ABOUT TMM'S LAYOUT IS WRITTEN HERE. Offsets, bit shifts, masks, struct sizes and the
 * parser-state bound all arrive from ls_ctx_parse_offsets.h, which mk_ctx_parse.py derives from a
 * build artifact. Field NAMES are specification -- which of TMM's fields the program may see is a
 * design choice -- but every number is read out of the build.
 *
 * WHY, AND IT IS NOT HYPOTHETICAL. This file used to open "GENERATED for build 1778975c" above
 * seven hand-written #defines. On 2026-08-25 the debug tree was e35ed0ed and the cluster was
 * running 499b8c30: three builds, one frozen set of literals, nothing in the tree able to say
 * whether they still held. They did -- verified against TMM's own debuginfo, all seven correct --
 * which is luck, not design, and luck is not a property you can ship. The builder also carried
 * `>> 4` and `& 0x3u` for the version bits; those are generated now too.
 *
 * WHY OFFSETS AT ALL, rather than including TMM's header. ls_tramp.c is compiled STDINC and the
 * structs live in src/modules/hudfilter/http/http_parser.h -- a source-tree header, not an
 * installed one. Reaching it means an include-path change with cascade risk. So the layout is
 * read from the build's DEBUG INFO instead, which needs no include world at all.
 *
 * ABSENCE IS A BUILD FAILURE, not a fallback. An earlier design let the checks compile out when
 * the generated header was missing; a check that silently degrades to "true" is the exact failure
 * this file already made once. See CONTESTED-PREMISES.md 12.
 */
#ifndef LS_CTX_PARSE_H
#define LS_CTX_PARSE_H

#if defined(__has_include)
#  if !__has_include("ls_ctx_parse_offsets.h")
#    error "ls_ctx_parse_offsets.h is missing. Generate it from THIS build: \
substrate/mk_ctx_parse.py --debuginfo <tmm.debug> -o substrate/ls_ctx_parse_offsets.h \
--- there are deliberately no fallback offsets, because a wrong one is silent."
#  endif
#endif
#include "ls_ctx_parse_offsets.h"

typedef unsigned long long ls_u64;
typedef unsigned int       ls_u32;
typedef unsigned short     ls_u16;


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
        /* little-endian: bitfields fill from the LSB. The shift and mask are DERIVED from the
         * declared widths of the fields ahead of `version`, not counted by hand. */
        c->version       = (p[LS_OFF_PI_BITS0] >> LS_PI_VERSION_SHIFT) & LS_PI_VERSION_MASK;
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
#define LS_CTX_PARSE_GATED 1     /* the bound is in the required generated header */

static inline int
ls_ctx_parse_sane(const struct ls_ctx_parse *c, const void *a0, const void *a2)
{
    if (a0 == 0 && a2 == 0)
        return 0;                       /* tier 1: nothing was read */

    if (a0 != 0 && c->state > LS_PARSE_STATE_MAX)
        return 0;                       /* tier 2: not a parser state */
    return 1;
}

#endif /* LS_CTX_PARSE_H */
