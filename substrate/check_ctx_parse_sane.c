/* check_ctx_parse_sane.c --- ls_ctx_parse_sane does what its banner claims.
 *
 * The function this file tests did not exist until 2026-08-24, while ls_ctx_parse.h had
 * referred readers to it by name for months (CONTESTED-PREMISES.md 12). A check written to
 * close that gap is worth nothing if it is itself only asserted, so it is executed here.
 *
 * Tier 2 is build-derived, so this file exercises it by defining the bound itself rather than
 * by requiring a generated header --- what is under test is the PREDICATE, not the bound.
 */
#include <stdio.h>
#include <string.h>
#include "ls_ctx_parse.h"

static int fails;
#define T(cond, what) do { if (!(cond)) { printf("  FAIL: %s\n", what); fails++; } } while (0)

int main(void)
{
    struct ls_ctx_parse c;
    char a0_obj, a2_obj;                 /* addresses only --- never dereferenced here */
    const void *a0 = &a0_obj, *a2 = &a2_obj;

    memset(&c, 0, sizeof c);

    /* TIER 1. Both sources null means the builder read nothing and every field is a zero it
     * wrote itself. A verdict over that is fabricated, not cautious. */
    T(ls_ctx_parse_sane(&c, 0, 0) == 0, "both pointers null must be refused");

    /* One real source is enough to have read something. */
    T(ls_ctx_parse_sane(&c, a0, 0) == 1, "a0 present, in-range state must be accepted");
    T(ls_ctx_parse_sane(&c, 0, a2) == 1, "a2 present must be accepted");
    T(ls_ctx_parse_sane(&c, a0, a2) == 1, "both present must be accepted");

    /* TIER 2, only meaningful when a bound exists. A state byte above the enum's greatest
     * enumerator is not a parser state, which is what a wrong offset usually yields. */
#if LS_CTX_PARSE_GATED
    c.state = (ls_u32)LS_PARSE_STATE_MAX;
    T(ls_ctx_parse_sane(&c, a0, 0) == 1, "state exactly at the bound must be accepted");
    c.state = (ls_u32)LS_PARSE_STATE_MAX + 1u;
    T(ls_ctx_parse_sane(&c, a0, 0) == 0, "state above the bound must be refused");
    /* and the bound must not be consulted when a0 was null --- there was no state to read */
    T(ls_ctx_parse_sane(&c, 0, a2) == 1, "out-of-range state is irrelevant when a0 was null");
    printf("  tier 2 ARMED (LS_PARSE_STATE_MAX=%u) --- 7 assertions\n", LS_PARSE_STATE_MAX);
#else
    printf("  tier 2 not armed for this build --- 4 assertions run, 3 skipped.\n");
    printf("  That is the honest state until check_ctx_parse.py --emit-bounds has run\n");
    printf("  against this build's debuginfo. It is NOT a pass of the skipped ones.\n");
#endif

    if (fails) { printf("  %d FAILED\n", fails); return 1; }
    printf("  ls_ctx_parse_sane: all assertions pass\n");
    return 0;
}
