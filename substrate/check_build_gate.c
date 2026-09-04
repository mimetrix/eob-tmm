/* check_build_gate.c --- assert the build gate, off-TMM.
 *
 * The gap this closes (CONTESTED-PREMISES.md 15) existed for weeks behind THREE
 * signals that all read as "enforced": the field is in the signed binding,
 * check_sig.c proves tampering with it is detected, and every audit record prints
 * it. What was missing was an assertion that the loader ACTS on it.
 *
 * So the assertions here are deliberately about the decision, not the plumbing:
 * every verdict reachable, the wildcard accepted, a hash range refused rather
 * than waved through, and an unreadable build id failing CLOSED once a range has
 * been asserted -- because "could not parse, so allow" is the failure this whole
 * file exists to prevent.
 *
 * Build: cc -O2 -Wall -Wextra -Werror -I. check_build_gate.c -o check_build_gate
 */
#include <stdio.h>
#include <string.h>
#include "ls_build_gate.h"

static int fails;

#define OK(cond, ...) do {                                              \
        if (cond) { printf("  ok    "); printf(__VA_ARGS__); }          \
        else      { printf("  FAIL  "); printf(__VA_ARGS__); fails++; } \
        printf("\n");                                                   \
    } while (0)

/* The real build id of the binary this work was done against. Written out in
 * full rather than as a prefix so the test says which binary it means. */
static const char *REAL = "269b5d25ad5ddde2cce0ea77bb883ab294a765fc";

int
main(void)
{
    printf("check_build_gate --- the signed build range, finally compared to something\n\n");

    printf("prefix encoding (first 4 bytes, big-endian)\n");
    {
        int ok = 0;
        uint32_t p = ls_build_prefix(REAL, &ok);
        OK(ok && p == 0x269b5d25u, "%s -> %#x (want 0x269b5d25)", "269b5d25...", p);

        ok = 0; (void)ls_build_prefix("269b5d2", &ok);
        OK(!ok, "a 7-digit id is refused, not zero-extended");

        ok = 0; (void)ls_build_prefix("269b5d2z", &ok);
        OK(!ok, "a non-hex digit is refused");

        ok = 0; (void)ls_build_prefix(NULL, &ok);
        OK(!ok, "NULL is refused");

        ok = 0; p = ls_build_prefix("269B5D25", &ok);
        OK(ok && p == 0x269b5d25u, "uppercase hex parses identically");

        ok = 0; p = ls_build_prefix("00000000ff", &ok);
        OK(ok && p == 0u, "a genuinely zero prefix parses as 0 and is VALID -- "
                          "distinct from a parse failure");
    }

    printf("\nthe decision\n");
    {
        uint32_t run = 0;
        enum ls_build_verdict v;

        v = ls_build_gate(REAL, 0x269b5d25u, 0x269b5d25u, &run);
        OK(v == LS_BUILD_OK && run == 0x269b5d25u,
           "min == max == this build            -> OK");

        v = ls_build_gate(REAL, 0x11111111u, 0x11111111u, &run);
        OK(v == LS_BUILD_MISMATCH,
           "min == max == a DIFFERENT build     -> MISMATCH  (the whole point)");

        v = ls_build_gate(REAL, LS_BUILD_WILDCARD_MIN, LS_BUILD_WILDCARD_MAX, &run);
        OK(v == LS_BUILD_WILDCARD,
           "0 .. 0xffffffff                     -> WILDCARD  (every program the "
           "pipeline has ever signed)");

        v = ls_build_gate(REAL, 0x00000000u, 0x269b5d25u, &run);
        OK(v == LS_BUILD_BAD_RANGE,
           "0 .. this build                     -> BAD_RANGE, not a pass -- a "
           "partial range over a hash means nothing");

        v = ls_build_gate(REAL, 0x269b5d25u, 0xffffffffu, &run);
        OK(v == LS_BUILD_BAD_RANGE,
           "this build .. 0xffffffff            -> BAD_RANGE");

        v = ls_build_gate(REAL, 0x269b5d26u, 0x269b5d24u, &run);
        OK(v == LS_BUILD_BAD_RANGE,
           "an INVERTED range                   -> BAD_RANGE (never silently empty)");
    }

    printf("\nfail-closed\n");
    {
        uint32_t run = 0xdeadbeef;
        enum ls_build_verdict v;

        v = ls_build_gate(NULL, 0x269b5d25u, 0x269b5d25u, &run);
        OK(v == LS_BUILD_NO_ID,
           "no running build id + a range asserted -> NO_ID, refused");
        OK(run == 0,
           "and the out-param is cleared, so a log line cannot print stack garbage "
           "as a build id");

        v = ls_build_gate("", 0x269b5d25u, 0x269b5d25u, &run);
        OK(v == LS_BUILD_NO_ID, "an EMPTY build id is refused, not treated as 0");

        /* Ordering matters and is asserted, not assumed: the wildcard is decided
         * before the id is required, so shipping this gate cannot break a load on
         * a binary whose build-id note we fail to parse. */
        v = ls_build_gate(NULL, LS_BUILD_WILDCARD_MIN, LS_BUILD_WILDCARD_MAX, &run);
        OK(v == LS_BUILD_WILDCARD,
           "no build id + WILDCARD                 -> still WILDCARD, so this gate "
           "arriving cannot brick an unparseable binary");
    }

    printf("\nevery verdict has a distinct message\n");
    {
        const enum ls_build_verdict all[] = {
            LS_BUILD_OK, LS_BUILD_WILDCARD, LS_BUILD_MISMATCH,
            LS_BUILD_BAD_RANGE, LS_BUILD_NO_ID
        };
        int n = (int)(sizeof all / sizeof all[0]), distinct = 1;
        for (int i = 0; i < n; i++)
            for (int j = i + 1; j < n; j++)
                if (strcmp(ls_build_strerror(all[i]), ls_build_strerror(all[j])) == 0)
                    distinct = 0;
        OK(distinct, "5 verdicts, 5 different strings -- a refusal names its reason");
    }

    printf("\n%s (%d failure%s)\n", fails ? "*** FAILED" : "all assertions passed",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
