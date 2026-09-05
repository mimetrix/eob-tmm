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

        /* THE CASE THE FIRST VERSION OF THIS FILE DID NOT HAVE, and its absence
         * is why 18 assertions passed on a change that would have refused every
         * load, arm, status and disarm the moment it shipped. ls_client.py builds
         * its message as bytearray(HDR) and never sets this field, so EVERY real
         * request carries 0..0 -- which read literally is min == max, the
         * "exactly one build" form, mismatching every real build id.
         *
         * I chose the test cases, so the test agreed with me. The defect was
         * found by going to look at what the client actually sends. */
        v = ls_build_gate(REAL, 0u, 0u, &run);
        OK(v == LS_BUILD_UNDECLARED,
           "0 .. 0 (what ls_client.py sends)  -> UNDECLARED, accepted -- NOT "
           "read as \"build zero\" and refused");

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

    printf("\nundeclared is distinct from the wildcard, and from a real zero build\n");
    {
        uint32_t run = 0;
        OK(ls_build_gate(REAL, 0u, 0u, &run) != ls_build_gate(REAL, 0u, 0xffffffffu, &run),
           "0..0 and 0..0xffffffff are DIFFERENT verdicts -- one is a client that "
           "never set the field, the other is a signature that vouched for every build");
        /* A binary whose build id genuinely begins 00000000 and a program signed
         * for it: the transition rule admits it. Asserted so the trade is explicit
         * rather than discovered later. */
        OK(ls_build_gate("00000000abcd", 0u, 0u, &run) == LS_BUILD_UNDECLARED,
           "a real 0x00000000 build + 0..0 is admitted as UNDECLARED -- the one "
           "value in 2^32 the transition rule cannot distinguish, and it fails OPEN");
    }

    printf("\nexpiry --- a field that was signed, logged, and read by nothing until 2026-09-05\n");
    {
        const uint64_t NOW = 1788000000ull;        /* 2026-09-05-ish, UTC */
        const uint64_t PAST = 1600000000ull;       /* 2020-09 */
        const uint64_t FUTURE = 1900000000ull;     /* 2030-03 */

        OK(ls_expiry_gate(0u, NOW) == LS_EXPIRY_NEVER,
           "0            -> NEVER   (what every client sends today)");
        OK(ls_expiry_gate(0xffffffffu, NOW) == LS_EXPIRY_NEVER,
           "0xffffffff   -> NEVER   (sign_shield.py's default)");
        OK(ls_expiry_gate((uint32_t)FUTURE, NOW) == LS_EXPIRY_OK,
           "a future deadline           -> OK");
        OK(ls_expiry_gate((uint32_t)PAST, NOW) == LS_EXPIRY_EXPIRED,
           "a past deadline             -> EXPIRED, refused");
        OK(ls_expiry_gate((uint32_t)NOW, NOW) == LS_EXPIRY_EXPIRED,
           "the deadline second ITSELF  -> EXPIRED (\"may not load at or after\")");
        OK(ls_expiry_gate((uint32_t)(NOW + 1), NOW) == LS_EXPIRY_OK,
           "one second before it        -> OK, so the boundary is not off by one");

        /* THE ASYMMETRY, ASSERTED SO IT IS NOT "FIXED" LATER BY SOMEONE WHO READS
         * IT AS A BUG. The build gate fails CLOSED on an unreadable id; expiry
         * fails OPEN on an unreadable clock. A shield exists to stop a crash, so
         * refusing one because the box booted before NTP ran converts a clock
         * problem into the outage the shield was preventing. A wrong build is a
         * correctness error; a wrong clock is an environment error. */
        OK(ls_expiry_gate((uint32_t)PAST, 0ull) == LS_EXPIRY_UNKNOWN,
           "an EXPIRED program + a 1970 clock -> UNKNOWN, ACCEPTED, not refused");
        OK(ls_expiry_gate((uint32_t)PAST, (uint64_t)LS_EPOCH_SANE - 1) == LS_EXPIRY_UNKNOWN,
           "one second before the sanity epoch -> still UNKNOWN");
        /* The deadline has to precede the sanity epoch for this to test what it
         * says. My first version used PAST (2020-09), which is AFTER the epoch
         * (2020-01) --- so at now == epoch the deadline had not been reached and OK
         * was the correct answer. The check caught the test, not the code. */
        OK(ls_expiry_gate(1500000000u, (uint64_t)LS_EPOCH_SANE) == LS_EXPIRY_EXPIRED,
           "AT the sanity epoch the clock is trusted again -> a 2017 deadline is EXPIRED");
        OK(ls_expiry_gate((uint32_t)PAST, (uint64_t)LS_EPOCH_SANE) == LS_EXPIRY_OK,
           "and a deadline AFTER the epoch is not yet reached at the epoch -> OK");
        OK(ls_expiry_gate(0u, 0ull) == LS_EXPIRY_NEVER,
           "no deadline + a bad clock -> NEVER; the clock is never consulted");
    }

    printf("\nevery verdict has a distinct message\n");
    {
        const enum ls_build_verdict all[] = {
            LS_BUILD_OK, LS_BUILD_WILDCARD, LS_BUILD_UNDECLARED,
            LS_BUILD_MISMATCH, LS_BUILD_BAD_RANGE, LS_BUILD_NO_ID
        };
        int n = (int)(sizeof all / sizeof all[0]), distinct = 1;
        for (int i = 0; i < n; i++)
            for (int j = i + 1; j < n; j++)
                if (strcmp(ls_build_strerror(all[i]), ls_build_strerror(all[j])) == 0)
                    distinct = 0;
        OK(distinct, "6 build verdicts, 6 different strings -- a refusal names its reason");

        const enum ls_expiry_verdict ex[] = { LS_EXPIRY_OK, LS_EXPIRY_NEVER,
                                              LS_EXPIRY_UNKNOWN, LS_EXPIRY_EXPIRED };
        int m = (int)(sizeof ex / sizeof ex[0]), exd = 1;
        for (int i = 0; i < m; i++)
            for (int j = i + 1; j < m; j++)
                if (strcmp(ls_expiry_strerror(ex[i]), ls_expiry_strerror(ex[j])) == 0)
                    exd = 0;
        OK(exd, "4 expiry verdicts, 4 different strings");
    }

    printf("\n%s (%d failure%s)\n", fails ? "*** FAILED" : "all assertions passed",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
