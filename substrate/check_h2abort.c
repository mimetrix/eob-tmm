/* check_h2abort.c --- the HTTP/2 stream-abort record and its builder.
 *
 * Same discipline as check_sslerr.c: the assertions that matter are the ones catching
 * PLAUSIBLE WRONG OUTPUT, not obvious failure. This builder runs on an h2 teardown path.
 *
 * The stream-id assertions are the ones specific to this record. It is a FOLDED
 * IDENTITY, not an address, and two properties have to hold or the field is misleading:
 * the same pointer must always give the same id (or you cannot group by stream), and two
 * different streams must not collide merely because they are near each other in memory
 * (or you group unrelated aborts together and conclude one stream is failing).
 */
#include "ls_ctx_h2abort.h"

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

_Static_assert(sizeof(struct ls_ctx_h2abort) == 48,
               "record must be 48 bytes --- host, program and drain all assert this");
_Static_assert(sizeof(struct ls_ctx_h2abort) <= 96,
               "PREVAIL's fentry ctx ceiling is 96 bytes (measured, not assumed)");
_Static_assert(_Alignof(struct ls_ctx_h2abort) == 4, "alignment must stay 4");
_Static_assert(offsetof(struct ls_ctx_h2abort, stream_id) == 0, "stream_id@0");
_Static_assert(offsetof(struct ls_ctx_h2abort, error)     == 4, "error@4");
_Static_assert(offsetof(struct ls_ctx_h2abort, why_len)   == 8, "why_len@8");
_Static_assert(offsetof(struct ls_ctx_h2abort, why)       == 12, "why@12");

static int n_assert;
#define CHECK(c) do { assert(c); n_assert++; } while (0)

static void poison(struct ls_ctx_h2abort *c) { memset(c, 0xA5, sizeof *c); }

int
main(void)
{
    struct ls_ctx_h2abort c;

    /* --- 1. the ordinary case, using a real literal from http2.c --------------- */
    poison(&c);
    ls_ctx_h2abort_build(&c, 0x7f9c00104520ULL, "Malformed Header Frame", 1);
    CHECK(strcmp(c.why, "Malformed Header Frame") == 0);
    CHECK(c.why_len == strlen("Malformed Header Frame"));
    CHECK(c.error == 1);
    CHECK(c.stream_id != 0);
    printf("ok    ordinary record: why, error, stream_id populated\n");

    /* --- 2. THE LONGEST REAL LITERAL fits whole ------------------------------- */
    /* "frame refused due to header size" is 32 chars, the longest of the 23 in
     * http2.c. If the field ever stops holding it, that is a build failure here
     * rather than a truncated string in the feed. */
    poison(&c);
    ls_ctx_h2abort_build(&c, 0x1000ULL, "frame refused due to header size", 7);
    CHECK(c.why_len == 32);
    CHECK(strcmp(c.why, "frame refused due to header size") == 0);
    CHECK(c.why_len < LS_H2ABORT_WHY_MAX - 1);   /* margin remains */
    printf("ok    the longest real literal (32 chars) fits with margin\n");

    /* --- 3. truncation reports itself ---------------------------------------- */
    poison(&c);
    ls_ctx_h2abort_build(&c, 1, "a reason considerably longer than the field can hold", 0);
    CHECK(c.why_len == LS_H2ABORT_WHY_MAX - 1);
    CHECK(c.why[LS_H2ABORT_WHY_MAX - 1] == '\0');
    CHECK(strlen(c.why) == LS_H2ABORT_WHY_MAX - 1);
    printf("ok    an over-long reason truncates, stays terminated, and says so\n");

    /* --- 4. a NULL why is survivable ----------------------------------------- */
    poison(&c);
    ls_ctx_h2abort_build(&c, 0xabcdefULL, 0, 9);
    CHECK(c.why_len == 0);
    CHECK(c.why[0] == '\0');
    CHECK(c.error == 9);            /* the other fields still land */
    printf("ok    a NULL reason costs the string and nothing else\n");

    /* --- 5. STREAM ID: stable, and distinct for nearby streams --------------- */
    {
        struct ls_ctx_h2abort a, b;
        unsigned long long p1 = 0x7f9c00104520ULL;
        /* Adjacent allocations. struct http2_stream is far larger than 16 bytes, so
         * real streams are at least this far apart --- if the fold dropped too many low
         * bits these would collide and six streams would look like one. */
        unsigned long long p2 = p1 + 0x100;

        poison(&a); poison(&b);
        ls_ctx_h2abort_build(&a, p1, "x", 0);
        ls_ctx_h2abort_build(&b, p1, "y", 0);
        CHECK(a.stream_id == b.stream_id);       /* stable for one stream */

        ls_ctx_h2abort_build(&b, p2, "x", 0);
        CHECK(a.stream_id != b.stream_id);       /* distinct for a neighbour */

        /* And a pointer differing only in its HIGH half must not collide --- the fold
         * mixes both halves precisely so two streams on different heaps stay apart. */
        ls_ctx_h2abort_build(&b, p1 ^ (1ULL << 36), "x", 0);
        CHECK(a.stream_id != b.stream_id);
        printf("ok    stream_id is stable per stream and distinct for neighbours "
               "and for a differing high half\n");
    }

    /* --- 6. it is NOT the raw address ---------------------------------------- */
    /* The point of folding is that a host address does not reach a telemetry stream.
     * If the id ever equals the low 32 bits of the pointer, that property is gone. */
    poison(&c);
    {
        unsigned long long p = 0x7f9c00104520ULL;
        ls_ctx_h2abort_build(&c, p, "x", 0);
        CHECK(c.stream_id != (unsigned int)(p & 0xffffffffu));
        CHECK(c.stream_id != (unsigned int)(p >> 32));
        printf("ok    stream_id is not the address, high or low half\n");
    }

    /* --- 7. no bleed between records ---------------------------------------- */
    poison(&c);
    ls_ctx_h2abort_build(&c, 1, "a considerably longer earlier reason", 0);
    ls_ctx_h2abort_build(&c, 1, "short", 0);
    {
        unsigned i;
        for (i = strlen("short"); i < LS_H2ABORT_WHY_MAX; i++)
            CHECK(c.why[i] == '\0');
        printf("ok    a shorter record leaves no tail of the previous one\n");
    }

    printf("ok    ls_ctx_h2abort.h  (%d assertions, 48 bytes)\n", n_assert);
    return 0;
}
