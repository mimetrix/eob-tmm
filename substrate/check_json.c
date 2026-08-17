/* check_json.c --- does the drain agent's output survive a hostile cause string?
 *
 * WHY THIS EXISTS. Until Phase 3 the agent emitted string fields with a bare
 * "%s". That was safe by accident: the only string in a record was a __FILE__
 * basename, always [a-z0-9_.]. Phase 3 forwards rst_why's sixth argument --- the
 * human-written cause, and at flow_table.c an entry from a runtime table --- and a
 * quote, a backslash or a control byte in any of those makes the whole line
 * unparseable.
 *
 * The failure would not appear here. It appears in whatever consumes the stream,
 * as a parse error blamed on the producer, hours later, with no record of which
 * line did it. So the escaping is asserted at build time.
 *
 * The assertions below check the ESCAPING RULES; check-json in the Makefile then
 * pipes the same output through a real JSON parser, because a hand-written escaper
 * that satisfies a hand-written test proves very little on its own.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "ls_json.h"

static char cap[512];

/* ls_json_str writes to stdout; redirect it into a buffer with a memstream so the
 * escaper needs no modification to be testable. */
static const char *
esc(const char *in, unsigned int n)
{
    FILE *ms;
    FILE *saved = stdout;
    size_t len = 0;
    char *buf = NULL;

    ms = open_memstream(&buf, &len);
    assert(ms != NULL);
    stdout = ms;
    ls_json_str(in, n);
    fflush(ms);
    stdout = saved;
    fclose(ms);

    assert(len < sizeof cap);
    memcpy(cap, buf, len);
    cap[len] = 0;
    free(buf);
    return cap;
}

/* Under -DLS_JSON_DUMP, print the hostile inputs as real JSON lines instead of
 * asserting, so the Makefile can hand them to python's parser. Same escaper, same
 * inputs --- the difference is who judges the output. */
#ifdef LS_JSON_DUMP
static void
dump(const char *in, unsigned int n)
{
    printf("{\"cause\":\"");
    ls_json_str(in, n);
    printf("\"}\n");
}

int
main(void)
{
    char hi[4]; hi[0] = 'a'; hi[1] = (char)0xff; hi[2] = 'b'; hi[3] = 0;
    char ctl[4]; ctl[0] = 'x'; ctl[1] = (char)0x01; ctl[2] = 'y'; ctl[3] = 0;
    dump("Closing", 7);
    dump("say \"hi\" and \\ that", 18);
    dump("line\nbreak\ttab\rcr", 17);
    dump(hi, 3);
    dump(ctl, 3);
    dump("No pool member available", 24);
    return 0;
}
#else

int
main(void)
{
    int n = 0;

    /* 1. ordinary text passes through unchanged --- escaping must not corrupt the
     *    overwhelmingly common case */
    assert(strcmp(esc("Closing", 7), "Closing") == 0);                        n++;
    assert(strcmp(esc("TCP RST from remote system", 26),
                  "TCP RST from remote system") == 0);                        n++;

    /* 2. the two characters that break JSON outright */
    assert(strcmp(esc("say \"hi\"", 8), "say \\\"hi\\\"") == 0);              n++;
    assert(strcmp(esc("a\\b", 3), "a\\\\b") == 0);                            n++;

    /* 3. control characters JSON forbids raw, with their short forms */
    assert(strcmp(esc("a\nb", 3), "a\\nb") == 0);                             n++;
    assert(strcmp(esc("a\rb", 3), "a\\rb") == 0);                             n++;
    assert(strcmp(esc("a\tb", 3), "a\\tb") == 0);                             n++;

    /* 4. anything else non-printable becomes \uXXXX. The record is a fixed-size
     *    field captured on a teardown path --- there is no guarantee it holds UTF-8,
     *    so bytes are escaped rather than passed through and hoped over. */
    assert(strcmp(esc("a\x01" "b", 3), "a\\u0001b") == 0);                     n++;
    assert(strcmp(esc("a\x7f" "b", 3), "a\\u007fb") == 0);                     n++;
    /* 0xff written via an array, not "a\xffb": that spells one hex escape "\xffb"
     * which is out of range for a char and fails -Werror. The high byte is the
     * interesting case precisely because the field is not guaranteed UTF-8. */
    {
        char hi[4]; hi[0] = 'a'; hi[1] = (char)0xff; hi[2] = 'b'; hi[3] = 0;
        assert(strcmp(esc(hi, 3), "a\\u00ffb") == 0);                          n++;
    }

    /* 5. bounded by BOTH the length and a NUL --- the field is fixed-size and may
     *    be either fully used or short. Reading past file_len into the next field
     *    is exactly the bug the length exists to prevent. */
    assert(strcmp(esc("abcdefgh", 3), "abc") == 0);                           n++;
    assert(strcmp(esc("ab\0cd", 5), "ab") == 0);                              n++;
    assert(strcmp(esc("", 0), "") == 0);                                      n++;

    /* 6. a cause made entirely of hostile bytes still terminates and stays bounded */
    {
        char hostile[41];
        unsigned int i;
        for (i = 0; i < sizeof hostile - 1; i++)
            hostile[i] = (char)(i % 2 ? '"' : '\\');
        hostile[sizeof hostile - 1] = 0;
        const char *out = esc(hostile, sizeof hostile - 1);
        /* every byte escaped to two, none dropped */
        assert(strlen(out) == (sizeof hostile - 1) * 2);                      n++;
    }

    printf("ok    ls_json.h  (%d assertions: quote, backslash, control bytes, "
           "\\uXXXX, length- and NUL-bounded)\n", n);
    return 0;
}
#endif /* LS_JSON_DUMP */
