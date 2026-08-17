/* ls_json.h --- JSON string escaping for the drain agent's output.

 * In its own header so check_json.c can reach it. It lived inside ls_drain.c as a
 * static, next to main(), where nothing could test it --- and escaping that is never
 * exercised is how a malformed line reaches a consumer, which then reports a bug
 * against the producer.
 */
#ifndef LS_JSON_H
#define LS_JSON_H

#include <stdint.h>
#include <stdio.h>

/*
 * JSON string escaping, which this file did NOT do before Phase 3.
 *
 * `file` is a __FILE__ basename --- always [a-z0-9_.] --- so emitting it raw
 * happened to produce valid JSON. `cause` is human-written prose from TMM's source
 * and, at flow_table.c, an entry from a runtime table: a quote, a backslash or a
 * stray control byte in any of those makes the whole line unparseable, and the
 * breakage surfaces in whatever consumes the stream rather than here. Escaping
 * arrives in the same change as the field that needs it.
 *
 * Bytes outside printable ASCII become \uXXXX rather than being passed through,
 * because the record is a fixed-size field from a teardown path and there is no
 * guarantee it holds UTF-8.
 */
static inline void
ls_json_str(const char *p, uint32_t n)
{
    uint32_t i;
    for (i = 0; i < n && p[i] != '\0'; i++) {
        unsigned char c = (unsigned char)p[i];
        switch (c) {
        case '"':  fputs("\\\"", stdout); break;
        case '\\': fputs("\\\\", stdout); break;
        case '\n': fputs("\\n", stdout);  break;
        case '\r': fputs("\\r", stdout);  break;
        case '\t': fputs("\\t", stdout);  break;
        default:
            if (c < 0x20 || c > 0x7e)
                printf("\\u%04x", c);
            else
                putchar(c);
        }
    }
}


#endif /* LS_JSON_H */
