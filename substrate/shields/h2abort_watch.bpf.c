/* tmm:http2:abort --- observe every HTTP/2 stream abort, and count them by error code.
 *
 * THE ONE HOOK OF THE FOUR whose reason reaches nothing else. Proven from the shipped
 * binary rather than by reading source: "initiates ABORT in" occurs 0 times in
 * tmm.no_pgo, because http2_stream_abort's only narration is TRACES() inside
 * #if HTTP2_DEBUG, which the build leaves undefined. For contrast ssl__err's log string
 * "Connection error" occurs 4 times, which is why that hook was dropped as a headline.
 *
 * ALWAYS FALLS THROUGH. A tracepoint must not alter an h2 teardown, and there is no
 * `return LS_SAFE_RETURN` anywhere below --- the guarantee is structural, not a promise.
 *
 * KEYED BY ERROR CODE, not by reason string. enum http2_error is a small dense space a
 * later reader can enumerate; a program cannot iterate its own map, so a string-keyed
 * table could be filled and never summarised. The per-record stream in the ring carries
 * the reason; the map carries the shape.
 *
 * The map name is h2abort_by_error and not `counts`, because map identity is the SYMBOL
 * NAME: a map called `counts` here would share storage with any other program declaring
 * the same name and shape, and the two would add into each other silently.
 */
#include "ls_ctx_h2abort_bpf.h"

typedef unsigned int  __u32;
typedef unsigned long long __u64;

struct bpf_map_def {
    __u32 type, key_size, value_size, max_entries, map_flags;
};
#define BPF_MAP_TYPE_HASH 1

struct bpf_map_def h2abort_by_error __attribute__((section("maps"), used)) = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 64,
};

static void *(*bpf_map_lookup_elem)(void *, const void *) = (void *)1;
static long (*bpf_map_update_elem)(void *, const void *, const void *, __u64) = (void *)2;

__attribute__((section("fentry/http2_stream_abort"), used))
__u64
shield(struct ls_ctx_h2abort *c)
{
    __u32 key = c->error;
    __u64 *n = bpf_map_lookup_elem(&h2abort_by_error, &key);
    __u64 one = 1;

    if (n)
        one = *n + 1;
    bpf_map_update_elem(&h2abort_by_error, &key, &one, 0);

    return LS_FALLTHROUGH;    /* structurally incapable of altering the teardown */
}
