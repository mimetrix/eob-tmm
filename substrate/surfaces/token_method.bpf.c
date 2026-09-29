/* Read an existing JSON token cache. Never invoke application accessors. */
#include "../config_snapshot.bpf.h"
#include "token_method_abi.h"
struct tm_ctx { jm_u64 arg[5], result, reserved[6]; };
struct tm_state { jm_u64 instance, calls, failures, reserved; };
struct tm_policy { jm_u64 run, reserved[3]; };
struct ls_cfg_map_def metadata_token_state __attribute__((section("maps"), used))
    = {1, 4, 32, 1, 0};
struct ls_cfg_map_def metadata_events __attribute__((section("maps"), used))
    = {4, 4, 4, 1, 0};
static void *(*lookup)(void *, const void *) = (void *)1;
static long (*update)(void *, const void *, const void *, jm_u64) = (void *)2;
static long (*read_mem)(void *, jm_u64, jm_u64) = (void *)4;
static jm_u64 (*clock_ns)(void) = (void *)5;
static long (*emit)(void *, void *, jm_u64, void *, jm_u64) = (void *)25;
#define INLINE static __attribute__((always_inline)) inline

INLINE int read_field(struct jm_event *e, void *dst, jm_u32 size, jm_u64 address)
{
    if (e->reads >= 40 || size > 64 || e->source_bytes > 1024 - size) {
        e->status = JM_BUDGET;
        return -1;
    }
    e->reads++;
    e->source_bytes += size;
    if (read_mem(dst, size, address)) {
        e->status = JM_READ_FAILED;
        return -1;
    }
    return 0;
}

INLINE int read_bytes(struct jm_event *e, jm_u64 head,
        jm_u32 offset, jm_u32 length)
{
    struct tm_frag frag = {0};
    jm_u32 copied = 0;
    if (length > 64)
        return -1;
#pragma unroll
    for (int i = 0; i < 4; i++) {
        if (copied == length)
            return 0;
        if (!head) {
            e->status = TM_INVALID_CACHE;
            return -1;
        }
        if (read_field(e, &frag, sizeof frag, head))
            return -1;
        if (offset < frag.len) {
            jm_u32 n = frag.len - offset;
            if (n > length - copied)
                n = length - copied;
            if (copied > 63 || n > 64 - copied)
                return -1;
            if (read_field(e, e->value + copied, n,
                    frag.base + frag.offset + offset))
                return -1;
            copied += n;
            offset = 0;
        } else {
            offset -= frag.len;
        }
        head = frag.next;
    }
    if (copied == length)
        return 0;
    e->status = JM_BUDGET;
    return -1;
}

INLINE void extract(struct tm_ctx *ctx, struct jm_event *e)
{
    union {
        struct { jm_u32 len, flags; jm_u64 head, tail; } raw;
        struct { jm_u32 capacity, limit; jm_u64 tokens; jm_u32 pos, used; } parser;
        struct tm_token token;
        jm_u64 root;
        jm_u32 valid;
    } s = {0};
    jm_u64 head = 0, tokens = 0, cache = 0;
    jm_u32 raw_length = 0, used = 0, index = 1, minimum = 0;
    e->status = TM_INVALID_CACHE;
    if (!ctx->arg[1]) {
        e->status = JM_UNAVAILABLE;
        return;
    }
    if (read_field(e, &s.valid, 4, ctx->arg[1] + 88))
        return;
    if ((s.valid & 0x24) != 0x24 || (s.valid & 0x1000)) {
        e->status = JM_OUT_OF_SCOPE;
        return;
    }
    if (read_field(e, &cache, 8, ctx->arg[1] + 24))
        return;
    if (!cache) {
        e->status = JM_UNAVAILABLE;
        return;
    }
    if (read_field(e, &s.root, 8, cache) || !s.root)
        return;
    if (read_field(e, &s.valid, 4, cache + 64) || s.valid != 1)
        return;
    if (read_field(e, &s.raw, 24, cache + 8))
        return;
    head = s.raw.head;
    raw_length = s.raw.len;
    if (read_field(e, &s.parser, 24, cache + 32))
        return;
    tokens = s.parser.tokens;
    used = s.parser.used;
    if (!tokens || !used || used > s.parser.capacity)
        return;
    if (read_field(e, &s.token, 20, tokens))
        return;
    if (s.token.type != 1) {
        e->status = JM_OUT_OF_SCOPE;
        return;
    }
    if (s.token.start < 0 || s.token.end < s.token.start ||
            (jm_u32)s.token.end > raw_length || s.token.size < 0)
        return;
    minimum = s.token.start;
    raw_length = s.token.end;
    e->getter_result = s.token.size;
#pragma unroll
    for (int member = 0; member < 4; member++) {
        if ((jm_u32)member >= e->getter_result) {
            e->status = TM_NO_LITERAL_METHOD;
            return;
        }
        if (index >= used || used - index < 2)
            return;
        if (read_field(e, &s.token, 20, tokens + (jm_u64)index * 20))
            return;
        if (s.token.type != 3 || s.token.start < 0 ||
                (jm_u32)s.token.start < minimum || s.token.end < s.token.start ||
                (jm_u32)s.token.end > raw_length)
            return;
        minimum = s.token.end;
        int match = 0;
        if (s.token.end - s.token.start == 6) {
            if (read_bytes(e, head, s.token.start, 6))
                return;
            match = e->value[0] == 'm' && e->value[1] == 'e' &&
                e->value[2] == 't' && e->value[3] == 'h' &&
                e->value[4] == 'o' && e->value[5] == 'd';
            __builtin_memset(e->value, 0, sizeof e->value);
        }
        index++;
        if (read_field(e, &s.token, 20, tokens + (jm_u64)index * 20))
            return;
        if (s.token.start < 0 || s.token.end < s.token.start ||
                (jm_u32)s.token.start < minimum || (jm_u32)s.token.end > raw_length)
            return;
        minimum = s.token.end;
        if (match) {
            if (s.token.type != 3) {
                e->status = TM_NONSTRING;
                return;
            }
            e->original_length = s.token.end - s.token.start;
            jm_u32 n = e->original_length;
            if (n > 64)
                n = 64;
            if (read_bytes(e, head, s.token.start, n))
                return;
            e->copied_length = n;
            e->status = n < e->original_length ? JM_TRUNCATED : JM_COMPLETE;
            return;
        }
        if ((jm_u32)(member + 1) < e->getter_result &&
                (s.token.sibling <= (int)index || (jm_u32)s.token.sibling >= used))
            return;
        index = s.token.sibling;
    }
    e->status = e->getter_result > 4 ? JM_BUDGET : TM_NO_LITERAL_METHOD;
}

__attribute__((section("fentry/json_filter_handle_json_complete"), used))
jm_u64 token_method(struct tm_ctx *ctx)
{
    struct jm_event event = {0};
    struct tm_state fresh = {0}, *state = 0;
    struct ls_cfg_meta *meta = ls_cfg_get(0);
    struct tm_policy *policy;
    jm_u32 zero = 0;
    event.magic = TM_MAGIC;
    event.abi = 1;
    event.status = JM_UNAVAILABLE;
    event.monotonic_ns = clock_ns();
    if (!event.monotonic_ns)
        event.flags |= 8;
    if (!meta) {
        event.flags |= 1;
        goto output;
    }
    event.instance = meta->instance;
    event.revision = meta->revision;
    policy = ls_cfg_get(1);
    if (!policy || meta->schema != 1 || meta->entries != 1 || !policy->run ||
            policy->reserved[0] || policy->reserved[1] || policy->reserved[2]) {
        event.flags |= 1;
        goto output;
    }
    event.run = policy->run;
    state = lookup(&metadata_token_state, &zero);
    if (!state || state->instance != event.instance) {
        fresh.instance = event.instance;
        if (update(&metadata_token_state, &zero, &fresh, 0)) {
            event.flags |= 2;
            state = 0;
            goto output;
        }
        state = lookup(&metadata_token_state, &zero);
    }
    if (!state) {
        event.flags |= 2;
        goto output;
    }
    event.output_failures = state->failures;
    if (state->calls == ~0ull)
        event.flags |= 4;
    else
        event.sequence = ++state->calls;
    extract(ctx, &event);
output:
    if (event.status != JM_COMPLETE && event.status != JM_TRUNCATED) {
        __builtin_memset(event.value, 0, sizeof event.value);
        event.copied_length = 0;
    }
    if (emit(ctx, &metadata_events, 0, &event, sizeof event) && state &&
            state->failures != ~0ull)
        state->failures++;
    return 0;
}
