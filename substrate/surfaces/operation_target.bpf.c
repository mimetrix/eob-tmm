/* Bounded direct-member reads from a qualified JSON token cache. */
#include "../config_snapshot.bpf.h"
#include "operation_target_abi.h"
struct ot_ctx { jm_u64 arg[5], result, reserved[6]; };
struct ot_state { jm_u64 instance, calls, failures, reserved; };
struct ot_policy { jm_u64 run, reserved[3]; };
struct ot_view { jm_u64 head, tokens; jm_u32 used, length; };
#ifndef LS_ACTIVITY_EMBED
struct ls_cfg_map_def operation_target_state
    __attribute__((section("maps"), used)) = {1, 4, 32, 1, 0};
struct ls_cfg_map_def metadata_events
    __attribute__((section("maps"), used)) = {4, 4, 4, 1, 0};
static void *(*lookup)(void *, const void *) = (void *)1;
static long (*update)(void *, const void *, const void *, jm_u64)
    = (void *)2;
static long (*read_mem)(void *, jm_u64, jm_u64) = (void *)4;
static jm_u64 (*clock_ns)(void) = (void *)5;
static long (*emit)(void *, void *, jm_u64, void *, jm_u64) = (void *)25;
#endif
#define INLINE static __attribute__((always_inline)) inline

INLINE int field(struct jm_event *e, void *dst, jm_u32 n, jm_u64 address)
{
    if (e->reads >= 96 || n > 64 || e->source_bytes > 4096 - n) {
        e->status = JM_BUDGET;
        return -1;
    }
    e->reads++;
    e->source_bytes += n;
    if (read_mem(dst, n, address)) {
        e->status = JM_READ_FAILED;
        return -1;
    }
    return 0;
}

INLINE int bytes(struct jm_event *e, jm_u64 head,
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
        if (field(e, &frag, sizeof frag, head))
            return -1;
        if (offset < frag.len) {
            jm_u32 n = frag.len - offset;
            if (n > length - copied)
                n = length - copied;
            if (copied > 63 || n > 64 - copied)
                return -1;
            if (field(e, e->value + copied, n,
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

INLINE int token(struct jm_event *e, struct ot_view *v,
        jm_u32 index, struct tm_token *t)
{
    e->status = TM_INVALID_CACHE;
    if (index >= v->used)
        return -1;
    if (field(e, t, 20, v->tokens + (jm_u64)index * 20))
        return -1;
    if (t->start < 0 || t->end < t->start ||
            (jm_u32)t->end > v->length || t->size < 0)
        return -1;
    return 0;
}

/* key: 0 method, 1 params, 2 name, 3 uri. Return the value token index. */
INLINE int member(struct jm_event *e, struct ot_view *v,
        jm_u32 object, jm_u32 key, struct tm_token *t)
{
    if (token(e, v, object, t))
        return -1;
    if (t->type != 1) {
        e->status = JM_OUT_OF_SCOPE;
        return -1;
    }
    jm_u32 count = t->size, end = t->end, minimum = t->start;
    jm_u32 index = object + 1;
#pragma unroll
    for (int i = 0; i < 4; i++) {
        if ((jm_u32)i >= count) {
            e->status = OT_NO_TARGET;
            return -1;
        }
        if (token(e, v, index, t))
            return -1;
        if (t->type != 3 || (jm_u32)t->start < minimum ||
                (jm_u32)t->end > end)
            return -1;
        minimum = t->end;
        jm_u32 len = key < 2 ? 6 : key == 2 ? 4 : 3;
        int match = 0;
        if ((jm_u32)(t->end - t->start) == len) {
            if (bytes(e, v->head, t->start, len))
                return -1;
            if (key == 0)
                match = !__builtin_memcmp(e->value, "method", 6);
            else if (key == 1)
                match = !__builtin_memcmp(e->value, "params", 6);
            else if (key == 2)
                match = !__builtin_memcmp(e->value, "name", 4);
            else
                match = !__builtin_memcmp(e->value, "uri", 3);
            __builtin_memset(e->value, 0, sizeof e->value);
        }
        index++;
        if (token(e, v, index, t))
            return -1;
        if ((jm_u32)t->start < minimum || (jm_u32)t->end > end)
            return -1;
        minimum = t->end;
        if (match)
            return index;
        if ((jm_u32)(i + 1) < count &&
                (t->sibling <= (int)index || (jm_u32)t->sibling >= v->used))
            return -1;
        index = t->sibling;
    }
    e->status = count > 4 ? JM_BUDGET : OT_NO_TARGET;
    return -1;
}

INLINE void extract(struct ot_ctx *ctx, struct jm_event *e)
{
    struct ot_view v = {0};
    union {
        struct { jm_u32 len, flags; jm_u64 head, tail; } raw;
        struct { jm_u32 capacity, limit; jm_u64 tokens; jm_u32 pos, used; } parser;
        struct tm_token t;
        jm_u64 root;
        jm_u32 valid;
    } s = {0};
    jm_u64 cache = 0;
    if (!ctx->arg[1])
        return;
    if (field(e, &s.valid, 4, ctx->arg[1] + 88))
        return;
    if ((s.valid & 0x24) != 0x24 || (s.valid & 0x1000)) {
        e->status = JM_OUT_OF_SCOPE;
        return;
    }
    if (field(e, &cache, 8, ctx->arg[1] + 24) || !cache)
        return;
    e->status = TM_INVALID_CACHE;
    if (field(e, &s.root, 8, cache) || !s.root ||
            field(e, &s.valid, 4, cache + 64) || s.valid != 1 ||
            field(e, &s.raw, 24, cache + 8))
        return;
    v.head = s.raw.head;
    v.length = s.raw.len;
    if (field(e, &s.parser, 24, cache + 32))
        return;
    v.tokens = s.parser.tokens;
    v.used = s.parser.used;
    if (!v.tokens || !v.used || v.used > s.parser.capacity)
        return;
    if (member(e, &v, 0, 0, &s.t) < 0) {
        if (e->status == OT_NO_TARGET)
            e->status = TM_NO_LITERAL_METHOD;
        return;
    }
    e->status = OT_UNSUPPORTED_METHOD;
    if (s.t.type != 3)
        return;
    jm_u32 n = s.t.end - s.t.start;
    if (n != 10 && n != 14)
        return;
    if (bytes(e, v.head, s.t.start, n))
        return;
    if (n == 10 && !__builtin_memcmp(e->value, "tools/call", 10))
        e->getter_result = OT_TOOL;
    if (n == 14 && !__builtin_memcmp(e->value, "resources/read", 14))
        e->getter_result = OT_RESOURCE;
    __builtin_memset(e->value, 0, sizeof e->value);
    if (!e->getter_result)
        return;
    int params = member(e, &v, 0, 1, &s.t);
    if (params < 0)
        return;
    if (member(e, &v, params, e->getter_result == OT_TOOL ? 2 : 3,
                &s.t) < 0)
        return;
    if (s.t.type != 3) {
        e->status = TM_NONSTRING;
        return;
    }
    e->original_length = s.t.end - s.t.start;
    n = e->original_length;
    if (n > 64)
        n = 64;
    if (bytes(e, v.head, s.t.start, n))
        return;
    e->copied_length = n;
    e->status = n < e->original_length ? JM_TRUNCATED : JM_COMPLETE;
}

#ifdef LS_ACTIVITY_EMBED
static __attribute__((noinline))
#else
__attribute__((section("fentry/json_filter_handle_json_complete"), used))
#endif
jm_u64 operation_target(struct ot_ctx *ctx)
{
    struct jm_event e = {0};
    struct ot_state fresh = {0}, *state = 0;
    struct ls_cfg_meta *meta = ls_cfg_get(0);
    struct ot_policy *policy;
    jm_u32 zero = 0;
    e.magic = OT_MAGIC;
    e.abi = 1;
    e.status = JM_UNAVAILABLE;
    e.monotonic_ns = clock_ns();
    if (!e.monotonic_ns)
        e.flags |= 8;
    if (!meta) {
        e.flags |= 1;
        goto output;
    }
    e.instance = meta->instance;
    e.revision = meta->revision;
    policy = ls_cfg_get(1);
    if (!policy || meta->schema != 1 || meta->entries != 1 || !policy->run ||
            policy->reserved[0] || policy->reserved[1] || policy->reserved[2]) {
        e.flags |= 1;
        goto output;
    }
    e.run = policy->run;
    state = lookup(&operation_target_state, &zero);
    if (!state || state->instance != e.instance) {
        fresh.instance = e.instance;
        if (update(&operation_target_state, &zero, &fresh, 0)) {
            e.flags |= 2;
            state = 0;
            goto output;
        }
        state = lookup(&operation_target_state, &zero);
    }
    if (!state) {
        e.flags |= 2;
        goto output;
    }
    e.output_failures = state->failures;
    if (state->calls == ~0ull)
        e.flags |= 4;
    else
        e.sequence = ++state->calls;
    extract(ctx, &e);
output:
    if (e.status != JM_COMPLETE && e.status != JM_TRUNCATED) {
        __builtin_memset(e.value, 0, sizeof e.value);
        e.copied_length = 0;
    }
    if (emit(ctx, &metadata_events, 0, &e, sizeof e) && state &&
            state->failures != ~0ull)
        state->failures++;
    return 0;
}
