/* Typed reply fields only. Never emit the result or error text. */
#include "../config_snapshot.bpf.h"
#include "reply_metadata_abi.h"
struct rp_ctx { jm_u64 arg[5], result, reserved[6]; };
struct rp_state { jm_u64 instance, calls, failures, reserved; };
struct rp_policy { jm_u64 run, reserved[3]; };
struct rp_view { jm_u64 head, tokens; jm_u32 used, length; };
struct rp_selection { jm_u32 mask, index; };
#ifndef LS_ACTIVITY_EMBED
struct ls_cfg_map_def reply_metadata_state
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

INLINE int field(struct rp_event *e, void *dst, jm_u32 n, jm_u64 address)
{
    if (e->reads >= 80 || n > 32 || e->source_bytes > 2048 - n)
        return JM_BUDGET;
    e->reads++;
    e->source_bytes += n;
    return read_mem(dst, n, address) ? JM_READ_FAILED : 0;
}

INLINE int bytes(struct rp_event *e, jm_u64 head, jm_u32 offset,
        jm_u32 length, unsigned char *dst)
{
    struct tm_frag frag = {0};
    jm_u32 copied = 0;
    if (length > 16)
        return JM_OUT_OF_SCOPE;
#pragma unroll
    for (int i = 0; i < 4; i++) {
        if (copied == length)
            return 0;
        if (!head)
            return TM_INVALID_CACHE;
        int err = field(e, &frag, sizeof frag, head);
        if (err)
            return err;
        if (offset < frag.len) {
            jm_u32 n = frag.len - offset;
            if (n > length - copied)
                n = length - copied;
            if (copied > 15 || n > 16 - copied)
                return TM_INVALID_CACHE;
            err = field(e, dst + copied, n,
                    frag.base + frag.offset + offset);
            if (err)
                return err;
            copied += n;
            offset = 0;
        } else offset -= frag.len;
        head = frag.next;
    }
    return copied == length ? 0 : JM_BUDGET;
}

INLINE int token(struct rp_event *e, struct rp_view *v,
        jm_u32 index, struct tm_token *t)
{
    if (index >= v->used)
        return TM_INVALID_CACHE;
    int err = field(e, t, 20, v->tokens + (jm_u64)index * 20);
    if (err)
        return err;
    if (t->start < 0 || t->end < t->start ||
            (jm_u32)t->end > v->length || t->size < 0)
        return TM_INVALID_CACHE;
    return 0;
}

/* mode 0: root result/error/method; 1: error.code; 2: result.isError.
 * Scan the whole bounded object before accepting the selected value. */
INLINE int scan(struct rp_event *e, struct rp_view *v, jm_u32 object,
        jm_u32 mode, struct rp_selection *out)
{
    struct tm_token t = {0};
    unsigned char key[16] = {0};
    int err = token(e, v, object, &t);
    out->mask = out->index = 0;
    if (err)
        return err;
    if (t.type != 1)
        return RP_WRONG_TYPE;
    if (t.size > 4)
        return JM_BUDGET;
    jm_u32 count = t.size, end = t.end, minimum = t.start;
    jm_u32 index = object + 1, duplicate = 0;
#pragma unroll
    for (int i = 0; i < 4; i++) {
        if ((jm_u32)i >= count)
            break;
        err = token(e, v, index, &t);
        if (err)
            return err;
        if (t.type != 3 || (jm_u32)t.start < minimum ||
                (jm_u32)t.end > end)
            return TM_INVALID_CACHE;
        minimum = t.end;
        jm_u32 n = t.end - t.start, bit = 0;
        if ((!mode && (n == 5 || n == 6)) ||
                (mode == 1 && n == 4) || (mode == 2 && n == 7)) {
            err = bytes(e, v->head, t.start, n, key);
            if (err)
                return err;
            if (!mode) {
                if (n == 6 && !__builtin_memcmp(key, "result", 6)) bit = 1;
                if (n == 5 && !__builtin_memcmp(key, "error", 5)) bit = 2;
                if (n == 6 && !__builtin_memcmp(key, "method", 6)) bit = 4;
            } else if (mode == 1) {
                if (!__builtin_memcmp(key, "code", 4)) bit = 1;
            } else if (!__builtin_memcmp(key, "isError", 7)) bit = 1;
        }
        index++;
        err = token(e, v, index, &t);
        if (err)
            return err;
        if ((jm_u32)t.start < minimum || (jm_u32)t.end > end)
            return TM_INVALID_CACHE;
        minimum = t.end;
        if (bit) {
            duplicate |= out->mask & bit;
            out->mask |= bit;
            if (bit != 4) out->index = index;
        }
        if ((jm_u32)(i + 1) < count &&
                (t.sibling <= (int)index || (jm_u32)t.sibling >= v->used))
            return TM_INVALID_CACHE;
        index = t.sibling;
    }
    return duplicate ? RP_AMBIGUOUS : 0;
}

INLINE int value(struct rp_event *e, struct rp_view *v,
        jm_u32 index, int boolean)
{
    struct tm_token t = {0};
    unsigned char buf[16] = {0};
    int err = token(e, v, index, &t);
    if (err) return err;
    if (t.type != 4) return RP_WRONG_TYPE;
    jm_u32 n = t.end - t.start;
    if (!n || n > (boolean ? 5u : 11u)) return JM_OUT_OF_SCOPE;
    err = bytes(e, v->head, t.start, n, buf);
    if (err) return err;
    if (boolean) {
        if (n == 4 && !__builtin_memcmp(buf, "true", 4)) {
            e->tool_error = 1;
            return JM_COMPLETE;
        }
        if (n == 5 && !__builtin_memcmp(buf, "false", 5))
            return JM_COMPLETE;
        return RP_WRONG_TYPE;
    }
    jm_u32 negative = buf[0] == '-', start = negative;
    jm_u64 number = 0;
    if (n == start) return JM_OUT_OF_SCOPE;
#pragma unroll
    for (int i = 0; i < 11; i++) {
        if ((jm_u32)i >= n) break;
        if ((jm_u32)i < start) continue;
        if (buf[i] < '0' || buf[i] > '9') return JM_OUT_OF_SCOPE;
        if ((jm_u32)i == start && buf[i] == '0' && n > start + 1)
            return JM_OUT_OF_SCOPE;
        number = number * 10 + buf[i] - '0';
        if (number > (negative ? 2147483648ull : 2147483647ull))
            return JM_OUT_OF_SCOPE;
    }
    e->error_code = (int)(negative ? 0ull - number : number);
    return JM_COMPLETE;
}

INLINE int extract(struct rp_ctx *ctx, struct rp_event *e)
{
    struct rp_view v = {0};
    struct rp_selection selection = {0};
    union {
        struct { jm_u32 len, flags; jm_u64 head, tail; } raw;
        struct { jm_u32 capacity, limit; jm_u64 tokens; jm_u32 pos, used; } parser;
        jm_u64 root;
        jm_u32 valid;
    } s = {0};
    jm_u64 cache = 0;
    int err = 0;
    if (!ctx->arg[1]) return JM_UNAVAILABLE;
    err = field(e, &s.valid, 4, ctx->arg[1] + 88);
    if (err) return err;
    if ((s.valid & 0x24) != 0x24 || (s.valid & 0x1000))
        return JM_OUT_OF_SCOPE;
    err = field(e, &cache, 8, ctx->arg[1] + 24);
    if (err) return err;
    if (!cache) return JM_UNAVAILABLE;
    err = field(e, &s.root, 8, cache);
    if (err) return err;
    if (!s.root) return TM_INVALID_CACHE;
    err = field(e, &s.valid, 4, cache + 64);
    if (err) return err;
    if (s.valid != 1) return TM_INVALID_CACHE;
    err = field(e, &s.raw, 24, cache + 8);
    if (err) return err;
    v.head = s.raw.head; v.length = s.raw.len;
    err = field(e, &s.parser, 24, cache + 32);
    if (err) return err;
    v.tokens = s.parser.tokens; v.used = s.parser.used;
    if (!v.tokens || !v.used || v.used > s.parser.capacity)
        return TM_INVALID_CACHE;
    err = scan(e, &v, 0, 0, &selection);
    if (err) return err;
    if (!(selection.mask & 3)) return 0;
    if (selection.mask != 1 && selection.mask != 2)
        return RP_AMBIGUOUS;
    e->result_present = selection.mask == 1;
    e->error_present = selection.mask == 2;
    err = scan(e, &v, selection.index, e->error_present ? 1 : 2, &selection);
    if (!err) {
        err = selection.mask ? value(e, &v, selection.index,
                e->result_present) : JM_UNAVAILABLE;
    }
    if (e->error_present) e->code_state = err;
    else e->tool_error_state = err;
    return JM_COMPLETE;
}

#ifdef LS_ACTIVITY_EMBED
static __attribute__((noinline))
#else
__attribute__((section("fentry/json_filter_handle_json_complete"), used))
#endif
jm_u64 reply_metadata(struct rp_ctx *ctx)
{
    struct rp_event e = {0};
    struct rp_state fresh = {0}, *state = 0;
    struct ls_cfg_meta *meta = ls_cfg_get(0);
    struct rp_policy *policy;
    jm_u32 zero = 0;
    e.magic = RP_MAGIC; e.abi = 1; e.status = JM_UNAVAILABLE;
    e.monotonic_ns = clock_ns();
    if (!e.monotonic_ns) e.flags |= 8;
    if (!meta) { e.flags |= 1; goto output; }
    e.instance = meta->instance; e.revision = meta->revision;
    policy = ls_cfg_get(1);
    if (!policy || meta->schema != 1 || meta->entries != 1 || !policy->run ||
            policy->reserved[0] || policy->reserved[1] || policy->reserved[2]) {
        e.flags |= 1;
        goto output;
    }
    e.run = policy->run;
    state = lookup(&reply_metadata_state, &zero);
    if (!state || state->instance != e.instance) {
        fresh.instance = e.instance;
        if (update(&reply_metadata_state, &zero, &fresh, 0)) {
            e.flags |= 2; state = 0; goto output;
        }
        state = lookup(&reply_metadata_state, &zero);
    }
    if (!state) { e.flags |= 2; goto output; }
    e.output_failures = state->failures;
    if (state->calls == ~0ull) e.flags |= 4;
    else e.sequence = ++state->calls;
    e.status = extract(ctx, &e);
output:
    if (emit(ctx, &metadata_events, 0, &e, sizeof e) && state &&
            state->failures != ~0ull) state->failures++;
    return 0;
}
