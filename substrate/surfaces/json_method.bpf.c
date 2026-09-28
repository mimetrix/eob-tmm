/* Observe a root-object method string after the application getter returns. */
#include "../config_snapshot.bpf.h"
#include "json_method_abi.h"

struct jm_ctx { jm_u64 arg[5], result, reserved[6]; };
struct jm_state { jm_u64 instance, calls, failures, reserved; };
struct jm_policy { jm_u64 run, reserved[3]; };
struct ls_cfg_map_def metadata_json_state __attribute__((section("maps"), used))
    = {1, 4, 32, 1, 0};
struct ls_cfg_map_def metadata_events __attribute__((section("maps"), used))
    = {4, 4, 4, 1, 0};
static void *(*lookup)(void *, const void *) = (void *)1;
static long (*update)(void *, const void *, const void *, jm_u64) = (void *)2;
static long (*read_mem)(void *, jm_u64, jm_u64) = (void *)4;
static jm_u64 (*clock_ns)(void) = (void *)5;
static long (*emit)(void *, void *, jm_u64, void *, jm_u64) = (void *)25;

static __attribute__((always_inline)) inline long
read_field(struct jm_event *e, void *dst, jm_u32 size, jm_u64 address)
{
    e->reads++;
    e->source_bytes += size;
    return read_mem(dst, size, address);
}

static __attribute__((always_inline)) inline void
extract(struct jm_ctx *ctx, struct jm_event *e)
{
    union {
        struct jm_value root;
        struct jm_member member;
        struct { jm_u64 base; jm_u32 len; } string;
        unsigned char key[8];
    } scratch = {0};
    jm_u64 owner = 0, last = 0, current = 0;
    e->status = JM_GETTER_ERROR;
    if (e->getter_result)
        return;
    e->status = JM_READ_FAILED;
    if (read_field(e, &owner, 8, ctx->arg[0] + 40))
        return;
    if (!owner) {
        e->status = JM_OUT_OF_SCOPE;
        return;
    }
    if (read_field(e, &scratch.root, 48, owner))
        return;
    if (scratch.root.owner || scratch.root.type != 1 || !(scratch.root.flags & 1)) {
        e->status = JM_OUT_OF_SCOPE;
        return;
    }
    if (read_field(e, &last, 8, scratch.root.value[0] + 16))
        return;
    if (!last) {
        e->status = JM_UNAVAILABLE;
        return;
    }
    /* TAILLIST_FIRST is last->next. Stop at last, not at a null pointer. */
    if (read_field(e, &current, 8, last + 32))
        return;
#pragma unroll
    for (int i = 0; i < 4; i++) {
        if (read_field(e, &scratch.member, 40, current))
            return;
        if (scratch.member.value == ctx->arg[0]) {
            if (!(scratch.member.flags & 1) || scratch.member.len != 6) {
                e->status = JM_OUT_OF_SCOPE;
                return;
            }
            jm_u64 key = scratch.member.key;
            if (read_field(e, scratch.key, 6, key))
                return;
            if (scratch.key[0] != 'm' || scratch.key[1] != 'e' ||
                    scratch.key[2] != 't' || scratch.key[3] != 'h' ||
                    scratch.key[4] != 'o' || scratch.key[5] != 'd') {
                e->status = JM_OUT_OF_SCOPE;
                return;
            }
            if (read_field(e, &scratch.string, 12, ctx->arg[1]))
                return;
            e->original_length = scratch.string.len;
            jm_u32 n = scratch.string.len;
            if (n > 64)
                n = 64;
            if (n && read_field(e, e->value, n, scratch.string.base)) {
                __builtin_memset(e->value, 0, sizeof e->value);
                return;
            }
            e->copied_length = n;
            e->status = e->original_length > n ? JM_TRUNCATED : JM_COMPLETE;
            return;
        }
        if (current == last) {
            e->status = JM_UNAVAILABLE;
            return;
        }
        current = scratch.member.next;
    }
    e->status = JM_BUDGET;
}

__attribute__((section("fexit/tmm_json_value_get_string"), used))
jm_u64 json_method(struct jm_ctx *ctx)
{
    struct jm_event event = {0};
    struct jm_state fresh = {0}, *state = 0;
    struct ls_cfg_meta *meta = ls_cfg_get(0);
    struct jm_policy *policy;
    jm_u32 zero = 0;
    event.magic = 0x4a4d4554;
    event.abi = 1;
    event.status = JM_UNAVAILABLE;
    event.getter_result = (jm_u32)ctx->result;
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
    state = lookup(&metadata_json_state, &zero);
    if (!state || state->instance != event.instance) {
        fresh.instance = event.instance;
        if (update(&metadata_json_state, &zero, &fresh, 0)) {
            event.flags |= 2;
            state = 0;
            goto output;
        }
        state = lookup(&metadata_json_state, &zero);
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
    if (emit(ctx, &metadata_events, 0, &event, sizeof event) && state &&
            state->failures != ~0ull)
        state->failures++;
    return 0;
}
