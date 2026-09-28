/* Parser-call diagnostics. An address tag is NOT an object lifetime. */
#include "../config_snapshot.bpf.h"

typedef ls_cfg_u32 u32;
typedef ls_cfg_u64 u64;

struct scope_ctx {
    u64 arg[5], result, reserved[6];
};
struct scope_state {
    u64 instance, calls, tags, output_failures;
};
struct scope_address {
    u64 instance, tag, completions, reserved;
};
struct scope_event {
    u32 magic, abi;
    u64 instance, call_seq, context_tag, completions, result;
    u64 output_failures;
    u32 flags, reserved;
};
_Static_assert(sizeof(struct scope_ctx) == 96, "context ABI");
_Static_assert(sizeof(struct scope_event) == 64, "event ABI");
_Static_assert(sizeof(struct scope_state) == 32, "map value limit");
_Static_assert(sizeof(struct scope_address) == 32, "map value limit");

struct ls_cfg_map_def scope_state __attribute__((section("maps"), used))
    = {1, 4, 32, 1, 0};
struct ls_cfg_map_def scope_addresses __attribute__((section("maps"), used))
    = {1, 8, 32, 256, 0};
struct ls_cfg_map_def scope_events __attribute__((section("maps"), used))
    = {4, 4, 4, 1, 0};

static void *(*lookup)(void *, const void *) = (void *)1;
static long (*update)(void *, const void *, const void *, u64) = (void *)2;
static long (*emit)(void *, void *, u64, void *, u64) = (void *)25;

#define NO_META 1u
#define MAP_FAILED 2u
#define TABLE_FULL 4u
#define COUNTER_FULL 8u
#define NULL_ADDRESS 16u

__attribute__((section("fexit/http_parse_client_headers"), used))
u64 request_scope(struct scope_ctx *ctx)
{
    struct scope_event event = {0};
    struct scope_state fresh = {0};
    struct scope_address address = {0};
    struct scope_state *state = 0;
    struct scope_address *saved = 0;
    struct ls_cfg_meta *meta = ls_cfg_get(0);
    u64 key = ctx->arg[0];
    u32 zero = 0;

    event.magic = 0x53434f50u;
    event.abi = 1;
    event.result = ctx->result;
    if (!meta) {
        event.flags = NO_META;
        goto output;
    }
    event.instance = meta->instance;
    state = lookup(&scope_state, &zero);
    if (!state || state->instance != event.instance) {
        fresh.instance = event.instance;
        if (update(&scope_state, &zero, &fresh, 0)) {
            event.flags = MAP_FAILED;
            state = 0;
            goto output;
        }
        state = lookup(&scope_state, &zero);
    }
    if (!state) {
        event.flags = MAP_FAILED;
        goto output;
    }
    event.output_failures = state->output_failures;
    if (state->calls == ~0ull) {
        event.flags = COUNTER_FULL;
        goto output;
    }
    event.call_seq = ++state->calls;
    if (!key) {
        event.flags = NULL_ADDRESS;
        goto output;
    }
    saved = lookup(&scope_addresses, &key);
    if (!saved || saved->instance != event.instance) {
        /* Refuse a new tag before insertion can evict an earlier address. */
        if (state->tags >= 256) {
            event.flags = TABLE_FULL;
            goto output;
        }
        address.instance = event.instance;
        address.tag = ++state->tags;
        if (update(&scope_addresses, &key, &address, 0)) {
            event.flags = MAP_FAILED;
            goto output;
        }
        saved = lookup(&scope_addresses, &key);
    }
    if (!saved) {
        event.flags = MAP_FAILED;
        goto output;
    }
    event.context_tag = saved->tag;
    if (event.result == 0) {
        if (saved->completions == ~0ull)
            event.flags = COUNTER_FULL;
        else
            saved->completions++;
    }
    event.completions = saved->completions;
output:
    /* Attempt output on every path. Later calls expose earlier refusals.
     * The collector must also reconcile the final call and ring losses. */
    if (emit(ctx, &scope_events, 0, &event, sizeof event) && state &&
            state->output_failures != ~0ull)
        state->output_failures++;
    return 0;
}
