/* Application handler-entry metadata. No application pointers are read. */
#include "../config_snapshot.bpf.h"

typedef ls_cfg_u32 u32;
typedef ls_cfg_u64 u64;

#if META_KIND == 1
#define META_SECTION "fentry/hud_a2a_handler"
#define META_STATE metadata_a2a_state
#elif META_KIND == 2
#define META_SECTION "fentry/hud_aimcp_handler"
#define META_STATE metadata_aimcp_state
#else
#error "META_KIND must be 1 (A2A) or 2 (AIMCP)"
#endif

struct meta_ctx { u64 arg[5], result, reserved[6]; };
struct meta_state { u64 instance, calls, failures, reserved; };
struct meta_policy { u64 run, reserved[3]; };
struct meta_event {
    u32 magic, abi;
    u64 instance, revision, run, monotonic_ns, sequence, output_failures;
    u32 kind, code, presence, flags;
};
_Static_assert(sizeof(struct meta_ctx) == 96, "context ABI");
_Static_assert(sizeof(struct meta_event) == 72, "metadata event ABI");
_Static_assert(sizeof(struct meta_state) == 32, "map value limit");

struct ls_cfg_map_def META_STATE __attribute__((section("maps"), used))
    = {1, 4, 32, 1, 0};
struct ls_cfg_map_def metadata_events __attribute__((section("maps"), used))
    = {4, 4, 4, 1, 0};
static void *(*lookup)(void *, const void *) = (void *)1;
static long (*update)(void *, const void *, const void *, u64) = (void *)2;
static u64 (*clock_ns)(void) = (void *)5;
static long (*emit)(void *, void *, u64, void *, u64) = (void *)25;

#define NO_CONFIG 1u
#define MAP_FAILED 2u
#define COUNTER_FULL 4u
#define CLOCK_FAILED 8u

__attribute__((section(META_SECTION), used))
u64 metadata_handler(struct meta_ctx *ctx)
{
    struct meta_event event = {0};
    struct meta_state fresh = {0};
    struct meta_state *state = 0;
    struct ls_cfg_meta *meta = ls_cfg_get(0);
    struct meta_policy *policy;
    u32 zero = 0;

    event.magic = 0x4d455441u;
    event.abi = 1;
    event.kind = META_KIND;
    event.code = (u32)ctx->arg[1];
    event.presence = (ctx->arg[0] != 0) |
        ((ctx->arg[2] != 0) << 1) | ((ctx->arg[3] != 0) << 2);
    event.monotonic_ns = clock_ns();
    if (!event.monotonic_ns)
        event.flags |= CLOCK_FAILED;
    if (!meta) {
        event.flags |= NO_CONFIG;
        goto output;
    }
    event.instance = meta->instance;
    event.revision = meta->revision;
    policy = ls_cfg_get(1);
    if (!policy || meta->schema != 1 || meta->entries != 1 ||
            !policy->run || policy->reserved[0] || policy->reserved[1] ||
            policy->reserved[2]) {
        event.flags |= NO_CONFIG;
        goto output;
    }
    event.run = policy->run;
    state = lookup(&META_STATE, &zero);
    if (!state || state->instance != event.instance) {
        fresh.instance = event.instance;
        if (update(&META_STATE, &zero, &fresh, 0)) {
            event.flags |= MAP_FAILED;
            state = 0;
            goto output;
        }
        state = lookup(&META_STATE, &zero);
    }
    if (!state) {
        event.flags |= MAP_FAILED;
        goto output;
    }
    event.output_failures = state->failures;
    if (state->calls == ~0ull)
        event.flags |= COUNTER_FULL;
    else
        event.sequence = ++state->calls;
output:
    if (emit(ctx, &metadata_events, 0, &event, sizeof event) && state &&
            state->failures != ~0ull)
        state->failures++;
    return 0;
}
