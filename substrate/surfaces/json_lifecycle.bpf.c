/* Entry observations and opaque storage tags. No qualified lifecycle. */
#include "../config_snapshot.bpf.h"
#include "json_lifecycle_abi.h"
#if JL_KIND == 1
#define SECTION "fentry/hud_json_handler"
#elif JL_KIND == 2
#define SECTION "fentry/json_filter_handle_json_complete"
#elif JL_KIND == 3
#define SECTION "fentry/json_filter_reset_ingress_for_reuse"
#else
#error "select JL_KIND 1, 2 or 3"
#endif
struct jl_ctx { jm_u64 arg[5], result, reserved[6]; };
struct jl_state { jm_u64 run, calls, tags, failures; };
struct jl_object { jm_u64 run, tag, seen, reserved; };
struct ls_cfg_map_def json_boundary_state
    __attribute__((section("maps"), used)) = {1, 4, 32, 1, 0};
struct ls_cfg_map_def json_boundary_objects
    __attribute__((section("maps"), used)) = {1, 8, 32, 128, 0};
struct ls_cfg_map_def json_boundary_events
    __attribute__((section("maps"), used)) = {4, 4, 4, 1, 0};
static void *(*lookup)(void *, const void *) = (void *)1;
static long (*update)(void *, const void *, const void *, jm_u64)
    = (void *)2;
#if JL_KIND != 3
static long (*read_mem)(void *, jm_u64, jm_u64) = (void *)4;
#endif
static jm_u64 (*clock_ns)(void) = (void *)5;
static long (*emit)(void *, void *, jm_u64, void *, jm_u64) = (void *)25;
#define INLINE static __attribute__((always_inline)) inline

#if JL_KIND != 3
INLINE int read_field(struct jl_event *e, void *dst, jm_u32 size,
        jm_u64 address)
{
    e->reads++;
    e->source_bytes += size;
    if (read_mem(dst, size, address)) {
        e->status = 4;
        return -1;
    }
    return 0;
}
#endif

INLINE jm_u64 context(struct jl_ctx *ctx, struct jl_event *e)
{
#if JL_KIND == 3
    e->status = ctx->arg[0] ? 2 : 0;
    return ctx->arg[0];
#else
    jm_u64 node = ctx->arg[0], flow = ctx->arg[2], cache = 0;
    jm_u32 header = 0;
    unsigned char side = 0;
    struct { jm_u32 payload, non_json, flags, padding; } tail = {0};
    if (!node || !flow)
        return 0;
    e->status = 3;
    if ((node & 7) || node > ~0ull - 160 || (flow & 63) ||
            flow > ~0ull - 38)
        return 0;
    if (read_field(e, &header, 4, node + 44))
        return 0;
    if ((header & 0xffff) < 96 || (header & 0xc00000) != 0xc00000 ||
            (header & 0x2000000))
        return 0;
#if JL_KIND == 2
    if (ctx->arg[1] != node + 64)
        return 0;
#endif
    if (read_field(e, &side, 1, flow + 37))
        return 0;
    side &= 0xc0;
    if (side != 0x40 && side != 0x80)
        return 0;
    if (read_field(e, &tail, 16, node + 144) ||
            read_field(e, &cache, 8, node + 88))
        return 0;
    e->flow_side = side == 0x40 ? 1 : 2;
    e->scb_flags = tail.flags & 0x3fff;
    e->cache_present = cache != 0;
    e->payload_bytes = tail.payload;
    e->status = (tail.flags & 1) ? 5 : 1;
    return node + 64;
#endif
}

__attribute__((section(SECTION), used))
jm_u64 json_lifecycle(struct jl_ctx *ctx)
{
    struct jl_event e = {0};
    struct jl_state fresh = {0}, *state = 0;
    struct jl_object next = {0}, *object = 0;
    struct ls_cfg_meta *meta = ls_cfg_get(0);
    jm_u64 *row = ls_cfg_get(1), key = 0, seen = 0;
    jm_u32 zero = 0;
    e.magic = JL_MAGIC; e.abi = 1; e.kind = JL_KIND;
#if JL_KIND == 1
    e.code = ctx->arg[1];
    seen = e.code == 57 ? 1 : (e.code == 1 || e.code == 5) ? 8 : 0;
#elif JL_KIND == 2
    seen = 2;
#else
    seen = 4;
#endif
    e.monotonic_ns = clock_ns();
    if (!e.monotonic_ns) e.flags |= 8;
    if (!meta || !row || meta->schema != 1 || meta->entries != 1 ||
            !row[0] || row[1] || row[2] || row[3]) {
        e.flags |= 1;
        goto out;
    }
    e.instance = meta->instance; e.revision = meta->revision;
    e.run = row[0];
    state = lookup(&json_boundary_state, &zero);
    if (!state) {
        fresh.run = e.run;
        if (update(&json_boundary_state, &zero, &fresh, 0)) {
            e.flags |= 2; e.status = 8;
            goto out;
        }
        state = lookup(&json_boundary_state, &zero);
    }
    if (!state) { e.flags |= 2; e.status = 8; goto out; }
    e.output_failures = state->failures;
    if (state->run != e.run) { e.status = 9; goto out; }
    if (state->calls == ~0ull) {
        e.flags |= 4; e.status = 7; goto out;
    }
    e.sequence = ++state->calls;
    key = context(ctx, &e);
    if (!key) goto out;
    object = lookup(&json_boundary_objects, &key);
#if JL_KIND != 3
    if (!object) {
        if (state->tags >= 128) { e.status = 6; goto out; }
        next.run = e.run; next.tag = ++state->tags;
        if (update(&json_boundary_objects, &key, &next, 0)) {
            e.flags |= 2; e.status = 8; goto out;
        }
        object = lookup(&json_boundary_objects, &key);
        if (!object) { e.flags |= 2; e.status = 8; goto out; }
    }
#else
    (void)next;
#endif
    if (object && object->run == e.run) {
        object->seen |= seen;
        e.context_tag = object->tag;
        e.seen_mask = object->seen;
    }
out:
    if (emit(ctx, &json_boundary_events, 0, &e, sizeof e) && state &&
            state->failures != ~0ull)
        state->failures++;
    return 0;
}
