/* Entry guards + matched normal return. No post-return application reads. */
#include "../config_snapshot.bpf.h"
#include "json_initialization_abi.h"
struct ji_state { __UINT64_TYPE__ instance, calls, failures, reserved; };
struct ls_cfg_map_def json_initialization_state
    __attribute__((section("maps"), used)) = {1, 4, 32, 1, 0};
struct ls_cfg_map_def json_initialization_events
    __attribute__((section("maps"), used)) = {4, 4, 4, 1, 0};
static void *(*lookup)(void *, const void *) = (void *)1;
static long (*update)(void *, const void *, const void *, __UINT64_TYPE__)
    = (void *)2;
static long (*read_mem)(void *, __UINT64_TYPE__, __UINT64_TYPE__)
    = (void *)4;
static __UINT64_TYPE__ (*clock_ns)(void) = (void *)5;
static long (*emit)(void *, void *, __UINT64_TYPE__, void *, __UINT64_TYPE__)
    = (void *)25;

__attribute__((section("fexit/snapshot/hud_json_handler"), used))
__UINT64_TYPE__ json_initialization(struct ls_snapshot_ctx *ctx)
{
    struct ji_capture *capture = (void *)ctx->state;
    struct ls_cfg_meta *meta = ls_cfg_get(0);
    __UINT64_TYPE__ *row = ls_cfg_get(1);
    if (ctx->phase == LS_SNAPSHOT_ENTRY) {
        __UINT64_TYPE__ node = ctx->arg[0], flow = ctx->arg[2];
        unsigned header = 0, flags = 0, status = 0, guards = 0, side = 0;
        unsigned reads = 0, bytes = 0;
        unsigned char flow_flags = 0;
        if (!meta || !row || meta->schema != 1 || meta->entries != 1 ||
            !row[0] || row[1] || row[2] || row[3])
            return 0;
        capture->instance = meta->instance;
        capture->revision = meta->revision;
        capture->run = row[0];
        if (ctx->arg[1] != 57) { status = 3; goto captured; }
        if (!node) goto captured;
        status = 5;
        if ((node & 7) || node > ~0ull - 156 || !flow ||
            (flow & 63) || flow > ~0ull - 38)
            goto captured;
        status = 4; reads++; bytes += 4;
        if (read_mem(&header, 4, node + 44)) goto captured;
        status = 5;
        if ((header & 0xffff) < 96 ||
            (header & 0xc00000) != 0xc00000 || (header & 0x2000000))
            goto captured;
        guards |= 1;
        status = 4; reads++; bytes += 4;
        if (read_mem(&flags, 4, node + 152)) goto captured;
        status = 2;
        if (flags & 1) goto captured;
        guards |= 2;
        status = 4; reads++; bytes++;
        if (read_mem(&flow_flags, 1, flow + 37)) goto captured;
        status = 5;
        flow_flags &= 0xc0;
        if (flow_flags != 0x40 && flow_flags != 0x80) goto captured;
        side = flow_flags == 0x40 ? 1 : 2;
        status = 1;
captured:
        capture->counts = (reads << 16) | bytes;
        capture->evidence = status | (side << 8) | (guards << 16);
        return 0;
    }
    if (ctx->phase == LS_SNAPSHOT_RETURN) {
        struct ji_event e = {0};
        struct ji_state fresh = {0}, *state = 0;
        unsigned zero = 0;
        e.magic = JI_MAGIC; e.abi = 1;
        e.code = ctx->arg[1]; e.invocation = ctx->sequence;
        e.monotonic_ns = clock_ns();
        if (!e.monotonic_ns) e.flags |= 8;
        if (ctx->flags != LS_SNAPSHOT_CAPTURED) { e.flags |= 1; goto out; }
        e.instance = capture->instance; e.revision = capture->revision;
        e.run = capture->run;
        e.status = capture->evidence & 0xff;
        e.flow_side = (capture->evidence >> 8) & 3;
        e.guards = capture->evidence >> 16;
        e.reads = capture->counts >> 16;
        e.source_bytes = capture->counts & 0xffff;
        if (!meta || !row || meta->schema != 1 || meta->entries != 1 ||
            !row[0] || row[1] || row[2] || row[3] ||
            meta->instance != e.instance || meta->revision != e.revision ||
            row[0] != e.run) {
            e.status = 6; e.flags |= 2; goto out;
        }
        state = lookup(&json_initialization_state, &zero);
        if (!state || state->instance != e.instance) {
            fresh.instance = e.instance;
            if (update(&json_initialization_state, &zero, &fresh, 0)) {
                e.flags |= 4; goto out;
            }
            state = lookup(&json_initialization_state, &zero);
        }
        if (!state || state->calls == ~0ull) { e.flags |= 4; goto out; }
        e.sequence = ++state->calls;
        e.output_failures = state->failures;
out:
        if (emit(ctx, &json_initialization_events, 0, &e, sizeof e) && state &&
            state->failures != ~0ull)
            state->failures++;
    }
    return 0;
}
