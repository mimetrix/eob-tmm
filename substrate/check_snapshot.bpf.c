/* Verified test program. Only the output receiver is replaced in the host test. */
#include "check_snapshot_abi.h"
#ifndef OWNER
#define OWNER 1
#endif
struct map_def { unsigned type, key_size, value_size, entries, flags; };
struct map_def snapshot_test_events
    __attribute__((section("maps"), used)) = {4, 4, 4, 1, 0};
static long (*read_mem)(void *, __UINT64_TYPE__, __UINT64_TYPE__)
    = (void *)4;
static long (*emit)(void *, void *, __UINT64_TYPE__, void *, __UINT64_TYPE__)
    = (void *)25;

__attribute__((section("fexit/snapshot/snapshot_victim"), used))
__UINT64_TYPE__ snapshot_probe(struct ls_snapshot_ctx *ctx)
{
    if (ctx->phase == LS_SNAPSHOT_ENTRY) {
        unsigned disabled = 0;
        if (ctx->arg[2] == 9)
            return 0; /* Intentional omitted capture. */
        if (ctx->arg[0] && read_mem(&disabled, 4, ctx->arg[0]))
            return 0;
        ctx->state[0] = 1;
        ctx->state[1] = ctx->arg[0] && ctx->arg[1] == 57 && !disabled;
        ctx->state[2] = ctx->arg[4];
        ctx->state[3] = OWNER;
        if (ctx->arg[2] == 11) {
            ctx->arg[0] = ctx->arg[1] = ctx->arg[2] = ~0ull;
            ctx->arg[3] = ctx->arg[4] = ctx->no_return = ~0ull;
            ctx->phase = ctx->flags = ~0u;
            ctx->sequence = ~0ull;
        }
    } else if (ctx->phase == LS_SNAPSHOT_RETURN) {
        struct snapshot_observation out = {0};
        out.sequence = ctx->sequence; out.serial = ctx->arg[4];
        out.owner = OWNER; out.no_return = ctx->no_return;
        out.node = ctx->arg[0]; out.event = ctx->arg[1];
        out.phase = ctx->phase; out.flags = ctx->flags;
        if (ctx->flags == LS_SNAPSHOT_CAPTURED) {
            out.known = ctx->state[0]; out.eligible = ctx->state[1];
            out.marker = ctx->state[3];
        }
        emit(ctx, &snapshot_test_events, 0, &out, sizeof out);
        /* Writes must not change the saved return address or caller state. */
        ctx->arg[0] = ctx->no_return = ctx->sequence = ~0ull;
    }
    return 1; /* Both phases must ignore a SAFE_RETURN selection. */
}
