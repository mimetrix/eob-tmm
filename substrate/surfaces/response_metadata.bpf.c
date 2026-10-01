/* Qualified handler input fields, without application accessor calls. */
#include "../config_snapshot.bpf.h"
#include "response_metadata_abi.h"
struct rm_ctx { jm_u64 arg[5], result, reserved[6]; };
struct rm_state { jm_u64 instance, calls, failures, reserved; };
struct rm_policy { jm_u64 run, reserved[3]; };
#ifndef LS_ACTIVITY_EMBED
struct ls_cfg_map_def response_metadata_state
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

INLINE int read_field(struct rm_event *e, void *dst, jm_u32 size,
        jm_u64 address)
{
    e->reads++;
    e->source_bytes += size;
    if (read_mem(dst, size, address)) {
        e->http_status_state = RM_READ_FAILED;
        return -1;
    }
    return 0;
}

INLINE void extract(struct rm_ctx *ctx, struct rm_event *e)
{
    if (!ctx->arg[0] || !ctx->arg[2])
        return;
    if (e->completion_state == RM_UNAVAILABLE) {
        if (ctx->arg[3] > 1) {
            e->completion_state = RM_OUT_OF_SCOPE;
        } else {
            e->transfer_complete = ctx->arg[3];
            e->completion_state = RM_COMPLETE;
        }
    } else if (e->http_status_state == RM_UNAVAILABLE) {
        unsigned char flags = 0;
        jm_u32 status = 0;
        if (!ctx->arg[3])
            return;
        if (read_field(e, &flags, 1, ctx->arg[3] + 28))
            return;
        if (flags & 3) {
            e->http_status_state = RM_OUT_OF_SCOPE;
            return;
        }
        /* f_invalid_status invalidates the HTTP/2 cached pseudo-header,
         * not this parsed numeric status. Do not use it as a validity bit. */
        if (read_field(e, &status, 4, ctx->arg[3] + 36))
            return;
        if (status < 100 || status > 999) {
            e->http_status_state = RM_OUT_OF_SCOPE;
            return;
        }
        e->http_status = status;
        e->http_status_state = RM_COMPLETE;
    }
}

#ifdef LS_ACTIVITY_EMBED
static __attribute__((noinline))
#else
__attribute__((section("fentry/hud_aimcp_handler"), used))
#endif
jm_u64 response_metadata(struct rm_ctx *ctx)
{
    struct rm_event e = {0};
    struct rm_state fresh = {0}, *state = 0;
    struct ls_cfg_meta *meta = ls_cfg_get(0);
    struct rm_policy *policy;
    jm_u32 zero = 0;
    e.magic = RM_MAGIC;
    e.abi = 1;
    e.code = ctx->arg[1];
    e.presence = (ctx->arg[0] != 0) | ((ctx->arg[2] != 0) << 1) |
        ((ctx->arg[3] != 0) << 2);
    if (e.code == 28 || e.code == 144)
        e.http_status_state = RM_UNAVAILABLE;
    if (e.code == 29 || e.code == 145)
        e.completion_state = RM_UNAVAILABLE;
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
    if (!policy || meta->schema != 1 || meta->entries != 1 ||
            !policy->run || policy->reserved[0] || policy->reserved[1] ||
            policy->reserved[2]) {
        e.flags |= 1;
        goto output;
    }
    e.run = policy->run;
    state = lookup(&response_metadata_state, &zero);
    if (!state || state->instance != e.instance) {
        fresh.instance = e.instance;
        if (update(&response_metadata_state, &zero, &fresh, 0)) {
            e.flags |= 2;
            state = 0;
            goto output;
        }
        state = lookup(&response_metadata_state, &zero);
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
    if (emit(ctx, &metadata_events, 0, &e, sizeof e) && state &&
            state->failures != ~0ull)
        state->failures++;
    return 0;
}
