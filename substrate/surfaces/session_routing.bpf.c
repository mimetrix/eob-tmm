/* Qualified ca69b84f metadata reads, with no application accessor calls. */
#include "../config_snapshot.bpf.h"
#include "session_routing_abi.h"
struct sr_ctx { jm_u64 arg[5], result, reserved[6]; };
struct sr_state { jm_u64 instance, calls, failures, reserved; };
struct sr_policy { jm_u64 run, reserved[3]; };
#if SR_KIND == 1
#define metadata_state session_header_state
#else
#define metadata_state selected_route_state
#endif
struct ls_cfg_map_def metadata_state
    __attribute__((section("maps"), used)) = {1, 4, 32, 1, 0};
struct ls_cfg_map_def metadata_events
    __attribute__((section("maps"), used)) = {4, 4, 4, 1, 0};
static void *(*lookup)(void *, const void *) = (void *)1;
static long (*update)(void *, const void *, const void *, jm_u64)
    = (void *)2;
static long (*read_mem)(void *, jm_u64, jm_u64) = (void *)4;
static jm_u64 (*clock_ns)(void) = (void *)5;
static long (*emit)(void *, void *, jm_u64, void *, jm_u64) = (void *)25;
#define INLINE static __attribute__((always_inline)) inline

INLINE int read_field(struct jm_event *e, void *dst, jm_u32 n,
        jm_u64 src)
{
    if (e->reads >= 80 || n > 64 || e->source_bytes > 256 - n) {
        e->status = JM_BUDGET;
        return -1;
    }
    e->reads++;
    e->source_bytes += n;
    if (read_mem(dst, n, src)) {
        e->status = JM_READ_FAILED;
        return -1;
    }
    return 0;
}

INLINE void extract(struct sr_ctx *ctx, struct sr_event *record)
{
    struct jm_event *e = &record->field;
    jm_u64 ptr = 0;
    e->status = JM_UNAVAILABLE;
    if (!ctx->arg[0] || !ctx->arg[1])
        return;
#if SR_KIND == 1
    struct { jm_u64 data, length; } saved = {0};
    jm_u32 flags = 0;
    if (read_field(e, &flags, 4, ctx->arg[0] + 44))
        return;
    if ((flags & 0xffff) < 88 || (flags & 0xc00000) != 0xc00000) {
        e->status = JM_OUT_OF_SCOPE;
        return;
    }
    if (read_field(e, &saved, 16, ctx->arg[0] + 128))
        return;
    if (!saved.data || saved.length > 0xffffffffu)
        return;
    ptr = saved.data;
    e->original_length = saved.length;
    jm_u32 n = saved.length > 64 ? 64 : saved.length;
    if (n && read_field(e, e->value, n, ptr))
        return;
    e->copied_length = n;
    e->status = n < saved.length ? JM_TRUNCATED : JM_COMPLETE;
#else
    if (read_field(e, &ptr, 8, ctx->arg[0] + 80) || !ptr)
        goto endpoint_error;
    if (ptr & 1) {
        e->status = JM_OUT_OF_SCOPE;
        goto endpoint_error;
    }
    if (read_field(e, &ptr, 8, ptr + 72) || !ptr)
        goto endpoint_error;
    if (ptr & 1) {
        e->status = JM_OUT_OF_SCOPE;
        goto endpoint_error;
    }
    if (read_field(e, &ptr, 8, ptr + 184) || !ptr)
        goto endpoint_error;
    if (read_field(e, record->address, 20, ptr + 136))
        goto endpoint_error;
    record->endpoint_status = JM_COMPLETE;
    if (read_field(e, &ptr, 8, ptr) || !ptr)
        return;
    if (read_field(e, &ptr, 8, ptr + 32) || !ptr)
        return;
    /* One extra byte distinguishes exactly 64 from a longer name. */
    for (jm_u32 i = 0; i < 65; i++) {
        unsigned char byte = 0;
        if (read_field(e, &byte, 1, ptr + i))
            return;
        if (!byte) {
            e->original_length = e->copied_length = i;
            e->status = JM_COMPLETE;
            return;
        }
        if (i < 64)
            e->value[i] = byte;
    }
    e->original_length = 0xffffffffu;
    e->copied_length = 64;
    e->status = JM_TRUNCATED;
    return;
endpoint_error:
    record->endpoint_status = e->status;
    __builtin_memset(record->address, 0, 20);
#endif
}

#if SR_KIND == 1
#define SECTION "fentry/aimcp_decrypt_and_parse_sessionid.constprop.0"
#else
#define SECTION "fentry/hud_aimcp_add_persist.isra.0"
#endif
__attribute__((section(SECTION), used))
jm_u64 session_routing(struct sr_ctx *ctx)
{
    struct sr_event record = {0};
    struct jm_event *e = &record.field;
    struct sr_state fresh = {0}, *state = 0;
    struct ls_cfg_meta *meta = ls_cfg_get(0);
    struct sr_policy *policy;
    jm_u32 zero = 0;
    e->magic = SR_MAGIC;
    e->abi = 1;
    e->getter_result = SR_KIND;
    e->status = JM_UNAVAILABLE;
    if (SR_KIND == SR_ROUTE)
        record.endpoint_status = JM_UNAVAILABLE;
    e->monotonic_ns = clock_ns();
    if (!e->monotonic_ns)
        e->flags |= 8;
    if (!meta) {
        e->flags |= 1;
        goto output;
    }
    e->instance = meta->instance;
    e->revision = meta->revision;
    policy = ls_cfg_get(1);
    if (!policy || meta->schema != 1 || meta->entries != 1 ||
            !policy->run || policy->reserved[0] ||
            policy->reserved[1] || policy->reserved[2]) {
        e->flags |= 1;
        goto output;
    }
    e->run = policy->run;
    state = lookup(&metadata_state, &zero);
    if (!state || state->instance != e->instance) {
        fresh.instance = e->instance;
        if (update(&metadata_state, &zero, &fresh, 0)) {
            e->flags |= 2;
            state = 0;
            goto output;
        }
        state = lookup(&metadata_state, &zero);
    }
    if (!state) {
        e->flags |= 2;
        goto output;
    }
    e->output_failures = state->failures;
    if (state->calls == ~0ull)
        e->flags |= 4;
    else
        e->sequence = ++state->calls;
    extract(ctx, &record);
output:
    if (e->status != JM_COMPLETE && e->status != JM_TRUNCATED) {
        __builtin_memset(e->value, 0, sizeof e->value);
        e->copied_length = 0;
    }
    if (emit(ctx, &metadata_events, 0, &record, sizeof record) && state &&
            state->failures != ~0ull)
        state->failures++;
    return 0;
}
