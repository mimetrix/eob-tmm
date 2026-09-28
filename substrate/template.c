/*
 * TMM eBPF tutorial. Read docs/EBPF-TUTORIAL.md before loading.
 *
 * Build the default entry variant, or use -DTEMPLATE_EXIT=1 for exit.
 * Both use the same input and event formats. Use monitor mode first.
 * Field offsets must be resolved before verification and signing.
 */
#include "config_snapshot.bpf.h"

typedef unsigned char u8;
typedef ls_cfg_u32 u32;
typedef ls_cfg_u64 u64;

#ifndef TEMPLATE_EXIT
#define TEMPLATE_EXIT 0
#endif

/* 1. The host supplies 96 bytes. At exit, byte 40 holds the return value.
 * Argument pointers are addresses, not permission to dereference them.
 */
struct template_ctx {
    u64 arg[5];
    u64 result;
    u64 reserved[6];
};
_Static_assert(sizeof(struct template_ctx) == 96, "tracing context size");

/* 2. Helpers are host functions. These numbers are the program interface.
 * This runtime supports six general helpers; it is not kernel eBPF.
 */
static void *(*bpf_map_lookup_elem)(void *, const void *) = (void *)1;
static long (*bpf_map_update_elem)(void *, const void *, const void *, u64)
    = (void *)2;
static long (*bpf_map_delete_elem)(void *, const void *) = (void *)3;
#if !TEMPLATE_EXIT
static long (*bpf_probe_read)(void *, u32, const void *) = (void *)4;
#endif
static u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_perf_event_output)(void *, void *, u64, void *, u64)
    = (void *)25;

/* 3. Configuration: schema 2, exactly one 32-byte row, little-endian.
 * threshold: entry buffer length, or exit result, at which matched=1.
 * reserved64: must be zero. Observability does not sample events.
 * reset_token: change this value to reset this thread's counter.
 * flags: bit 0 enables observation; bit 1 requests entry SAFE_RETURN.
 * reserved must be zero. Missing/invalid input continues normal TMM work.
 */
struct template_policy {
    u64 threshold;
    u64 reserved64;
    u64 reset_token;
    u32 flags;
    u32 reserved;
};
#define ENABLED 1u
#define REQUEST_SAFE_RETURN 2u

/* 4. Mutable state is per thread, not shared across all TMM threads.
 * Do not use a pointer or this counter as an authenticated request ID.
 * The instance token prevents a reload from using old counter contents.
 */
struct template_state {
    u64 instance;
    u64 reset_token;
    u64 seen;
    u64 reserved; /* Keep the 32-byte map shape; not an output timer. */
};
struct ls_cfg_map_def tutorial_state __attribute__((section("maps"), used))
    = {1, 4, 32, 1, 0};
/* One key, one entry. Requires the repaired host's small-table lookup. */
struct ls_cfg_map_def tutorial_events __attribute__((section("maps"), used))
    = {4, 4, 4, 1, 0};
/* Keep map symbols global. The pinned verifier rejects local map symbols.
 * The configuration map is declared by config_snapshot.bpf.h.
 */

/* 5. Event ABI 1: fixed-width fields, no raw pointers or credentials.
 * The transport adds its own timestamp, sequence, slot and schema.
 * magic+abi identify THIS payload within the generic program schema.
 */
struct template_event {
    u32 magic, abi;
    u64 instance, revision, monotonic_ns, seen;
    u64 observed, threshold, result;
    u32 kind, flags, version, header_count;
    u32 matched, verdict;
};
_Static_assert(sizeof(struct template_policy) == 32, "configuration row");
_Static_assert(sizeof(struct template_state) == 32, "map value limit");
_Static_assert(sizeof(struct template_event) == 88, "event ABI");
#define NO_POLICY 1u
#define BAD_POLICY 2u
#define READ_FAILED 4u
#define MAP_FAILED 8u
#define CLOCK_FAILED 16u
#define DISABLED 32u
#define COUNTER_FULL 64u

#if !TEMPLATE_EXIT
/* 6. Minimal named-field views. Local offsets are placeholders.
 * CO-RE (Compile Once, Run Everywhere) supplies relocation records.
 * The build tools resolve them against the target build's type data.
 */
struct http_parser {
    u32 header_count;
} __attribute__((preserve_access_index));
struct http_parse_ctx {
    u8 version_num;
    struct http_parser *parser;
} __attribute__((preserve_access_index));
struct xbuf {
    u32 len;
} __attribute__((preserve_access_index));

static __attribute__((always_inline)) inline int
read_fields(struct template_ctx *ctx, struct template_event *event)
{
    struct http_parse_ctx *http = (void *)ctx->arg[0];
    struct xbuf *buffer = (void *)ctx->arg[1];
    struct http_parser *parser = 0;
    u8 version = 0;
    u32 length = 0;
    int valid = 0;

    if (!http || !buffer)
        goto out;
    if (bpf_probe_read(&version, sizeof version, &http->version_num))
        goto out;
    if (bpf_probe_read(&length, sizeof length, &buffer->len))
        goto out;
    /* Two-hop read: copy the pointer, check it, then copy its field. */
    if (bpf_probe_read(&parser, sizeof parser, &http->parser) || !parser)
        goto out;
    if (bpf_probe_read(&event->header_count, sizeof event->header_count,
                      &parser->header_count))
        goto out;
    event->version = version;
    event->observed = length;
    valid = 1;
out:
    return valid;
}
#define TEMPLATE_SECTION "fentry/http_parse_client_headers"
#else
/* At exit an argument's object might have been freed. Read only result. */
#define TEMPLATE_SECTION "fexit/http_parse_client_headers"
#endif

/* 7. One entry point per object. All helper errors have an explicit path.
 * The host owns actions: 0=FALLTHROUGH, 1=SAFE_RETURN at an entry hook.
 * SAFE_RETURN is a selection, not the error value returned to TMM's caller.
 */
__attribute__((section(TEMPLATE_SECTION), used))
u64 template(struct template_ctx *ctx)
{
    struct template_event event = {0};
    struct template_state fresh = {0};
    struct template_state *state = 0;
    struct ls_cfg_meta *meta = ls_cfg_get(0);
    struct template_policy *policy = 0;
    u32 key = 0;

    event.magic = 0x544d4d31u;
    event.abi = 1;
    event.kind = TEMPLATE_EXIT ? 2 : 1;
    event.monotonic_ns = bpf_ktime_get_ns();
    if (!meta) {
        event.flags = NO_POLICY;
        goto emit;
    }
    event.instance = meta->instance;
    event.revision = meta->revision;
    if (meta->schema != 2 || meta->entries != 1) {
        event.flags = BAD_POLICY;
        goto emit;
    }
    policy = ls_cfg_get(1);
    if (!policy) {
        event.flags = NO_POLICY;
        goto emit;
    }
    if (policy->reserved64 || policy->reserved || (policy->flags & ~3u)) {
        event.flags = BAD_POLICY;
        goto emit;
    }
    event.threshold = policy->threshold;
    state = bpf_map_lookup_elem(&tutorial_state, &key);
    if (!(policy->flags & ENABLED)) {
        event.flags = DISABLED;
        if (state && bpf_map_delete_elem(&tutorial_state, &key))
            event.flags |= MAP_FAILED;
        state = 0; /* A deleted value pointer must not be used. */
        goto emit;
    }
    if (!state || state->instance != meta->instance ||
        state->reset_token != policy->reset_token) {
        fresh.instance = meta->instance;
        fresh.reset_token = policy->reset_token;
        if (bpf_map_update_elem(&tutorial_state, &key, &fresh, 0)) {
            event.flags = MAP_FAILED;
            state = 0;
            goto emit;
        }
        state = bpf_map_lookup_elem(&tutorial_state, &key);
        if (!state) {
            event.flags = MAP_FAILED;
            goto emit;
        }
    }
    /* Saturate instead of wrapping a counter into an old value. */
    if (state->seen == ~0ull)
        event.flags |= COUNTER_FULL;
    else
        state->seen++;
    event.seen = state->seen;
#if TEMPLATE_EXIT
    event.result = ctx->result;
    event.observed = event.result;
    event.matched = event.observed >= policy->threshold;
#else
    if (!read_fields(ctx, &event)) {
        event.flags |= READ_FAILED;
        goto emit;
    }
    event.matched = event.observed >= policy->threshold;
    event.verdict = event.matched && (policy->flags & REQUEST_SAFE_RETURN);
#endif
emit:
    /* 8. Timestamp every call. Time never decides whether to emit.
     * The program clock is monotonic; transport time is wall-clock time. */
    if (!event.monotonic_ns)
        event.flags |= CLOCK_FAILED;
    /* 9. Attempt one record on EVERY call, including diagnostics.
     * A full ring can drop a record. The collector must report that loss.
     * Output success or failure never suppresses a later call's record and
     * never changes the verdict. The host's result conversion is tested
     * separately by check_output_result.c; see CONTESTED-PREMISES.md section 24.
     */
    (void)bpf_perf_event_output(ctx, &tutorial_events, 0, &event, sizeof event);
    return event.verdict;
}
