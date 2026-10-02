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
/* Client TLS state of this connection (TLS-MODE.md), build 2ab960fa layout.
 * Walk the filter chain from connflow.bottom_node (+80) along hudnode.above
 * (+24). Identify a filter by its type name: the type objects are
 * thread-local, so their addresses are not stable. Every failure yields
 * RM_TLS_UNKNOWN with a reason. Nothing is inferred from silence. */
#define RM_SSL_NAME 0x004c5353u /* "SSL\0" */
struct rm_walk { jm_u64 node, ssl; };

/* One chain step. Returns nonzero with t->reason set on failure. A finished
 * walk (node == 0) is a no-op, so the caller needs no early exit. */
static __attribute__((noinline)) int
tls_step(struct rm_walk *w, struct rm_tls *t)
{
    jm_u64 node = w->node, link = 0;
    jm_u32 name = 0;
    if (!node)
        return 0;
    t->nodes++;
    /* filter = private - 136; typeid is filter + 64 = private - 72. */
    if ((node & 7) || node > ~0ull - 64 ||
            read_mem(&link, 8, node + 48) || link < 72 ||
            read_mem(&link, 8, link - 72) || !link ||
            read_mem(&link, 8, link) || !link ||
            read_mem(&name, 4, link)) {
        t->reason = 1;
        return -1;
    }
    if (name == RM_SSL_NAME) {
        if (w->ssl) {
            t->reason = 3;
            return -1;
        }
        w->ssl = node;
    }
    if (read_mem(&w->node, 8, node + 24)) {
        t->reason = 1;
        return -1;
    }
    return 0;
}

static __attribute__((noinline)) void
tls_mode(jm_u64 flow, struct rm_tls *t)
{
    struct rm_walk walk = {0};
    jm_u64 node = 0, ssl = 0, link = 0, pointers[5] = {0}, suite[2] = {0};
    jm_u32 w[11] = {0}, flags = 0, retain = 0;
    int failed = 0;
    unsigned short type = 0;
    t->mode = RM_TLS_UNKNOWN;
    if (!flow || (flow & 63) || flow > ~0ull - 96) {
        t->reason = 6;
        return;
    }
    if (read_mem(&type, 2, flow + 36)) {
        t->reason = 1;
        return;
    }
    if ((type & 255) != 6 || ((type >> 8) & 0xc0) != 0x40) {
        /* Not a client-side TCP flow: client TLS is not read here. */
        t->mode = RM_TLS_NA;
        return;
    }
    if (read_mem(&node, 8, flow + 80)) {
        t->reason = 1;
        return;
    }
    walk.node = node;
#pragma unroll
    for (jm_u32 i = 0; i < RM_TLS_NODES_MAX; i++)
        failed |= !failed && tls_step(&walk, t);
    if (failed)
        return;
    node = walk.node;
    ssl = walk.ssl;
    if (node) {
        t->reason = 2; /* limit reached, or a cycle */
        return;
    }
    if (!ssl) {
        t->mode = RM_TLS_NO_FILTER;
        return;
    }
    /* HUDNODE_CTX: valid only with f_active (bit 22) and f_ctx (bit 23). */
    if (read_mem(&flags, 4, ssl + 44)) {
        t->reason = 1;
        return;
    }
    if ((flags & (3u << 22)) != (3u << 22)) {
        t->reason = 5;
        return;
    }
    /* ssl_pcb is the node context at +64. */
    if (read_mem(w, 44, ssl + 64) || read_mem(pointers, 40, ssl + 64 + 72) ||
            read_mem(suite, 16, ssl + 64 + 520)) {
        t->reason = 1;
        return;
    }
    if (!(w[3] & 1)) {
        t->reason = 4; /* SSL_E_CLIENT: a server-side SSL filter */
        return;
    }
    t->vfyresult = (w[0] >> 22) & 127;
    t->pcm = (w[1] >> 15) & 3;
    t->suite = (jm_u32)(suite[1] & 0xffff);
    t->proto = (jm_u32)(suite[1] >> 40) & 15;
    if (w[3] >> 26 & 1) t->bits |= RM_TLS_HSOK;
    if (w[3] >> 16 & 1) t->bits |= RM_TLS_PASSTHRU;
    if (w[5] >> 9 & 1) t->bits |= RM_TLS_ST_RESUME;
    if (w[5] >> 11 & 1) t->bits |= RM_TLS_SS_RESUME;
    if (w[10] >> 20 & 1) t->bits |= RM_TLS_ALLOW_NONSSL;
    if (pointers[4]) t->bits |= RM_TLS_CHAIN;
    /* pointers: prf +72, session +80, +88, hs +96, peercertchain +104 */
    if (pointers[1]) {
        if (read_mem(&link, 8, pointers[1] + 216)) {
            t->reason = 1;
            t->mode = RM_TLS_UNKNOWN;
            return;
        }
        if (link) t->bits |= RM_TLS_SESSION_CERT;
    }
    if (pointers[0]) {
        if (read_mem(&retain, 4, pointers[0] + 716)) {
            t->reason = 1;
            return;
        }
        if (retain >> 19 & 1) t->bits |= RM_TLS_RETAIN;
    }
    t->mode = (t->bits & RM_TLS_HSOK) && !(t->bits & RM_TLS_PASSTHRU) ?
        RM_TLS_TERMINATED : RM_TLS_NOT_DECRYPTING;
}
#endif

#ifdef LS_ACTIVITY_EMBED
static __attribute__((noinline))
#else
__attribute__((section("fentry/hud_aimcp_handler"), used))
#endif
jm_u64 response_metadata(struct rm_ctx *ctx)
{
#ifdef LS_ACTIVITY_EMBED
    struct rm_event2 record = {0};
    struct rm_event *e = &record.base;
#else
    struct rm_event record = {0};
    struct rm_event *e = &record;
#endif
    struct rm_state fresh = {0}, *state = 0;
    struct ls_cfg_meta *meta = ls_cfg_get(0);
    struct rm_policy *policy;
    jm_u32 zero = 0;
    e->magic = RM_MAGIC;
#ifdef LS_ACTIVITY_EMBED
    e->abi = 2;
#else
    e->abi = 1;
#endif
    e->code = ctx->arg[1];
    e->presence = (ctx->arg[0] != 0) | ((ctx->arg[2] != 0) << 1) |
        ((ctx->arg[3] != 0) << 2);
    if (e->code == 28 || e->code == 144)
        e->http_status_state = RM_UNAVAILABLE;
    if (e->code == 29 || e->code == 145)
        e->completion_state = RM_UNAVAILABLE;
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
            !policy->run || policy->reserved[0] || policy->reserved[1] ||
            policy->reserved[2]) {
        e->flags |= 1;
        goto output;
    }
    e->run = policy->run;
    state = lookup(&response_metadata_state, &zero);
    if (!state || state->instance != e->instance) {
        fresh.instance = e->instance;
        if (update(&response_metadata_state, &zero, &fresh, 0)) {
            e->flags |= 2;
            state = 0;
            goto output;
        }
        state = lookup(&response_metadata_state, &zero);
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
    extract(ctx, e);
#ifdef LS_ACTIVITY_EMBED
    /* Once per exchange: the request-header event that confirms it. */
    if (e->code == 142 && ctx->arg[0])
        tls_mode(ctx->arg[2], &record.tls);
#endif
output:
    if (emit(ctx, &metadata_events, 0, &record, sizeof record) && state &&
            state->failures != ~0ull)
        state->failures++;
    return 0;
}
