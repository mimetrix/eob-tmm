/* AI gateway latency attribution (P24): one ELF, several entry programs,
 * joined on the request's client-side struct aigw_scb address.
 *
 * Every entry emits one 64-byte event: which point, the scb key, a
 * monotonic timestamp and the point's own arguments that classify it. The
 * consumer computes the stages; the bytecode keeps only what a later point
 * cannot recover: per-scb request start (admit) and the most recent store
 * send per host ctx. Maps are owned by this one program; its entries share
 * them by name.
 *
 * Points (build 2521bd23 layouts; see the per-point comments):
 *   ADMIT        aigw_rbac_admit(node, uf, hd)         scb = node->ctx (+64)
 *   STORE_SEND   aigw_host_hgetall(hc, key, len, token) / aigw_host_eval(hc, ...)
 *                scb = hc->scb (+24)
 *   STORE_REPLY  aigw_host_store_reply(hc, req_id, val) scb = hc->scb (+24)
 *   EVENT        aigw_host_session_event(scb, ev, status)
 *   REPLY_PARSE  aigw_host_reply_parse(hc, side)       scb = hc->scb (+24)
 *   REPLY_DONE   aigw_host_reply_done(scb, side)
 *   PUBLISH      aigw_host_obs_publish(hctx, pub, line, len)  hctx->scb (+24)
 *
 * Monitor only. */
#include "../config_snapshot.bpf.h"

typedef ls_cfg_u32 u32;
typedef ls_cfg_u64 u64;

#define AT_MAGIC 0x41544d47u /* "GMTA" */
enum at_point {
    AT_ADMIT = 1, AT_STORE_SEND, AT_STORE_REPLY, AT_EVENT,
    AT_REPLY_PARSE, AT_REPLY_DONE, AT_PUBLISH,
};
#define AT_NO_CONFIG 1u
#define AT_READ_FAILED 2u
#define AT_NO_KEY 4u
#define AT_MAP_FAILED 8u

struct at_ctx { u64 arg[5], result, reserved[6]; };
struct at_event {
    u32 magic, abi;
    u64 instance, sequence, monotonic_ns;
    u64 scb;           /* the join key; an address, never an identity */
    u32 point, flags;
    u32 a, b;          /* point-specific: side, event, status, length */
    u64 admit_ns;      /* this scb's admit time, if known (0 otherwise) */
};
_Static_assert(sizeof(struct at_ctx) == 96, "context ABI");
_Static_assert(sizeof(struct at_event) == 64, "event ABI");

struct at_state { u64 instance, calls, failures, reserved; };
struct at_req { u64 admit_ns, generation, reserved[2]; };
_Static_assert(sizeof(struct at_req) == 32, "map value limit");

struct ls_cfg_map_def aigw_timing_state __attribute__((section("maps"), used))
    = {1, 4, 32, 1, 0};
struct ls_cfg_map_def aigw_timing_req __attribute__((section("maps"), used))
    = {1, 8, 32, 128, 0};
struct ls_cfg_map_def aigw_timing_events __attribute__((section("maps"), used))
    = {4, 4, 4, 1, 0};
static void *(*lookup)(void *, const void *) = (void *)1;
static long (*update)(void *, const void *, const void *, u64) = (void *)2;
static long (*read_mem)(void *, u64, u64) = (void *)4;
static u64 (*clock_ns)(void) = (void *)5;
static long (*emit)(void *, void *, u64, void *, u64) = (void *)25;

static __attribute__((noinline)) u64
at_scb_from_ctx(u64 hc, u32 *flags)
{
    u64 scb = 0;
    if (!hc || (hc & 7) || hc > ~0ull - 32 || read_mem(&scb, 8, hc + 24)) {
        *flags |= AT_READ_FAILED;
        return 0;
    }
    return scb;
}

static __attribute__((noinline)) u64
at_scb_from_node(u64 node, u32 *flags)
{
    u32 bits = 0;
    if (!node || (node & 7) || node > ~0ull - 72 ||
            read_mem(&bits, 4, node + 44)) {
        *flags |= AT_READ_FAILED;
        return 0;
    }
    /* HUDNODE_CTX: f_active (bit 22) and f_ctx (bit 23); ctx is inline at
     * +64, so the scb address is node + 64. */
    if ((bits & (3u << 22)) != (3u << 22)) {
        *flags |= AT_NO_KEY;
        return 0;
    }
    return node + 64;
}

static __attribute__((noinline)) long
at_emit(struct at_ctx *ctx, struct at_event *e)
{
    struct at_state fresh = {0}, *state;
    struct ls_cfg_meta *meta = ls_cfg_get(0);
    struct at_req *req;
    u32 zero = 0;
    e->magic = AT_MAGIC;
    e->abi = 1;
    e->monotonic_ns = clock_ns();
    if (!meta) {
        e->flags |= AT_NO_CONFIG;
    } else {
        e->instance = meta->instance;
        state = lookup(&aigw_timing_state, &zero);
        if (!state || state->instance != e->instance) {
            fresh.instance = e->instance;
            update(&aigw_timing_state, &zero, &fresh, 0);
            state = lookup(&aigw_timing_state, &zero);
        }
        if (state)
            e->sequence = ++state->calls;
        else
            e->flags |= AT_MAP_FAILED;
    }
    if (e->scb) {
        if (e->point == AT_ADMIT) {
            struct at_req next = {0};
            next.admit_ns = e->monotonic_ns;
            next.generation = e->sequence;
            if (update(&aigw_timing_req, &e->scb, &next, 0))
                e->flags |= AT_MAP_FAILED;
            e->admit_ns = e->monotonic_ns;
        } else {
            req = lookup(&aigw_timing_req, &e->scb);
            if (req)
                e->admit_ns = req->admit_ns;
        }
    } else {
        e->flags |= AT_NO_KEY;
    }
    return emit(ctx, &aigw_timing_events, 0, e, sizeof *e);
}

__attribute__((section("fentry/aigw_rbac_admit"), used))
u64 at_admit(struct at_ctx *ctx)
{
    struct at_event e = {0};
    e.point = AT_ADMIT;
    e.scb = at_scb_from_node(ctx->arg[0], &e.flags);
    at_emit(ctx, &e);
    return 0;
}

/* The session's store requests are issued through two host-table entries,
 * both taking the aigw_host_ctx as arg0: hgetall (virtual-key lookup) and
 * eval (the Lua scripts). Hooking these, not aigw_dssm_send, keys the send to
 * the request: aigw_dssm_send's own cb_arg is a script-call record for scripts,
 * not the host ctx (attempt 01 finding). a = 1 hgetall, 2 eval; b = io_token
 * != 0 (a parked, awaited reply rather than a detached charge). */
static __attribute__((noinline)) void
at_store(struct at_ctx *ctx, u32 kind, u64 token)
{
    struct at_event e = {0};
    e.point = AT_STORE_SEND;
    e.a = kind;
    e.b = token != 0;
    e.scb = at_scb_from_ctx(ctx->arg[0], &e.flags);
    at_emit(ctx, &e);
}

__attribute__((section("fentry/aigw_host_hgetall"), used))
u64 at_store_hgetall(struct at_ctx *ctx)
{
    at_store(ctx, 1, ctx->arg[3]);
    return 0;
}

/* aigw_host_eval(hctx, script, keys, nkeys, args, nargs, io_token): the
 * token is the seventh argument and is not in the context; report only
 * that this was an eval. A detached eval has a NULL-safe hctx check in the
 * host; at_scb_from_ctx refuses a NULL ctx. */
__attribute__((section("fentry/aigw_host_eval"), used))
u64 at_store_eval(struct at_ctx *ctx)
{
    at_store(ctx, 2, 1);
    return 0;
}

__attribute__((section("fentry/aigw_host_store_reply"), used))
u64 at_store_reply(struct at_ctx *ctx)
{
    struct at_event e = {0};
    e.point = AT_STORE_REPLY;
    e.a = ctx->arg[2] != 0; /* a reply value is present */
    e.scb = at_scb_from_ctx(ctx->arg[0], &e.flags);
    at_emit(ctx, &e);
    return 0;
}

__attribute__((section("fentry/aigw_host_session_event"), used))
u64 at_event(struct at_ctx *ctx)
{
    struct at_event e = {0};
    e.point = AT_EVENT;
    e.scb = ctx->arg[0];
    e.a = (u32)ctx->arg[1]; /* AIGW_LIB_SESS_EV_* */
    e.b = (u32)ctx->arg[2]; /* status */
    at_emit(ctx, &e);
    return 0;
}

__attribute__((section("fentry/aigw_host_reply_parse"), used))
u64 at_reply_parse(struct at_ctx *ctx)
{
    struct at_event e = {0};
    e.point = AT_REPLY_PARSE;
    e.a = (u32)ctx->arg[1] & 1; /* AIGW_LIB_SIDE_SERVER */
    e.scb = at_scb_from_ctx(ctx->arg[0], &e.flags);
    at_emit(ctx, &e);
    return 0;
}

__attribute__((section("fentry/aigw_host_reply_done"), used))
u64 at_reply_done(struct at_ctx *ctx)
{
    struct at_event e = {0};
    e.point = AT_REPLY_DONE;
    e.scb = ctx->arg[0];
    e.a = (u32)ctx->arg[1] & 1;
    at_emit(ctx, &e);
    return 0;
}

__attribute__((section("fentry/aigw_host_obs_publish"), used))
u64 at_publish(struct at_ctx *ctx)
{
    struct at_event e = {0};
    e.point = AT_PUBLISH;
    e.b = (u32)(ctx->arg[3] > 0xffffffffull ? 0xffffffffu : ctx->arg[3]);
    e.scb = at_scb_from_ctx(ctx->arg[0], &e.flags);
    at_emit(ctx, &e);
    return 0;
}
