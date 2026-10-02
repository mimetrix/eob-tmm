/* AI gateway per-request record, observed at TMM's publish callback.
 *
 * Hook: fentry/aigw_host_obs_publish(void *hctx,
 *                                    const struct aigw_lib_span *publisher,
 *                                    const uint8_t *line, size_t len)
 * The library calls this once per settled or denied request with its own
 * formatted record (JSON, up to 8 KiB). The probe emits the record's length
 * and its leading bytes in bounded chunks; it never reads the library's
 * private state, and it never changes the return value (monitor only).
 *
 * One invocation emits at most AR_CHUNKS frames of AR_CHUNK bytes, so a long
 * record is visibly truncated rather than silently cut. Every frame carries
 * the invocation's sequence and the chunk index, so a consumer can tell a
 * complete prefix from a gap. */
#include "../config_snapshot.bpf.h"

typedef ls_cfg_u32 u32;
typedef ls_cfg_u64 u64;

#define AR_MAGIC 0x41474f42u /* "BOGA": AIGW observation */
#define AR_CHUNK 128u
#define AR_CHUNKS 12u

struct ar_ctx { u64 arg[5], result, reserved[6]; };
struct ar_state { u64 instance, calls, failures, reserved; };
struct ar_frame {
    u32 magic, abi;
    u64 instance, sequence, monotonic_ns;
    u32 total_len, chunk, chunks, copied;
    u32 flags, reserved;
    unsigned char data[AR_CHUNK];
};
_Static_assert(sizeof(struct ar_ctx) == 96, "context ABI");
_Static_assert(sizeof(struct ar_frame) == 184, "frame fits the record and the 256-byte stack");

struct ls_cfg_map_def aigw_record_state __attribute__((section("maps"), used))
    = {1, 4, 32, 1, 0};
struct ls_cfg_map_def aigw_record_events __attribute__((section("maps"), used))
    = {4, 4, 4, 1, 0};
static void *(*lookup)(void *, const void *) = (void *)1;
static long (*update)(void *, const void *, const void *, u64) = (void *)2;
static long (*read_mem)(void *, u64, u64) = (void *)4;
static u64 (*clock_ns)(void) = (void *)5;
static long (*emit)(void *, void *, u64, void *, u64) = (void *)25;

#define NO_CONFIG 1u
#define MAP_FAILED 2u
#define READ_FAILED 4u
#define TRUNCATED 8u
#define BAD_ARGS 16u

__attribute__((section("fentry/aigw_host_obs_publish"), used))
u64 aigw_record(struct ar_ctx *ctx)
{
    struct ar_frame f = {0};
    struct ar_state fresh = {0}, *state = 0;
    struct ls_cfg_meta *meta = ls_cfg_get(0);
    u64 line = ctx->arg[2], len = ctx->arg[3];
    u32 zero = 0, failures = 0;

    f.magic = AR_MAGIC;
    f.abi = 1;
    f.monotonic_ns = clock_ns();
    if (!meta) {
        f.flags |= NO_CONFIG;
    } else {
        f.instance = meta->instance;
        state = lookup(&aigw_record_state, &zero);
        if (!state || state->instance != f.instance) {
            fresh.instance = f.instance;
            if (update(&aigw_record_state, &zero, &fresh, 0))
                f.flags |= MAP_FAILED;
            state = lookup(&aigw_record_state, &zero);
        }
        if (state) {
            state->calls++;
            f.sequence = state->calls;
        } else {
            f.flags |= MAP_FAILED;
        }
    }
    if (!line || !len || len > 65536 || line > ~0ull - len) {
        f.flags |= BAD_ARGS;
        f.total_len = (u32)(len > 0xffffffffull ? 0xffffffffu : len);
        f.chunks = 1;
        if (emit(ctx, &aigw_record_events, 0, &f, sizeof f))
            failures++;
        goto out;
    }
    f.total_len = (u32)len;
    f.chunks = (u32)((len + AR_CHUNK - 1) / AR_CHUNK);
    if (f.chunks > AR_CHUNKS) {
        f.chunks = AR_CHUNKS;
        f.flags |= TRUNCATED;
    }
#pragma unroll
    for (u32 i = 0; i < AR_CHUNKS; i++) {
        u64 off = (u64)i * AR_CHUNK;
        if (i < f.chunks) {
            /* Always read a full chunk-sized constant when the chunk is
             * whole; read a masked, verifier-bounded size for the tail. */
            u64 rest = len - off;
            u32 n = rest >= AR_CHUNK ? AR_CHUNK : (u32)rest;
            f.chunk = i;
            f.copied = n;
            __builtin_memset(f.data, 0, AR_CHUNK);
            if (n == AR_CHUNK) {
                if (read_mem(f.data, AR_CHUNK, line + off))
                    f.flags |= READ_FAILED;
            } else {
                u64 m = n & (AR_CHUNK - 1);
                if (m == 0 || read_mem(f.data, m, line + off))
                    f.flags |= READ_FAILED;
            }
            if (emit(ctx, &aigw_record_events, 0, &f, sizeof f))
                failures++;
        }
    }
out:
    if (state && failures)
        state->failures += failures;
    return 0;
}
