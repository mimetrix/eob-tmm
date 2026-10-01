/* Admission preflight: the pinned tracing descriptor must permit this copy. */
typedef unsigned long long u64;
struct snapshot_context {
    u64 args[5], no_return;
    unsigned phase, captured;
    u64 sequence, state[4];
};
__attribute__((section("fexit/snapshot/snapshot_victim"), used))
u64 snapshot_probe(struct snapshot_context *ctx)
{
    if (ctx->phase == 1) {
        ctx->state[0] = ctx->args[1];
        ctx->state[1] = 1;
        ctx->state[2] = ctx->sequence;
        ctx->state[3] = 0;
    }
    return 0;
}
