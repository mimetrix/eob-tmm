/* Monitor the entry of adapt_set_state. The state argument is REQUESTED,
 * before the host flushes a preview or assigns the new state. This is not
 * a client-receipt or completed-release event. Resolve all fields on the
 * build box; no offsets or bitfield layouts are copied from TMM source. */
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

static long (*probe_read)(void *, u32, const void *) = (void *)4;
static u64 (*ktime_ns)(void) = (void *)5;
static long (*event_output)(void *, void *, u64, void *, u64) = (void *)25;

struct bpf_map_def {
    u32 type, key_size, value_size, max_entries, map_flags;
};
struct bpf_map_def events __attribute__((section("maps"), used)) = {
    .type = 4, .key_size = 4, .value_size = 4, .max_entries = 1,
};

#define CORE __attribute__((preserve_access_index))
/* ctx is a flexible inline allocation, NOT a pointer in hudnode. */
struct hudnode { u8 unused; u8 ctx[]; } CORE;
struct xbuf { u32 len; } CORE;
struct adapt_context {
    struct xbuf xpreview;
    struct xbuf xdraining_preview;
    u32 irid;
} CORE;
struct adapt_pcb { struct adapt_context *ctx; } CORE;
struct generic_context { u64 args[5]; };

/* 64 bytes, little-endian; pointers are lifetime-local correlation handles.
 * Validity: bit 0 = context read, 1 = preview, 2 = draining, 3 = irid.
 * A successful pointer read does not make it a durable operation identity. */
struct state_record {
    u32 schema, kind;
    u64 monotonic_ns, node, context, connflow;
    u32 requested_state, valid, preview_bytes, draining_bytes, irid, reserved;
};
_Static_assert(sizeof(struct state_record) == 64, "record ABI");

__attribute__((section("fentry/adapt_set_state"), used))
u64 adapt_set_state(struct generic_context *c)
{
    struct hudnode *node = (void *)c->args[0];
    struct adapt_context *ctx = (void *)0;
    struct adapt_pcb *pcb;
    struct state_record rec = {0};

    rec.schema = 1;
    rec.kind = 0x49434150; /* ICAP experiment state request */
    rec.monotonic_ns = ktime_ns();
    rec.node = c->args[0];
    rec.connflow = c->args[1];
    rec.requested_state = (u32)c->args[2];
    if (node) {
        pcb = (void *)node->ctx;
        if (probe_read(&ctx, sizeof(ctx), &pcb->ctx) == 0 && ctx) {
            rec.context = (u64)ctx;
            rec.valid |= 1;
            if (probe_read(&rec.preview_bytes, sizeof(u32),
                          &ctx->xpreview.len) == 0)
                rec.valid |= 2;
            if (probe_read(&rec.draining_bytes, sizeof(u32),
                          &ctx->xdraining_preview.len) == 0)
                rec.valid |= 4;
            if (probe_read(&rec.irid, sizeof(u32), &ctx->irid) == 0)
                rec.valid |= 8;
        }
    }
    event_output(c, &events, 0, &rec, sizeof(rec));
    return 0; /* observation only */
}
