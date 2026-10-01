/* Reuse the frozen ID reader; add flow side just before its single output. */
#include "id_flow_abi.h"
static __attribute__((always_inline)) inline long id_flow_emit(
        void *, void *, jm_u64, void *, jm_u64);
#define message_id_state id_flow_state
#ifdef LS_ACTIVITY_EMBED
#undef emit
#endif
/* Function-like expansion leaves the helper pointer declaration unchanged. */
#define emit(...) id_flow_emit(__VA_ARGS__)
#include "message_id.bpf.c"
#undef emit
#ifdef LS_ACTIVITY_EMBED
#define emit activity_emit
#endif
#undef message_id_state

static __attribute__((always_inline)) inline long
id_flow_emit(void *context, void *map, jm_u64 flags, void *data, jm_u64 size)
{
    struct mi_ctx *ctx = context;
    struct jm_event *e = data;
    jm_u64 flow = ctx->arg[2];
    jm_u32 status = 0, side = 0;
    unsigned char type = 0;

    e->magic = IF_MAGIC;
    if ((e->flags & 3) || !flow) goto output;
    if (flow & 1) { status = IF_OUT_OF_SCOPE; goto output; }
    if (flow & 63) { status = IF_INVALID; goto output; }
    if (e->reads >= 80 || e->source_bytes >= 2048) {
        status = IF_BUDGET; goto output;
    }
    e->reads++; e->source_bytes++;
    if (read_mem(&type, 1, flow + 37)) {
        status = IF_READ_FAILED; goto output;
    }
    type &= 0xc0;
    if (type == 0x40) side = 1;
    else if (type == 0x80) side = 2;
    else { status = IF_INVALID; goto output; }
    status = IF_COMPLETE;
output:
    e->flags |= (side << IF_SIDE_SHIFT) | (status << IF_STATUS_SHIFT);
    return emit(context, map, flags, data, size);
}
