/* Use the real output bridge. Check its result against a consumed record and
 * an observed full-ring drop. The cached pre-fix execution returned 1.
 */
#include "ls_tp_emit.c"

enum ls_verdict ls_vm_call(int slot, void *ctx, size_t len)
{
    (void)slot; (void)ctx; (void)len;
    abort(); /* This test must never enter the VM dispatch path. */
}

int main(void)
{
    g_tp_seg = calloc(1, LS_TP_SEG_SZ);
    if (!g_tp_seg)
        return 2;
    g_tp_seg_tried = 1;
    g_tp_seg->n_rings = 1;
    g_tp_seg->ring_stride = LS_TP_STRIDE;
    struct ls_ring *ring = ls_tp_seg_ring(g_tp_seg, 0);
    ls_ring_init(ring, LS_TP_RING_BYTES, LS_RING_STREAM);
    uint64_t payload = 42, received = 0;
    struct ls_rec header;
    int delivered = ls_tp_publish_raw(5, &payload, sizeof payload);
    int length = ls_ring_consume(ring, &header, &received, sizeof received);
    if (length != (int)sizeof payload || received != payload)
        return 2;
    int dropped = 99;
    for (unsigned i = 0; i < 2000 && !atomic_load(&ring->drops); i++)
        dropped = ls_tp_publish_raw(5, &payload, sizeof payload);
    int passed = delivered == 0 && dropped == -1 && atomic_load(&ring->drops) == 1;
    printf("{\"delivered_result\":%d,\"consumed_bytes\":%d,"
           "\"dropped_result\":%d,\"drops\":%llu,\"passed\":%s}\n",
           delivered, length, dropped, (unsigned long long)atomic_load(&ring->drops),
           passed ? "true" : "false");
    free(g_tp_seg);
    g_tp_seg = NULL;
    if (ls_tp_publish_raw(5, &payload, sizeof payload) != -1)
        return 2; /* Disabled output must not report delivery. */
    return passed ? 0 : 1;
}
