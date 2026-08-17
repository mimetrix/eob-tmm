/* ls_tp_emit.c --- the STDINC side of the tracepoint boundary.
 *
 * It exists as its own translation unit because the caller cannot reach ls_vm.h:
 * every file in modules/hudfilter/http compiles in TMM's -nostdinc world, and
 * ls_vm.h needs stdint/stddef. This file is marked STDINC in src/compile/filelist
 * and is the only place the two worlds meet for telemetry --- the same shape
 * ls_prep.c already uses for the bootstrap.
 *
 * TWO CONSUMERS, ONE RECORD. Every record reaching this function goes to:
 *
 *   1. the VM, which answers a question about it (counted in fired/safe_returns)
 *   2. the shared-memory ring, which carries the bytes themselves off-box
 *
 * They are independent. The VM answers "how many were malformed" with two
 * counters and no transport. The ring answers "show me that request", which
 * needs a drain agent and a segment. Neither is a substitute for the other, and
 * the ring is off unless LS_TP_RING names a path.
 *
 * WHY THE VERDICT IS DISCARDED HERE. ls_vm_call returns one, because the shield
 * path needs it. A tracepoint does not, and giving the call site no way to
 * receive it means no future edit there can accidentally start acting on it. The
 * cast to void is the entire safety property, and it is cheaper and more durable
 * than a mode check --- see ls_tp.h.
 */
#include "ls_tp.h"
#include "ls_tp_ring.h"
#include "ls_vm.h"

#include <stdlib.h>
#include <time.h>

/* Segment handle, resolved once. NULL means "ring disabled", which is the
 * default and the shipped state: LS_TP_RING unset costs a load and a branch. */
static struct ls_tp_seg *g_tp_seg;
static int               g_tp_seg_tried;
/* Atomic, and the live run is why. Two TMM threads reach this call site --- the
 * segment showed claimed=2 --- so a plain ++ is a data race that silently hands
 * two records the same seq. It did not collide in an 18-record sample, which is
 * exactly how this class of bug survives testing. A consumer ordering or
 * de-duplicating by seq would be quietly wrong under load. */
static _Atomic unsigned long long g_tp_seq;

/*
 * Bring up the segment. Called from the tracepoint path rather than from init,
 * because INIT_LATE runs once per TMM thread and the map only needs to happen
 * once --- the guard below is simpler than a second election, and open/mmap on
 * the very first request is a one-time cost, not a per-record one.
 *
 * Every failure is silent and permanent for the process. Telemetry that keeps
 * retrying a failed mmap on the hot path is worse than telemetry that is off.
 */
static void
ls_tp_seg_bootstrap(void)
{
    const char *path;

    if (g_tp_seg_tried)
        return;
    g_tp_seg_tried = 1;

    path = getenv("LS_TP_RING");
    if (path == NULL || *path == '\0')
        return;

    g_tp_seg = ls_tp_seg_open(path, 1);
    fprintf(stderr, "ls_tp: ring %s %s (%u rings x %u bytes)\n", path,
            g_tp_seg ? "mapped" : "FAILED --- telemetry off, traffic unaffected",
            (unsigned)LS_TP_MAX_RINGS, (unsigned)LS_TP_RING_BYTES);
}

int
ls_tp_dispatch(int slot, const void *rec, unsigned long len, unsigned int hook_id)
{
    enum ls_verdict v;

    /*
     * ls_vm_call takes void*, not const void*, because a verified program may
     * legally write every byte of what it is handed: PREVAIL does not consume a
     * `writable: []` annotation, so it cannot express a read-only region
     * (finding O1). The cast is safe HERE for a reason specific to this path ---
     * `rec` points at the caller's own stack record, built fresh for this
     * invocation and dead when it returns. A program that scribbles on it
     * corrupts nothing but its own input.
     *
     * That is exactly why the record is a stack copy rather than a view onto
     * TMM state. Handing a program a pointer into hd->ci would turn a telemetry
     * mechanism into a way to modify the parsed request.
     */
    v = ls_vm_call(slot, (void *)(unsigned long)rec, (size_t)len);

    /*
     * Then the bytes. AFTER the VM, deliberately: the program may write to the
     * record, and what a consumer should see is what the program left, not a
     * pre-program copy that disagrees with the counters.
     */
    ls_tp_seg_bootstrap();
    if (g_tp_seg != NULL) {
        struct timespec ts;
        /* CLOCK_REALTIME resolves through the vDSO --- no syscall, tens of ns ---
         * and wall clock is what a feed needs to correlate with anything else.
         * CLOCK_REALTIME_COARSE is a few ns cheaper at ~4ms granularity, which
         * would be fine for rates and useless for latency; revisit if the
         * per-call budget ever demands it. Read only when the ring is on. */
        clock_gettime(CLOCK_REALTIME, &ts);
        (void)ls_tp_ring_publish(g_tp_seg, hook_id,
                                 ls_tp_schema_for(hook_id),
                                 (unsigned)slot,
                                 atomic_fetch_add_explicit(&g_tp_seq, 1,
                                                           memory_order_relaxed),
                                 (unsigned long long)ts.tv_sec * 1000000000ull
                                     + (unsigned long long)ts.tv_nsec,
                                 rec, (unsigned int)len);
    }
    return (int)v;
}
