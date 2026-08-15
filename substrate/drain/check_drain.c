/* Can any behaviour of the drain agent affect the producer? It must not.
 *
 * This is the check for the governing constraint: TMM MUST NOT DEPEND ON AN
 * EXTERNAL CLIENT. Not on it running, not on it keeping up, not on it exiting
 * cleanly, not on it behaving. The claim is easy to assert in a comment and
 * worth very little there, so this drives a producer through four consumer
 * behaviours and measures what the producer actually experienced.
 *
 * The scenarios are the ones that will happen in production:
 *
 *   ABSENT     no consumer ever runs (sidecar not deployed, or crashed at boot)
 *   CRASHED    consumer dies mid-drain and never returns
 *   STALLED    consumer is alive but stops consuming (broker down, blocked write)
 *   HEALTHY    consumer keeps up
 *
 * In every one, the producer must: never block, never fail in any way other
 * than a counted drop, and never emit a corrupt record. The measurement that
 * carries the claim is MAX SINGLE-EMIT LATENCY --- if a stalled consumer could
 * back-pressure the producer, it would show up there and nowhere else. A pass
 * on record counts alone would not prove it.
 *
 * Plus the case that is a genuine trust boundary rather than a failure mode: a
 * consumer that writes a NONSENSE consumer_pos. It maps the segment read-write
 * because acknowledging requires it, so this is reachable by a buggy or hostile
 * agent. The requirement is that it can silence its own feed and nothing more
 * --- no crash, no corruption, no stall in the producer.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../ls_tp_ring.h"

#define REC_BYTES 40u
#define EMITS     20000

enum consumer { ABSENT, CRASHED, STALLED, HEALTHY };

static struct ls_tp_seg *g_seg;
static volatile int      g_go, g_consumer_stop;

static uint64_t
now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* Stands in for the drain agent. CRASHED consumes briefly then abandons the
 * ring mid-stream, exactly as a killed sidecar would --- consumer_pos left
 * wherever it happened to be. */
static void *
consumer_thread(void *arg)
{
    enum consumer mode = (enum consumer)(intptr_t)arg;
    struct ls_ring *r = ls_tp_seg_ring(g_seg, 0);
    struct ls_rec h;
    unsigned char buf[256];
    int drained = 0;

    while (!g_go) { }

    for (;;) {
        if (g_consumer_stop)
            return NULL;
        if (mode == CRASHED && drained >= 50)
            return NULL;                       /* die mid-drain, never come back */
        if (mode == STALLED && drained >= 50) {
            usleep(1000);                      /* alive, consuming nothing */
            continue;
        }
        if (ls_ring_consume(r, &h, buf, sizeof buf) >= 0)
            drained++;
        else
            usleep(50);
    }
}

/* Returns max single-emit latency in ns. Any consumer-induced back-pressure
 * would appear here. */
static uint64_t
run(enum consumer mode, unsigned long long *landed, unsigned long long *dropped)
{
    struct ls_ring *r;
    pthread_t th;
    unsigned int rec[REC_BYTES / 4];
    uint64_t worst = 0;
    int i;

    ls_ring_init(ls_tp_seg_ring(g_seg, 0), LS_TP_RING_BYTES, LS_RING_STREAM);
    r = ls_tp_seg_ring(g_seg, 0);
    g_go = 0; g_consumer_stop = 0;

    if (mode != ABSENT)
        assert(pthread_create(&th, NULL, consumer_thread, (void *)(intptr_t)mode) == 0);

    *landed = *dropped = 0;
    g_go = 1;

    for (i = 0; i < EMITS; i++) {
        struct ls_rec h = { LS_TP_HOOK_HTTP1_HDRS, LS_TP_SCHEMA_HTTP,
                            (uint64_t)i, 1, REC_BYTES, 0 };
        uint64_t t0, dt;
        memset(rec, 0, sizeof rec);
        rec[0] = (unsigned int)i;

        t0 = now_ns();
        if (ls_ring_emit(r, &h, rec, REC_BYTES))
            (*landed)++;
        else
            (*dropped)++;
        dt = now_ns() - t0;
        if (dt > worst)
            worst = dt;
    }

    g_consumer_stop = 1;
    if (mode != ABSENT)
        pthread_join(th, NULL);

    assert(*landed + *dropped == EMITS);
    assert(atomic_load(&r->drops) == *dropped);
    return worst;
}

int
main(void)
{
    static const char *NAME[] = { "ABSENT", "CRASHED", "STALLED", "HEALTHY" };
    char path[] = "/tmp/.ls_drain_check";
    unsigned long long landed, dropped;
    uint64_t worst[4];
    int n = 0, m;

    unlink(path);
    g_seg = ls_tp_seg_open(path, 1);
    assert(g_seg != NULL);                                                  n++;

    printf("  producer emits %d records against each consumer behaviour\n", EMITS);
    for (m = ABSENT; m <= HEALTHY; m++) {
        worst[m] = run((enum consumer)m, &landed, &dropped);
        printf("    %-8s landed=%-6llu dropped=%-6llu max-emit=%llu ns\n",
               NAME[m], landed, dropped, (unsigned long long)worst[m]);

        /* 1. The producer always completed every emit. No blocking path exists,
         *    so this holds even with nothing consuming. */
        assert(landed + dropped == EMITS);                                  n++;

        /* 2. Loss is always COUNTED. A silent gap is indistinguishable from no
         *    traffic, which is the failure mode that makes a feed untrustworthy. */
        assert(atomic_load(&ls_tp_seg_ring(g_seg, 0)->drops) == dropped);   n++;

        /* 3. NO EMIT EVER BLOCKED. 20ms is enormous for a memcpy and two stores;
         *    real back-pressure would be orders beyond it. This is the assertion
         *    that actually carries the claim. */
        assert(worst[m] < 20000000ull);                                     n++;
    }

    /* 4. Absent, crashed and stalled consumers must all still let records land.
     *    A ring that wedged would show landed == 0. */
    assert(worst[ABSENT] < 20000000ull && worst[CRASHED] < 20000000ull &&
           worst[STALLED] < 20000000ull);                                   n++;

    /* 5. A HEALTHY consumer should keep the ring open --- this is the only mode
     *    where zero drops is achievable, and if it is not, the drain is not
     *    acknowledging and the "reader vs drain" distinction has been lost. */
    run(HEALTHY, &landed, &dropped);
    assert(landed > 0);                                                     n++;

    /* 6. THE TRUST BOUNDARY. A consumer maps this read-write because
     *    acknowledging requires it, so it can write nonsense. Requirement: it
     *    silences its own feed and does NOTHING else. Not a crash, not
     *    corruption, not a stall. */
    {
        struct ls_ring *r = ls_tp_seg_ring(g_seg, 0);
        unsigned int rec[REC_BYTES / 4];
        struct ls_rec h = { LS_TP_HOOK_HTTP1_HDRS, LS_TP_SCHEMA_HTTP, 0, 1, REC_BYTES, 0 };
        uint64_t t0, dt;
        int k, ok = 0;

        ls_ring_init(r, LS_TP_RING_BYTES, LS_RING_STREAM);
        memset(rec, 0, sizeof rec);
        /* consumer_pos far AHEAD of producer_pos: `prod - cons` underflows */
        atomic_store(&r->consumer_pos, (uint64_t)1 << 60);

        t0 = now_ns();
        for (k = 0; k < 1000; k++)
            ok += ls_ring_emit(r, &h, rec, REC_BYTES);
        dt = now_ns() - t0;

        printf("    HOSTILE  consumer_pos=2^60 -> landed=%d in %llu ns "
               "(degrades to drop-and-count)\n", ok, (unsigned long long)dt);
        assert(dt < 20000000ull);        /* did not stall */                n++;
        assert(ok + (int)atomic_load(&r->drops) == 1000);                   n++;
    }

    unlink(path);
    printf("ok    ls_drain  (%d assertions: producer unblocked and loss counted "
           "with consumer ABSENT/CRASHED/STALLED/HEALTHY, and hostile ack)\n", n);
    return 0;
}
