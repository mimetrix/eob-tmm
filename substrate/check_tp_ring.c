/* Does the tracepoint's shared-memory segment actually work, from the outside?
 *
 * check_ring.c already proves the RING: SPSC exactness, both full-policies,
 * wraparound. None of that is retested here. What is untested until now is the
 * SEGMENT around it --- the part that has to hold when a separate process maps
 * the same bytes:
 *
 *   - geometry a consumer can navigate without walking anything
 *   - every thread gets a DISTINCT ring, which is ls_ring's single-producer
 *     precondition and a correctness requirement, not a tuning choice
 *   - a SECOND MAPPING sees the records --- the actual claim, since the drain
 *     agent is another process and shares nothing but these bytes
 *   - a full ring drops and COUNTS, never blocks, never corrupts
 *   - a consumer opening a segment that was never initialised is refused
 *
 * The last one matters more than it looks: a drain that maps an uninitialised or
 * wrong-sized file and starts decoding would emit garbage that looks like
 * traffic. In Kubernetes that is the likely failure --- if /dev/shm is not a
 * shared emptyDir, the sidecar maps its OWN empty tmpfs and sees a valid-looking
 * segment with no records, which reads as "no traffic" rather than as a
 * misconfiguration.
 */
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ls_tp_ring.h"

#define REC_BYTES 40u

static struct ls_tp_seg *g_seg;
static struct ls_ring   *g_claimed[4];
static int               g_n;
static pthread_mutex_t   g_mu = PTHREAD_MUTEX_INITIALIZER;

/* Each thread claims through the same path TMM uses, then records which ring it
 * got so the test can prove they are distinct. */
static void *
claimer(void *arg)
{
    struct ls_ring *r;
    unsigned int rec[REC_BYTES / 4];
    int i;
    long id = (long)arg;

    r = ls_tp_my_ring(g_seg);
    assert(r != NULL);

    pthread_mutex_lock(&g_mu);
    g_claimed[g_n++] = r;
    pthread_mutex_unlock(&g_mu);

    for (i = 0; i < 10; i++) {
        memset(rec, 0, sizeof rec);
        rec[0] = (unsigned int)id;
        rec[1] = (unsigned int)i;
        assert(ls_tp_ring_publish(g_seg, LS_TP_HOOK_HTTP_HDRS,
                                  LS_TP_SCHEMA_HTTP, (unsigned int)id,
                                  (unsigned long long)i, rec, REC_BYTES) == 1);
    }
    return NULL;
}

int
main(void)
{
    char path[] = "/tmp/.ls_tp_seg_check";
    struct ls_tp_seg *consumer;
    struct ls_ring *r;
    struct ls_rec h;
    unsigned char out[256];
    unsigned int rec[REC_BYTES / 4];
    pthread_t th[3];
    long i;
    int n = 0, got, total;

    unlink(path);

    /* 1. geometry */
    g_seg = ls_tp_seg_open(path, 1);
    assert(g_seg != NULL);                                                  n++;
    assert(g_seg->magic == LS_TP_SEG_MAGIC);                                n++;
    assert(g_seg->n_rings == LS_TP_MAX_RINGS);                              n++;
    /* data_size must be a power of two or ls_ring's masking is wrong */
    assert((g_seg->ring_data_size & (g_seg->ring_data_size - 1)) == 0);     n++;
    /* ring i must be findable by stride alone --- a consumer walks nothing */
    assert((unsigned char *)ls_tp_seg_ring(g_seg, 1)
           - (unsigned char *)ls_tp_seg_ring(g_seg, 0)
           == (long)g_seg->ring_stride);                                    n++;

    /* 2. THE PRECONDITION: distinct ring per thread. If two threads shared one,
     *    ls_ring's lock-free producer would be multi-producer and its proof
     *    would not apply --- and the symptom would be occasional corrupt
     *    records, not a crash. */
    for (i = 0; i < 3; i++)
        assert(pthread_create(&th[i], NULL, claimer, (void *)i) == 0);
    for (i = 0; i < 3; i++)
        pthread_join(th[i], NULL);
    assert(g_n == 3);                                                       n++;
    assert(g_claimed[0] != g_claimed[1] &&
           g_claimed[1] != g_claimed[2] &&
           g_claimed[0] != g_claimed[2]);                                   n++;
    assert(atomic_load(&g_seg->claimed) >= 3);                              n++;

    /* 3. THE CLAIM: a SECOND MAPPING --- what the drain agent is --- sees them.
     *    Opened with create=0, exactly as a consumer would. */
    consumer = ls_tp_seg_open(path, 0);
    assert(consumer != NULL);                                               n++;
    assert(consumer != g_seg);        /* genuinely a different mapping */    n++;
    assert(consumer->magic == LS_TP_SEG_MAGIC);                             n++;

    total = 0;
    for (i = 0; i < (long)consumer->n_rings; i++) {
        r = ls_tp_seg_ring(consumer, (unsigned int)i);
        while ((got = ls_ring_consume(r, &h, out, sizeof out)) > 0) {
            assert(h.hook_id == LS_TP_HOOK_HTTP_HDRS);
            assert(h.schema_id == LS_TP_SCHEMA_HTTP);
            assert(h.len == REC_BYTES);
            total++;
        }
    }
    assert(total == 30);              /* 3 threads x 10 records */          n++;

    /* 4. a full ring drops and COUNTS. Never blocks, never corrupts, and the
     *    gap is visible --- a silent gap is indistinguishable from no traffic. */
    r = ls_tp_seg_ring(g_seg, 15);    /* untouched ring, known empty */
    memset(rec, 0, sizeof rec);
    {
        struct ls_rec hh = { LS_TP_HOOK_HTTP_HDRS, LS_TP_SCHEMA_HTTP, 0, 0, REC_BYTES };
        int landed = 0, dropped = 0, k;
        for (k = 0; k < 100000; k++) {
            if (ls_ring_emit(r, &hh, rec, REC_BYTES)) landed++;
            else                                       dropped++;
        }
        assert(landed > 0 && dropped > 0);                                  n++;
        assert(atomic_load(&r->drops) == (unsigned long long)dropped);      n++;
        assert(landed + dropped == 100000);                                 n++;
    }

    /* 5. a segment that was never initialised must be REFUSED, not decoded. */
    {
        char bad[] = "/tmp/.ls_tp_seg_bad";
        FILE *f;
        unlink(bad);
        f = fopen(bad, "wb");
        assert(f != NULL);
        for (i = 0; i < (long)LS_TP_SEG_SZ; i++)
            fputc(0, f);
        fclose(f);
        assert(ls_tp_seg_open(bad, 0) == NULL);                             n++;
        unlink(bad);
    }

    /* 6. a missing path is disabled, not fatal --- the default state */
    assert(ls_tp_seg_open("", 0) == NULL);                                  n++;
    assert(ls_tp_seg_open(NULL, 0) == NULL);                                n++;

    unlink(path);
    printf("ok    ls_tp_ring.h  (%d assertions: distinct ring per thread, second "
           "mapping reads records, drop-and-count, bad segment refused)\n", n);
    return 0;
}
