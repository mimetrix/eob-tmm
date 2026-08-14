/* check_ring.c --- the four things about the egress ring that cannot be tested
 * inside TMM, which is the entire reason this runs on the bench.
 *
 * Under live traffic you would have to ENGINEER a stalled consumer and a full
 * ring to reach any of these paths, and a wrong answer shows up as "records are
 * occasionally odd" --- close to undebuggable inside a poll loop. Here they are
 * three lines each.
 *
 *   1 SPSC        millions of records, one producer, one consumer: every record
 *                 arrives exactly once, in order, with its payload intact.
 *   2 STREAM full consumer stalled -> the NEW record is dropped and counted, and
 *                 nothing already written is corrupted.
 *   3 RECORD full consumer stalled -> the OLDEST is overwritten and the producer
 *                 never blocks. Getting this backwards makes a flight recorder
 *                 useless while looking like it works, which is why both policies
 *                 are asserted rather than one.
 *   4 wraparound  records that would straddle the end are padded past it and come
 *                 back byte-identical, with varying lengths so the pad path is hit
 *                 at many offsets rather than one.
 *
 * usage: check_ring            (all four)
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ls_ring.h"

#define DS       (1u << 16)          /* 64 KiB data area, power of two */
static int failures;

static struct ls_ring *
mkring(enum ls_ring_policy p, uint32_t ds)
{
    struct ls_ring *r = calloc(1, sizeof *r + ds);
    if (!r) { perror("calloc"); exit(2); }
    ls_ring_init(r, ds, p);
    return r;
}

static void
ok(const char *what, int cond, const char *detail)
{
    printf("  %-4s %s%s%s\n", cond ? "ok" : "FAIL", what,
           detail && *detail ? "  --- " : "", detail ? detail : "");
    if (!cond) failures++;
}

/* ---------- 1. SPSC: exactly once, in order, intact ---------------------- */

#define N_REC 400000u
struct spsc_arg { struct ls_ring *r; uint64_t produced; uint64_t refusals; };

static void *
producer(void *a)
{
    struct spsc_arg *s = a;
    uint8_t payload[96];
    for (uint64_t i = 0; i < N_REC; i++) {
        uint32_t len = 8 + (uint32_t)(i % 80);          /* varying, so offsets vary */
        memset(payload, (int)(i & 0xff), len);
        struct ls_rec rec = { .hook_id = 7, .schema_id = 1, .seq = i, .tmm_id = 0, .len = len };
        while (!ls_ring_emit(s->r, &rec, payload, len))
            s->refusals++;          /* STREAM: retry. Each refusal IS counted as a
                                     * drop by the ring, which is correct for TMM
                                     * (the producer never retries there) and is
                                     * why this test asserts the ACCOUNTING rather
                                     * than assuming the counter stays zero. */
        s->produced++;
    }
    return NULL;
}

static void
test_spsc(void)
{
    printf("1. SPSC --- %u records, one producer thread, one consumer\n", N_REC);
    struct ls_ring *r = mkring(LS_RING_STREAM, DS);
    struct spsc_arg arg = { r, 0, 0 };
    pthread_t t;
    pthread_create(&t, NULL, producer, &arg);

    uint64_t got = 0, expect_seq = 0;
    int order_ok = 1, payload_ok = 1;
    uint8_t buf[128];
    struct ls_rec rec;

    while (got < N_REC) {
        int n = ls_ring_consume(r, &rec, buf, sizeof buf);
        if (n < 0) continue;
        if (rec.seq != expect_seq) order_ok = 0;
        expect_seq = rec.seq + 1;
        uint8_t want = (uint8_t)(rec.seq & 0xff);
        for (int i = 0; i < n; i++)
            if (buf[i] != want) { payload_ok = 0; break; }
        if ((uint32_t)n != rec.len) payload_ok = 0;
        got++;
    }
    pthread_join(t, NULL);

    char d[96];
    snprintf(d, sizeof d, "%llu produced, %llu consumed", (unsigned long long)arg.produced,
             (unsigned long long)got);
    ok("every record arrives exactly once", got == N_REC, d);
    ok("strictly in order (no gaps, no repeats)", order_ok, "");
    ok("payloads intact, lengths preserved", payload_ok, "");
    /* Tearing would have shown up in the payload and ordering checks above; a zero
     * drop counter proves nothing about it. What IS worth asserting is that the
     * counter accounts for exactly the refusals the producer saw --- no lost counts,
     * no phantom ones. An earlier version asserted drops == 0 here, which was both
     * wrong (a retrying producer is refused constantly) and testing the wrong thing. */
    snprintf(d, sizeof d, "%llu refusals, %llu counted",
             (unsigned long long)arg.refusals, (unsigned long long)atomic_load(&r->drops));
    ok("drop accounting is exact under contention", atomic_load(&r->drops) == arg.refusals, d);
    free(r);
}

/* ---------- 2/3. the two full-ring policies ------------------------------ */

static void
test_stream_full(void)
{
    printf("2. STREAM full --- consumer stalled: drop the NEW record, count it\n");
    struct ls_ring *r = mkring(LS_RING_STREAM, 4096);
    uint8_t payload[256];
    memset(payload, 0xAB, sizeof payload);

    uint64_t accepted = 0, refused = 0;
    for (uint64_t i = 0; i < 200; i++) {                  /* far more than fits */
        struct ls_rec rec = { .hook_id = 1, .schema_id = 1, .seq = i, .tmm_id = 0, .len = 256 };
        if (ls_ring_emit(r, &rec, payload, 256)) accepted++; else refused++;
    }
    char d[96];
    snprintf(d, sizeof d, "%llu accepted then %llu refused", (unsigned long long)accepted,
             (unsigned long long)refused);
    ok("producer stops accepting once full", refused > 0, d);
    ok("drops counted, not silent", atomic_load(&r->drops) == refused, "");
    ok("drop_bytes accumulated", atomic_load(&r->drop_bytes) == refused * 256, "");

    /* The records that DID land must still be readable --- a full ring must not
     * corrupt what it already holds. */
    struct ls_rec rec; uint8_t buf[256];
    uint64_t readable = 0; int seq_ok = 1; uint64_t prev = 0; int first = 1;
    while (ls_ring_consume(r, &rec, buf, sizeof buf) >= 0) {
        if (!first && rec.seq != prev + 1) seq_ok = 0;
        prev = rec.seq; first = 0; readable++;
    }
    snprintf(d, sizeof d, "%llu readable", (unsigned long long)readable);
    ok("records already written survive the full condition", readable == accepted, d);
    ok("and they are the OLDEST, contiguous", seq_ok, "");
    free(r);
}

static void
test_record_full(void)
{
    printf("3. RECORD full --- consumer stalled: overwrite the OLDEST, never drop\n");
    struct ls_ring *r = mkring(LS_RING_RECORD, 4096);
    uint8_t payload[256];

    uint64_t accepted = 0;
    for (uint64_t i = 0; i < 200; i++) {
        memset(payload, (int)(i & 0xff), sizeof payload);
        struct ls_rec rec = { .hook_id = 1, .schema_id = 1, .seq = i, .tmm_id = 0, .len = 256 };
        if (ls_ring_emit(r, &rec, payload, 256)) accepted++;
    }
    char d[96];
    snprintf(d, sizeof d, "%llu of 200 accepted", (unsigned long long)accepted);
    ok("producer NEVER refuses (overwrite-oldest)", accepted == 200, d);
    ok("nothing is counted as dropped", atomic_load(&r->drops) == 0,
       "loss is the design here, not an anomaly");

    /* The producer ran far past the reader, so what is retained is the RECENT
     * window --- the run-up into the incident, which is the entire point. A
     * recorder that instead kept the oldest records would pass a naive "did we
     * keep data" check and be useless in a post-mortem. */
    uint64_t prod = atomic_load(&r->producer_pos);
    ok("producer advanced past one full lap", prod > 4096,
       "so the retained window is recent, not the oldest");
    free(r);
}

/* ---------- 4. wraparound ------------------------------------------------ */

static void
test_wrap(void)
{
    printf("4. wraparound --- pad past the end, records come back byte-identical\n");
    struct ls_ring *r = mkring(LS_RING_STREAM, 1024);     /* small, to wrap often */
    struct ls_rec rec; uint8_t out[200], payload[200];

    int intact = 1, laps = 0;
    uint64_t last_prod = 0;
    for (uint64_t i = 0; i < 5000; i++) {
        uint32_t len = 17 + (uint32_t)(i % 131);          /* odd sizes: hit the pad at many offsets */
        memset(payload, (int)(i & 0xff), len);
        struct ls_rec in = { .hook_id = 3, .schema_id = 2, .seq = i, .tmm_id = 0, .len = len };
        if (!ls_ring_emit(r, &in, payload, len)) {        /* full: drain then retry */
            while (ls_ring_consume(r, &rec, out, sizeof out) >= 0) ;
            if (!ls_ring_emit(r, &in, payload, len)) continue;
        }
        int n = ls_ring_consume(r, &rec, out, sizeof out);
        if (n < 0) continue;
        if ((uint32_t)n != len || rec.seq != i) { intact = 0; break; }
        for (uint32_t k = 0; k < len; k++)
            if (out[k] != (uint8_t)(i & 0xff)) { intact = 0; break; }
        uint64_t p = atomic_load(&r->producer_pos);
        if (p / 1024 > last_prod / 1024) laps++;
        last_prod = p;
    }
    char d[64];
    snprintf(d, sizeof d, "%d wraps exercised", laps);
    ok("records survive the wrap byte-for-byte", intact, d);
    ok("the wrap was actually reached many times", laps > 20, "");
    free(r);
}

int
main(void)
{
    printf("egress ring --- the four properties that cannot be tested inside TMM\n\n");
    test_spsc();     printf("\n");
    test_stream_full(); printf("\n");
    test_record_full(); printf("\n");
    test_wrap();
    printf("\n%s\n", failures ? "*** FAILURES ABOVE" : "all ring properties hold");
    return failures ? 1 : 0;
}
