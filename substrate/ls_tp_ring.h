/* ls_tp_ring.h --- the shared-memory segment the tracepoint publishes into.
 *
 * ls_ring.h is the ring: lock-free, bounded, 15 assertions, TSan clean. It has
 * never run inside TMM. This file is the missing half --- the segment that holds
 * the rings, who creates it, and which ring a given thread writes to.
 *
 * WHY SHARED MEMORY IS FORCED, NOT PREFERRED. TMM aliases malloc to a per-core
 * allocator whose spinlock is never initialised on a thread TMM did not create,
 * so a drain agent that allocates spins forever. Everything here is mmap.
 * Equally, the consumer must live in another process: a broker client linked
 * into TMM would put a socket, a reconnect and a stalled subscriber inside the
 * poll loop. TMM writes bytes and forgets; the agent maps them read-only and
 * publishes. It can crash without TMM noticing.
 *
 * ONE RING PER THREAD, BY CONSTRUCTION. ls_ring.h is single-producer --- that is
 * what lets it be lock-free, and it is a correctness precondition, not a
 * performance note. g_slots in ls_vm.c is a plain process-global despite
 * ls_prep.c describing "per-thread VM state", and the TMM process here runs
 * three threads. Whether more than one reaches the tracepoint is exactly the
 * kind of thing that has been assumed wrongly before, so each thread claims its
 * own ring by atomic index and writes only to that. The precondition then holds
 * whatever the thread model turns out to be.
 *
 * OFF UNLESS ASKED. Nothing here allocates, maps or executes unless LS_TP_RING
 * names a segment --- the same discipline as the loader socket. The shipped path
 * is a load of one pointer and a branch.
 */
#ifndef LS_TP_RING_H
#define LS_TP_RING_H

#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "ls_ring.h"

#define LS_TP_SEG_MAGIC   0x4c53534547303031ull   /* "LSSEG001" */
/* Segment format version. ls_rec gained ts_ns, so a consumer built against
 * version 1 walks records at the wrong stride --- it must be REFUSED, not left to
 * decode plausible garbage. Checked in ls_tp_seg_open below. */
#define LS_TP_SEG_VERSION   2u
#define LS_TP_MAX_RINGS    16u
#define LS_TP_RING_BYTES   (64u * 1024u)          /* power of two --- ls_ring requires it */

/* ONE SCHEMA, THREE HOOKS. struct http_parse_info is shared by all three HTTP
 * implementations --- http/ (1.x), http2/ and http3/ all fill ci->http --- so the
 * 40-byte record shape is identical and only the call site differs. The hook id
 * is what tells a consumer which protocol produced a record, and which fields of
 * it are load-bearing:
 *
 *   HTTP/1.x   version, method, header_count, body_pos, hdr_bytes, err
 *   HTTP/2,3   the five f_invalid_* pseudo-header bits (invalid_flags)
 *
 * Those bits are set ONLY by http2/ and http3/ code --- struct http_parse_info
 * documents them as "HTTP/2 pseudo-headers are invalid". On the 1.x path they
 * are never written, so invalid_flags there is uninitialised and must not be
 * read. It is kept in the record rather than dropped precisely because it is the
 * right field the moment an h2 or h3 call site lands. */
#define LS_TP_HOOK_HTTP1_HDRS  1u
#define LS_TP_HOOK_HTTP2_HDRS  2u      /* http2_stream_process_ingress_headers  */
#define LS_TP_HOOK_HTTP3_HDRS  3u      /* http3_process_stream_ingress_headers  */

/* Bumped 1 -> 2 with ts_ns. A consumer built against schema 1 walks records at
 * the wrong stride now, so it must fail rather than decode plausible garbage. */
#define LS_TP_SCHEMA_HTTP      2u

/* Segment header, at offset 0. Rings follow at a fixed stride so a consumer can
 * find ring i without walking anything. */
struct ls_tp_seg {
    uint64_t magic;
    uint32_t version;
    uint32_t n_rings;
    uint32_t ring_stride;            /* bytes from one ring's start to the next */
    uint32_t ring_data_size;
    _Atomic uint32_t claimed;        /* how many threads have taken a ring      */
    uint32_t _pad;
};

#define LS_TP_STRIDE  ((uint32_t)sizeof(struct ls_ring) + LS_TP_RING_BYTES)
#define LS_TP_SEG_SZ  ((size_t)sizeof(struct ls_tp_seg) + \
                       (size_t)LS_TP_MAX_RINGS * LS_TP_STRIDE)

static inline struct ls_ring *
ls_tp_seg_ring(struct ls_tp_seg *s, uint32_t i)
{
    return (struct ls_ring *)((uint8_t *)s + sizeof(struct ls_tp_seg)
                              + (size_t)i * s->ring_stride);
}

/*
 * Create and map the segment. Idempotent and safe to call from every thread:
 * the loser of the race unmaps its own view and takes the winner's.
 *
 * Returns NULL when disabled or on any failure. EVERY failure path here is
 * non-fatal by design --- telemetry that can prevent TMM from starting is worse
 * than no telemetry.
 */
static inline struct ls_tp_seg *
ls_tp_seg_open(const char *path, int create)
{
    int fd, i;
    void *p;
    struct ls_tp_seg *s;

    if (path == NULL || *path == '\0')
        return NULL;

    fd = open(path, create ? (O_RDWR | O_CREAT) : O_RDWR, 0600);
    if (fd < 0)
        return NULL;

    if (create && ftruncate(fd, (off_t)LS_TP_SEG_SZ) != 0) {
        close(fd);
        return NULL;
    }

    p = mmap(NULL, LS_TP_SEG_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);                        /* the mapping keeps the object alive */
    if (p == MAP_FAILED)
        return NULL;

    s = (struct ls_tp_seg *)p;
    if (!create) {
        if (s->magic != LS_TP_SEG_MAGIC || s->version != LS_TP_SEG_VERSION ||
            s->ring_stride != LS_TP_STRIDE) {
            munmap(p, LS_TP_SEG_SZ);
            return NULL;             /* wrong magic, wrong version, or wrong geometry */
        }
        return s;
    }

    /* Initialise every ring before publishing the magic, so a consumer that
     * opens mid-setup either sees no segment or sees a complete one. */
    s->version        = LS_TP_SEG_VERSION;
    s->n_rings        = LS_TP_MAX_RINGS;
    s->ring_stride    = LS_TP_STRIDE;
    s->ring_data_size = LS_TP_RING_BYTES;
    atomic_store_explicit(&s->claimed, 0, memory_order_relaxed);
    for (i = 0; i < (int)LS_TP_MAX_RINGS; i++)
        ls_ring_init(ls_tp_seg_ring(s, (uint32_t)i), LS_TP_RING_BYTES,
                     LS_RING_STREAM);

    /* STREAM, not RECORD, and the choice matters. A streaming analytic feed must
     * never have a record pulled out from under a mid-read consumer, and the
     * data plane must never wait on that consumer. Full therefore means drop the
     * NEW record and count it --- a counted gap, never a silent one, and never
     * backpressure into the poll loop. */

    __atomic_store_n(&s->magic, LS_TP_SEG_MAGIC, __ATOMIC_RELEASE);
    return s;
}

/*
 * The calling thread's own ring, claimed once and remembered.
 *
 * __thread rather than an index derived from a TMM thread id: the id is not
 * available in this include world, and a wrong index would silently give two
 * threads the same ring --- which does not crash, it corrupts records
 * occasionally, which is the worst way for this to be wrong.
 */
static inline struct ls_ring *
ls_tp_my_ring(struct ls_tp_seg *s)
{
    static __thread struct ls_ring *mine;
    static __thread int tried;
    uint32_t idx;

    if (mine != NULL || tried)
        return mine;
    tried = 1;                        /* claim at most once, even on failure */

    if (s == NULL)
        return NULL;

    idx = atomic_fetch_add_explicit(&s->claimed, 1, memory_order_relaxed);
    if (idx >= s->n_rings)
        return NULL;                  /* more threads than rings: this one is silent */

    mine = ls_tp_seg_ring(s, idx);
    return mine;
}

/*
 * Publish one record. Returns 1 if it landed, 0 if dropped or disabled.
 *
 * The entire cost on the hot path: a bounded memcpy and two ordered stores. No
 * allocation, no syscall, no lock --- which is the property that makes this
 * acceptable in a poll loop at all, and the one check_ring asserts by
 * construction rather than by inspection.
 */
static inline int
ls_tp_ring_publish(struct ls_tp_seg *seg, uint32_t hook_id, uint32_t schema_id,
                   uint32_t tmm_id, uint64_t seq, uint64_t ts_ns,
                   const void *rec, uint32_t len)
{
    struct ls_ring *r = ls_tp_my_ring(seg);
    struct ls_rec h;

    if (r == NULL)
        return 0;

    h.hook_id   = hook_id;
    h.schema_id = schema_id;
    h.seq       = seq;
    h.tmm_id    = tmm_id;
    h.len       = len;
    h.ts_ns     = ts_ns;
    return ls_ring_emit(r, &h, rec, len);
}

#endif /* LS_TP_RING_H */
