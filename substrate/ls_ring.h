/* ls_ring.h --- the egress ring. One variable-length class, SPSC, shm-backed.
 *
 * Implements data-plane-egress-primitives.md sections 5.1-5.5. Header-only so the
 * producer side can be inlined into the trampoline and the consumer side compiled
 * into a separate drain process from the same source --- one definition of the
 * layout, which is the only way the two stay in agreement.
 *
 * THE PROPERTY THIS EXISTS TO PRESERVE: the transport never inspects the payload.
 * A record is a length and some bytes. Whether those bytes are a ctx struct, a
 * byte window, or a derived feature vector is invisible here, which is what lets a
 * new tracepoint be a new schema id rather than new plumbing.
 *
 * WRAPAROUND: pad-to-end with a DISCARD record, NOT a double mapping. The kernel's
 * ringbuf maps its data area twice so a record can straddle the end transparently;
 * that needs MAP_FIXED trickery over the shm fd. Padding is simpler, portable, and
 * costs one skipped header per wrap --- and the consumer already handles DISCARD,
 * so it adds no new path. This answers section 8's "pow2+mask or a true bip-buffer"
 * question with a third, cheaper option; revisit if the padding waste ever matters.
 *
 * ORDERING is specified by semantics, not per architecture (section 5.2): positions
 * and the header word are _Atomic, accessed with acquire/release, so the payload
 * memcpy is part of the release and cannot become visible after the commit. On
 * x86-64 that lowers to plain accesses plus a compiler barrier; on aarch64 to
 * ldar/stlr. Same source, no #ifdef.
 */
#ifndef LS_RING_H
#define LS_RING_H

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#define LS_RING_MAGIC     0x4c53524e47303031ull   /* "LSRNG001" */
#define LS_RING_HDR_SZ    8u                       /* kernel BPF-ringbuf record header */
#define LS_RING_BUSY      (1u << 31)               /* producer is mid-write */
#define LS_RING_DISCARD   (1u << 30)               /* consumer must skip this record */
#define LS_RING_LEN_MASK  (~(LS_RING_BUSY | LS_RING_DISCARD))
#define LS_RING_ALIGN     8u

/* Policy is declared at creation and is NOT interchangeable (section 5.1):
 * a flight recorder must overwrite its oldest record or its dump holds the state
 * of the box long before the incident; a streaming drain must never overwrite or
 * a consumer has records pulled out from under it mid-read. */
enum ls_ring_policy {
    LS_RING_STREAM = 0,   /* full -> drop the new record and count it */
    LS_RING_RECORD = 1    /* full -> overwrite the oldest; never blocks, never drops */
};

/* The control block, at offset 0 of the shared segment. The data area follows,
 * `data_size` bytes, which MUST be a power of two so positions mask cleanly. */
struct ls_ring {
    uint64_t magic;
    uint32_t version;
    uint32_t policy;
    uint32_t data_size;              /* power of two                                */
    uint32_t _pad;
    _Atomic uint64_t producer_pos;   /* monotonic byte position; masked into data   */
    _Atomic uint64_t consumer_pos;   /* STREAM only; RECORD never consults a reader */
    _Atomic uint64_t drops;          /* STREAM only (section 5.5)                   */
    _Atomic uint64_t drop_bytes;
};

/* Our record header, inside the payload the transport carries. The transport does
 * not read these fields; the CONSUMER uses hook_id+schema_id to find a layout in
 * the hook map. Kept fixed and small so a drain can index records without a schema. */
struct ls_rec {
    uint32_t hook_id;
    uint32_t schema_id;
    uint64_t seq;
    /* THE SLOT THE PROGRAM RAN IN --- renamed from tmm_id 2026-08-18, because that is
     * what has always been written here. The only producer passes (unsigned)slot, and
     * the drain emitted it as "tmm", so every record claimed a TMM instance number and
     * carried a slot. Every live record read "tmm":5 on both pods for the obvious
     * reason: slot 5 is where rst_why was armed.
     *
     * Nothing detected it because both are small integers and 5 is a plausible TMM id.
     * The BYTE layout is unchanged --- same offset, same width --- so a consumer walking
     * records is unaffected; only the JSON key changes, and it changes because the old
     * one was a false statement.
     *
     * A real TMM instance id would be worth having and is NOT available here: `tid`
     * lives in TMM's -nostdinc include world and this file is STDINC. It would need the
     * same kind of crossing ls_flow_cookie.c uses. Left undone rather than approximated. */
    uint32_t slot;
    uint32_t len;                    /* payload bytes following this header         */
    uint64_t ts_ns;                  /* CLOCK_REALTIME at capture, ns since epoch   */
};

/* WHY ts_ns LIVES HERE AND NOT IN THE PAYLOAD. It describes the capture, not the
 * thing captured, so it belongs with hook_id and seq rather than inside any one
 * hook's record --- which means an HTTP/2 or HTTP/3 call site inherits it without
 * a second schema bump. seq gives ordering; a clock is what lets a feed compute
 * rate, correlate with other systems, and detect a stalled producer. */

static inline uint8_t *ls_ring_data(struct ls_ring *r) { return (uint8_t *)(r + 1); }
static inline uint32_t ls_ring_round(uint32_t n) { return (n + LS_RING_ALIGN - 1) & ~(LS_RING_ALIGN - 1); }

static inline void
ls_ring_init(struct ls_ring *r, uint32_t data_size, enum ls_ring_policy policy)
{
    memset(r, 0, sizeof *r);
    r->magic = LS_RING_MAGIC;
    r->version = 1;
    r->policy = (uint32_t)policy;
    r->data_size = data_size;
    atomic_store_explicit(&r->producer_pos, 0, memory_order_relaxed);
    atomic_store_explicit(&r->consumer_pos, 0, memory_order_relaxed);
}

/* Write one record. Returns 1 if it landed, 0 if dropped (STREAM, ring full).
 *
 * The whole producer is this function: bounded memcpy, two ordered stores, no
 * allocation, no syscall, no lock. That is the property the hot path depends on
 * and the one check_ring asserts by construction rather than by inspection. */
static inline int
ls_ring_emit(struct ls_ring *r, const struct ls_rec *rec, const void *payload, uint32_t len)
{
    uint8_t *data = ls_ring_data(r);
    const uint32_t ds = r->data_size;
    const uint32_t need = ls_ring_round(LS_RING_HDR_SZ + (uint32_t)sizeof *rec + len);

    if (need > ds)
        return 0;                                        /* never fits; not a drop of THIS ring's making */

    uint64_t prod = atomic_load_explicit(&r->producer_pos, memory_order_relaxed);
    uint32_t off  = (uint32_t)(prod & (ds - 1));

    /* Pad to the end rather than straddle. One DISCARD record, which the consumer
     * already knows how to skip --- see the header note on wraparound. */
    if (off + need > ds) {
        uint32_t pad = ds - off;
        if (pad >= LS_RING_HDR_SZ) {
            uint32_t phdr = (pad - LS_RING_HDR_SZ) | LS_RING_DISCARD;
            memcpy(data + off, &phdr, 4);
            uint32_t aux = 0; memcpy(data + off + 4, &aux, 4);
        }
        prod += pad;
        atomic_store_explicit(&r->producer_pos, prod, memory_order_release);
        off = 0;
    }

    if (r->policy == LS_RING_STREAM) {
        uint64_t cons = atomic_load_explicit(&r->consumer_pos, memory_order_acquire);
        if (prod - cons + need > ds) {                    /* would overwrite unconsumed data */
            atomic_fetch_add_explicit(&r->drops, 1, memory_order_relaxed);
            atomic_fetch_add_explicit(&r->drop_bytes, len, memory_order_relaxed);
            return 0;
        }
    }
    /* RECORD never checks: full means overwrite-oldest, so reserve cannot fail. */

    /* The header word is accessed AS AN ATOMIC, not as bytes plus a standalone
     * barrier. Section 5.2 specifies it that way and it matters twice over: the
     * release attaches to the store that publishes the record, which is the
     * pairing the consumer's acquire needs; and ThreadSanitizer can model it,
     * whereas a bare standalone barrier it cannot model at all. An earlier
     * version here used memcpy plus a barrier and was therefore unverifiable. */
    _Atomic uint32_t *hdrp = (_Atomic uint32_t *)(void *)(data + off);
    uint32_t body = (uint32_t)sizeof *rec + len;

    atomic_store_explicit(hdrp, body | LS_RING_BUSY, memory_order_relaxed);
    uint32_t aux = 0; memcpy(data + off + 4, &aux, 4);

    memcpy(data + off + LS_RING_HDR_SZ, rec, sizeof *rec);
    if (len)
        memcpy(data + off + LS_RING_HDR_SZ + sizeof *rec, payload, len);

    /* Publish: this release makes the payload above visible to any consumer that
     * acquires this same word. */
    atomic_store_explicit(hdrp, body, memory_order_release);
    atomic_store_explicit(&r->producer_pos, prod + need, memory_order_release);
    return 1;
}

/* Consume one record. Returns the payload length and fills *rec, or -1 when the
 * ring is empty or the next record is still BUSY. DISCARD records are skipped
 * transparently, which is what makes the pad-to-end wrap invisible to callers. */
static inline int
ls_ring_consume(struct ls_ring *r, struct ls_rec *rec, void *out, uint32_t out_max)
{
    uint8_t *data = ls_ring_data(r);
    const uint32_t ds = r->data_size;

    for (;;) {
        uint64_t cons = atomic_load_explicit(&r->consumer_pos, memory_order_relaxed);
        uint64_t prod = atomic_load_explicit(&r->producer_pos, memory_order_acquire);
        if (cons >= prod)
            return -1;                                   /* empty */

        uint32_t off = (uint32_t)(cons & (ds - 1));
        _Atomic uint32_t *hdrp = (_Atomic uint32_t *)(void *)(data + off);
        uint32_t hdr = atomic_load_explicit(hdrp, memory_order_acquire);
        if (hdr & LS_RING_BUSY)
            return -1;                                   /* producer mid-write; try later */

        uint32_t body = hdr & LS_RING_LEN_MASK;
        uint32_t step = ls_ring_round(LS_RING_HDR_SZ + body);

        if (hdr & LS_RING_DISCARD) {                     /* padding, or an abandoned record */
            atomic_store_explicit(&r->consumer_pos, cons + step, memory_order_release);
            continue;
        }
        if (body < sizeof *rec)
            return -1;                                   /* structurally invalid; do not trust it */

        memcpy(rec, data + off + LS_RING_HDR_SZ, sizeof *rec);
        uint32_t plen = body - (uint32_t)sizeof *rec;
        if (plen > out_max)
            plen = out_max;
        if (plen)
            memcpy(out, data + off + LS_RING_HDR_SZ + sizeof *rec, plen);

        atomic_store_explicit(&r->consumer_pos, cons + step, memory_order_release);
        return (int)plen;
    }
}

/* Wire-layout assertions. These are the reason section 6's framing-compatibility
 * claim is enforced rather than merely described: an 8-byte record header with the
 * length in the low bits and BUSY/DISCARD in bits 31/30 is what a stock libbpf
 * ring_buffer consumer walks. */
_Static_assert(LS_RING_HDR_SZ == 8, "kernel BPF-ringbuf record header is 8 bytes");
_Static_assert(LS_RING_BUSY == 0x80000000u, "BUSY is bit 31, as in the kernel");
_Static_assert(LS_RING_DISCARD == 0x40000000u, "DISCARD is bit 30, as in the kernel");
_Static_assert(sizeof(struct ls_rec) == 32, "ls_rec is fixed at 32 bytes (24 + ts_ns)");
_Static_assert(sizeof(struct ls_ring) % 8 == 0, "control block keeps the data area 8-aligned");

#endif /* LS_RING_H */
