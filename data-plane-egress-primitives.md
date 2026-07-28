# TMM Data-Plane Egress Primitives — moving signal & captures out of the poll loop

### How data leaves the embedded VM: a per-core, single-producer, shared-memory ring — the host emits, the program only signals

**Status:** Proposal / design · **Companions:** [`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) (the substrate), [`tmm-usdt-tracepoints.md`](tmm-usdt-tracepoints.md) (§10.6 `tmmdump` is the behavioral spec this implements), [`data-plane-intelligence.md`](data-plane-intelligence.md) (the one-way signal-out/payload-in sink builds on this), [`prototype/`](prototype/) (the shm-backed `head[]` ring is the seed)
**Audience:** TMM core engineering, data-path performance

---

## 1. The problem

The embedded uBPF VM runs **inline in TMM's poll loop** — a core-pinned, single-threaded, kernel-bypass run-to-completion loop that never syscalls for traffic. That is what makes TMM fast, and it is exactly why moving data *out* of it is the hard part. Observability, RCA, and capture all need to get something — a `ctx` sample, an event, a window of actual bytes — from **inside the hot path** to an **out-of-TMM consumer** (`tmmtrace` summaries, `tmmdump` captures, off-box export, an in-situ feature sink) **without ever stalling forwarding**.

This document specifies the egress primitive. It deliberately does **not** solve program-directed capture or program-reachable state — those need helpers and are Phase 2 (§7).

## 2. Design rule (the one that shapes everything else)

> **The VM selects. The host streams. The program signals; the host emits.**

The eBPF program **returns a value** — a select/flag, optionally a small tag. It does **not** call an emit helper. The **host** (the hook trampoline) owns the ring and does the copy. Two consequences, and they are the whole reason this fits Phase 1:

- **No helper** to define, register, or secure — egress is host-side plumbing keyed off the return code.
- **Stock PREVAIL, unextended** — the program is still just a bounded predicate over a typed `ctx`; nothing new for the verifier to model.

This is the deliberate **inversion of the kernel/bpftime model**, where the *program* calls `bpf_ringbuf_reserve/submit/output` (helper ids 130–133) or `bpf_perf_event_output` (id 25) to push data — helpers the verifier must know about. We move that work to the host so day-one egress needs neither helpers nor a verifier extension.

## 3. Hard constraints

1. **Never block.** Under sink pressure, **drop and count** — never stall the poll loop, never overwrite unconsumed data.
2. **Bounded inline work.** The inline side does at most one bounded `memcpy` (a window), or just a descriptor write. All heavy work (serialize, off-box) is off-loop.
3. **Single producer per ring.** The producer is the pinned poll-loop core → strict **SPSC** → no locks, plain reserve. (Contrast: bpftime carries a `pthread_spinlock` only because it supports MPSC producers — we don't need it.)
4. **Host-emits / program-signals** (§2) — no helpers, stock verifier, initially.
5. **shm-backed.** The ring lives in shared memory so it **survives a data-plane crash** and is drainable post-mortem (the flight-recorder property).
6. **Coverage honesty.** A flow handled entirely in hardware (ePVA/FPGA/DPU) never enters TMM software, so it is not in software to capture — the same limit iRules and kernel eBPF already have.

## 4. Prior art — what we evaluated, what we take

TMM is kernel-bypass DNA, so the **nearest idiom is DPDK**, not the kernel-eBPF world. We take the primitive from there and borrow one thing from bpftime.

| Source | What it offers | What we take |
|---|---|---|
| **DPDK `rte_ring`** | Canonical lock-free SPSC/MPSC ring; the native idiom for a core-pinned engine | The **SPSC ring structure** and busy-poll drain model |
| **Kernel `BPF_MAP_TYPE_RINGBUF`** | A variable-length, libbpf-drainable ring ABI (consumer/producer pages, pow2 data, BUSY/DISCARD bits, 8-byte header) | The **record byte-layout** (documented ABI; clean-room implementable) |
| **bpftime** (userspace eBPF, MIT) | The eBPF-flavored instance — a port of the kernel ringbuf ABI over Boost.Interprocess shm | A **worked reference** that the kernel-ringbuf byte-layout drains at the byte level in userspace |

**What bpftime's transport actually is** (read from source, `runtime/src/bpf_map/userspace/ringbuf_map.{hpp,cpp}`):

- Ring is a near-line-for-line port of the kernel/libbpf ringbuf ABI (BUSY `0x80000000` / DISCARD `0x40000000` bits, `HDR_SZ=8`, pow2 data, acquire/release `producer_pos`/`consumer_pos`; x86 = `volatile`+`barrier()`, aarch64 = `ldar`/`stlr`). **Its header's 2nd word holds a map fd where the kernel stores `pg_off`.**
- Backed by **Boost.Interprocess `managed_shared_memory`** (one global 50 MB segment `/dev/shm/bpftime_maps_shm`) with `offset_ptr` for cross-process addressing.
- Producer serialized by `pthread_spinlock` (MPSC-safe); consumer lock-free single-consumer.
- **Wakeup is bpftime's own epoll shim**, not kernel epoll on an fd → a stock libbpf `ring_buffer__poll` **cannot** drop-in-drain it; libbpf compat is at the byte layout only, not the transport.
- Backpressure: reserve fails with `ENOSPC` and the program's `bpf_ringbuf_output` returns an error — **no dropped-sample counter**.
- License **MIT**; the ring algorithm (~250 lines) is liftable, but it is coupled to the global shm singleton, the map-handler dispatch, and the epoll shim — which we do **not** want.

**Decision — own the primitive, borrow the layout:**

- **Own** a DPDK-idiom **per-core SPSC shm ring** — drop the spinlock (SPSC), drop Boost/`offset_ptr` (per-access indirection on a hot core) for a plain fixed `mmap` arena, drop the epoll shim (we busy-poll off-core).
- **Borrow** the kernel-ringbuf **record byte-layout** so a stock libbpf `ring_buffer` consumer can optionally be pointed at our pages later (bpftime demonstrates the byte-level compat), while our own drainer maps the arena directly. This is exactly bpftime's byte-layout-yes / transport-no split — chosen deliberately.
- **Skip** the verifier/helper indirection entirely — we own the producer, so we call the ring API directly (§2).
- **Clean-room** the layout from the documented kernel ABI (the kernel source is GPL; the *ABI* is not), so we carry no copyleft. If we instead lift bpftime's MIT ring, it's an OSPO/attribution item (§7).

## 5. The primitives

### 5.1 Two ring classes

- **Event ring — fixed-slot.** For `ctx` samples, counter/histogram feeds, small events. One fixed record size per ring, power-of-two slots, plain head/tail indices. Cheapest possible; this is what the flight recorder (tracepoint-catalog §10.1) dumps on a trigger.
- **Capture ring — variable-length.** For `tmmdump` byte-windows. Length-prefixed records in the **kernel-ringbuf byte-layout** (8-byte header: `u32 len` + BUSY/DISCARD bits, `u32` reserved/aux; 8-byte-aligned payload; pow2 data area with wraparound by mask). Optionally libbpf-drainable (§4).

### 5.2 Per-core, single-producer

One ring instance **per core, per active sink** (or per hook class). The producer is the pinned poll loop → strict **SPSC** → no spinlock, no CAS. `producer_pos`/`consumer_pos` synchronize with acquire/release (`ldar`/`stlr` on aarch64; `volatile`+compiler barrier on x86-64). Per-CPU rings are the natural analog of kernel per-CPU maps — with no locking, because each core owns its ring.

### 5.3 The no-helper emit contract

At a hook, the trampoline runs the program and switches on its return:

```
ret = ubpf_exec(vm, &ctx, sizeof ctx, &r);   // program: pure fn of ctx, returns a value
switch (host_action(hook, r)) {               // HOST decides — not the program
  case RECORD:  host_counter_update(...);                 // scalar → metric/histogram/ring
  case CAPTURE: slot = ring_reserve(ring, win_len);        // host owns the ring
                if (slot) { memcpy(slot, window, win_len);  // bounded, host-declared window
                            ring_commit(ring, slot); }
                else       ring->drops++;                   // full → drop-and-count (§5.5)
  case NONE:    break;
}
```

The program never sees `ring_reserve`. **What may be emitted without a helper:** host policy (first *N* bytes of the record, a hook's declared byte-window) or fields already in `ctx`. **What may not:** an arbitrary program-computed `(offset, len)` — that is a helper, deferred to §7.

### 5.4 Reserve / commit protocol

- `ring_reserve(ring, len)` → if free space < needed, bump `drops`/`drop_bytes` and return `NULL`; else write the header with the **BUSY** bit set and return the payload pointer.
- Host does the bounded `memcpy` into the reserved slot.
- `ring_commit` → clear BUSY via an atomic **store-release** of `len`, publishing `producer_pos`.
- Consumer (single, off-core): acquire-load `producer_pos`, walk records, skip **DISCARD**, copy out, store-release `consumer_pos`. Reserve→fill→commit keeps the BUSY window a few instructions wide.

### 5.5 Backpressure = drop-and-count (explicit)

Full ring → increment **per-ring `drops` and `drop_bytes`** counters and return no slot. We **keep the counter** (bpftime does not) so that a gap in captured data is *visible as a stat*, never mistaken for "nothing happened." Never block, never overwrite unconsumed data. This is the "drop, don't block" discipline of tracepoint-catalog §10.6 made concrete.

### 5.6 Wakeup — batched, off the hot path

- **Default: no wakeup at all.** A housekeeping/drainer thread on a **non-pinned core** busy-polls `has_data()` across rings (DPDK-style). The producer does zero wakeup work — no syscall on the hot path.
- **Optional: batched `eventfd`/futex.** If the drainer should sleep when idle, the producer signals only on an empty→non-empty edge, or every *K* records / *T* µs — **never per record**. The signal cost is amortized; forwarding is never charged for it.

### 5.7 shm lifecycle & crash semantics

- Own `mmap`'d, named shm segment(s) (not Boost). Consumers map **read-only**. A small **header** carries a build-id + `layout_version` so a consumer verifies ABI before draining.
- **Survives a producer crash** → post-mortem drain (flight recorder).
- **Crash-consistency:** a producer that dies mid-`reserve` leaves one **BUSY** record; the consumer drains up to it and stops — the ring is readable, minus the in-flight record. Because we are **SPSC with no spinlock**, there is *no held-lock recovery problem* (bpftime's process-shared spinlock can strand a dead lock-holder — dropping it removes that failure mode). A per-record `seq`+timestamp makes a stale BUSY detectable.

## 6. Consumer ABI — the one deliberate compatibility choice

Records use the **kernel BPF-ringbuf byte-layout** (len+bits header, 8-byte alignment, pow2 data), so a stock libbpf `ring_buffer` consumer can be pointed at our pages if we ever want an off-the-shelf drainer — bpftime proves this works at the byte level. **But we do not adopt libbpf's fd+`epoll` transport**; our drainer maps the shm arena directly. Byte-layout compatible, transport ours. This keeps the ecosystem-reuse option open (fits `tmmdump : tcpdump :: tmmtrace : bpftrace`) at zero hot-path cost.

## 7. Out of scope — Phase 2 (needs helpers / verifier work)

Everything here holds the **no-helpers-initially** line. These reintroduce a helper ABI + verifier surface and are explicitly deferred:

- **Program-directed dynamic capture** — the program computing an arbitrary `(offset, len)` to emit (rather than a host-declared window). This is the one capture case that wants an emit helper.
- **Program-reachable state / maps** — cross-invocation or cross-flow state the *bytecode itself* reads/writes (kernel-style `bpf_map_lookup/update`). In Phase 1 that role is played by **host-owned** structures the host updates from the return value; a program-reachable map is the optional helper tier of substrate §5.6.
- **MPSC rings** — only needed if a non-poll-loop producer ever writes; would reintroduce the spinlock/CAS. Not needed while every producer is a core-pinned SPSC.

## 8. Open questions / to decide

- Ring sizing per core / per sink; **hugepage** backing for the arena on appliances?
- `eventfd` batching thresholds (*K* records / *T* µs) — or commit to pure busy-poll drain.
- Capture-ring wraparound: match kernel-ringbuf pow2+mask, or a true bip-buffer?
- **Commit to libbpf byte-layout compat**, or keep it merely optional?
- **Licensing:** clean-room the layout from the documented kernel ABI (carry nothing), or lift bpftime's MIT ~250-line ring (attribution + OSPO SBOM item). Recommend clean-room.

---

> **IP note.** The host-emits/program-signals inversion and the specific egress primitives here may be disclosure-worthy. Per policy, novel method & claims are kept in a **separate invention disclosure** (gitignored), not in this repo; this document is the engineering design only.
