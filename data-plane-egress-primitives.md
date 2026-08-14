# TMM Data-Plane Egress Primitives — moving signal & captures out of the poll loop

### How data leaves the embedded VM: a per-core, single-producer, shared-memory ring — the host emits, the program only signals

**Status:** Proposal / design · **Companions:** [`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) (the substrate), [`tmm-usdt-tracepoints.md`](tmm-usdt-tracepoints.md) (§10.6 `tmmdump` is the behavioral spec this implements), [`data-plane-intelligence.md`](data-plane-intelligence.md) (**strategy annex, not part of the current ask** — its host-owned one-way sink builds on this primitive), [`substrate/`](substrate/) (candidate ABI artifacts + checkers)
**Audience:** TMM core engineering, data-path performance

---

> **What this document is.** A **written specification, not an implemented or measured one.** No ring
> described here has been produced into or drained anywhere in this repo; every cost, ordering, and
> crash-survival property below is a design claim to be validated, not a result. Where the text reads
> declaratively ("the host copies", "the drainer publishes"), read it as the specified behavior.

## 1. The problem

The embedded uBPF VM runs **inline in TMM's poll loop** — a core-pinned, single-threaded, kernel-bypass run-to-completion loop that never syscalls for traffic. That is what makes TMM fast, and it is exactly why moving data *out* of it is the hard part. Observability, RCA, and capture all need to get something — a `ctx` sample, an event, a window of actual bytes — from **inside the hot path** to an **out-of-TMM consumer** (`tmmtrace` summaries, `tmmdump` captures — both **proposed** front-ends under placeholder names, `tmm-usdt-tracepoints.md` §1 — off-box export, an in-situ feature sink) **without ever stalling forwarding**.

This document specifies the egress primitive. It deliberately does **not** solve program-directed capture or program-reachable state — those need helpers and are Phase 2 (§7).

## 2. Design rule (the one that shapes everything else)

> **The VM selects. The host streams. The program signals; the host emits.**

The eBPF program **returns a value** — a select/flag, optionally a small tag. It does **not** call an emit helper. The **host** (the hook trampoline) owns the ring and does the copy. Two consequences, and they are the whole reason this fits Phase 1:

- **No helper** to define, register, or secure — egress is host-side plumbing keyed off the return code.
- **Stock PREVAIL under its existing `tracing` program type** — the program is still just a bounded predicate over a typed `ctx`, so there is nothing new for the verifier to model and no fork in the trust path. Worth stating precisely, because "stock" is doing real work in that sentence: PREVAIL has **no `--program-type` flag** — the type is deduced from the ELF section-name prefix against a compiled-in C++ table (fallback `socket_filter`). Registering a *named* TMM program type is therefore a PREVAIL patch set carrying a per-release rebase cost, which we have deliberately **not** taken; we ride the existing `tracing` type instead.

This is the deliberate **inversion of the kernel/bpftime model**, where the *program* calls `bpf_ringbuf_reserve/submit/output` (helper ids 130–133) or `bpf_perf_event_output` (id 25) to push data — helpers the verifier must know about. We move that work to the host so day-one egress needs neither helpers nor a verifier extension.

## 3. Hard constraints

1. **Never block.** Under sink pressure the ring's **declared policy** decides which end loses: a `STREAM` ring **drops the new record and counts it**; a `RECORD` ring **overwrites its oldest record**. Neither ever stalls the poll loop. These are two policies, not one rule, and they are mutually exclusive — see §5.1.
2. **Bounded inline work.** The inline side does at most one bounded `memcpy` (a window), or just a descriptor write. All heavy work (serialize, off-box) is off-loop.
3. **Single producer per ring.** The producer is the pinned poll-loop core → strict **SPSC** (single-producer / single-consumer) → no locks, plain reserve. (Contrast: bpftime carries a `pthread_spinlock` only because it supports MPSC — multi-producer — rings; ours has one producer by construction.)
4. **Host-emits / program-signals** (§2) — no helpers, stock verifier, initially.
5. **shm-backed.** The ring lives in shared memory, so the *segment* outlives the producer process and is drainable post-mortem (the flight-recorder property). State the bound with it: the fault class a flight recorder exists to capture is largely memory-safety faults, and a fault that corrupted memory on the way down can have scribbled the ring itself. Records are therefore **structurally validated** on drain rather than trusted, and the ring is **not** trustworthy after a memory-corruption fault (§5.7).
6. **Coverage honesty.** A flow handled entirely in hardware (ePVA/FPGA/DPU) never enters TMM software, so it is not in software to capture — the same limit iRules and kernel eBPF already have.

## 4. Prior art — what we evaluated, what we take

TMM is kernel-bypass DNA, so the **nearest idiom is DPDK**, not the kernel-eBPF world. We take the primitive from there and borrow one thing from bpftime.

| Source | What it offers | What we take |
|---|---|---|
| **DPDK `rte_ring`** | Canonical lock-free SPSC/MPSC ring; the native idiom for a core-pinned engine | The **SPSC ring structure** and busy-poll drain model |
| **Kernel `BPF_MAP_TYPE_RINGBUF`** | A variable-length, libbpf-drainable ring ABI — application binary interface (consumer/producer pages, pow2 data, BUSY/DISCARD bits, 8-byte header) | The **record byte-layout** (documented ABI; clean-room implementable) |
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
- **Clean-room** the layout from the documented kernel ABI (the kernel source is GPL; the *ABI* is not), so we carry no copyleft. If we instead lift bpftime's MIT ring, it's an OSPO/attribution item (§8, last bullet).

## 5. The primitives

### 5.1 One ring class, and — separately — two ring policies

> **Changed 2026-08-14, and it is a real design change rather than a clarification.** This section
> previously defined **two** ring classes: a fixed-slot *event* ring and a length-prefixed *capture*
> ring. That is now **one class — variable-length, length-prefixed** — because of a requirement that
> was implicit and is now explicit:
>
> **The transport must not know or care what a tracepoint exposes.**
>
> A fixed-slot ring binds a ring to a record *size*. So a tracepoint exposing a differently shaped
> `ctx` needs a different ring — a **transport change per tracepoint**, which is exactly what this
> requirement rules out. A fixed-size `ctx` is not a separate class; it is a payload that happens
> always to be the same length.
>
> **Cost:** 8 bytes of header per record, and byte-wraparound rather than a slot mask.
> **Gain:** one transport, permanently. Adding a tracepoint becomes a new **schema id**, not new
> plumbing. And the libbpf framing compatibility of §6 — previously available only to the capture
> class — now applies to everything the system emits.

**The record shape.** The producer copies a host-declared window and commits. It never interprets
the bytes:

```
[ ring header  ]  u32 len + BUSY/DISCARD bits, u32 aux    <- transport owns it; kernel-ringbuf layout
[ record header]  hook_id, schema_id, seq, tmm_id         <- ours; fixed and small
[ payload      ]  opaque bytes                             <- the transport NEVER inspects this
```

Whether the payload is a `ctx` struct, a raw byte window, or a derived feature vector is invisible
to the ring. That is the property being bought.

**Where the schema lives, and why this ships before the hook map does.** Decoding is the
**consumer's** job, resolved out of band by `hook_id` + `schema_id` against the per-build hook map
and its BTF ([`development-scope.md`](development-scope.md) item 5, **unbuilt**). The split is
clean and worth stating because it decides sequencing: **the transport needs no schema; only
decoding does.** A consumer can drain and record `hook_id`/`schema_id` plus opaque bytes today, and
nothing in the transport changes when the map arrives.

One knock-on for §5.3: `host_window()` must be generic — the host declares *(source, offset, len)*
per hook, and that declaration eventually comes from the hook map. Until then it is a per-hook
configuration constant. The program is still uninvolved, so the no-helper property is untouched.

**Policies** decide what happens when the ring is *full*, and unlike the classes they do **not** collapse — a flight recorder and a streaming feed want genuinely opposite things. Policy is a **per-ring property declared at ring creation**, and the two are mutually exclusive:

| Policy | On full | Loss reporting | Consumer position | Used by |
|---|---|---|---|---|
| **`STREAM`** | **drop the new record and count it** — never overwrite unconsumed data | `drops` / `drop_bytes` (§5.5) | yes — the drainer publishes `consumer_pos` | live drain: `tmmtrace` feeds, streaming `tmmdump` capture, the feature sink |
| **`RECORD`** | **overwrite the oldest record** | none — loss is the design, not an anomaly; the ring instead reports the window it holds | none — the producer never consults a reader | the **flight recorder** (`tmm-usdt-tracepoints.md` §10.1): a rolling window of recent records, frozen and dumped on a trigger |

A flight recorder **requires** overwrite-oldest: the reason it exists is that its dump holds the **run-up into the fault**. A recorder that drops-and-counts when full stops recording at the moment it fills, so its dump contains the *oldest* records — the state of the box long before the incident. Conversely a streaming ring must never overwrite, because a consumer draining for export cannot have records pulled out from under it mid-read. Assigning one ring to both roles under a single "never overwrite unconsumed data" rule makes the recorder useless, which is why the rule is now stated per policy: **§5.5's drop-and-count applies to `STREAM` only.** §5.4's reserve/commit protocol is shared, with the per-policy differences called out step by step.

### 5.2 Per-core, single-producer

One ring instance **per core, per active sink** (or per hook class). The producer is the pinned poll loop → strict SPSC → no spinlock, no CAS (compare-and-swap). Per-CPU rings are the natural analog of kernel per-CPU maps — with no locking, because each core owns its ring.

**Ordering is specified by semantics, not per architecture.** `producer_pos`, `consumer_pos`, and each record's header word are C11 `_Atomic` and are accessed with `memory_order_acquire` / `memory_order_release`; the compiler emits whatever the target needs. We deliberately do **not** write the spec as `volatile` plus a compiler barrier. `volatile` is not an ordering primitive: it constrains neither the compiler nor the hardware with respect to the *surrounding non-`volatile` accesses* — and the access that matters most here is exactly one of those, the payload `memcpy` that must not become visible after the commit. Writing the rule as an acquire/release pair makes the payload part of the release, which is the property we actually depend on. (§4 attributes the `volatile`+`barrier()` idiom to *bpftime*; that is a description of bpftime's source, not an inherited spec.)

*What that lowers to, for the reader who wants it:* on aarch64, `ldar`/`stlr`; on x86-64, a plain load/store plus a compiler barrier, because that architecture's TSO (total store ordering) memory model already supplies the hardware ordering. Same source, no `#ifdef`.

### 5.3 The no-helper emit contract

At a hook, the trampoline runs the program and switches on its return:

```c
int64_t  ret = jit_fn(&ctx);           // program: pure fn of ctx, JIT'd once at load
void    *slot;
uint32_t win_len;

switch (host_egress(hook, ret)) {      // HOST decides the disposition — not the program
  case EG_COUNT:
    host_counter_update(hook, ret);                        // scalar → metric / histogram / event ring
    break;

  case EG_CAPTURE: {
    const void *window = host_window(hook, &ctx, &win_len);  // host-declared window
    slot = ring_reserve(ring, win_len);                      // host owns the ring
    if (slot) {
      memcpy(slot, window, win_len);                         // bounded
      ring_commit(ring, slot, win_len);                      // TWO ordered stores (§5.4)
    } else {
      ring->drops++; ring->drop_bytes += win_len;            // STREAM only — see below
    }
    break;
  }

  case EG_NONE:
    break;
}
```

Two notes on reading that switch. First, `host_egress` yields an **egress disposition** — count it, capture a window, or do nothing — which is orthogonal to the *traffic outcome* the host selects at a decision point (PASS · DROP · RESET · SAFE-RETURN · STEER · SAMPLE, `embedded-ebpf-substrate.md` §2). A program selects; it never acts; and it certainly never emits. Second, the `else` branch is reachable only on a **`STREAM`** ring: on a **`RECORD`** ring `ring_reserve` cannot fail, because full means overwrite-oldest (§5.1), so a `RECORD` ring has no `drops` counter to bump.

The program never sees `ring_reserve`. **What may be emitted without a helper:** host policy (first *N* bytes of the record, a hook's declared byte-window) or fields already in `ctx`. **What may not:** an arbitrary program-computed `(offset, len)` — that is a helper, deferred to §7.

### 5.4 Reserve / commit protocol

The protocol below is shared by both policies. With one variable-length class (§5.1) every record carries the 8-byte ring header for the BUSY/DISCARD bits plus the `seq`+timestamp preamble, never bare payload: a uniform commit and a uniform crash-recovery rule across every ring cost a few bytes per slot, and the alternative is two protocols.

**`ring_reserve(ring, len)`** — the one step that differs by policy (§5.1):

- **`STREAM`:** if free space < needed, bump `drops`/`drop_bytes` and return `NULL`.
- **`RECORD`:** cannot fail. The producer owns a `tail` marking its own oldest retained record — there is no reader position to consult (§5.1) — and advances it past as many oldest records as the new one needs, then reserves.
- Either policy: write the record header with the **BUSY** bit set, write the **record preamble** (`seq`, timestamp — see below) at the head of the payload area, and return a pointer just past the preamble.

Host then does the bounded `memcpy` into the reserved slot.

**`ring_commit(ring, slot, len)` is two ordered stores, not one.** The BUSY bit lives in the *record header*; `producer_pos` lives in the *producer page*. They are **different memory locations**, so no single store can publish both; any spec that says "clear BUSY, publishing `producer_pos`" as one operation is not implementable as written:

1. **`store-release` the record header word with BUSY cleared.** This publishes the *payload*: the release pairs with the consumer's acquire on the same word, so the `memcpy` cannot be observed after the header.
2. **`store-release` the advanced `producer_pos`.** This publishes the record's *existence*.

The order matters in that direction. Reversed, a consumer can observe the position advance and then read a header still marked BUSY — a spurious stall on live data. Collapsed into one store, the consumer either never sees the advance at all, or sees a committed length against a stale position.

**Consumer** (single, off-core), one drain pass:

1. acquire-load `producer_pos`;
2. at `consumer_pos`, acquire-load the record header;
3. **structurally validate** before trusting anything: header magic, `len` sanity (nonzero, ≤ ring size, and the record fits below `producer_pos`), preamble `seq` monotonic against the last record drained, generation matching the segment header. A failure means the arena is not what it claims from here on — stop, record the position, mark the segment untrustworthy, and report how far the drain got (§5.7). Do not hand a plausible-looking record to an RCA;
4. **BUSY set → treat as head-of-line blocking, because it is.** Commit is in-order SPSC, so a BUSY record sitting at `consumer_pos` blocks **every record committed behind it**, not just itself — i.e. the newest data, which for a flight recorder is exactly the evidence being sought. So BUSY is not simply "wait." Apply an explicit **abandon rule**: if the record's preamble timestamp is older than `abandon_us`, **or** its generation does not match the segment's current generation, the producer that reserved it is gone — mark the record **DISCARD**, advance past it, and keep draining. Otherwise the producer is live and mid-`memcpy`; return and retry on the next pass;
5. skip records already marked **DISCARD**; copy out the rest;
6. `store-release consumer_pos` — **`STREAM` only.** A `RECORD` ring has no consumer position (§5.1); its drainer snapshots the frozen arena instead.

Reserve→fill→commit keeps the BUSY window a few instructions wide, which is what makes `abandon_us` able to be small enough to be useful.

**Where `seq` and the timestamp actually live.** Not in the 8-byte kernel-ringbuf header: that layout has exactly one spare `u32` (which the kernel uses for `pg_off`, and which bpftime repurposes for a map fd — §4), and four bytes will not hold both a sequence number and a timestamp. They go in a **record preamble at the head of the payload**. The consequence has to be stated rather than buried, because §6 offers stock-libbpf drainability off this layout: a stock libbpf `ring_buffer` consumer will still *frame* our records correctly, but their contents become opaque to it — the compatibility is at the **framing level only**. §8 already lists libbpf compat as an open decision; this is a known cost on that decision, not a surprise discovered later.

### 5.5 Backpressure = drop-and-count — `STREAM` rings only

Full **`STREAM`** ring → increment **per-ring `drops` and `drop_bytes`** counters and return no slot. We **keep the counter** (bpftime does not) so that a gap in captured data is *visible as a stat*, never mistaken for "nothing happened." Never block, never overwrite unconsumed data. This is the "drop, don't block" discipline of `tmm-usdt-tracepoints.md` §10.6 made concrete.

A **`RECORD`** ring has no drop counter and cannot report loss this way, because overwriting the oldest record is its intended steady-state behavior rather than an anomaly worth counting — a flight recorder that had been running for an hour would otherwise report a meaningless and enormous drop count. What it exposes instead is **the window it currently holds**: `oldest_seq`, `newest_seq`, and a wrap count, so a dump can state how far back the evidence reaches and whether it reaches back far enough to cover the incident. Both policies share the never-block rule; they differ only in which end of the buffer loses, and in how that loss is reported.

### 5.6 Wakeup — batched, off the hot path

Wakeup is a **`STREAM`** concern only. A `RECORD` ring has no standing drainer to wake: it is read once, on a trigger or post-mortem (§5.1), so its producer does no wakeup work at all.

- **Default: a sleeping drainer, woken by a batched `eventfd`/futex.** The producer signals only on an empty→non-empty edge, or every *K* records / *T* µs — **never per record**. Be explicit about what this costs the producer rather than calling it free: the wakeup *is* a syscall, issued from the poll loop, which is exactly why it is edge-triggered and batched. §1's "never syscalls for traffic" remains true — no syscall sits on the per-packet path — but an amortized wakeup syscall on the *emit* path is a real, measurable cost that belongs in the budget.
- **Opt-in: busy-poll drain, no wakeup at all** (the DPDK idiom) — a drainer thread that polls `has_data()` across rings and never sleeps, so the producer does zero wakeup work. This is **not** the appliance default, because on an appliance there is no spare core: TMM owns nearly all of them, and what remains runs the entire control plane (`mcpd`, `bd`, `restjavad`/`icrd`, `restnoded`, monitors). A 100 %-CPU busy-poll drainer there competes with the control plane rather than soaking up idle cycles, which is the opposite of the "use cycles only when the data plane has them" discipline the companion docs commit to. Enable it on VE and lab rigs where a core can be dedicated, or where a measurement needs zero wakeup jitter.

### 5.7 shm lifecycle & crash semantics

> **Measured on BNK/datkube, 2026-08-14** (`env/scripts/bnk-check-shm.sh`, re-runnable):
>
> - **`/dev/shm` is present and writable** in the `f5-tmm` container, tmpfs, and two processes map
>   the same segment and see each other's writes in both directions. The basic requirement holds.
> - **The cap is 64 MB** (`size=65536k`). That is the ceiling on *total* ring bytes across every
>   core and sink, not per ring — it turns §8's "ring sizing per core / per sink" from an open
>   question into a division problem with a fixed numerator.
> - **A sidecar can read what `f5-tmm` writes.** Containers in a pod share the IPC namespace by
>   default, so containerd bind-mounts one `/dev/shm` into each. **The drain agent can be a sidecar
>   with no deployment change** — no `emptyDir{medium: Memory}`, no volume, no manifest edit. That
>   was the deployment question this section left open and it is now answered.
>
> **What this does not establish, and it is the half that can still invalidate the design:** that a
> **TMM poll thread** can create and write the mapping. TMM has its own memory manager, and a thread
> we create already cannot call `malloc` — it spins on an uninitialised spinlock
> ([`load-path-scope.md`](load-path-scope.md) §1). Only a build doing the mapping from `INIT_LATE`
> settles it. Until then this section's lifecycle is proven for ordinary processes in the container
> and assumed for the producer.


**Mapping — and which single word the consumer must be allowed to write.** Own `mmap`'d, named shm segment(s) (not Boost). A small **header** carries a build-id, `layout_version`, the ring's declared policy (§5.1), and a **generation** counter, so a consumer verifies ABI and provenance before draining. Consumers map the **data area and the producer page read-only**; on a `STREAM` ring the **consumer page is writable**, because it has to be — draining means publishing `consumer_pos` (§5.4 step 6), and a wholly read-only mapping makes drain impossible. That one word is the entire writable surface exposed to the drainer. If even that is unacceptable for a given consumer, the alternative is to keep the drain position in a private state file outside the shm and declare the ring **`RECORD`**, so the producer never consults a reader position at all.

**Generation / epoch, so a restart cannot destroy the evidence.** The generation is bumped at producer start, and the producer sets a `dirty` flag while live. Without this, a restarted TMM re-maps the same named segment and immediately begins clobbering pre-crash records **before anyone has drained them** — losing the exact data the recorder exists to hold, in the exact scenario it was deployed for. So on start, a producer that finds `dirty` already set must **either allocate a fresh segment or refuse to reuse the old one until a drainer has claimed it**. Which of the two is a config choice; refusing is the safer default for a `RECORD` ring. The generation is also what lets the consumer's abandon rule (§5.4 step 4) distinguish a live producer's in-flight record from a dead one's.

**Drainable after a producer crash — with an honest bound.** Because we are **SPSC with no spinlock**, there is no held-lock recovery problem (bpftime's process-shared spinlock can strand a dead lock-holder; dropping it removes that failure mode outright). But the segment outliving the process is not the same as its *contents* being sound, and it is worth naming which crash we are discussing: the fault class this recorder exists to capture is largely **memory-safety faults**, and a fault that corrupted memory on the way down can have scribbled the ring itself. The integrity assumption — "this header is a valid `len` plus bits" — is the first casualty. Hence, concretely:

- every record is **structurally validated** on drain (magic, `len` sanity, `seq` monotonicity, generation match) rather than trusted (§5.4 step 3);
- a validation failure **truncates** the drain at that point and marks the segment untrustworthy, instead of handing a plausible-looking but fabricated record to an RCA;
- a producer that dies mid-`reserve` leaves one **BUSY** record, which under the abandon rule costs that record — not, as the earlier formulation implied, everything committed behind it;
- so the claim we make is "**usually recoverable, and self-describing about how much it recovered**" — *not* "survives any crash." After a memory-corruption fault the ring is evidence to be corroborated, not a trusted log.

## 6. Consumer ABI — the one deliberate compatibility choice

Records (§5.1) use the **kernel BPF-ringbuf byte-layout** (len+bits header, 8-byte alignment, pow2 data), so a stock libbpf `ring_buffer` consumer can be pointed at those pages if we ever want an off-the-shelf drainer — bpftime proves this works at the byte level. **But we do not adopt libbpf's fd+`epoll` transport**; our drainer maps the shm arena directly. Byte-layout compatible, transport ours. This keeps the ecosystem-reuse option open (fits `tmmdump : tcpdump :: tmmtrace : bpftrace`) at zero hot-path cost.

**Scope the compat claim precisely, though.** Our records carry a `seq`+timestamp **preamble inside the payload** (§5.4), because the 8-byte header has no room for it. A stock libbpf consumer therefore *frames* our records correctly — it walks lengths and bits and hands each record to a callback — but the record contents are **opaque** to it: it does not know the preamble is there, so it cannot interpret `seq`, ordering, or the abandon logic. Compatibility is at the **framing level**, not the record level. That is enough for "point an existing tool at these pages and get records out," and not enough for "an existing tool understands our records." §8 keeps the commit-or-not decision open on those terms.

## 7. Out of scope — Phase 2 (needs helpers / verifier work)

Everything here holds the **no-helpers-initially** line. These reintroduce a helper ABI + verifier surface and are explicitly deferred:

- **Program-directed dynamic capture** — the program computing an arbitrary `(offset, len)` to emit (rather than a host-declared window). This is the one capture case that wants an emit helper.
- **Program-reachable state / maps** — cross-invocation or cross-flow state the *bytecode itself* reads/writes (kernel-style `bpf_map_lookup/update`). In Phase 1 that role is played by **host-owned** structures the host updates from the return value; a program-reachable map is the deferred helper/map tier (`engine-hard-problems.md` §3, *maps under CMP and connection mirroring* — with the helper/`ctx`/program-type ABI it rides on in §2).
- **`tmmdump` — the payload-capture consumer.** Deliberately pushed out, and *not* because the
  transport cannot carry it: with one variable-length class (§5.1) a byte window is just another
  payload. It waits on the **full payload initiatives** — `tmmdump`'s entire value is streaming the
  *actual bytes* at a hook alongside the internal state there, and substrate §6.3 withholds keys,
  PII and decrypted payload by default behind separate authorization. That is a data-governance and
  TMA decision, not plumbing, and it is the part that takes longest to get agreement on. The feed
  built first therefore carries **derived features, not payload** — which needs no such decision.
  `tmmdump` remains important; it is sequenced after, not descoped.
- **MPSC rings** — only needed if a non-poll-loop producer ever writes; would reintroduce the spinlock/CAS. Not needed while every producer is a core-pinned SPSC.

## 8. Open questions / to decide

- Ring sizing per core / per sink — and, for `RECORD` rings, sizing stated as **retained window** (how many µs of run-up into a fault the recorder must hold) rather than as a byte count; **hugepage** backing for the arena on appliances?
- `eventfd` batching thresholds (*K* records / *T* µs), and the measured producer-side cost of the wakeup syscall (§5.6).
- `abandon_us` for the consumer's stale-BUSY rule (§5.4) — small enough to not stall a drain, large enough to never abandon a live producer's `memcpy`.
- On restart with `dirty` set: fresh segment, or refuse-until-drained? (§5.7) Default per policy, or per sink?
- Ring wraparound: match kernel-ringbuf pow2+mask, or a true bip-buffer?
- **Commit to libbpf byte-layout compat**, or keep it merely optional — knowing the compat is framing-level only, because of the record preamble (§5.4, §6)?
- **Licensing:** clean-room the layout from the documented kernel ABI (carry nothing), or lift bpftime's MIT ~250-line ring (attribution + OSPO SBOM item). Recommend clean-room.

---

