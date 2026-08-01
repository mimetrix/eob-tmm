# TMM USDT Tracepoint Catalog — the hook-point surface of the embedded eBPF framework

### A proposed set of designed-in hook points for TMM — USDT-style tracepoints plus filter-capable decision points — consumed by the embedded userspace-eBPF VM. Observability, debug & RCA are the primary lens here; CVE shields, steering, and self-tuning are **peer consumers of the same hooks**. The engine is generic; the shield is one application.

**Status:** Proposal / engineering menu · **Companion:** [`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) (the substrate), [`big-ip-live-shield-design.md`](big-ip-live-shield-design.md) (Live Shield), [`data-plane-egress-primitives.md`](data-plane-egress-primitives.md) (how a record leaves the box), [`explainers/cve-shield-walkthrough.html`](explainers/cve-shield-walkthrough.html) (the worked CVE example, end to end), [`substrate/`](substrate/) (candidate ABI artifacts + checkers — **not** a running prototype)
**Audience:** TMM core engineering, F5 SIRT, observability & support

---

## 1. What this is (and why it's cheap)

This is a candidate catalog of **designed-in hook points** to build into TMM's source as the generic instrumentation-and-control surface of the embedded eBPF framework. Each is a named, versioned hook that exposes a small **typed context (`ctx`)** — a curated view of the internal state present at that point. The embedded uBPF VM runs a small **verified** program at the hook; the host owns all state and effects and applies the program's return as one of an **enumerated set of outcomes** — the program cannot invent control flow. Two hook kinds share the engine: this curated USDT catalog (stable, versioned `ctx`) for the *anticipated* surface, and **function-boundary probes** at any named symbol (`ctx` = the function's typed arguments) for the *unforeseen* — this document catalogs the first kind.

Most hooks are consumed in **observe mode**: the program reads `ctx`, returns a value, and the host aggregates it (a counter, a histogram, a ring) — traffic is untouched. A subset sit at a clean decision point and also support **act mode**: the same `ctx`-in / value-out program picks among the host-owned outcomes declared for that hook — the canonical set is `PASS · DROP · RESET · SAFE-RETURN · STEER · SAMPLE`, defined once in [`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) §2 and referenced everywhere else. Observability, debug & RCA are the primary lens of this catalog — but the **same hooks** are the surface for a spectrum of applications, of which the CVE shield is only one:

- **Observability, debug & RCA** — the focus of this catalog: bpftrace-for-TMM summaries, flight recorders, per-flow latency, in-situ field-support probes.
- **CVE shields (Live Shield)** — a `filter`/drop program at a parser or plugin hook blocks a live exploit path between patch windows. One consumer, *not* the purpose.
- **Steering & policy** — member-selection / mirror / A-B decisions driven by internal signal.
- **Self-tuning** — read internal load and emit a scalar recommendation the host's tuning controller applies within sanctioned bounds; live hot-path profiling.

> *Forward-looking, and deliberately not part of this ask.* The same `ctx` fields are also the natural
> feature inputs for in-situ data intelligence — a verified transform distilling `ctx` into derived
> features rather than payload ([`data-plane-intelligence.md`](data-plane-intelligence.md)). That is a
> separate proposal carrying its own data-governance questions, and **nothing in this catalog depends on
> it**; the hooks below are justified by observability, RCA, and CVE mitigation alone.

The engine is generic; the shield is one application on top of it. The reason a rich catalog is affordable:

- **Dark until lit.** A hook with nothing attached costs ~one predictable branch (a designed-in call site; an unarmed function boundary is a nop pad — **free at runtime**). You pay only when a program is loaded onto it, on demand. The pads are *not* free at **build** time: `-fpatchable-function-entry` inflates `.text` and carries an i-cache / i-TLB footprint that every customer pays whether or not anything is ever armed. That cost is **measured, not assumed** — it is the dark-cost experiment that is the first deliverable of the feasibility phase, with a stated kill criterion of roughly 1% of pps (`big-ip-live-shield-design.md` §12).
- **No helpers, no verifier *extension* — stock PREVAIL under its existing `tracing` program type.** A program is a pure function of `ctx` (read fields → return a value); the host owns all state and effects. So a new hook needs **no eBPF helper** and **no verifier extension**: PREVAIL already proves the canonical case — a bounded predicate over a fixed-width `ctx` — and Phase 1 rides its existing `tracing` type (12 `u64` args, nothing dereferenced) so there is **no fork in the trust path**. PREVAIL has no `--program-type` switch; a *named* TMM program type is a patch set with a per-release rebase cost, which we deliberately have not taken. It will also reject plenty of predicates that are bounded in principle (awkward loop shapes, unresolved pointer arithmetic) — write to the canonical case. The `ctx`/program-type descriptor is the real, bounded work (`engine-hard-problems.md` §2). Adding a hook is then: *define its `ctx`, place the hook, publish it in the hook-point map.*
- **Incremental.** Each subsystem owner can instrument their own code in a normal release. The surface grows over time; every new `ctx` field widens what can be **observed, enforced, steered, or distilled into signal** (a hook can only act on what its `ctx` exposes).

> **Consuming a hook.** A few lines of C compiled with `clang -target bpf` — or, with a DSL front-end,
> a one-liner convenience: `dptrace list 'tmm:l7:*'` to discover, then e.g.
> `dptrace run 'tmm:l7:http2_frame { @streams = hist(args.n_streams); }'`. The **same grammar** would author an
> acting program — a `filter`/drop shield, a steer, a sampler — by swapping the action verb; observe and act
> share the machinery (design §6.1, `big-ip-live-shield-design.md`).

**Two companion utilities — both proposed, neither built.** `dptrace` would be the *summary* consumer — bpftrace-for-the-data-plane: counters, histograms, predicates, shields. `dpdump` would be the *capture* consumer — tcpdump-for-the-data-plane: it streams a bounded window of the **actual bytes** at a hook off the box, *together with the internal state at that hook* — the one thing an interface-boundary packet capture cannot correlate for you (§10.6). One summarizes, one captures; both would be thin front-ends over the same in-process VM: **`dptrace : bpftrace :: dpdump : tcpdump`**.

> **On the names, and on what exists.** `dptrace` and `dpdump` are **placeholder names for proposed
> utilities** — nothing by either name exists, here or in any product, and no invocation shown in this
> document has ever been run. They are written in imperative CLI form because that is the clearest way to
> specify an interface, not because there is a binary behind it. Names are deliberately kept free of
> `tmm` so they are not mistaken for existing TMM components; final naming is a product decision. The
> tracepoint *namespace* (`tmm:<stage>:<event>`, §2) does keep the `tmm` prefix — it names hooks in TMM,
> which is exactly what it should say. Every example invocation and every field name below is a **proposal**
> against a hook-point catalog that is itself proposed.

## 2. Conventions

- **Naming:** `tmm:<stage>:<event>` — e.g. `tmm:l4:conn_state`, `tmm:bd:ipc_verdict`, `tmm:rt:poll_stall`.
- **`ctx` typing:** every field is a fixed-width scalar or a small fixed byte array (BTF-described per build). No pointers out; sensitive fields (keys, PII, decrypted payload) are **withheld by default** and gated behind separate authorization (substrate §6.3).
- **The `ctx` is a copy, not a view.** The host builds a **per-core scratch copy** of the curated fields before the call and **discards it on fall-through** — it is never a live window onto TMM's own structures. This is not defensive stylistics: PREVAIL does not express a read-only region for `ctx` (it does not consume `writable: []`), so a *verified* program can write every byte of its `ctx`. A live view would therefore hand every armed hook a state-injection primitive, delivered by the safety mechanism itself (`engine-hard-problems.md` §2).
- **Two fields are mandatory in every `ctx`:** `tmm_id` (the emitting TMM instance) and `offloaded` (whether this flow's steady state is being handled outside TMM software — ePVA/FPGA, FastL4 fast path, or pass-through). Without them a zero is ambiguous three ways: *no attack*, *handled in silicon and therefore never seen*, or *counted on a different TMM instance*. Every aggregate field in this catalog is **per-instance, not per-box** — on a CMP box each counter is roughly 1/N of the box and DAG decides which N. The tables below omit both fields for brevity; they are always present.
- **`path_class` — the rate class, not a code-location label:** `hot` (per packet), `warm` (per connection / per request), `cold` (per exceptional event — error, malformed input, watchdog). It sets the **per-invocation** cycle budget *and* the sampling divisor under load, because what makes an invocation affordable is its rate (`engine-hard-problems.md` §1; design §11). It must be read as **structure ∧ adversarial reachability**: anything reachable from unauthenticated input at an attacker-controlled rate is budgeted **`hot`** wherever it sits in the source, because the attacker supplies the steady state. Where the two readings differ, the tables give both as *structure* → **budgeted class**.
- **Runtime guard (fuel).** The per-invocation budget is checked at admission, but admission bounds *instruction count*, not wall-clock time — so arming a `hot` or attacker-reachable hook depends on the **back-edge fuel guard**. That is real runtime work, not a free property: `ubpf_set_instruction_limit` *"has no effect on JIT'd programs,"* so fuel means a **uBPF JIT patch** (fuel does work in the interpreter today). A wall-clock deadline is **reporting, not enforcement** — on aarch64 the counter's 10–40 ns granularity is coarser than a hot hook's whole budget (`engine-hard-problems.md` §1).
- **`mode`:** every hook supports `observe`; a subset that sit at a clean decision point also support **act mode** — the program selects among the host-owned outcomes declared for that hook — the canonical set is in [`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) §2 (`PASS · DROP · RESET · SAFE-RETURN · STEER · SAMPLE`), of which a CVE `filter`/drop shield uses only two. This catalog marks act-capable hooks with **◆**. Note `observe` is **not a seventh outcome**: the program still selects one of the six, and observe mode is the host **declining to apply** it while still counting that it was selected.
- **RCA columns:** *Observe* = the steady-state signal; *Debug/RCA* = what it yields when an incident is being chased (often via the flight-recorder / tripwire patterns in §10).

---

## 3. The ingress edge — NIC rings, CMP disaggregation, offload, L3/L4 and the connection table

| Tracepoint | `ctx` (typed fields) | Observe | Debug / RCA | path_class |
|---|---|---|---|---|
| `tmm:nic:ring` | `dir, ring_id, ring_full_events, no_buf, hsb_backpressure` | ingress/egress ring occupancy and no-buffer events | **the first question on any drop report** — were the drops in the ring, in HSB backpressure, or in software? | hot (sampled per *K* iterations) |
| `tmm:cmp:disagg` | `hash_inputs, chosen_tmm, redirected, reselect_reason` | DAG hash distribution across instances | uneven per-instance counts (the reason every aggregate here is per-instance); redirect/reselect storms | hot |
| `tmm:hw:offload_decision` ◆ | `decision (accelerate/escalate/reject), reason, flow_key_hash` | share of flows accelerated vs. escalated to software | **what the rest of this catalog didn't see** — an accelerated flow leaves no further software trace; also why a shield's counters can read zero | warm |
| `tmm:l4:conn_new` | `saddr_hash, dport, proto, flags` | new-flow rate, PPS, port spread | SYN-flood onset; scan/`saddr` fan-out; conn-table fill rate before exhaustion | *warm* (per connection) → **hot** (unauthenticated SYN rate) |
| `tmm:l4:conn_state` ◆ | `old_state, new_state, dport` | TCP-state distribution | state-machine anomalies; half-open growth | warm |
| `tmm:l4:rst_send` / `tmm:l4:rst_recv` | `rst_reason, dir, old_state, dport, flow_key_hash` | RST rate by enumerated internal cause | **"why is BIG-IP resetting my connection?"** — one of the top support questions, and the enumerated cause is only knowable inside TMM | *cold* → **hot** (RST storms are attacker-driven) |
| `tmm:l4:frag` ◆ | `frag_off, more_frags, id, total_seen` | fragment stats | fragment-reassembly abuse (a data-plane CVE class no rule layer expresses) | *cold* (structurally) → **hot** (per packet on fragmented traffic, attacker-controlled) |
| `tmm:l4:conntab` | `occupancy, high_watermark, evictions` | table occupancy (this instance's share) | pre-exhaustion run-up; eviction thrash under load | warm |

## 4. Client-side TLS / record layer

| Tracepoint | `ctx` (typed fields) | Observe | Debug / RCA | path_class |
|---|---|---|---|---|
| `tmm:tls:clienthello` ◆ | `tls_ver, cipher_list_hash, ext_list_hash, n_exts, sni_len, ja4[32], ja4_valid` | version/cipher mix, fingerprint clustering | fingerprint an attacker population; malformed ClientHello **before** `CLIENTSSL_*` fires | warm |
| `tmm:tls:sni_select` ◆ | `sni_hash, match_kind (virtual/cert/default), vs_id, cert_id` | how SNI resolves to a virtual and a certificate | **the selection decision itself** — wrong-cert and fell-through-to-default misconfigurations, and a recurring CVE-adjacent surface | warm |
| `tmm:tls:record` ◆ | `rec_type, rec_len, ver, parse_state` | record-layer stats | record-parse anomalies ahead of the earliest iRule hook (the design-§10 dead-zone edge) | hot |
| `tmm:tls:handshake_done` | `cipher, ver, resumed, ms_elapsed` | handshake outcomes / latency | handshake failure clusters; downgrade attempts | warm |
| `tmm:tls:reneg` ◆ | `count, since_ms` | renegotiation counts | renegotiation-abuse DoS | *cold* → **hot** (renegotiation abuse is attacker-rate by construction) |
| `tmm:tls:decrypt_err` | `err_code, rec_type` | decrypt error rate | crypto-path faults; corrupt-record floods | *cold* → **hot** (a corrupt-record flood *is* the steady state) |

`ja4[32]` is populated **only when a profile or iRule has already asked TMM to compute a fingerprint** — a
catalog hook cannot presume that work was done, hence the `ja4_valid` bit. The raw inputs
(`cipher_list_hash`, `ext_list_hash`, `n_exts`, `sni_len`) are exposed alongside it so a program can cluster
unconditionally.

## 5. L7 protocol parse (HTTP/1·2·3, QUIC, DNS, SIP, MQTT, DIAMETER)

| Tracepoint | `ctx` (typed fields) | Observe | Debug / RCA | path_class |
|---|---|---|---|---|
| `tmm:l7:http_request` ◆ | `method, path_hash, hdr_count, hdr_bytes, flow_key_hash` | per-method / per-URI rates | header-count/size abuse; request-smuggling shape | warm (per request — but it fires on *every* request, so: measured per-invocation budget and a sampling divisor under load) |
| `tmm:l7:http2_frame` ◆ | `frame_type, n_streams, hdr_tbl_sz, flags, flow_key_hash` | stream/header stats | **HTTP/2 malformed-frame crash class**; stream-count flood (Rapid Reset family) | hot (per frame) |
| `tmm:l7:parse_error` ◆ | `proto, err_state, offset, opcode_raw, opcode_valid` | malformed-encoding counts | the exact pre-crash predicate for parser CVEs; captures the frame that terminates the parser | *cold* (an error branch) → **hot** (the flagship attacker-driven branch; at line rate it is the hottest code on the box) |
| `tmm:l7:dns_query` ◆ | `qtype, qname_len, n_queries, flow_key_hash` | DNS query mix | amplification / malformed-name abuse | hot (DNS over UDP is per packet with no connection — the canonical unauthenticated amplification vector) |
| `tmm:l7:h3_quic` | `pkt_type, n_streams, cc_state` | QUIC/H3 stats | connection-migration abuse; congestion anomalies | hot |

On a malformed frame the opcode may be *the field that failed to parse*, so `opcode_raw` is defined as **the
bytes as read** and `opcode_valid` says whether they were accepted — a program that treats `opcode_raw` as a
decoded enum is reading attacker-chosen bytes.

## 6. Enforcement — in-TMM filters, and the out-of-process `bd` boundary

**Two address spaces, and the distinction is load-bearing.** AFM and the DoS/rate-limiting enforcement run
**inside TMM** as filters in the stack, and are hookable exactly like any other TMM code. APM is **split** —
a TMM-side filter plus out-of-process daemon state. `bd` (ASM / Advanced WAF) is a **separate process**: its
policy, opcode, signature and queue state are not in TMM's address space, so no TMM-side hook can expose
them. What a TMM hook *can* see is the **IPC boundary** — direction, message type, backlog, round-trip
latency, and the verdict that came back. A genuine `bd`-internal hook is a *second engine instance in `bd`*,
with its own program type, its own address space, and its own safe-point problem in multi-threaded C++ with
no poll loop (`engine-hard-problems.md` §5) — out of scope for this catalog, and explicitly **not** the Live
Shield Phase 1 target (`big-ip-live-shield-design.md` §12: Phase 1 is a designed-in call site on a `warm`/`cold` TMM
path, precisely because `bd` is the hardest first target, not the easiest).

### 6.1 In-TMM enforcement filters (AFM, DoS, the TMM side of APM)

| Tracepoint | `ctx` (typed fields) | Observe | Debug / RCA | path_class |
|---|---|---|---|---|
| `tmm:afm:rule_eval` ◆ | `rule_set_id, match_idx, action, eval_us` | per-rule-set hit rates and evaluation cost | which rule actually matched on a live box without a debug build; ACL-ordering surprises | warm |
| `tmm:dos:vector_eval` ◆ | `vector_id, rate_1s, threshold, state` | per-vector rate against threshold | which DoS vector fired and by how much; per-instance skew under DAG | hot |
| `tmm:plugin:degrade` ◆ | `plugin_id, reason, latency_us` | per-plugin latency | trip a **host-owned** circuit-breaker on a degrading plugin (an observe signal the host acts on — not a program outcome); catch the degradation run-up | warm |

### 6.2 The `bd` IPC boundary — TMM-visible fields only

| Tracepoint | `ctx` (typed fields) | Observe | Debug / RCA | path_class |
|---|---|---|---|---|
| `tmm:bd:ipc_request` ◆ | `msg_type, payload_len, backlog, inflight` | request-leg rate, queue depth | `bd` handoff stalls; backlog run-up *before* a hang | warm |
| `tmm:bd:ipc_verdict` ◆ | `msg_type, verdict, rtt_us, backlog` | verdict mix, `bd` round-trip latency | slow or absent verdicts; attribute a TMM-side stall to `bd` rather than to TMM | warm |

Splitting the request and verdict legs is not cosmetic: on the request leg there is **no round-trip latency
yet**, so a single hook carrying `latency_us` in both directions is undefined half the time. Policy and
signature identifiers (`policy_id`, `sig_id`) are `bd`-internal — a false-positive investigation therefore
needs either an in-`bd` hook (above) or correlation of the TMM-visible verdict with `bd`'s own logging.

## 7. LB / persistence / pool selection

| Tracepoint | `ctx` (typed fields) | Observe | Debug / RCA | path_class |
|---|---|---|---|---|
| `tmm:lb:member_select` ◆ | `pool_id, member_idx, algo, health` | member selection distribution | steer away from a member under attack; hot-member skew | warm (per connection; per request with OneConnect) |
| `tmm:lb:persist` ◆ | `persist_type, key_hash, hit` | persistence behavior | persistence-table anomalies; affinity breakage | warm |
| `tmm:lb:member_health` | `member_idx, state, rtt_us` | member health/latency | flap correlation; slow-member detection | warm |

## 8. Server side + response path

| Tracepoint | `ctx` (typed fields) | Observe | Debug / RCA | path_class |
|---|---|---|---|---|
| `tmm:srv:tls_record` ◆ | `rec_type, rec_len, parse_state` | server-side record stats | **server-side record-parse shield** (same class as client TLS) | hot |
| `tmm:srv:response` | `status, hdr_count, body_len` | response-code mix | response-parse anomalies; upstream misbehavior | warm |
| `tmm:srv:oneconnect` | `reuse, pool_conns, idle_ms` | OneConnect reuse stats | connection-reuse leaks; pool starvation | warm |

## 9. Cross-cutting runtime (poll loop, filter stack, memory, IPC, TCL VM)

These signals are already **counted** — poll-loop statistics, memory pools and IPC counters are all readable
today via `tmctl`/`tmstat` and land in every qkview. What they are not is **conditional**: you can read the
aggregate, but you cannot say *keep the last 200 samples leading into the stall*, or *sample this only while
this flow is in state X*, or *freeze on the first allocation failure in this pool*. That gap — aggregate
counters vs. conditional, triggered, correlated capture — is what this class buys, and it is the
highest-leverage RCA class because the conditional view exists nowhere else.

| Tracepoint | `ctx` (typed fields) | Observe | Debug / RCA | path_class |
|---|---|---|---|---|
| `tmm:rt:poll_iter` | `duration_us, events` | poll-loop cadence / jitter | latency-spike RCA; correlate stalls to a flow or plugin | hot (per iteration — sampled at a stated divisor) |
| `tmm:rt:poll_stall` ◆ | `stall_us, last_event` | tail-latency events | **global tripwire** — dump on a stall over threshold (substrate §3.1) | cold |
| `tmm:rt:filter_enter` / `tmm:rt:filter_exit` | `filter_id, flow_key_hash, elapsed_us (exit only)` | per-filter occupancy of the stack | **per-filter latency attribution** — TMM *is* a filter stack, and without these the §10.2 stage breakdown is hardcoded to a handful of named hooks | hot |
| `tmm:rt:mem_pool` | `pool_id, in_use, high_watermark` | memory-pool pressure | leak run-up; pre-OOM forensics | warm (a **periodic sample** at a stated interval, not an event) |
| `tmm:rt:alloc_fail` | `subsystem, pool_id, obj_class (packet buffer / connflow / handle), size, in_use` | allocation-failure rate by requester | the data-plane-relevant failure: *which* subsystem failed to get *which* object, not just that some pool had failures | cold (per failure) |
| `tmm:rt:loop_budget` | `iter_us, work_units, deferred_queue_depth, idle_us` | where an iteration's time went | starvation, a stage monopolising the loop, deferred work backing up | hot per iteration — emit under a stated sampling divisor |
| `tmm:rt:watchdog` ◆ | `subsystem, elapsed_ms, reason` | watchdog events | **emergency-mode trigger** — freeze the flight recorder on watchdog fire | cold |
| `tmm:rt:tclvm` | `rule_id, event_id, depth, exec_us` | TCL-VM execution stats per rule and event | **attribute a stall to a specific iRule** — the runaway-rule case the proposal cites as an argument needs the rule and event identity, not just an aggregate; also shield a CVE in the TCL VM itself | warm |

Splitting the old `mem_pool.fails` field out into `tmm:rt:alloc_fail` also fixes a rate conflation: `in_use`
and `high_watermark` only make sense as a **periodic sample**, while a failure is a **per-event** emission.
One hook cannot honestly carry both rate classes.

---

## 10. Turning tracepoints into RCA features

The catalog above is raw signal. These are the **reusable patterns** that turn it into named RCA capabilities — each built from the same observe machinery — no helpers, no verifier *extension* (stock PREVAIL under its existing `tracing` program type; the `ctx` descriptor is the real, bounded work).

### 10.1 Flight recorder (the run-up *into* a fault)
A host-owned per-CPU **ring** of recent `ctx` records at a hook, **frozen and dumped on a trigger** (an error-branch tracepoint, a watchdog, a stall). Yields the state leading *into* the failure — the blind spot a post-crash core dump can't give you. Because the ring is shm-backed it **usually survives** a data-plane crash and can be drained post-mortem (with the honest caveat that a memory-safety fault may have scribbled the ring on its way down; see [`data-plane-egress-primitives.md`](data-plane-egress-primitives.md)). *Two coordinated hooks: one records, one trips.* (**Proposed, not demonstrated in this repo** — no artifact here records, trips, or drains such a ring; the pattern is specified in substrate §3.1 and in [`data-plane-egress-primitives.md`](data-plane-egress-primitives.md).)

- **Per-context ring** — recent state for the active flow, dumped on that flow's error branch.
- **Global tripwire** — cross-cutting state (poll jitter, pool pressure), dumped on `tmm:rt:poll_stall` / `tmm:rt:watchdog`.

### 10.2 Per-flow latency breakdown
Timestamp fields (`ms_elapsed`, `latency_us`, `rtt_us`, `elapsed_us`, `duration_us`) across ordered stage hooks — `tmm:l4:conn_new` → `tmm:tls:handshake_done` → `tmm:l7:http_request` → `tmm:bd:ipc_request`/`ipc_verdict` → `tmm:lb:member_select` → `tmm:srv:response`. The host differences them into a **per-stage latency profile** for a target flow/tenant, on demand — answering "where did the latency go?" *inside* TMM, per stage. The named stages above are the readable default; `tmm:rt:filter_enter`/`filter_exit` (§9) generalize the same breakdown to **every** filter in the stack, so the profile is not limited to a hardcoded list.

### 10.3 Error-branch tripwire
Arm `tmm:l7:parse_error` / `tmm:tls:decrypt_err` / `tmm:plugin:degrade` as **conditional recorders**: they begin capturing once a leading indicator appears, and freeze on the fault. This is the "record only when something is starting to go wrong" discipline — but note what it does *not* buy. On benign traffic these branches are quiet, so the standing cost is near zero; under the attack they exist to catch, the same branches run at attacker rate, which is exactly when the recorder is armed. So the program at an error-branch hook is budgeted **`hot`** (§2), the capture carries a sampling divisor, and the recorder degrades by dropping samples rather than by borrowing cycles from the poll loop.

### 10.4 Signed support probe (field RCA in situ)
A narrowly-scoped observe program targeting the *exact* hook + condition behind an intermittent field issue, **signed, shipped, loaded read-only, captured, then pulled** — with context minimization, a one-way audited sink, and auto-retirement (substrate §3.1). Turns "ship a debug build and wait for it to recur" into "load signed bytecode for a while." Reaches in-TMM state logs and iRules can't.

### 10.5 Combined play — enforce **and** capture
Pair a `filter` shield with a flight recorder on the *same* condition (e.g. `tmm:l7:parse_error`): the malformed frame is **dropped** (data plane survives) *and* the run-up into the blocked attempt is **captured**. Every block becomes an intelligence source for SIRT. Be careful to claim only half of what that sounds like, though: a capture of **blocked** attempts is strong evidence for "are these real attacks?" and no evidence at all for "is it breaking legitimate traffic?" — the second half needs monitor-mode data over a legitimate-traffic corpus, where the predicate runs and is counted without acting. The two questions need two different datasets, and only one of them comes from enforcing. (**Proposed, not demonstrated in this repo**: arming two programs on one condition is a lifecycle-engine behavior nothing here implements.)

### 10.6 Targeted data capture / streaming — `dpdump`
Sometimes you don't want a summary, you want **the actual bytes** traversing the proxy. Be precise about what already exists here, because a TMM engineer will be: BIG-IP implements **its own capture path**, so `tcpdump -i 0.0` works today, the `:p`/`:n`/`:0.0` suffixes give pre- and post-TMM views of the same flow, and `tcpdump --f5 ssl` exports the session secrets needed to decrypt it offline. What a packet tap at the **interface boundary** cannot give you is **post-parse, post-decrypt state at an arbitrary internal hook** — the parser state variable that was set when the frame was rejected, the header-table size, the plugin queue depth — *alongside* the bytes and correlated to them by construction. That tap has to be **in-process, where the VM already sits.** But the single-threaded, core-pinned poll loop forbids bulk work inline, so the division of labor is strict:

> **The VM selects. The host streams. Nothing blocks the poll loop.**

- **Select inline (cheap, verified).** The program matches the target — a `flow_key_hash`, tenant, hook, or predicate over declared `ctx` fields — and signals "capture this." Tiny and bounded; it is *not* the pipe.
- **Bounded copy.** The host copies a **window** — headers, first *N* bytes, or one field (a *byte-window* `ctx`) — into a per-CPU ring. Not full payloads by default.
- **Drain off-loop.** A separate, lower-priority path serializes the ring to the sink, using cycles only when the data plane has them.
- **Drop, don't block.** Under sink pressure, **drop samples and count the drops** — never stall forwarding for observability.

The concrete mechanism — a per-core, single-producer, shared-memory ring where the **host emits and the program only signals** (no helpers, stock verifier), plus the reserve/commit protocol, backpressure counters, wakeup, and crash semantics — is specified in [`data-plane-egress-primitives.md`](data-plane-egress-primitives.md).

Levers that keep it tractable: **target** (one flow, not all), **sample** (1-in-*N* under load), **window** (bounded bytes), **redact** (context minimization). Dark-until-lit; full-fidelity capture of all flows at line rate is a measured-budget decision (design §11), and traffic offloaded to ePVA/FPGA isn't in software to capture at all (design §10; the mandatory `offloaded` bit is how a capture reports that gap instead of silently under-counting).

**Payoff:** in-process at L7 means **decrypted** application data — post-TLS content a wire tap can only reach by exporting the session secrets (`tcpdump --f5 ssl`, which the box will do for you today), which is precisely why the in-process path sits at the **strictest authorization tier** instead: signed, RBAC-gated, redact-by-default, time-boxed, one-way audited sink (substrate §6.3). "Vendor streams my decrypted traffic" is a non-starter *without* that governance.

**`dpdump`** is the proposed utility — `dptrace : bpftrace :: dpdump : tcpdump`, both over the in-process VM. The invocations below are an **interface sketch for a tool that does not exist** (§1, placeholder names):

```
dpdump --hook tmm:l7:http_request --filter 'args.method == POST' --snap 256 --ttl 5m --sink file
dpdump --flow 10.0.0.5:443 --decrypted --snap 512      # decrypted L7 — strict authz tier
dpdump --hook tmm:tls:record --headers-only            # bounded window, no payload
```

Two things about that syntax, so it isn't read as more than it is. **`--flow` is a host-side pre-filter, not a
program predicate**: no `ctx` in this catalog exposes raw addresses and ports (`tmm:l4:conn_new` carries only
`saddr_hash`; the L7 rows carry `flow_key_hash`), so the host resolves the 5-tuple to the hook's `flow_key_hash`
and the program compares hashes. And a bare symbol like `POST` resolves against the **enum declared for that
`ctx` field in the per-build hook map** — there is no implicit vocabulary; a field with no declared enum is
compared as a number.

The VM program is the **selector** (verified inline); `dpdump` (the host) owns the bounded copy + off-loop export. It is deliberately distinct from `dptrace`'s scalar summaries — heavier, governed, capture-oriented. *(Proposed. The copy-and-drain path it depends on is specified in [`data-plane-egress-primitives.md`](data-plane-egress-primitives.md) and is likewise unbuilt — a written ring protocol, not a measured one.)*

---

## 11. Suggested first set (highest leverage, with the exposure stated per item)

If the team lands a handful first, these give the most RCA value for the least exposure. All five are
**observe-mode** to begin with; the mix of rate classes is stated rather than smoothed over, because it decides
what runtime machinery each one needs:

1. `tmm:l7:parse_error` — the pre-crash predicate for the flagship malformed-input CVE class; the flight-recorder trigger. Structurally an error branch, **budgeted `hot`** (attacker-driven).
2. `tmm:rt:poll_stall` + `tmm:rt:mem_pool` — the global tripwire and the pre-OOM run-up; `cold` and periodically-sampled `warm` respectively, and the two that turn today's aggregate counters into conditional capture.
3. `tmm:bd:ipc_verdict` — `bd` round-trip latency and verdict mix at the IPC boundary, `warm`. Note this is **telemetry, not a shield target**: Live Shield Phase 1 is a designed-in call site on a **cold TMM path**, deliberately *not* `bd` (`big-ip-live-shield-design.md` §12).
4. `tmm:tls:clienthello` — fingerprint clustering plus malformed-ClientHello detection ahead of the earliest iRule event, `warm`.
5. `tmm:l7:http2_frame` — HTTP/2 stream/frame stats covering the Rapid-Reset-style abuse family. This one is **`hot` (per frame)** and therefore the one that carries a measured per-invocation budget and the runtime guard; it is in the first set because the abuse family justifies it, not because it is cheap. Drop it if the guard is not ready.

Each is a `ctx` definition plus a call site — no verifier *extension* (stock PREVAIL under its existing
`tracing` type), no helper ABI; the `ctx` descriptor is the real, bounded work. **"No VM change" holds only for
observe-mode hooks running in the interpreter or under a fuel-capable JIT.** Arming a hook that is `hot` or
attacker-reachable — items 1 and 5 above — depends on the back-edge fuel guard, and that is a **uBPF JIT
patch** (`engine-hard-problems.md` §1); wall-clock is reporting, not enforcement. Where marked ◆ a hook can
graduate from observe to an **acting program** — a `filter`/drop shield, a steer, a sampler — once the signal
is trusted, reusing the same hook and the same verify gate, and paying for the guard.

---

## 12. Notes

- **Producer/consumer ordering:** these hooks and their `ctx` are **TMM's**, designed in ahead of time and emitted in the signed per-build hook-point map; a probe (or shield) against a **catalog hook** is written against a `ctx` that already exists. For an unforeseen bug, the `ctx` is the vulnerable function's **own typed arguments** from the build's hook map (BTF/DWARF) — a build-specific contract re-validated per build. Either way the `ctx` handed to the program is a **per-core scratch copy** of curated fields that TMM already holds — never raw memory, and never a live view of TMM's own structures, because a verified program can write every byte of its `ctx` (§2, substrate §6.3).
- **Coverage bound — a list, not a footnote.** An in-TMM tracepoint sees only what runs in **TMM software**, and the gaps are enumerable:
  - **Hardware offload** — flows accelerated by ePVA/FPGA/TurboFlex on appliances never re-enter software (design §10). `tmm:hw:offload_decision` (§3) is what tells you this happened.
  - **FastL4** — a fast-path flow bypasses the full proxy, so the L7 and TLS hooks never fire for it.
  - **SSL pass-through and client-SSL-only virtuals** — no decrypt, or only one side of it; the server-side record hooks see nothing useful.
  - **Non-terminated UDP/QUIC** — no connection state to hang a `warm` hook on.
  - **CMP / DAG scope** — every hook fires on **one TMM instance**, so each counter is that instance's share and DAG chose the split (hence the mandatory `tmm_id`, §2).
  - **Per-box scope** — nothing here sees a peer in the device group or another box in the tier.

  These are the same blind spots iRules and kernel eBPF have, and **BIG-IP VE** removes only the first one: with no offload the whole data path is in software, but an L7 hook still cannot see a pass-through virtual. The practical consequence is that a zero from any hook needs the `offloaded` bit and `tmm_id` beside it to be interpretable at all.
- **This is a menu, not a commitment.** Exact hook placement and `ctx` layout are set against TMM source and emitted per build (design §5.3). Field lists here are illustrative of the *kind* of state each hook would expose.
