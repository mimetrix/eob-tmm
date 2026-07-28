# TMM USDT Tracepoint Catalog — the hook-point surface of the embedded eBPF framework

### A proposed set of designed-in hook points for TMM — USDT-style tracepoints plus filter-capable decision points — consumed by the embedded userspace-eBPF VM. Observability, debug & RCA are the primary lens here; CVE shields, in-situ data-intelligence, steering, and self-tuning are **peer consumers of the same hooks**. The engine is generic; the shield is one application.

**Status:** Proposal / engineering menu · **Companion:** [`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) (the substrate), [`big-ip-live-shield-design.md`](big-ip-live-shield-design.md) (Live Shield), [`data-plane-intelligence.md`](data-plane-intelligence.md) (these `ctx` fields are also the feature inputs for in-situ data intelligence), [`prototype/tmmtrace`](prototype/tmmtrace) (the front-end)
**Audience:** TMM core engineering, F5 SIRT, observability & support

---

## 1. What this is (and why it's cheap)

This is a candidate catalog of **designed-in hook points** to build into TMM's source as the generic instrumentation-and-control surface of the embedded eBPF framework. Each is a named, versioned hook that exposes a small **typed context (`ctx`)** — a curated view of the internal state present at that point. The embedded uBPF VM runs a small **verified** program at the hook; the host owns all state and effects and applies the program's return as one of an **enumerated set of outcomes** — the program cannot invent control flow.

Most hooks are consumed in **observe mode**: the program reads `ctx`, returns a value, and the host aggregates it (a counter, a histogram, a ring) — traffic is untouched. A subset sit at a clean decision point and also support **act mode**: the same `ctx`-in / value-out program picks among host-owned actions (pass · drop · steer · mark · sample). Observability, debug & RCA are the primary lens of this catalog — but the **same hooks** are the surface for a spectrum of applications, of which the CVE shield is only one:

- **Observability, debug & RCA** — the focus of this catalog: bpftrace-for-TMM summaries, flight recorders, per-flow latency, in-situ field-support probes.
- **CVE shields (Live Shield)** — a `filter`/drop program at a parser or plugin hook blocks a live exploit path between patch windows. One consumer, *not* the purpose.
- **In-situ data-intelligence** — a verified transform distills `ctx` into features that leave the box as **signal, never payload**, feeding an F5 model (see [`data-plane-intelligence.md`](data-plane-intelligence.md)).
- **Steering & policy** — member-selection / mirror / A-B decisions driven by internal signal.
- **Self-tuning** — read internal load and nudge a knob; live hot-path profiling.

The engine is generic; the shield is one application on top of it. The reason a rich catalog is affordable:

- **Dark until lit.** A hook with nothing attached costs ~one predictable branch. You pay only when a program is loaded onto it, on demand.
- **No helpers, no verifier work.** A program is a pure function of `ctx` (read fields → return a value); the host owns all state and effects. So a new hook needs **no eBPF helper** and **no verifier extension** — stock PREVAIL verifies any bounded predicate over the new `ctx` (substrate §2). Adding one is just: *define its `ctx`, place the hook, publish it in the hook-point map.*
- **Incremental.** Each subsystem owner can instrument their own code in a normal release. The surface grows over time; every new `ctx` field widens what can be **observed, enforced, steered, or distilled into signal** (a hook can only act on what its `ctx` exposes).

> **Consuming a hook.** With `tmmtrace`: `tmmtrace list 'tmm:l7:*'` to discover, then e.g.
> `tmmtrace run 'tmm:l7:http2_frame { @streams = hist(args.n_streams); }'`. The **same grammar** authors an
> acting program — a `filter`/drop shield, a steer, a sampler — by swapping the action verb; observe and act
> share the machinery (substrate §6.1).

**Two companion utilities.** `tmmtrace` is the *summary* consumer — bpftrace-for-TMM: counters, histograms, predicates, shields. `tmmdump` (proposed) is the *capture* consumer — tcpdump-for-TMM: it streams a bounded window of the **actual bytes** at a hook off the box, the only viable tap for a kernel-bypassed data plane (§10.6). One summarizes, one captures; both are thin front-ends over the same in-process VM: **`tmmtrace : bpftrace :: tmmdump : tcpdump`**.

## 2. Conventions

- **Naming:** `tmm:<stage>:<event>` — e.g. `tmm:l4:conn_state`, `tmm:bd:request_eval`, `tmm:rt:poll_stall`.
- **`ctx` typing:** every field is a fixed-width scalar or a small fixed byte array (BTF-described per build). No pointers out; sensitive fields (keys, PII, decrypted payload) are **withheld by default** and gated behind separate authorization (substrate §6.3).
- **`path_class`:** `hot` (per-packet/per-flow steady state), `warm` (per-connection / per-request), `cold` (exceptional / error / malformed branch). Cold is free-in-steady-state; hot is allowed under a measured budget (design §11).
- **`mode`:** every hook supports `observe`; a subset that sit at a clean decision point also support **act mode** — the program selects among host-owned actions (drop/`filter`, steer, mark, sample), of which a CVE `filter`/drop shield is one (design §6.1). This catalog marks act-capable hooks with **◆**.
- **RCA columns:** *Observe* = the steady-state signal; *Debug/RCA* = what it yields when an incident is being chased (often via the flight-recorder / tripwire patterns in §10).

---

## 3. L3/L4 ingress + connection table

| Tracepoint | `ctx` (typed fields) | Observe | Debug / RCA | path_class |
|---|---|---|---|---|
| `tmm:l4:conn_new` | `saddr_hash, dport, proto, flags` | new-flow rate, PPS, port spread | SYN-flood onset; scan/`saddr` fan-out; conn-table fill rate before exhaustion | hot |
| `tmm:l4:conn_state` ◆ | `old_state, new_state, dport, rst_reason` | TCP-state distribution, RST causes | state-machine anomalies; RST storms; half-open growth | warm |
| `tmm:l4:frag` ◆ | `frag_off, more_frags, id, total_seen` | fragment stats | fragment-reassembly abuse (a data-plane CVE class no rule layer expresses) | cold |
| `tmm:l4:conntab` | `occupancy, high_watermark, evictions` | table occupancy | pre-exhaustion run-up; eviction thrash under load | warm |

## 4. Client-side TLS / record layer

| Tracepoint | `ctx` (typed fields) | Observe | Debug / RCA | path_class |
|---|---|---|---|---|
| `tmm:tls:clienthello` ◆ | `tls_ver, n_exts, sni_len, ja4[32]` | version/cipher mix, JA3/JA4 fingerprints | fingerprint an attacker population; malformed ClientHello **before** `CLIENTSSL_*` fires | warm |
| `tmm:tls:record` ◆ | `rec_type, rec_len, ver, parse_state` | record-layer stats | record-parse anomalies ahead of the earliest iRule hook (the §10 dead-zone edge) | hot |
| `tmm:tls:handshake_done` | `cipher, ver, resumed, ms_elapsed` | handshake outcomes / latency | handshake failure clusters; downgrade attempts | warm |
| `tmm:tls:reneg` ◆ | `count, since_ms` | renegotiation counts | renegotiation-abuse DoS | cold |
| `tmm:tls:decrypt_err` | `err_code, rec_type` | decrypt error rate | crypto-path faults; corrupt-record floods | cold |

## 5. L7 protocol parse (HTTP/1·2·3, QUIC, DNS, SIP, MQTT, DIAMETER)

| Tracepoint | `ctx` (typed fields) | Observe | Debug / RCA | path_class |
|---|---|---|---|---|
| `tmm:l7:http_request` ◆ | `method, path_hash, hdr_count, hdr_bytes` | per-method / per-URI rates | header-count/size abuse; request-smuggling shape | hot |
| `tmm:l7:http2_frame` ◆ | `frame_type, n_streams, hdr_tbl_sz, flags` | stream/header stats | **HTTP/2 malformed-frame crash class**; stream-count flood (Rapid Reset family) | hot |
| `tmm:l7:parse_error` ◆ | `proto, err_state, offset, opcode` | malformed-encoding counts | the exact pre-crash predicate for parser CVEs; captures the frame that terminates the parser | cold |
| `tmm:l7:dns_query` ◆ | `qtype, qname_len, n_queries` | DNS query mix | amplification / malformed-name abuse | warm |
| `tmm:l7:h3_quic` | `pkt_type, n_streams, cc_state` | QUIC/H3 stats | connection-migration abuse; congestion anomalies | hot |

## 6. Enforcement plugins (`bd`/WAF, APM, AFM, DoS)

| Tracepoint | `ctx` (typed fields) | Observe | Debug / RCA | path_class |
|---|---|---|---|---|
| `tmm:bd:request_eval` ◆ | `policy_id, opcode, queue_depth, state` | `bd` decision latency, hit rates | **the `bd`-termination shield hook** (design §14); internal state just before a known `bd` fault | warm |
| `tmm:bd:ipc` | `dir, msg_type, latency_us, backlog` | plugin-IPC health | `bd` handoff stalls; IPC backlog before a hang | warm |
| `tmm:plugin:degrade` ◆ | `plugin_id, reason, latency_us` | per-plugin latency | circuit-break a degrading plugin; catch the degradation run-up | warm |
| `tmm:waf:policy_hit` | `policy_id, sig_id, action` | per-policy/sig hit rates | false-positive investigation on a live policy without a debug build | warm |

## 7. LB / persistence / pool selection

| Tracepoint | `ctx` (typed fields) | Observe | Debug / RCA | path_class |
|---|---|---|---|---|
| `tmm:lb:member_select` ◆ | `pool_id, member_idx, algo, health` | member selection distribution | steer away from a member under attack; hot-member skew | hot |
| `tmm:lb:persist` ◆ | `persist_type, key_hash, hit` | persistence behavior | persistence-table anomalies; affinity breakage | warm |
| `tmm:lb:member_health` | `member_idx, state, rtt_us` | member health/latency | flap correlation; slow-member detection | warm |

## 8. Server side + response path

| Tracepoint | `ctx` (typed fields) | Observe | Debug / RCA | path_class |
|---|---|---|---|---|
| `tmm:srv:tls_record` ◆ | `rec_type, rec_len, parse_state` | server-side record stats | **server-side record-parse shield** (same class as client TLS) | hot |
| `tmm:srv:response` | `status, hdr_count, body_len` | response-code mix | response-parse anomalies; upstream misbehavior | warm |
| `tmm:srv:oneconnect` | `reuse, pool_conns, idle_ms` | OneConnect reuse stats | connection-reuse leaks; pool starvation | warm |

## 9. Cross-cutting runtime (poll loop, memory, scheduler, IPC, TCL VM)

These are TMM-internal health signals with **no iRule / data-model surface at all** — the highest-leverage RCA class, because nothing else can see them.

| Tracepoint | `ctx` (typed fields) | Observe | Debug / RCA | path_class |
|---|---|---|---|---|
| `tmm:rt:poll_iter` | `duration_us, events, cpu` | poll-loop cadence / jitter | latency-spike RCA; correlate stalls to a flow or plugin | hot |
| `tmm:rt:poll_stall` ◆ | `stall_us, last_event, cpu` | tail-latency events | **global tripwire** — dump on a stall over threshold (substrate §3.1) | cold |
| `tmm:rt:mem_pool` | `pool_id, in_use, high_watermark, fails` | memory-pool pressure | leak run-up; pre-OOM forensics; alloc-fail bursts | warm |
| `tmm:rt:sched` | `runnable, migrations, cpu` | scheduler occupancy | starvation / imbalance across core-pinned instances | hot |
| `tmm:rt:watchdog` ◆ | `subsystem, elapsed_ms, reason` | watchdog events | **emergency-mode trigger** — freeze the flight recorder on watchdog fire | cold |
| `tmm:rt:tclvm` | `event, depth, exec_us` | TCL-VM execution stats | iRule-engine hotspots; shield a CVE in the TCL VM itself | warm |

---

## 10. Turning tracepoints into RCA features

The catalog above is raw signal. These are the **reusable patterns** that turn it into named RCA capabilities — each built from the same observe machinery, no helpers, no verifier work.

### 10.1 Flight recorder (the run-up *into* a fault)
A host-owned per-CPU **ring** of recent `ctx` records at a hook, **frozen and dumped on a trigger** (an error-branch tracepoint, a watchdog, a stall). Yields the state leading *into* the failure — the blind spot a post-crash core dump can't give you. shm-backed, so it **survives** a data-plane crash for post-mortem. *Two coordinated hooks: one records, one trips.* (Worked in the prototype: `minimm-trace` + `ctl flightrec`; substrate §3.1.)

- **Per-context ring** — recent state for the active flow, dumped on that flow's error branch.
- **Global tripwire** — cross-cutting state (poll jitter, pool pressure), dumped on `tmm:rt:poll_stall` / `tmm:rt:watchdog`.

### 10.2 Per-flow latency breakdown
Timestamp fields (`ms_elapsed`, `latency_us`, `duration_us`) across ordered stage hooks — `tmm:l4:conn_new` → `tmm:tls:handshake_done` → `tmm:l7:http_request` → `tmm:bd:request_eval` → `tmm:lb:member_select` → `tmm:srv:response`. The host differences them into a **per-stage latency profile** for a target flow/tenant, on demand. Answers "where did the latency go?" *inside* TMM, per stage.

### 10.3 Error-branch tripwire
Arm `tmm:l7:parse_error` / `tmm:tls:decrypt_err` / `tmm:plugin:degrade` as **conditional recorders**: cheap in steady state, they begin capturing once a leading indicator appears, and freeze on the fault. This is the "record only when something is starting to go wrong" discipline that keeps the standing cost near zero.

### 10.4 Signed support probe (field RCA in situ)
A narrowly-scoped observe program targeting the *exact* hook + condition behind an intermittent field issue, **signed, shipped, loaded read-only, captured, then pulled** — with context minimization, a one-way audited sink, and auto-retirement (substrate §3.1). Turns "ship a debug build and wait for it to recur" into "load signed bytecode for a while." Reaches in-TMM state logs and iRules can't.

### 10.5 Combined play — enforce **and** capture
Pair a `filter` shield with a flight recorder on the *same* condition (e.g. `tmm:l7:parse_error`): the malformed frame is **dropped** (data plane survives) *and* the run-up into the blocked attempt is **captured**. Every block becomes an intelligence source for SIRT, and it directly answers "how do you know the shield catches real attacks and isn't breaking legit traffic?" (Worked in the prototype: `LS_FLIGHTREC=1`.)

### 10.6 Targeted data capture / streaming — `tmmdump`
Sometimes you don't want a summary, you want **the actual bytes** traversing the proxy. Standard capture (tcpdump, SPAN, tc/XDP) is **blind to TMM's kernel-bypassed fast path** — the packets never enter the kernel. The only viable tap is **in-process, where the VM already sits.** But the single-threaded, core-pinned poll loop forbids bulk work inline, so the division of labor is strict:

> **The VM selects. The host streams. Nothing blocks the poll loop.**

- **Select inline (cheap, verified).** The program matches the target — a 5-tuple, tenant, hook, or predicate — and signals "capture this." Tiny and bounded; it is *not* the pipe.
- **Bounded copy.** The host copies a **window** — headers, first *N* bytes, or one field (a *byte-window* `ctx`) — into a per-CPU ring. Not full payloads by default.
- **Drain off-loop.** A separate, lower-priority path serializes the ring to the sink, using cycles only when the data plane has them.
- **Drop, don't block.** Under sink pressure, **drop samples and count the drops** — never stall forwarding for observability.

The concrete mechanism — a per-core, single-producer, shared-memory ring where the **host emits and the program only signals** (no helpers, stock verifier), plus the reserve/commit protocol, backpressure counters, wakeup, and crash semantics — is specified in [`data-plane-egress-primitives.md`](data-plane-egress-primitives.md).

Levers that keep it tractable: **target** (one flow, not all), **sample** (1-in-*N* under load), **window** (bounded bytes), **redact** (context minimization). Dark-until-lit; full-fidelity capture of all flows at line rate is a measured-budget decision (design §11), and traffic offloaded to ePVA/FPGA isn't in software to capture (design §10).

**Payoff:** in-process at L7 means **decrypted** application data — post-TLS content no wire tap can give you without the keys — which is also why it sits at the **strictest authorization tier**: signed, RBAC-gated, redact-by-default, time-boxed, one-way audited sink (substrate §6.3). "Vendor streams my decrypted traffic" is a non-starter *without* that governance.

**`tmmdump`** is the proposed utility — `tmmtrace : bpftrace :: tmmdump : tcpdump`, both over the in-process VM:

```
tmmdump --hook tmm:l7:http_request --filter 'args.method == POST' --snap 256 --ttl 5m --sink file
tmmdump --flow 10.0.0.5:443 --decrypted --snap 512      # decrypted L7 — strict authz tier
tmmdump --hook tmm:tls:record --headers-only            # bounded window, no payload
```

The VM program is the **selector** (verified inline); `tmmdump` (the host) owns the bounded copy + off-loop export. It is deliberately distinct from `tmmtrace`'s scalar summaries — heavier, governed, capture-oriented. *(Proposed; the prototype's shm-backed `head[]` ring is the reduction-to-practice kernel of the copy-and-drain path.)*

---

## 11. Suggested first set (highest leverage, lowest risk)

If the team lands a handful first, these give the most RCA value for the least exposure — all **cold/warm** observe-mode, read-only:

1. `tmm:l7:parse_error` — the pre-crash predicate for the flagship malformed-input CVE class; the flight-recorder trigger.
2. `tmm:rt:poll_stall` + `tmm:rt:mem_pool` — the global tripwire and pre-OOM run-up; RCA signals with no other surface.
3. `tmm:bd:request_eval` — the `bd`-termination hook (Live Shield Phase 1 target) doubling as `bd` latency/telemetry.
4. `tmm:tls:clienthello` — JA4 fingerprints + malformed-ClientHello detection ahead of the earliest iRule event.
5. `tmm:l7:http2_frame` — HTTP/2 stream/frame stats covering the Rapid-Reset-style abuse family.

Each is a `ctx` definition plus a call site — no VM change, no verifier work, no helper ABI. Where marked ◆ they graduate from observe to an **acting program** — a `filter`/drop shield, a steer, a sampler — once the signal is trusted, reusing the same hook and the same verify gate.

---

## 12. Notes

- **Producer/consumer ordering:** these hooks and their `ctx` are **TMM's**, designed in ahead of time and emitted in the signed per-build hook-point map; a probe (or shield) is always written *against* a `ctx` that already exists. The `ctx` is a curated window onto state TMM already holds — not raw memory (substrate §6.3).
- **Coverage bound:** an in-TMM tracepoint sees only what runs in TMM software; traffic offloaded to ePVA/FPGA on appliances is out of view (design §10) — as it is for iRules and kernel eBPF. **BIG-IP VE** (no offload) sees the whole data path.
- **This is a menu, not a commitment.** Exact hook placement and `ctx` layout are set against TMM source and emitted per build (design §5.3). Field lists here are illustrative of the *kind* of state each hook would expose.
