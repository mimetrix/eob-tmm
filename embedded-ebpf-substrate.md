# The Embedded eBPF Substrate in TMM

### The third programmability surface — verified, dynamic, in the data plane. Live Shield is its first instance.

**Status:** Strategy / use-case exploration
**Audience:** TMOS architecture, F5 SIRT, BIG-IP security & observability engineering, product
**Companion:** `big-ip-live-shield-design.md` (the detailed Live Shield mechanism — the first instance of this substrate) · `explainers/cve-shield-walkthrough.html` (the worked CVE example, end to end) · `substrate/` (**candidate ABI artifacts and their checkers** — the shield ABI header, the hook-map schema + an example map, the budget/offset/gate checks. These are proposed interfaces under mechanical check, **not a running prototype**: nothing in this repo executes a shield.)
**Scope:** What becomes possible once a verified userspace-eBPF VM (uBPF) is embedded in TMM and instrumented with designed-in hook points **and function-boundary probes at entries the build already emitted**

---

## 1. Where this fits: TMM's programmability spectrum

TMM's defining strength is **dynamic programmability** — the ability to change the data plane's behavior at runtime, without a rebuild or reboot. iRules and WASM established that strength. Embedded eBPF is not a new idea bolted on; it is the *continuation* of it, extended to a layer the existing surfaces cannot reach.

| Surface | Layer it programs | Best at | Dynamic? | Safety of dynamic change |
|---|---|---|---|---|
| **iRules** | traffic logic at proxy events | connection / L7 traffic decisions | yes | TCL, **unbounded in practice** — a runaway rule is a documented cause of a stalled TMM and a watchdog restart |
| **WASM** | rich extensions | complex custom logic, transforms, real languages | yes | enforced dynamically — bounds-checked at run time, time bounded by a fuel counter that aborts |
| **Embedded eBPF** | the data plane's **own code & internal state** | verified probes, compensating controls, deep telemetry | yes | **statically verified before load** — memory-safe, and terminating where the check is enabled (§6.1); time bounded at admission by the budget pass, and at runtime by a fuel-metered guard |

iRules made *traffic logic* dynamically configurable. WASM made *rich extensions* dynamically configurable. **Embedded eBPF makes the data plane's own code-level behavior and internal state dynamically configurable** — the parsers, plugin internals, connection state, error paths — which neither of the others can touch.

And it occupies a unique slot in the *dynamic-configurability* story: **eBPF is the only surface that is dynamically loadable *and* statically proven (memory-safe + terminating) before load.** That is what makes it trustworthy for runtime reconfiguration of the **most sensitive paths** — the data-plane hot path and inline security controls — which is exactly where dynamic change is otherwise hardest to allow. Dynamic configurability is most valuable where it is most dangerous; the verifier is what makes it permissible there.

> **The value prop is not "we added eBPF."** It is: *TMM's power is dynamic programmability; eBPF extends that power to the code/instrumentation layer, and is the one surface that makes runtime reconfiguration of even the data-plane fast path provably safe.*

### 1.1 Why TMM's architecture suits an embedded VM

An embedded verified VM is not the right answer for every high-performance data plane. It is the right answer for *this* one, and it is worth being explicit about why — because these are preconditions, not preferences, and they are the reason the same idea would be a poor fit elsewhere.

The first three are the load-bearing ones, and the first two follow from the same fact: **TMM is a proxy, not a packet-forwarding plane.**

- **A proxy's budget makes bytecode nearly free; a forwarder's does not.** A packet-forwarding data plane's unit of work is the packet, with a per-packet budget in the low single-digit nanoseconds at line rate — a verified-bytecode invocation is a *meaningful fraction* of that, which is why bytecode struggles to earn its keep in a forwarder. TMM's unit of work is a flow, a connection, a request: it terminates TCP, negotiates TLS, parses L7 and evaluates policy, spending **microseconds where a forwarder spends nanoseconds**. A hook costing tens of nanoseconds is noise against that, because the invocation cost is amortized over work that was already expensive. **But be careful not to over-collect on that argument, because it describes the cheapest tier rather than the only one.** TMM holds three budgets, not two: per request (microseconds — a hook is genuinely free), per packet *inside the proxy path* (TCP reassembly, TLS records, L7 framing — hundreds of nanoseconds, where a hook costs a few percent and needs measurement plus sign-off), and a pure FastL4 fast path (tens of nanoseconds, where the forwarder's objection applies to us too and should be conceded). The middle tier is not optional: the **pre-L7 CVE classes this substrate exists for fault there**, before any request exists. See `engine-hard-problems.md` §1.1 for what is plausible at each rate and the measurement that would settle it.
- **A proxy has internal state worth looking at, and it is where the bugs live.** A forwarder's state is thin — headers, a flow-table entry. A proxy carries deep structured state: listeners, profiles, connection-flow objects, TLS record and L7 parser state, plugin internals. That is precisely what makes a curated `ctx` valuable rather than trivial, and it is also where a proxy's CVEs concentrate: parsers and protocol state machines, not the forwarding path. Both the value of *observing* and the value of *intervening* are therefore higher here — and they land on the paths where the time budget is loosest.

- **The loop is run-to-completion and core-pinned.** TMM processes per-flow and per-packet through a stack, so a per-invocation hook **fits the existing control flow** rather than fighting it. This is the load-bearing architectural fit: eBPF's calling convention takes **one `ctx`, once** and cannot express "here is a vector of 256 packets," so a data plane whose performance comes from a stage seeing an entire batch at once would be a poor host for it. TMM is not that shape. (Where TMM *does* batch — burst receive on hot paths — the answer is a burst-capable invocation form; see [`engine-hard-problems.md`](engine-hard-problems.md) §5.)
The remaining four are about being a shipped product rather than a component:

- **F5 owns the source and the build.** Hook points can therefore be **designed in** — named, versioned, placed deliberately — and a per-build signed hook map can be emitted from the build's own debug info. Where the data plane is assembled from third-party code, none of that is available: there is no single vendor-owned build to instrument or to sign. Ownership is what makes the whole mechanism possible rather than merely desirable.
- **It is a shipped, closed appliance, so the proof is a requirement.** Where the operator writes and runs their own extension, they own the crash risk and can rationally accept it. F5 cannot ship a customer a mitigation that *might* take the data plane down. That asymmetry is why a static verifier earns its keep here: safety is not a nicety we're adding to a scripting surface, it is the precondition for the artifact being shippable at all.
- **A rebuild costs a maintenance window, not a `make`.** The value of dynamic change is proportional to the cost of the alternative. For software you rebuild and redeploy at will, "just recompile" is a perfectly good answer and dynamic loading buys little. For a certified appliance inside a customer's change-controlled window, the same change is weeks to quarters — which is where a loadable, provable artifact becomes worth real engineering.

- **The problem is vendor-delivered change, not third-party extension.** "How does someone else add functionality to this?" and "how does the vendor change the behaviour of an already-shipped closed data plane, between releases, provably safely?" are different questions. Native extension answers the first well and the second not at all.

Stated as one line: **we need vendor-deliverable change under proof, and a proof is precisely what native extension cannot give us.** That is the trade this substrate exists to change.

## 2. The capability, stated plainly

Embedding a uBPF VM in TMM and exposing a curated set of designed-in **hook points** lets the host run a small, verified eBPF program at each point that either:

- **observes** internal state and emits telemetry (a *tracepoint*), or
- **acts** — returns a verdict the host applies (a *datapath control*).

**The outcome set, canonically — this is the one list; everything else references it.** A program never performs an action; it selects one the host already owns at that hook, and the hook's entry in the signed map declares which of these are available there:

| Outcome | Meaning | Available where |
|---|---|---|
| `PASS` | proceed unchanged — the default, and what a non-matching program always yields | every hook |
| `DROP` | discard this frame/request; the connection survives | hooks the host can drop at |
| `RESET` | tear down the connection | hooks with a reject path |
| `SAFE-RETURN` | skip the hooked function's body, returning the value its safe-return policy declares | function-boundary hooks whose body is provably skippable |
| `STEER` | choose among host-enumerated targets (pool member, mirror, queue) | selection points only |
| `SAMPLE` | mark this flow for capture/telemetry; traffic unaffected | every hook |

`observe` mode is not a seventh outcome — it is the host declining to apply whichever outcome the program selected, while still counting it. That is what makes monitor-before-enforce the same program, unchanged.

Two hook kinds share the engine: the curated catalog of designed-in USDT tracepoints (stable,
versioned `ctx`) covers the *anticipated* surface, and **function-boundary probes** at any named
symbol — `ctx` = the function's typed arguments from the build's signed hook map, re-validated per
build — cover the *unforeseen*.

The properties that make the substrate valuable:

| Property | Why it matters |
|---|---|
| **Dynamic** — load / swap at runtime | behavior ships in hours, decoupled from the TMOS release train; no reboot |
| **Verified** — PREVAIL proves bounded memory + termination before load | programs are proven memory-safe + terminating; their *time* is bounded at admission by the budget pass and at runtime by a fuel-metered guard (register §1), and blast radius by the host-owned outcome set |
| **Cheap** — JIT'd; ~tens of ns/invocation; an empty hook = one branch at a designed-in call site — and literally nothing (a nop pad) at an unarmed function boundary | usable on cold *and* (under a measured budget) hot paths |
| **In-process** — runs in TMM's address space | sees data-plane internals that kernel eBPF (kernel-bypass) and iRules (proxy data-model) cannot |
| **Host-owned outcomes** | a program *chooses among* sanctioned effects; it cannot invent new control flow |
| **Zero-helper by default** — a program is a pure function of `ctx` (read fields, return a value); the host does everything else | **no custom eBPF helpers to define/secure, and no verifier *extension*** — the core substrate is buildable without modifying PREVAIL or standing up a helper ABI (see below). Note that "stock" hides a choice, because PREVAIL has no `--program-type` flag and deduces the type from the ELF section-name prefix: day one rides its existing `tracing` type, whereas a *named* TMM type would be a patch set with a per-release rebase cost |

Observability (the engine) and runtime compensating controls (the shield) are two faces of one embedded-eBPF substrate.

**The zero-helper property, stated once.** Everything the substrate does today — `filter` shields and `observe` tracepoints alike — is a program that reads its context and returns a number. It calls nothing. The host owns all state and effects: it packs facts into `ctx`, reads the return, and updates counters / maintains rings / applies the verdict *around* the call. Two things fall out, and they cut the "hard parts" dramatically:

- **No helper functions.** eBPF helpers are the program's syscalls — the surface you must design, register, audit, and confine. With none, there is nothing to confine: a program that can only read `ctx` and return a value is **maximally sandboxed by construction** (§6.3).
- **No verifier extension.** A bounded predicate over a typed `ctx` is the canonical case PREVAIL already proves. You *configure* the `ctx` layout; you do not *extend* the verifier — so **stock PREVAIL**, no fork in the trust path.

Anything stateful (rates, time, cross-flow counters) is handled by the host computing it into `ctx`. Helpers — letting the program touch host maps directly — are an **optional later tier** for richer stateful programs, not a prerequisite. **Live Shield and the tracepoint/`dptrace` surface need no helpers and no verifier *extension* — stock PREVAIL; the real (bounded) work is the `ctx`/program-type descriptor.** And because a new tracepoint is just "define a `ctx`, place a hook, emit it in the map," the dev team can **grow the instrumentation surface incrementally** — USDT-style — in normal releases, each hook dark-until-lit and each new `ctx` field widening what can be observed *and* shielded, all without touching the VM, the verifier, or a helper ABI.

## 3. Use-case families

- **Security beyond CVE shields** — behavioral exploit detection on internal state; inline protocol-anomaly detection at the parser (pre-event); adaptive rate-limit / circuit-break on internal load; TLS/crypto policy at the record layer.
- **Observability, dynamic & on-demand** — *bpftrace-for-TMM* (deep telemetry for a specific condition/flow/tenant, on then off); per-flow latency breakdown across internal stages; *flight recorder* (snapshot state when an error branch fires — worked in §3.1); new metrics as bytecode, no TMOS rev.
- **Diagnostics & field support** — ship a customer a *signed probe* to characterize a production issue in situ, then remove it (worked in §3.1). No debug build, no core-dump archaeology.
- **Lightweight policy / steering** — steering, mirror-selection, A/B decisions driven by internal signals (decision in eBPF; heavy logic in iRules/WASM).
- **Self-tuning / performance** — read internal load and nudge a knob; live hot-path profiling.
- **Data intelligence (the proxy's unique vantage)** — because TMM terminates TLS, an `observe` program can compute a **verified in-situ transform** over decrypted, in-context, line-rate traffic and emit only the *derived* signal (a feature vector, sketch, API inventory, attestation) through the host-owned sink — the payload never leaves the box. This turns the proxy's discarded traffic into a governed data source that improves the product (detection, tuning, fleet-scale baselines) on data no competitor can source. Detailed opportunity, use-cases, and a reference architecture: [`data-plane-intelligence.md`](data-plane-intelligence.md).

### 3.1 Two diagnostic patterns, worked

The diagnostics leg is the substrate's lowest-risk, highest-leverage near-term use: both patterns below are **observe-mode, read-only, and verified**, so they run on a *live production* data plane without the "a bad shield crashes TMM" exposure of `filter` mode. They turn "ship a debug build / wait for it to recur" into "load signed bytecode for a while," and they reuse the existing security spine (§6) at a lower authorization tier — read-only, but exfiltration still governed (§6.2).

**Signed support probe.** F5 support/SIRT authors a small program targeting the *exact* hook + condition behind an intermittent field issue (a sporadic reset, a latency spike, a plugin misbehaving under one traffic shape), signs it, and ships it. The operator — RBAC-gated, explicit consent — loads it in observe mode; it captures precisely the needed signal, exports to the controlled sink, then is pulled. eBPF earns this specifically because it is **verified** (proven memory-safe + terminating — with the budget pass and a runtime fuel guard bounding cost on a customer's production box; non-negotiable for vendor code attached inline on live traffic), cleanly **removable**, and reaches **in-TMM** state that logs and iRules cannot. Design points not otherwise specified:

- **Context minimization by default** — a support probe does *not* expose TLS secrets / PII / decrypted payload unless separately justified and authorized; redact by default (§6.3).
- **Data residency** — captures land in a **customer-controlled, audited** location; the customer decides what to share with support. Auto-phone-home to F5 is the wrong default for a security appliance.
- **Time-boxed** — auto-retirement (design §7) applies: a probe must not outlive the investigation. Expiry + kill-switch + a tamper-evident log of what was loaded and what it captured.

The governance *is* the feature here: without it, "vendor loads code on my box to read my traffic" is a non-starter.

**Flight recorder.** A small **per-CPU ring** of recent internal state is maintained at the relevant hook(s); on a **trigger**, the ring is frozen and dumped — yielding the run-up *into* a failure rather than the wreckage after it (the core-dump's blind spot). Two flavors: a *per-context ring* (recent state for the active flow, dumped on the error branch) and a *global tripwire* (cross-cutting state — poll-loop jitter, memory-pool pressure — dumped on an emergency-mode / watchdog event). Design points:

- **Steady-state cost** — this is the one observe pattern that is *not* free when nothing is wrong: writing the ring on every event is a standing tax, hence a measured-budget decision (design §11, `big-ip-live-shield-design.md`). Mitigate with a small per-CPU ring (the single-threaded poll loop makes the freeze lock-free), cheap recorded fields, or **conditional arming** (record only once a leading indicator appears).
- **Trigger taxonomy** — entry to a known-vulnerable function, a parser reaching an error state, an assertion, a watchdog event. The trigger is itself a hook, so a flight recorder is really *two* coordinated hooks (record + trip).
- **Dump path off the hot path** — freeze the ring cheaply; hand serialization/export to the lifecycle engine.

**This pattern is proposed and is not demonstrated in this repo** — there is no running artifact here to point at, so read what follows as the intended shape rather than an observed result. An observe program in the embedded VM keeps a shm-backed ring of recent frames and arms a dump on the crash precondition; the run-up is captured at the hook *before* the data plane crashes and, because the ring is shm-backed, is expected to survive it for post-mortem drain. The proposed **`dptrace`** front-end ([`tmm-usdt-tracepoints.md`](tmm-usdt-tracepoints.md) §1 — a proposed utility, name a placeholder) is what would make it ergonomic: a bpftrace-style one-liner — `tmm:l7:frame /args.opcode >= 4/ { snapshot(); }` — compiling to the observe program, passing the verify gate, and arming the recorder; swapping the action verb to `drop()` would author a `filter` shield from the same grammar.

**The combined play.** Pair `enforce` + flight recorder on the *same* condition: when a shield drops a malformed frame, the recorder simultaneously snapshots the context. Every block becomes an intelligence source — SIRT gets the exact attempt that was stopped — and it goes a long way toward answering "how do you know the shield catches real attacks and isn't breaking legitimate traffic?" — though only half of it: a capture of *blocked* attempts is evidence about attacks, and no evidence at all about false positives, which needs monitor-mode data over a legitimate-traffic corpus ([`tmm-usdt-tracepoints.md`](tmm-usdt-tracepoints.md) §10.5). **The pairing is likewise proposed, not demonstrated here:** it is a design claim about two hooks armed on one condition, and no artifact in this repo exercises it.

Both patterns reuse the same machinery — signing + RBAC, context minimization, the **one-way audited sink** (the program cannot read back or redirect its own output, so even a malicious probe cannot phone home), auto-retirement + kill-switch, tamper-evident audit log (§6.3). Neither needs new substrate.

## 4. Candidate hook points — observability & active datapath

This is the differentiated engineering asset: *where* in TMM a hook earns its keep. Below are candidate points by data-path stage, in both modes. A concrete, named candidate set — with per-hook `ctx` fields and their observability/debug/RCA use — is proposed in [`tmm-usdt-tracepoints.md`](tmm-usdt-tracepoints.md). (These are architectural stages; exact named hook points are placed against TMM source and emitted in the per-build hook-point map — design §5.3. `path_class` per design §11 (`big-ip-live-shield-design.md`).)

| Data-path stage | **Observe** (tracepoint) | **Active** (datapath control) | Why eBPF (what iRules / kernel eBPF miss) |
|---|---|---|---|
| **L3/L4 ingress + connection table** | flow/PPS rates, fragment stats, TCP-state transitions, SYN/flood signals, conn-table occupancy, malformed-L4 counts | drop/rate-limit malformed fragments, TCP-state-exhaustion mitigation, early drop of a crafted L4 pattern (L4-stack CVE) | runs **before any iRule event**; kernel-bypass hides it from kernel eBPF |
| **Client-side TLS / record layer** | handshake outcomes, cipher/version mix, record-layer anomalies, decrypt errors, JA3/JA4-style fingerprints, renegotiation counts | block malformed ClientHello/record (TLS record-parse CVE), enforce cipher/version policy at the record layer, mitigate renegotiation abuse | record-layer parse **precedes** `CLIENTSSL_*` events — iRules can't reach it |
| **L7 protocol parse** (HTTP/1·2·3/QUIC, DNS, SIP, MQTT, DIAMETER) | per-protocol frame/message stats, parser state, malformed-encoding counts, HTTP/2 stream/header counts, conditions preceding known crash classes | **drop or reset the malformed frame that terminates TMM** (the flagship CVE class), enforce protocol limits (max streams/headers) inline | malformed encodings aren't exposed as clean iRule fields; thin-event protocols have no event |
| **In-TMM enforcement filters** (AFM, DoS, the TMM side of APM) | rule- and vector-evaluation outcomes, per-policy hit rates, filter enter/exit latency | shield a filter's own decision path; attribute latency per filter | in TMM's address space, so a hook reaches them directly — but no iRule event or data-model field exposes filter internals |
| **The out-of-process `bd` boundary** (`bd`/WAF; APM is split) | IPC direction and message type, queue backlog, round-trip latency, the verdict that came back | guard the handoff *into* `bd`; drive a host-owned breaker from an observe signal on a degrading plugin | the handoff is invisible to iRules. Note the asymmetry, because it is easy to lose: **AFM and DoS enforcement run inside TMM**, and only `bd` is a separate process — so `bd`'s policy, opcode and queue state is **not in TMM's address space** and a TMM-side hook cannot expose it. Reaching it means a second engine instance in `bd`, with its own program type, address space, and safe-point problem |
| **LB / persistence / pool selection** | per-member selection distribution, persistence behavior, member health/latency | steer away from a member under attack, dynamic persistence override, mitigate an LB-algorithm edge case | reads internal selection/health state no iRule command exposes |
| **Server side + response path** | server-side TLS outcomes, response codes, response-parse anomalies, OneConnect reuse stats | server-side record-parse shield (same class as client TLS), response blocking | server-side record parse precedes `HTTP_RESPONSE`; same pre-event gap |
| **Cross-cutting runtime** (poll loop, memory, scheduler, IPC, iRule/TCL VM) | poll-loop jitter, per-core CPU, memory-pool pressure, scheduler stalls, plugin-IPC latency, TCL-VM execution stats | admission control / backpressure under memory or CPU pressure, emergency-mode triggers, shield a CVE in the TCL VM itself | these are TMM-internal health signals with no iRule/data-model surface at all |

Three cross-cutting notes:
- **Observe vs. active is the same hook in two modes** (design §6.1) — many of the rows above start as a read-only tracepoint (lowest risk) and graduate to an active control once the signal is trusted.
- **Most of these are condition-scoped** (the malformed branch, the error path, the crash precondition) → cold/cheap. The genuinely hot-path ones (per-packet L3/L4 telemetry, per-flow latency) are legitimate under a measured budget (design §11), not excluded.
- **Hardware offload bounds the L3/L4 rows.** On appliances, flows offloaded to ePVA/FPGA bypass TMM software, so an in-TMM hook cannot see them — true for iRules and kernel eBPF just the same (design §10). These rows apply to the *software* data path; **BIG-IP VE** (no offload) sees all of it. A hardware boundary, not a per-surface weakness.

## 5. The two force-multipliers

1. **Decoupled from the TMOS release train.** Mitigations, telemetry, and diagnostics ride a *fast lane* — signed bytecode in hours, not a quarterly build. During active CVE exploitation or a customer-down incident, that cadence difference is decisive.
2. **Verified ⇒ safe to be aggressive, and to broaden the contributor set.** Because each program is proven unable to scribble memory or loop forever — and budget-gated, so the surface is engineered not to take the box down (verified ≠ correct: the canary/kill-switch is the backstop) — it becomes palatable to let more sources contribute (SIRT, support, eventually vetted partner logic) onto a device inline on production traffic.

## 6. Securing the substrate

The property that makes this powerful — execute bytecode in the data plane — also makes it a crown-jewel target: whoever can load a program runs code where decrypted traffic, keys, and every flow are visible. Securing it starts from one principle and proceeds in layers.

### 6.1 Verified ≠ secure

PREVAIL proves a program is **memory-safe**, and **terminating only when the termination check is enabled** — `--termination` is off by PREVAIL's default, and where it is on the guarantee is a ceiling of 100,000 loop iterations, roughly 300 µs, which is a bound rather than a budget (the admission budget pass and a runtime fuel guard carry the time load). It will not scribble memory *outside its context*; note that PREVAIL's context descriptor expresses no read-only region, so writes **to the context itself** are not bounded — which is why the host hands the program a per-core scratch copy and discards it on fall-through. It proves **nothing** about whether the program is malicious *within the rules*: it can still read sensitive data it is permitted to touch, weaken a control, monopolize a hot path, or have been loaded by the wrong party. **The verifier is a safety gate, not a security gate.** Treating "it's verified" as "it's safe to run arbitrary bytecode" is the fatal mistake. Security is the governance *around* the VM.

### 6.2 Threat model

- **The load path is a crown-jewel target** — code execution in the data plane. (Note the irony: the management plane that loads programs is the same plane with the historical RCEs.)
- **Provenance** — forged or tampered programs.
- **Exfiltration** — an *observe* program reading TLS secrets / PII / decrypted payload and leaking it. Read-only ≠ harmless.
- **Subversion** — a "shield" that disables WAF, drops legitimate traffic (DoS), or weakens a policy.
- **Resource abuse** — a verified-but-expensive program on a hot hook is a performance DoS.
- **Fleet spread** — a bad program propagating via config-sync across a device group.
- **Persistence** — a planted program surviving reboot.

### 6.3 Layered controls

1. **Provenance & authorization — default deny.** Vendor **code-signing is mandatory in production**: the box checks the signature over the binding (PREVAIL ran earlier, in F5's admission pipeline, before signing); only F5-signed programs load. Signing is also the backstop if the load path is breached — no signing key, no arbitrary code. **Authorization tiers:** SIRT-signed by default; operator/partner-authored programs are a separate, off-by-default, RBAC-gated capability. **Active (filter) programs require stricter authorization than read-only observe.**
2. **Capability confinement.** For the **core substrate, this is free**: with zero helpers (see §2), a program is a pure function of `ctx` — it can only read the exposed fields and return a value, so there are no "syscalls" to confine, no I/O, no memory reach, no sockets, *by construction*. Confinement here reduces to **context minimization**: the **hook-point map declares, per hook, the allowed attach mode and exposed `ctx` fields**, and sensitive fields (TLS secrets, PII, decrypted payload) are gated and redacted by default, exposed only on explicit, separately-authorized justification — because what a program can see *is* what its `ctx` exposes. **If** an optional helper tier is later added (letting a program touch host maps directly), *those* helpers become the program's "syscalls" and must be kept **minimal and audited** (no general memory read, no arbitrary I/O, no config write, no sockets), with the map declaring **permitted helpers** per hook. That surface is opt-in; the base surface has none.
3. **Exfiltration control.** Telemetry egress is **one-way through a controlled, logged sink** the program cannot read back or redirect; no program-initiated I/O. A malicious observe program still cannot phone home — its output goes only where the host sends it, audited.
4. **Harden the load path.** Treat it as the highest-value target: strong authN/authZ, mTLS, RBAC, network-restricted, rate-limited, fully audited; consider an out-of-band / HSM-gated authorization decision. Signing limits the blast radius if it is ever breached.
5. **Lifecycle, audit, revocation.** **Attestation/inventory** — enumerate every loaded program with provenance (signer, hook, mode, when, by whom) so an unexpected one is detectable. **Tamper-evident audit log** of every load / mode-change / unload. **Instant kill-switch + signer/program revocation** (CRL-style), fleet-wide. **No silent persistence** — programs are re-applied from the signed catalog, not from local state an attacker could plant. **Auto-retirement** (design §7) prevents zombies.
6. **Resource governance.** Per-hook **perf budget + watchdog** (design §9/§11): auto-disable + alert if TMM degrades after a load. Cap the count/total overhead of loaded programs. Verified ≠ cheap.
7. **Fleet & TCB.** **Config-sync is in the trust path** (design §13): a program propagating across a device group carries its signature/authorization with it. The **loader + verifier + signature-check are part of the TCB** — minimal, hardened, higher-integrity than the programs they gate.

### 6.4 Coverage vs. the design doc

Already specified in `big-ip-live-shield-design.md`: signing and SIRT-author/red-team (§8), the mandatory verifier and watchdog (§9), monitor-first and auto-retirement (§7), mode-promotion governance and config-sync-in-trust-path (§13). This section adds the substrate-level pieces those don't yet name: **verified≠secure**, **capability confinement + context minimization** (free in the zero-helper core; §2), the **observe-mode exfiltration** control, **authorization tiers + load-path hardening**, and **attestation/inventory + revocation/kill-switch**. Together they are the difference between "we sign shields" and "we can safely operate a programmable data plane."

## 7. The honest boundary (where this is *not* the tool)

eBPF's compute model is deliberately constrained — bounded loops, small stack, no arbitrary calls. This is the home of **probe / decide / transform-lite**, not heavy computation. Rich, unbounded logic — a full protocol transform, a complex customer-authored filter — belongs in the **WASM** lane (design §2.3). The spectrum (§1) is the point: **WASM for expressive extensions; embedded eBPF for verified, cheap instrumentation & control.**

## 8. Suggested sequencing

Build the substrate once; land use cases in order (each reuses the same VM + verifier + hook-point map):

1. **Live Shield on `bd`** — proves the embedded-VM + verify + lifecycle spine against a real bug, off the hot path. *(Companion doc, Phase 1.)*
2. **Control-plane daemon shields** — the bulk of disclosed TMOS CVEs.
3. **Observe-mode tracepoints for diagnostics & support** — high value, low risk (read-only), same machinery.
4. **TMM-internal shields** on exceptional paths — the data-plane CVE classes nothing else reaches.
5. **Hot-path hooks under a measured budget** — adaptive controls and full-fidelity telemetry where the value justifies the cost.

## 8.5 A further direction: AI-assisted shield authoring

CVE disclosure now moves at machine speed; the verified-shield model is unusually well suited to machine-speed *authoring* in response. Because a shield is a bounded, statically-verified program that only selects among host-owned outcomes, its worst case is **provable** — so a generative model can draft one and the **verifier becomes an automatic, fail-closed acceptance gate** on that draft: safety is proven, not trusted, which is what makes machine authorship of inline data-plane code tractable at all. A pipeline reads a CVE (advisory / PoC / patch diff), emits a bounded **C** predicate (clang → eBPF) grounded on the signed hook-point map — a `dptrace`-style front-end could emit the same one-liner form as an optional convenience — compiles it, and iterates it against **three mechanical oracles** — verifier pass, exploit-replay blocks the PoC, low false-positive against a legitimate-traffic corpus — before a human signs. A **shieldability classifier** declares "not shieldable → engineering hotfix" when no safe interception point exists. Human authorization stays non-autonomous; deployment is observe-first and auto-retiring (design §7).

**Be clear about the support for that argument: none of the three oracles is implemented in this repo, and the pipeline is proposed, not demonstrated.** What can honestly be said is narrower and weaker: two of the three gates are *ordinary* engineering rather than research — the verifier gate is an existing tool (PREVAIL) invoked in a build step, and exploit replay is a test harness against a PoC — while the third, a low-false-positive judgment over a legitimate-traffic corpus, is the one that needs a corpus we do not have. So the case above is a feasibility argument, and it should be read as one. See [`explainers/cve-shield-walkthrough.html`](explainers/cve-shield-walkthrough.html) (the worked CVE example, end to end) and [`explainers/cve-mitigation.html`](explainers/cve-mitigation.html) (the plain-language shield explainer).

## 9. One-line thesis

**TMM's power is dynamic programmability. Embedded eBPF is the third surface — alongside iRules and WASM — extending that power to the data plane's own code and internal state, and the only one whose runtime changes carry a static proof (memory-safety + termination) — with time-safety bounded at admission by the budget pass and at runtime by a fuel-metered guard. Live Shield is the first instance; the substrate, and the hook-point map, are the asset.**
