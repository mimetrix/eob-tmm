# The Embedded eBPF Substrate in TMM

> **Status — pre-build design.** This page was written before anything ran, and still
> describes a substrate that does not execute. It now does: verified programs load into a
> running TMM, arm at function entries, fire under traffic, and emit records. The
> programmability spectrum, use-case families and hook-point catalogue below stand; treat
> any statement about what *exists* as superseded by
> [`tmm-bpf-engine-architect-brief.md`](tmm-bpf-engine-architect-brief.md). Reading order:
> [`DOC-STATUS.md`](DOC-STATUS.md).

### The third programmability surface — verified, dynamic, in the data plane. The CVE shield is its first instance.

**Status:** Strategy / use-case exploration
**Audience:** TMOS (Traffic Management Operating System) architecture, F5 SIRT (Security Incident Response Team), BIG-IP security & observability engineering, product
**Companion:** `big-ip-live-surface-design.md` (the detailed Live Surface mechanism — whose CVE shield is the first instance of this substrate) · `explainers/cve-shield-walkthrough.html` (the worked CVE example, end to end) · `substrate/` (**candidate ABI (application binary interface) artifacts and their checkers** — the shield ABI header, the hook-map schema + an example map, the budget/offset/gate checks. These are proposed interfaces under mechanical check, **not a running prototype**: nothing in this repo executes a shield.)
**Scope:** What becomes possible once a verified userspace eBPF (extended Berkeley Packet Filter) virtual machine (uBPF) is embedded in TMM and instrumented with designed-in hook points **and function-boundary probes at entries the build already emitted**

---

## 1. Where this fits: TMM's programmability spectrum

TMM — the Traffic Management Microkernel, BIG-IP's data-plane process — has **dynamic programmability** as a defining strength: behavior changes at runtime, without a rebuild or reboot. Config, profiles, WAF (web application firewall) policy, iRules and an arriving WASM (WebAssembly) surface all already do this, each acting on the curated traffic model the proxy chose to expose, at the events it chose to fire. Embedded eBPF continues that line, extended to a layer the existing surfaces cannot reach: the code's own internals, which today require a build.

| Surface | Layer it programs | Best at | Dynamic? | Safety of dynamic change |
|---|---|---|---|---|
| **iRules** | traffic logic at proxy events | connection / L7 traffic decisions | yes | TCL, **unbounded in practice** — a runaway rule is a documented cause of a stalled TMM and a watchdog restart |
| **WASM** | rich extensions | complex custom logic, transforms, real languages | yes | enforced dynamically — bounds-checked at run time, time bounded by a fuel counter that aborts |
| **Embedded eBPF** | the data plane's **own code & internal state** | verified probes, compensating controls, deep telemetry | yes | **statically verified before load** — memory-safe, and terminating where the check is enabled (§6.1); time bounded at admission by the budget pass, and at runtime by a fuel-metered guard |

iRules made *traffic logic* dynamically configurable. WASM made *rich extensions* dynamically configurable. **Embedded eBPF makes the data plane's own code-level behavior and internal state dynamically configurable** — the parsers, plugin internals, connection state, error paths — which neither of the others can touch.

And it occupies a unique slot in the *dynamic-configurability* story: **eBPF is the only surface that is dynamically loadable *and* statically proven — memory-safe, and terminating where the termination check is enabled (§6.1) — before load.** That is the basis for runtime reconfiguration of the **most sensitive paths**: the data-plane hot path and inline security controls, where dynamic change is otherwise hardest to allow.

> **The value prop is not "we added eBPF."** It is: *TMM's power is dynamic programmability; eBPF extends that power to the code/instrumentation layer, and is the one surface that makes runtime reconfiguration of even the data-plane fast path provably safe.*

### 1.1 Why TMM's architecture suits an embedded VM

An embedded verified VM (virtual machine) fits *this* data plane for reasons that are preconditions rather than preferences, and that would not hold elsewhere.

> **First, the term, because uBPF's naming splits it and this document has used one word for both.**
> **The engine** is one place in memory: ~150 KB of library code — the interpreter loop, the JIT
> translator, helper dispatch — linked into TMM once and shared by everything. That is what "an embedded
> VM" means throughout. **`struct ubpf_vm` is not the engine.** It is a per-*program* container holding
> one program's bytecode (`insts`, `num_insts`), its JIT'd buffer (`jitted`, `jitted_size`), its helper
> table, and its own policy flags — verified in `ubpf/vm/ubpf_int.h`. uBPF calls it a VM; it behaves as a
> program handle, and there is one per armed program (`engine-hard-problems.md` §3.1). **And on the JIT
> path the engine does not run bytecode at all:** it translates once at load and returns a native
> function pointer, which the trampoline then calls directly. Running bytecode is the *interpreter's*
> job. So "a VM per hook" implies no per-invocation dispatch cost, and none is paid.

The first two follow from the same fact: **TMM is a proxy, not a packet-forwarding plane.**

- **A proxy's budget makes bytecode nearly free; a forwarder's does not.** A packet-forwarding data plane's unit of work is the packet, with a per-packet budget of a few nanoseconds at line rate — a verified-bytecode invocation is a *meaningful fraction* of that, which is why bytecode struggles in a forwarder. TMM's unit of work is a flow, a connection, a request: it terminates TCP, negotiates TLS, parses L7 (application-layer protocol) and evaluates policy, spending **microseconds where a forwarder spends nanoseconds**. A hook costing tens of nanoseconds is noise against that, because the invocation cost is amortized over work that was already expensive. **That argument describes the cheapest tier rather than the only one.** TMM holds three budgets, not two: per request (microseconds), per packet *inside the proxy path* (TCP reassembly, TLS records, L7 framing — hundreds of nanoseconds, where a hook is a fraction of the budget and needs measurement plus sign-off), and a pure FastL4 fast path (tens of nanoseconds, where the forwarder's objection applies to us too and is conceded). The middle tier is where the **pre-L7 CVE (Common Vulnerabilities and Exposures) classes this substrate exists for fault**, before any request exists. See `engine-hard-problems.md` §1.1 for what is affordable at each rate and the measurement that would settle it.
- **A proxy has deep internal state, and it is where the bugs concentrate.** A forwarder's state is thin — headers, a flow-table entry. A proxy carries listeners, profiles, connection-flow objects, TLS record and L7 parser state, plugin internals. That is what a curated `ctx` exposes, and it is where a proxy's CVEs sit: parsers and protocol state machines rather than the forwarding path — paths on which the time budget is loosest.

- **The loop is run-to-completion and core-pinned.** TMM processes per-flow and per-packet through a stack, so a per-invocation hook **fits the existing control flow** rather than fighting it. eBPF's calling convention takes **one `ctx`, once** and cannot express "here is a vector of 256 packets," so a data plane whose performance comes from a stage seeing an entire batch at once would be a poor host for it. TMM is not that shape. (Where TMM *does* batch — burst receive on hot paths — the answer is a burst-capable invocation form; see [`engine-hard-problems.md`](engine-hard-problems.md) §5.)

The remaining four are about being a shipped product rather than a component:

- **F5 owns the source and the build.** Hook points can therefore be **designed in** — named, versioned, placed deliberately — and a per-build signed hook map can be emitted from the build's own debug info. Where the data plane is assembled from third-party code, none of that is available: there is no single vendor-owned build to instrument or to sign.
- **It is a shipped, closed appliance, so the proof is a requirement.** Where the operator writes and runs their own extension, they own the crash risk. F5 cannot ship a mitigation that *might* fault: `sod` restarts TMM in seconds and HA (high availability) fails over, so the harm is a repeatable crash-loop on a traffic pattern the attacker controls rather than a sustained outage — and a crash-loop is still not shippable. That asymmetry is what the static verifier answers: safety is the precondition for the artifact being shippable at all.
- **The two delivery forms have different artifact properties.** A build has to be installed: that means a restart or a failover, regression risk across everything else the build changes, and a rollback plan. A signed shield has none of those properties — it applies with no restart and no failover, and `REVOKE` disarms it by restoring the original bytes at a safe point. Whether and when any given operator installs a build is an **assumption**, not a fact: `big-ip-live-surface-design.md` §1.1 records it as assumption 9 and marks it as ending the case if false.

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

Two hook kinds share the engine: the curated catalog of designed-in USDT (user statically-defined
tracing) tracepoints (stable,
versioned `ctx`) covers the *anticipated* surface, and **function-boundary probes** at any named
symbol — `ctx` = the function's typed arguments from the build's signed hook map, re-validated per
build — cover the *unforeseen*.

The properties that make the substrate valuable:

| Property | Why it matters |
|---|---|
| **Dynamic** — load / swap at runtime | behavior is delivered as a signed artifact, decoupled from the TMOS release train; no restart, no failover, no reboot |
| **Verified** — the PREVAIL verifier proves bounded memory before load, and termination where that check is enabled (§6.1) | their *time* is bounded at admission by the budget pass and at runtime by a fuel-metered guard (register §1 — which needs a uBPF JIT patch), and blast radius by the host-owned outcome set |
| **Cheap** — JIT'd (just-in-time compiled to native code); an unarmed function boundary costs a nop pad and nothing else | usable on cold *and* (under a measured budget) hot paths. Both the idle cost of the pads and the cost of an armed hook at rate are **unmeasured** (`engine-hard-problems.md` §1.1) |
| **In-process** — runs in TMM's address space | sees data-plane internals that kernel eBPF (kernel-bypass) and iRules (proxy data-model) cannot |
| **Host-owned outcomes** | a program *chooses among* sanctioned effects; it cannot invent new control flow |
| **Zero-helper by default** — a program is a pure function of `ctx` (read fields, return a value); the host does everything else | **no custom eBPF helpers to define/secure, and no verifier *extension*** — the core substrate is buildable without modifying PREVAIL or standing up a helper ABI (see below). Note that "stock" hides a choice, because PREVAIL has no `--program-type` flag and deduces the type from the ELF section-name prefix: day one rides its existing `tracing` type, whereas a *named* TMM type would be a patch set with a per-release rebase cost |

Observability (the engine) and runtime compensating controls (the shield) are two faces of one embedded-eBPF substrate.

**The zero-helper property, stated once.** Everything the substrate does today — `filter` shields and `observe` tracepoints alike — is a program that reads its context and returns a number. It calls nothing. The host owns all state and effects: it packs facts into `ctx`, reads the return, and updates counters / maintains rings / applies the verdict *around* the call. Two things fall out, and they cut the "hard parts" dramatically:

- **No helper functions.** eBPF helpers are the program's syscalls — the surface you must design, register, audit, and confine. With none, there is nothing to confine: a program that can only read `ctx` and return a value is **maximally sandboxed by construction** (§6.3).
- **No verifier extension.** A bounded predicate over a typed `ctx` is the canonical case PREVAIL already proves. You *configure* the `ctx` layout; you do not *extend* the verifier — so **stock PREVAIL**, no fork in the trust path.

Anything stateful (rates, time, cross-flow counters) is handled by the host computing it into `ctx`. Helpers — letting the program touch host maps directly — are an **optional later tier** for richer stateful programs, not a prerequisite. **CVE shields and the tracepoint/`tmmtrace` surface need no helpers and no verifier *extension* — stock PREVAIL; the real (bounded) work is the `ctx`/program-type descriptor.** And because a new tracepoint is just "define a `ctx`, place a hook, emit it in the map," the dev team can **grow the instrumentation surface incrementally** — USDT-style — in normal releases, each hook dark-until-lit and each new `ctx` field widening what can be observed *and* shielded, all without touching the VM, the verifier, or a helper ABI.

## 3. Use-case families

- **Security beyond CVE shields** — behavioral exploit detection on internal state; inline protocol-anomaly detection at the parser (pre-event); adaptive rate-limit / circuit-break on internal load; TLS/crypto policy at the record layer.
- **Observability, dynamic & on-demand** — *bpftrace-for-TMM* (deep telemetry for a specific condition/flow/tenant, on then off); per-flow latency breakdown across internal stages; *flight recorder* (snapshot state when an error branch fires — worked in §3.1); new metrics as bytecode, no TMOS rev.
- **Diagnostics & field support** — ship a customer a *signed probe* to characterize a production issue in situ, then remove it (worked in §3.1). No debug build, no core-dump archaeology.
- **Lightweight policy / steering** — steering, mirror-selection, A/B decisions driven by internal signals (decision in eBPF; heavy logic in iRules/WASM).
- **Self-tuning / performance** — read internal load and nudge a knob; live hot-path profiling.
- **Data intelligence (the proxy's unique vantage)** — because TMM terminates TLS, an `observe` program can compute a **verified in-situ transform** over decrypted, in-context, line-rate traffic and emit only the *derived* signal (a feature vector, sketch, API inventory, attestation) through the host-owned sink — the payload never leaves the box. This turns the proxy's discarded traffic into a governed data source for detection, tuning and fleet-scale baselines. Detailed opportunity, use-cases, and a reference architecture: [`data-plane-intelligence.md`](data-plane-intelligence.md).

### 3.1 Two diagnostic patterns, worked

Both patterns below are **observe-mode, read-only, and verified**, so they carry no "a bad shield crashes TMM" exposure of `filter` mode. They turn "ship a debug build / wait for it to recur" into "load signed bytecode for a while," and they reuse the existing security spine (§6) at a lower authorization tier — read-only, but exfiltration still governed (§6.2).

**Signed support probe.** F5 support/SIRT authors a small program targeting the *exact* hook + condition behind an intermittent field issue (a sporadic reset, a latency spike, a plugin misbehaving under one traffic shape), signs it, and ships it. The operator — RBAC-gated, explicit consent — loads it in observe mode; it captures precisely the needed signal, exports to the controlled sink, then is pulled. The properties that make this form of probe available are that it is **verified** (memory-safe, terminating where the check is enabled, with the budget pass and a runtime fuel guard bounding cost), cleanly **removable**, and able to reach **in-TMM** state that logs and iRules cannot. Design points not otherwise specified:

- **Context minimization by default** — a support probe does *not* expose TLS secrets, PII (personally identifiable information) or decrypted payload unless separately justified and authorized; redact by default (§6.3).
- **Data residency** — captures land in a **customer-controlled, audited** location, and are not transmitted to F5 automatically; the customer decides what to share with support.
- **Time-boxed** — auto-retirement (design §7) applies: a probe must not outlive the investigation. Expiry + kill-switch + a tamper-evident log of what was loaded and what it captured.

**Flight recorder.** A small **per-CPU ring** of recent internal state is maintained at the relevant hook(s); on a **trigger**, the ring is frozen and dumped — yielding the run-up *into* a failure rather than the wreckage after it (the core-dump's blind spot). Two flavors: a *per-context ring* (recent state for the active flow, dumped on the error branch) and a *global tripwire* (cross-cutting state — poll-loop jitter, memory-pool pressure — dumped on an emergency-mode / watchdog event). Design points:

- **Steady-state cost** — this is the one observe pattern that is *not* free when nothing is wrong: writing the ring on every event is a standing tax, hence a measured-budget decision (design §11, `big-ip-live-surface-design.md`). Mitigate with a small per-CPU ring (the single-threaded poll loop makes the freeze lock-free), cheap recorded fields, or **conditional arming** (record only once a leading indicator appears).
- **Trigger taxonomy** — entry to a known-vulnerable function, a parser reaching an error state, an assertion, a watchdog event. The trigger is itself a hook, so a flight recorder is really *two* coordinated hooks (record + trip).
- **Dump path off the hot path** — freeze the ring cheaply; hand serialization/export to the lifecycle engine.

**This pattern is proposed and is not demonstrated in this repo** — there is no running artifact here to point at, so read what follows as the intended shape rather than an observed result. An observe program in the embedded VM keeps a shm-backed ring of recent frames and arms a dump on the crash precondition; the run-up is captured at the hook *before* the data plane crashes and, because the ring is shm-backed, is expected to survive it for post-mortem drain. The proposed **`tmmtrace`** front-end ([`tmm-usdt-tracepoints.md`](tmm-usdt-tracepoints.md) §1 — a proposed utility, name a placeholder) is what would make it ergonomic: a bpftrace-style one-liner — `tmm:l7:frame /args.opcode >= 4/ { snapshot(); }` — compiling to the observe program, passing the verify gate, and arming the recorder; swapping the action verb to `drop()` would author a `filter` shield from the same grammar.

**The combined play.** Pair `enforce` + flight recorder on the *same* condition: when a shield drops a malformed frame, the recorder simultaneously snapshots the context. Every block becomes an intelligence source — SIRT gets the exact attempt that was stopped. That answers half of "how do you know the shield catches real attacks and isn't breaking legitimate traffic?": a capture of *blocked* attempts is evidence about attacks, and no evidence at all about false positives, which needs monitor-mode data over a legitimate-traffic corpus ([`tmm-usdt-tracepoints.md`](tmm-usdt-tracepoints.md) §10.5). **The pairing is likewise proposed, not demonstrated here:** it is a design claim about two hooks armed on one condition, and no artifact in this repo exercises it.

Both patterns reuse the same machinery — signing + RBAC, context minimization, the **one-way audited sink** (the program cannot read back or redirect its own output, so even a malicious probe cannot phone home), auto-retirement + kill-switch, tamper-evident audit log (§6.3). Neither needs new substrate.

## 4. Candidate hook points — observability & active datapath

Below are candidate points by data-path stage, in both modes. How many real advisories clear the four shieldability conditions in `big-ip-live-surface-design.md` §10.1 — a surviving out-of-line boundary before the fault, a condition derivable from that boundary's arguments, a safe outcome, and a budget — is an **assumption**, recorded there as assumption 8 and marked as ending the case if false. Nobody has checked published advisories one by one; the fraction is unknown rather than merely unproven. A concrete, named candidate set — with per-hook `ctx` fields and their observability/debug/RCA use — is proposed in [`tmm-usdt-tracepoints.md`](tmm-usdt-tracepoints.md). (These are architectural stages; exact named hook points are placed against TMM source and emitted in the per-build hook-point map — design §5.3. `path_class` per design §11 (`big-ip-live-surface-design.md`).)

| Data-path stage | **Observe** (tracepoint) | **Active** (datapath control) | Why eBPF (what iRules / kernel eBPF miss) |
|---|---|---|---|
| **L3/L4 ingress + connection table** | flow and pps (packets-per-second) rates, fragment stats, TCP-state transitions, SYN/flood signals, conn-table occupancy, malformed-L4 counts | drop/rate-limit malformed fragments, TCP-state-exhaustion mitigation, early drop of a crafted L4 pattern (L4-stack CVE) | runs **before any iRule event**; kernel-bypass hides it from kernel eBPF |
| **Client-side TLS / record layer** | handshake outcomes, cipher/version mix, record-layer anomalies, decrypt errors, JA3/JA4-style fingerprints, renegotiation counts | block malformed ClientHello/record (TLS record-parse CVE), enforce cipher/version policy at the record layer, mitigate renegotiation abuse | record-layer parse **precedes** `CLIENTSSL_*` events — iRules can't reach it |
| **L7 protocol parse** (HTTP/1·2·3/QUIC, DNS, SIP, MQTT, DIAMETER) | per-protocol frame/message stats, parser state, malformed-encoding counts, HTTP/2 stream/header counts, conditions preceding known crash classes | **drop or reset the malformed frame that terminates TMM** (the flagship CVE class), enforce protocol limits (max streams/headers) inline | malformed encodings aren't exposed as clean iRule fields; thin-event protocols have no event |
| **In-TMM enforcement filters** (AFM — Advanced Firewall Manager, DoS — denial-of-service vectors, the TMM side of APM — Access Policy Manager) | rule- and vector-evaluation outcomes, per-policy hit rates, filter enter/exit latency | shield a filter's own decision path; attribute latency per filter | in TMM's address space, so a hook reaches them directly — but no iRule event or data-model field exposes filter internals |
| **The out-of-process `bd` boundary** (`bd`/WAF; APM is split) | IPC direction and message type, queue backlog, round-trip latency, the verdict that came back | guard the handoff *into* `bd`; drive a host-owned breaker from an observe signal on a degrading plugin | the handoff is invisible to iRules. Note the asymmetry, because it is easy to lose: **AFM and DoS enforcement run inside TMM**, and only `bd` is a separate process — so `bd`'s policy, opcode and queue state is **not in TMM's address space** and a TMM-side hook cannot expose it. Reaching it means a second engine instance in `bd`, with its own program type, address space, and safe-point problem |
| **LB / persistence / pool selection** | per-member selection distribution, persistence behavior, member health/latency | steer away from a member under attack, dynamic persistence override, mitigate an LB-algorithm edge case | reads internal selection/health state no iRule command exposes |
| **Server side + response path** | server-side TLS outcomes, response codes, response-parse anomalies, OneConnect reuse stats | server-side record-parse shield (same class as client TLS), response blocking | server-side record parse precedes `HTTP_RESPONSE`; same pre-event gap |
| **Cross-cutting runtime** (poll loop, memory, scheduler, IPC, iRule/TCL VM) | poll-loop jitter, per-core CPU, memory-pool pressure, scheduler stalls, plugin-IPC latency, TCL-VM execution stats | admission control / backpressure under memory or CPU pressure, emergency-mode triggers, shield a CVE in the TCL VM itself | these are TMM-internal health signals with no iRule/data-model surface at all |

Three cross-cutting notes:
- **Observe vs. active is the same hook in two modes** (design §6.1) — many of the rows above start as a read-only tracepoint (lowest risk) and graduate to an active control once the signal is trusted.
- **Most of these are condition-scoped** (the malformed branch, the error path, the crash precondition) → cold/cheap. The hot-path ones (per-packet L3/L4 telemetry, per-flow latency) are available under a measured budget (design §11) rather than excluded.
- **Hardware offload splits the L3/L4 rows three ways** (design §10), and the three have different answers. A flow accelerated end-to-end in ePVA (embedded Packet Velocity Accelerator) or FPGA (field-programmable gate array) never presents itself to a software hook, so its **contents** are out of reach — a hardware boundary that bounds iRules and kernel eBPF identically. The offload **boundary** is ordinary TMM software — the decision to accelerate, descriptor construction, escalation return, completion and error paths — so it is hookable before the call and after it returns. Only a fault *inside* the silicon needs a firmware fix. Two consequences: a hook at the decision point makes offloaded coverage **measurable** rather than an ambiguous zero, and **declining the offload is itself a mitigation** (`STEER` onto the software path, trading acceleration for reach while armed). **BIG-IP VE** (Virtual Edition, no offload) has none of this split.

## 5. The two force-multipliers

1. **Decoupled from the TMOS release train.** Mitigations, telemetry, and diagnostics ship as a signed artifact rather than as a build. The artifact difference is the one stated in §1.1: a build has to be installed (restart or failover, regression risk, rollback plan); a signed program applies with no restart and no failover, and is revoked the same way.
2. **Verified ⇒ the authoring set can widen.** Each program is proven memory-safe, terminating where the check is enabled, and budget-gated (verified ≠ correct: the canary/kill-switch is the backstop). Those are the properties that let sources beyond the core build team — SIRT, support, later vetted partner logic — put code on a device inline on production traffic.

## 6. Securing the substrate

The property that makes this powerful — execute bytecode in the data plane — also makes it a crown-jewel target: whoever can load a program runs code where decrypted traffic, keys, and every flow are visible. Securing it starts from one principle and proceeds in layers.

### 6.1 Verified ≠ secure

PREVAIL proves a program is **memory-safe**, and **terminating only when the termination check is enabled** — `--termination` is off by PREVAIL's default ("Verify termination. Default: ignore"), and where it is on the guarantee is a ceiling of 100,000 loop iterations (`BoundedLoopCount::limit` in PREVAIL's source), which is a loop-iteration bound and not a time budget. The time load is carried by the admission budget pass and a runtime fuel guard — and fuel needs a patch to uBPF's JIT, since `ubpf_set_instruction_limit` "has no effect on JIT'd programs" (`engine-hard-problems.md` §1). It will not scribble memory *outside its context*; note that PREVAIL's context descriptor expresses no read-only region, so writes **to the context itself** are not bounded — which is why the host hands the program a per-core scratch copy and discards it on fall-through. It proves **nothing** about whether the program is malicious *within the rules*: it can still read sensitive data it is permitted to touch, weaken a control, monopolize a hot path, or have been loaded by the wrong party. **The verifier is a safety gate, not a security gate**: "verified" does not mean "safe to run arbitrary bytecode." Security is the governance *around* the VM.

### 6.2 Threat model

- **The load path is a crown-jewel target** — code execution in the data plane. The management plane that loads programs is the same plane that carries the historical remote-code-execution (RCE) bugs.
- **Provenance** — forged or tampered programs.
- **Exfiltration** — an *observe* program reading TLS secrets, PII or decrypted payload and leaking it. Read-only ≠ harmless.
- **Subversion** — a "shield" that disables WAF, drops legitimate traffic (a denial of service), or weakens a policy.
- **Resource abuse** — a verified-but-expensive program on a hot hook is a performance DoS.
- **Fleet spread** — a bad program propagating via config-sync across a device group.
- **Persistence** — a planted program surviving reboot.

### 6.3 Layered controls

1. **Provenance & authorization — default deny.** Vendor **code-signing is mandatory in production**: the box checks the signature over the binding (PREVAIL ran earlier, in F5's admission pipeline, before signing); only F5-signed programs load. Signing is also the backstop if the load path is breached — no signing key, no arbitrary code. **Authorization tiers:** SIRT-signed by default; operator/partner-authored programs are a separate, off-by-default capability gated by RBAC (role-based access control). **Active (filter) programs require stricter authorization than read-only observe.**
2. **Capability confinement.** For the **core substrate, this is free**: with zero helpers (see §2), a program is a pure function of `ctx` — it can only read the exposed fields and return a value, so there are no "syscalls" to confine, no I/O, no memory reach, no sockets, *by construction*. Confinement here reduces to **context minimization**: the **hook-point map declares, per hook, the allowed attach mode and exposed `ctx` fields**, and sensitive fields (TLS secrets, PII, decrypted payload) are gated and redacted by default, exposed only on explicit, separately-authorized justification — because what a program can see *is* what its `ctx` exposes. **If** an optional helper tier is later added (letting a program touch host maps directly), *those* helpers become the program's "syscalls" and must be kept **minimal and audited** (no general memory read, no arbitrary I/O, no config write, no sockets), with the map declaring **permitted helpers** per hook. That surface is opt-in; the base surface has none.
3. **Exfiltration control.** Telemetry egress is **one-way through a controlled, logged sink** the program cannot read back or redirect; no program-initiated I/O. A malicious observe program still cannot phone home — its output goes only where the host sends it, audited.
4. **Harden the load path.** Treat it as the highest-value target: strong authN/authZ, mTLS, RBAC, network-restricted, rate-limited, fully audited; consider an out-of-band authorization decision gated by an HSM (hardware security module). Signing limits the blast radius if it is ever breached.
5. **Lifecycle, audit, revocation.** **Attestation/inventory** — enumerate every loaded program with provenance (signer, hook, mode, when, by whom) so an unexpected one is detectable. **Tamper-evident audit log** of every load / mode-change / unload. **Instant kill-switch + signer/program revocation**, published fleet-wide the way a certificate revocation list is. **No silent persistence** — programs are re-applied from the signed catalog, not from local state an attacker could plant. **Auto-retirement** (design §7) prevents zombies.
6. **Resource governance.** Per-hook **perf budget + watchdog** (design §9/§11): auto-disable + alert if TMM degrades after a load. Cap the count/total overhead of loaded programs. Verified ≠ cheap.
7. **Fleet & trusted computing base (TCB).** **Config-sync is in the trust path** (design §13): a program propagating across a device group carries its signature/authorization with it. The **loader + verifier + signature-check are part of the TCB** — minimal, hardened, higher-integrity than the programs they gate.

### 6.4 Coverage vs. the design doc

Already specified in `big-ip-live-surface-design.md`: signing and SIRT-author/red-team (§8), the mandatory verifier and watchdog (design §9), monitor-first and auto-retirement (design §7), mode-promotion governance and config-sync-in-trust-path (design §13). This section adds the substrate-level pieces those don't yet name: **verified≠secure**, **capability confinement + context minimization** (free in the zero-helper core; §2), the **observe-mode exfiltration** control, **authorization tiers + load-path hardening**, and **attestation/inventory + revocation/kill-switch**.

## 7. The honest boundary (where this is *not* the tool)

eBPF's compute model is deliberately constrained — bounded loops, small stack, no arbitrary calls. This is the home of **probe / decide / transform-lite**, not heavy computation. Rich, unbounded logic — a full protocol transform, a complex customer-authored filter — belongs in the **WASM** lane (design §2.3). The spectrum (§1) is the point: **WASM for expressive extensions; embedded eBPF for verified, cheap instrumentation & control.**

## 8. Suggested sequencing

Build the substrate once; land use cases in order (each reuses the same VM + verifier + hook-point map):

1. **A CVE shield on `bd`** — proves the embedded-VM + verify + lifecycle spine against a real bug, off the hot path. *(Companion doc, Phase 1.)*
2. **Control-plane daemon shields** — the bulk of disclosed TMOS CVEs.
3. **Observe-mode tracepoints for diagnostics & support** — high value, low risk (read-only), same machinery.
4. **TMM-internal shields** on exceptional paths — the data-plane CVE classes nothing else reaches.
5. **Hot-path hooks under a measured budget** — adaptive controls and full-fidelity telemetry where the value justifies the cost.

## 8.5 A further direction: AI-assisted shield authoring

CVE disclosure moves at machine speed, and the verified-shield model admits machine-speed *authoring* in response. Because a shield is a bounded, statically-verified program that only selects among host-owned outcomes, two properties of a draft are checked mechanically rather than reviewed: memory-safety, and (where the check is enabled) termination. So a generative model can draft one and the **verifier is a fail-closed acceptance gate** on that draft — which is what makes machine authorship of inline data-plane code approachable. It bounds memory-safety and termination, not correctness and not execution time. A pipeline reads a CVE (advisory / PoC / patch diff), emits a bounded **C** predicate (clang → eBPF) grounded on the signed hook-point map — a `tmmtrace`-style front-end could emit the same one-liner form as an optional convenience — compiles it, and iterates it against **three mechanical oracles** — verifier pass, exploit-replay blocks the PoC, low false-positive against a legitimate-traffic corpus — before a human signs. A **shieldability classifier** declares "not shieldable → engineering hotfix" when no safe interception point exists. Human authorization stays non-autonomous; deployment is observe-first and auto-retiring (design §7).

**The support for that argument: none of the three oracles is implemented in this repo, and the pipeline is proposed, not demonstrated.** What can be said is narrower: two of the three gates are *ordinary* engineering rather than research — the verifier gate is an existing tool (PREVAIL) invoked in a build step, and exploit replay is a test harness against a proof-of-concept (PoC) exploit — while the third, a low-false-positive judgment over a legitimate-traffic corpus, needs a corpus that does not exist here. The section above is a feasibility argument and reads as one. See [`explainers/cve-shield-walkthrough.html`](explainers/cve-shield-walkthrough.html) (the worked CVE example, end to end) and [`explainers/cve-mitigation.html`](explainers/cve-mitigation.html) (the plain-language shield explainer).

## 9. One-line thesis

**TMM's power is dynamic programmability. Embedded eBPF is the third surface — alongside iRules and WASM — extending that power to the data plane's own code and internal state, and the only one whose runtime changes carry a static proof — memory-safety, and termination where that check is enabled — with time-safety bounded at admission by the budget pass and at runtime by a fuel-metered guard. The CVE shield is the first consumer; the substrate, and the hook-point map, are the asset.**
