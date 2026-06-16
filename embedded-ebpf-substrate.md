# The Embedded eBPF Substrate in TMM

### The third programmability surface — verified, dynamic, in the data plane. Live Shield is its first instance.

**Status:** Strategy / use-case exploration
**Audience:** TMOS architecture, F5 SIRT, BIG-IP security & observability engineering, product
**Companion:** `big-ip-live-shield-design.md` (the detailed Live Shield mechanism — the first instance of this substrate) · `prototype/` (working proof: uBPF embedded + PREVAIL verify gate, enforce + observe demonstrated)
**Scope:** What becomes possible once a verified userspace-eBPF VM (uBPF) is embedded in TMM and instrumented with designed-in hook points

---

## 1. Where this fits: TMM's programmability spectrum

TMM's defining strength is **dynamic programmability** — the ability to change the data plane's behavior at runtime, without a rebuild or reboot. iRules and WASM established that strength. Embedded eBPF is not a new idea bolted on; it is the *continuation* of it, extended to a layer the existing surfaces cannot reach.

| Surface | Layer it programs | Best at | Dynamic? | Safety of dynamic change |
|---|---|---|---|---|
| **iRules** | traffic logic at proxy events | connection / L7 traffic decisions | yes | TCL, runtime-bounded; can misbehave / be costly |
| **WASM** | rich extensions | complex custom logic, transforms, real languages | yes | sandbox isolation; can hang (runtime "fuel" kills it) |
| **Embedded eBPF** | the data plane's **own code & internal state** | verified probes, compensating controls, deep telemetry | yes | **statically verified before load** — provably bounded + terminating |

iRules made *traffic logic* dynamically configurable. WASM made *rich extensions* dynamically configurable. **Embedded eBPF makes the data plane's own code-level behavior and internal state dynamically configurable** — the parsers, plugin internals, connection state, error paths — which neither of the others can touch.

And it occupies a unique slot in the *dynamic-configurability* story: **eBPF is the only surface that is dynamically loadable *and* statically proven safe.** That is what makes it trustworthy for runtime reconfiguration of the **most sensitive paths** — the data-plane hot path and inline security controls — which is exactly where dynamic change is otherwise hardest to allow. Dynamic configurability is most valuable where it is most dangerous; the verifier is what makes it permissible there.

> **The value prop is not "we added eBPF."** It is: *TMM's power is dynamic programmability; eBPF extends that power to the code/instrumentation layer, and is the one surface that makes runtime reconfiguration of even the data-plane fast path provably safe.*

## 2. The capability, stated plainly

Embedding a uBPF VM in TMM and exposing a curated set of designed-in **hook points** lets the host run a small, verified eBPF program at each point that either:

- **observes** internal state and emits telemetry (a *tracepoint*), or
- **acts** — returns a verdict the host applies (PASS / DROP / RESET) (a *datapath control*).

The properties that make the substrate valuable:

| Property | Why it matters |
|---|---|
| **Dynamic** — load / swap at runtime | behavior ships in hours, decoupled from the TMOS release train; no reboot |
| **Verified** — PREVAIL proves bounded memory + termination before load | programs **cannot hang or corrupt** the data plane; blast radius bounded *by construction* |
| **Cheap** — JIT'd; ~tens of ns/invocation; empty hook = one branch | usable on cold *and* (under a measured budget) hot paths |
| **In-process** — runs in TMM's address space | sees data-plane internals that kernel eBPF (kernel-bypass) and iRules (proxy data-model) cannot |
| **Host-owned outcomes** | a program *chooses among* sanctioned effects; it cannot invent new control flow |

This is what the `eob-patch` name has pointed at all along: **eob** (observability) and **patch** (runtime compensating controls) are two faces of one embedded-eBPF substrate.

## 3. Use-case families

- **Security beyond CVE shields** — behavioral exploit detection on internal state; inline protocol-anomaly detection at the parser (pre-event); adaptive rate-limit / circuit-break on internal load; TLS/crypto policy at the record layer.
- **Observability, dynamic & on-demand** — *bpftrace-for-TMM* (deep telemetry for a specific condition/flow/tenant, on then off); per-flow latency breakdown across internal stages; *flight recorder* (snapshot state when an error branch fires — worked in §3.1); new metrics as bytecode, no TMOS rev.
- **Diagnostics & field support** — ship a customer a *signed probe* to characterize a production issue in situ, then remove it (worked in §3.1). No debug build, no core-dump archaeology.
- **Lightweight policy / steering** — steering, mirror-selection, A/B decisions driven by internal signals (decision in eBPF; heavy logic in iRules/WASM).
- **Self-tuning / performance** — read internal load and nudge a knob; live hot-path profiling.

### 3.1 Two diagnostic patterns, worked

The diagnostics leg is the substrate's lowest-risk, highest-leverage near-term use: both patterns below are **observe-mode, read-only, and verified**, so they run on a *live production* data plane without the "a bad shield crashes TMM" exposure of `filter` mode. They turn "ship a debug build / wait for it to recur" into "load signed bytecode for a while," and they reuse the existing security spine (§6) at a lower authorization tier — read-only, but exfiltration still governed (§6.2).

**Signed support probe.** F5 support/SIRT authors a small program targeting the *exact* hook + condition behind an intermittent field issue (a sporadic reset, a latency spike, a plugin misbehaving under one traffic shape), signs it, and ships it. The operator — RBAC-gated, explicit consent — loads it in observe mode; it captures precisely the needed signal, exports to the controlled sink, then is pulled. eBPF earns this specifically because it is **verified** (cannot crash or hang a customer's production box — non-negotiable for vendor code attached inline on live traffic), cleanly **removable**, and reaches **in-TMM** state that logs and iRules cannot. Design points not otherwise specified:

- **Context minimization by default** — a support probe does *not* expose TLS secrets / PII / decrypted payload unless separately justified and authorized; redact by default (§6.3).
- **Data residency** — captures land in a **customer-controlled, audited** location; the customer decides what to share with support. Auto-phone-home to F5 is the wrong default for a security appliance.
- **Time-boxed** — auto-retirement (design §7) applies: a probe must not outlive the investigation. Expiry + kill-switch + a tamper-evident log of what was loaded and what it captured.

The governance *is* the feature here: without it, "vendor loads code on my box to read my traffic" is a non-starter.

**Flight recorder.** A small **per-CPU ring** of recent internal state is maintained at the relevant hook(s); on a **trigger**, the ring is frozen and dumped — yielding the run-up *into* a failure rather than the wreckage after it (the core-dump's blind spot). Two flavors: a *per-context ring* (recent state for the active flow, dumped on the error branch) and a *global tripwire* (cross-cutting state — poll-loop jitter, memory-pool pressure — dumped on an emergency-mode / watchdog event). Design points:

- **Steady-state cost** — this is the one observe pattern that is *not* free when nothing is wrong: writing the ring on every event is a standing tax, hence a measured-budget decision (§11). Mitigate with a small per-CPU ring (the single-threaded poll loop makes the freeze lock-free), cheap recorded fields, or **conditional arming** (record only once a leading indicator appears).
- **Trigger taxonomy** — entry to a known-vulnerable function, a parser reaching an error state, an assertion, a watchdog event. The trigger is itself a hook, so a flight recorder is really *two* coordinated hooks (record + trip).
- **Dump path off the hot path** — freeze the ring cheaply; hand serialization/export to the lifecycle engine.

**The combined play.** Pair `enforce` + flight recorder on the *same* condition: when a shield drops a malformed frame, the recorder simultaneously snapshots the context. Every block becomes an intelligence source — SIRT gets the exact attempt that was stopped — and it directly answers "how do you know the shield catches real attacks and isn't breaking legitimate traffic?"

Both patterns reuse the same machinery — signing + RBAC, context minimization, the **one-way audited sink** (the program cannot read back or redirect its own output, so even a malicious probe cannot phone home), auto-retirement + kill-switch, tamper-evident audit log (§6.3). Neither needs new substrate.

## 4. Candidate hook points — observability & active datapath

This is the differentiated engineering asset: *where* in TMM a hook earns its keep. Below are candidate points by data-path stage, in both modes. (These are architectural stages; exact named hook points are placed against TMM source and emitted in the per-build hook-point map — design §5.3. `path_class` per §11.)

| Data-path stage | **Observe** (tracepoint) | **Active** (datapath control) | Why eBPF (what iRules / kernel eBPF miss) |
|---|---|---|---|
| **L3/L4 ingress + connection table** | flow/PPS rates, fragment stats, TCP-state transitions, SYN/flood signals, conn-table occupancy, malformed-L4 counts | drop/rate-limit malformed fragments, TCP-state-exhaustion mitigation, early drop of a crafted L4 pattern (L4-stack CVE) | runs **before any iRule event**; kernel-bypass hides it from kernel eBPF |
| **Client-side TLS / record layer** | handshake outcomes, cipher/version mix, record-layer anomalies, decrypt errors, JA3/JA4-style fingerprints, renegotiation counts | block malformed ClientHello/record (TLS record-parse CVE), enforce cipher/version policy at the record layer, mitigate renegotiation abuse | record-layer parse **precedes** `CLIENTSSL_*` events — iRules can't reach it |
| **L7 protocol parse** (HTTP/1·2·3/QUIC, DNS, SIP, MQTT, DIAMETER) | per-protocol frame/message stats, parser state, malformed-encoding counts, HTTP/2 stream/header counts, conditions preceding known crash classes | **drop/sanitize the malformed frame that terminates TMM** (the flagship CVE class), enforce protocol limits (max streams/headers) inline | malformed encodings aren't exposed as clean iRule fields; thin-event protocols have no event |
| **Enforcement plugins** (`bd`/WAF, APM, AFM, DoS) | plugin decision latency, queue depth, per-policy hit rates, internal state before a known `bd` termination, plugin-IPC health | the `bd`-termination shield (design §14), guard the handoff into `bd`, circuit-break a degrading plugin | plugin-process internals are invisible to iRules and to the proxy data-model |
| **LB / persistence / pool selection** | per-member selection distribution, persistence behavior, member health/latency | steer away from a member under attack, dynamic persistence override, mitigate an LB-algorithm edge case | reads internal selection/health state no iRule command exposes |
| **Server side + response path** | server-side TLS outcomes, response codes, response-parse anomalies, OneConnect reuse stats | server-side record-parse shield (same class as client TLS), response sanitization | server-side record parse precedes `HTTP_RESPONSE`; same pre-event gap |
| **Cross-cutting runtime** (poll loop, memory, scheduler, IPC, iRule/TCL VM) | poll-loop jitter, per-core CPU, memory-pool pressure, scheduler stalls, plugin-IPC latency, TCL-VM execution stats | admission control / backpressure under memory or CPU pressure, emergency-mode triggers, shield a CVE in the TCL VM itself | these are TMM-internal health signals with no iRule/data-model surface at all |

Two cross-cutting notes:
- **Observe vs. active is the same hook in two modes** (design §6.1) — many of the rows above start as a read-only tracepoint (lowest risk) and graduate to an active control once the signal is trusted.
- **Most of these are condition-scoped** (the malformed branch, the error path, the crash precondition) → cold/cheap. The genuinely hot-path ones (per-packet L3/L4 telemetry, per-flow latency) are legitimate under a measured budget (design §11), not excluded.

## 5. The two force-multipliers

1. **Decoupled from the TMOS release train.** Mitigations, telemetry, and diagnostics ride a *fast lane* — signed bytecode in hours, not a quarterly build. During active CVE exploitation or a customer-down incident, that cadence difference is decisive.
2. **Verified ⇒ safe to be aggressive, and to broaden the contributor set.** Because each program is proven unable to hang or scribble memory, the surface **cannot crash the box** — making it palatable to let more sources contribute (SIRT, support, eventually vetted partner logic) onto a device inline on production traffic.

## 6. Securing the substrate

The property that makes this powerful — execute bytecode in the data plane — also makes it a crown-jewel target: whoever can load a program runs code where decrypted traffic, keys, and every flow are visible. Securing it starts from one principle and proceeds in layers.

### 6.1 Verified ≠ secure

PREVAIL proves a program is **memory-safe and terminating** — it will not crash or hang TMM. It proves **nothing** about whether the program is malicious *within the rules*: it can still read sensitive data it is permitted to touch, weaken a control, monopolize a hot path, or have been loaded by the wrong party. **The verifier is a safety gate, not a security gate.** Treating "it's verified" as "it's safe to run arbitrary bytecode" is the fatal mistake. Security is the governance *around* the VM.

### 6.2 Threat model

- **The load path is a crown-jewel target** — code execution in the data plane. (Note the irony: the management plane that loads programs is the same plane with the historical RCEs.)
- **Provenance** — forged or tampered programs.
- **Exfiltration** — an *observe* program reading TLS secrets / PII / decrypted payload and leaking it. Read-only ≠ harmless.
- **Subversion** — a "shield" that disables WAF, drops legitimate traffic (DoS), or weakens a policy.
- **Resource abuse** — a verified-but-expensive program on a hot hook is a performance DoS.
- **Fleet spread** — a bad program propagating via config-sync across a device group.
- **Persistence** — a planted program surviving reboot.

### 6.3 Layered controls

1. **Provenance & authorization — default deny.** Vendor **code-signing is mandatory in production**: signature checked *before* the verifier sees bytecode; only F5-signed programs load. Signing is also the backstop if the load path is breached — no signing key, no arbitrary code. **Authorization tiers:** SIRT-signed by default; operator/partner-authored programs are a separate, off-by-default, RBAC-gated capability. **Active (filter) programs require stricter authorization than read-only observe.**
2. **Capability confinement.** Helpers are the program's "syscalls" — keep the set **minimal and audited** (no general memory read, no arbitrary I/O, no config write, no sockets). The **hook-point map declares, per hook, the allowed attach mode, exposed ctx fields, and permitted helpers** — a program can do only what its hook permits. **Context minimization:** sensitive fields (TLS secrets, PII, decrypted payload) are gated and redacted by default, exposed only on explicit, separately-authorized justification.
3. **Exfiltration control.** Telemetry egress is **one-way through a controlled, logged sink** the program cannot read back or redirect; no program-initiated I/O. A malicious observe program still cannot phone home — its output goes only where the host sends it, audited.
4. **Harden the load path.** Treat it as the highest-value target: strong authN/authZ, mTLS, RBAC, network-restricted, rate-limited, fully audited; consider an out-of-band / HSM-gated authorization decision. Signing limits the blast radius if it is ever breached.
5. **Lifecycle, audit, revocation.** **Attestation/inventory** — enumerate every loaded program with provenance (signer, hook, mode, when, by whom) so an unexpected one is detectable. **Tamper-evident audit log** of every load / mode-change / unload. **Instant kill-switch + signer/program revocation** (CRL-style), fleet-wide. **No silent persistence** — programs are re-applied from the signed catalog, not from local state an attacker could plant. **Auto-retirement** (design §7) prevents zombies.
6. **Resource governance.** Per-hook **perf budget + watchdog** (design §9/§11): auto-disable + alert if TMM degrades after a load. Cap the count/total overhead of loaded programs. Verified ≠ cheap.
7. **Fleet & TCB.** **Config-sync is in the trust path** (design §13): a program propagating across a device group carries its signature/authorization with it. The **loader + verifier + signature-check are part of the TCB** — minimal, hardened, higher-integrity than the programs they gate.

### 6.4 Coverage vs. the design doc

Already specified in `big-ip-live-shield-design.md`: signing and SIRT-author/red-team (§8), the mandatory verifier and watchdog (§9), monitor-first and auto-retirement (§7), mode-promotion governance and config-sync-in-trust-path (§13). This section adds the substrate-level pieces those don't yet name: **verified≠secure**, **helper/capability confinement + context minimization**, the **observe-mode exfiltration** control, **authorization tiers + load-path hardening**, and **attestation/inventory + revocation/kill-switch**. Together they are the difference between "we sign shields" and "we can safely operate a programmable data plane."

## 7. The honest boundary (where this is *not* the tool)

eBPF's compute model is deliberately constrained — bounded loops, small stack, no arbitrary calls. This is the home of **probe / decide / transform-lite**, not heavy computation. Rich, unbounded logic — a full protocol transform, a complex customer-authored filter — belongs in the **WASM** lane (design §2.3). The spectrum (§1) is the point: **WASM for expressive extensions; embedded eBPF for verified, cheap instrumentation & control.**

## 8. Suggested sequencing

Build the substrate once; land use cases in order (each reuses the same VM + verifier + hook-point map):

1. **Live Shield on `bd`** — proves the embedded-VM + verify + lifecycle spine against a real bug, off the hot path. *(Companion doc, Phase 1.)*
2. **Control-plane daemon shields** — the bulk of disclosed TMOS CVEs.
3. **Observe-mode tracepoints for diagnostics & support** — high value, low risk (read-only), same machinery.
4. **TMM-internal shields** on exceptional paths — the data-plane CVE classes nothing else reaches.
5. **Hot-path hooks under a measured budget** — adaptive controls and full-fidelity telemetry where the value justifies the cost.

## 9. One-line thesis

**TMM's power is dynamic programmability. Embedded eBPF is the third surface — alongside iRules and WASM — extending that power to the data plane's own code and internal state, and the only one whose runtime changes are provably safe. Live Shield is the first instance; the substrate, and the hook-point map, are the asset.**
