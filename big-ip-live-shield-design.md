# BIG-IP Runtime Compensating Controls ("Live Shield")
### Design proposal — embedded userspace eBPF for between-window CVE mitigation

**Status:** Draft for architecture review
**Audience:** TMOS architecture, F5 SIRT, BIG-IP security engineering
**Scope:** On-box, vendor-authored runtime shields for TMOS's *own* control-plane and data-plane code paths
**Companion:** `embedded-ebpf-substrate.md` (the broader substrate, programmability-spectrum, hook-point catalog & security model — Live Shield is its first instance) · `prototype/` (working proof: uBPF embedded + PREVAIL verify gate)

---

## 1. Problem statement

Two shifts have collapsed the old "patch on a quarterly cadence" model for infrastructure:

1. **Infrastructure is now a primary attack surface.** Load balancers, firewalls, and routers are being targeted directly rather than as a path to the apps behind them.
2. **AI-assisted vulnerability discovery has compressed the disclosure-to-exploitation window.** Frontier models can reason over large, mature codebases and surface obscure interdependencies, and they operate at machine speed. The interval between a CVE becoming known and active exploitation is shrinking.

For a BIG-IP operator this creates an exposure gap: a TMOS CVE is disclosed, but the operator cannot always take an emergency maintenance window to install a patched build immediately. They need a **temporary, surgical, reversible control** that blocks the specific exploit path until the permanent patched build is deployed on their normal schedule.

This document proposes **Live Shield**: a vendor-authored, signed, auto-retiring runtime compensating control for TMOS. It is explicitly **not** a patch and does not replace lifecycle discipline. It is a finger-in-the-dike between maintenance windows.

The model is directly analogous to Cisco's Live Protect (eBPF shields embedded in NX-OS), but it must be adapted to a fundamentally different OS architecture — which is the crux of the rest of this document.

## 2. Why TMOS cannot copy the Cisco approach directly

Cisco's mechanism is kernel eBPF in NX-OS's Linux kernel. TMOS is not one OS; it is a partitioned system with two execution environments, and a single mechanism cannot cover both.

| Plane | What runs there | Exploit classes | Reachable by kernel eBPF? |
|---|---|---|---|
| **Control plane** | Hardened RHEL-family Linux (CentOS → Rocky). Hosts httpd, iControl REST, tmsh, config daemons (MCPD), logging, SNMP. | iControl REST auth-bypass, Config-utility RCE, command injection, privilege escalation | Yes — normal Linux processes and syscalls |
| **Data plane** | TMM — F5's own microkernel. Own scheduler, own memory manager, own TCP/IP stacks. Core-pinned poll loop; bypasses the Linux kernel for all traffic. | Malformed-input crashes, parser bugs, `bd`/enforcement-process termination, traffic-borne RCE | **No** — TMM does not syscall for the data path, so kernel eBPF sees nothing of its internal processing |

The consequence is the central design constraint:

> **Kernel eBPF can shield the control plane but is structurally blind to TMM.** The most damaging data-plane CVEs live exactly where kernel-based instrumentation cannot see.

### 2.1 The data-plane coverage map

It is tempting to assume iRules — the sanctioned, in-TMM scripting surface — can shield any data-path CVE. They cannot. An iRule can shield a CVE only when **(a)** an iRule event fires *before* the vulnerable code executes, **(b)** the triggering condition is observable through the iRule command/data model at that event, and **(c)** the flow actually reaches the iRule VM (it isn't bypassed by FastL4/hardware offload). Whenever any one fails, there is a hole — and the holes are positional, clustering before L7 parsing and inside the enforcement plugins, bracketing the reachable middle:

```
 Ingress
    |
    v
 +-----------------------------+
 | L3 / L4 stack               |  HOLE      runs before any iRule event
 +-----------------------------+
 | Client-side TLS             |  PARTIAL   record/handshake parse precedes events
 +-----------------------------+
 | L7 protocol parse           |  REACHABLE HTTP_REQUEST / HTTP::collect
 +-----------------------------+
 | WAF / bd enforcement        |  HOLE      plugin-process internals
 +-----------------------------+
 | LB + server side            |  REACHABLE LB_SELECTED, HTTP_RESPONSE
 +-----------------------------+
    |
    v
 Egress
```

This is the case for a layered adapter stack rather than iRules alone: each pipeline band has a different owning adapter, and one residual sliver belongs to no runtime control at all.

| Pipeline band | Reachability | Owning adapter (§5.1) | Residual gap |
|---|---|---|---|
| L3 / L4 stack | Hole for iRules | AFM (L3/L4 rules) | Fragment-reassembly and TCP-state crashes not expressible at any rule layer |
| Client-side TLS | Partial | TMM hook point (userspace eBPF); iRules partial via `CLIENTSSL_CLIENTHELLO` | Record-layer parse crash that fires before the earliest hook |
| L7 protocol parse | Reachable | iRules / Advanced WAF | Malformed encodings not exposed as clean fields; thin-event protocols |
| WAF / `bd` enforcement | Hole for iRules | `bd` hook point (userspace eBPF) | Trigger not observable before the handoff into `bd` |
| LB + server side | Reachable | iRules / Advanced WAF | Server-side TLS record parse (same class as client-side TLS) |

The iRule execution engine itself is a further exclusion: a CVE in the TCL VM or rule dispatcher cannot be shielded by a rule, and falls to the control-plane adapter or an engineering hotfix. The TLS record-parse and L3/L4 pre-event crashes in the right-hand column are the same residual dead zone formalized in §10 — the portion that no runtime adapter closes.

### 2.2 What the embedded VM uniquely enables (uBPF vs. iRules)

§2.1 mapped where iRules *cannot* reach. This section states the positive case: what the embedded userspace-eBPF VM (§3.1) does that iRules structurally cannot. The test is the inverse of §2.1's three conditions:

> An iRule acts only when **(a)** a sanctioned iRule *event* fires, **(b)** the triggering condition is visible in the iRule *traffic data-model* at that event, and **(c)** the flow reaches the iRule VM. The embedded VM runs wherever a **code hook point** is placed — no event required — and sees TMM's **internal program state**, not just the exposed traffic model.

In short: **iRules express traffic logic in the sanctioned data-model at proxy events; the embedded VM is code-level instrumentation and control at arbitrary sanctioned points in TMM.** Different layer. iRules see what the proxy decided to expose; the VM sees what the code is actually doing.

| Use case (iRules don't help) | iRule test that fails | What the embedded VM does |
|---|---|---|
| Pre-L7 / record-layer paths — TLS record parse, L3/L4 stack, protocol framers | (a) — no event fires before the vulnerable code | hook at the parser function itself |
| Enforcement-plugin internals — `bd` / WAF / ASM | (b)+(c) — plugin-process internals invisible to the proxy model | hook *inside* the plugin process |
| The iRule / TCL engine or rule dispatcher | — a rule cannot shield itself | a separate mechanism hooks it |
| FastL4 / hardware-offload fast paths | (c) — flow bypasses the iRule VM | hook in the fast-path code |
| Internal program state — connection-table internals, memory-pool pressure, parser state machines, inter-function latency, error-branch hit-counts | (b) — no iRule command exposes it | an `observe`-mode tracepoint (§6.1) reads it in-process |
| Code-level virtual patch for a malformed condition not surfaced as a clean field | (b) — condition invisible in the data model | inspect the raw argument at the vulnerable function |

Two consequences worth making explicit:

- **One substrate, two missions.** The same embedded VM and hook-point machinery serve enforcement (`filter`-mode shields, §6.1) *and* observability (`observe`-mode tracepoints) — the latter reaching internal data-plane state that kernel-based eBPF observability ("eob") cannot see, because TMM bypasses the kernel. Enforcement and observability differ only in whether the host acts on the program's return value.
- **These are condition-scoped, not a per-packet firehose.** Every use case above fires on a *specific* code path or condition (the malformed-input branch, the error path, the plugin handoff) — i.e. cold/exceptional paths (§11). So they incur cost only when that condition is evaluated, the same discipline that keeps shields off the steady-state hot path. This is *not* blanket per-packet telemetry, and does not depend on sampling.

iRules remain the **first-line** control for anything an iRule event *can* observe (§5.1, adapter 1) — they are sanctioned, well-understood, and lowest-risk. The embedded VM is for the cases above, where no iRule event, data-model field, or reachable path exists.

### 2.3 Relationship to WASM data-plane programmability

As TMM gains a **WASM** runtime for data-plane programmability, the natural question is whether that subsumes the embedded eBPF VM. It does not — they are complementary, optimized for different jobs, and WASM arriving *clarifies* the split rather than eroding it.

| | **eBPF / uBPF** | **WASM** |
|---|---|---|
| Built for | tiny, bounded **probes / hooks** | general-purpose **extensions** |
| Safety model | **statically verified before run** (PREVAIL proves bounded memory + termination, §9) | sandbox *confinement* — memory-isolated, but can loop forever; bounded only by runtime "fuel"/epoch kills (a runtime kill mid-execution, not a proof) |
| Invocation cost | ~tens of ns (direct JIT call, tiny ctx) | heavier (runtime entry, linear-memory marshaling) |
| Footprint | ~150 KB | multi-MB runtime |
| Shape | attach-at-a-point → read ctx → return verdict / update map | call rich logic written in a full language |

The decisive differentiator for a **shield or tracepoint running inline in the poll loop** is the verifier: eBPF gives a *static proof* that the program terminates and touches only what it should, **before** it ever runs. WASM gives isolation, but a WASM module can hang — you bound it with runtime fuel, which is a mid-execution kill, not a guarantee. For an always-must-be-safe in-data-plane control, "provably can't hang" beats "we'll kill it if it does." You cannot safely run unverified WASM on the TMM hot path the way you can a verified eBPF program.

On the hot path specifically: **WASM pays the same per-invocation tax as uBPF — in fact more** (heavier runtime entry). So WASM is not the lighter option for per-packet hooks; if anything the verified eBPF program is. The hot-path cost (§11) is intrinsic to *any* in-data-plane runtime, not a uBPF-specific objection.

**Where WASM genuinely wins** (the honest division of labor): rich, possibly customer- or partner-authored **data-plane extensions** — a full protocol transform, a complex custom filter, substantial logic in a real language. eBPF is the wrong tool for that, and Live Shield does not claim it.

So the architecture is **both**, with a clean line:

- **WASM** = the rich programmable-extension surface (expressive power, real languages).
- **Embedded eBPF / uBPF** = the **verified, near-zero-cost instrumentation + security surface** (CVE shields, tracepoints) — where you need *proof of safety* and *hot-path cheapness*, not expressiveness.

Doing safety-critical inline shields *in* WASM would mean reinventing eBPF's verifier — which is exactly why the uBPF investment is durable: its value is the verifier + cost profile, neither of which WASM provides.

## 3. Why userspace eBPF (and why F5 specifically wants it)

A userspace eBPF VM runs eBPF bytecode entirely in userspace — an interpreter plus a JIT — with no dependency on the kernel eBPF subsystem. The chosen engine is **uBPF**: a small (~150 KB), Apache-2.0, embeddable VM with x86-64 and arm64 JITs. It is the same userspace execution engine Microsoft ships in eBPF-for-Windows, and the engine inside bpftime — i.e. the proven floor of this space, consumed here as a **library**, not a framework.

There are two ways to get userspace eBPF into a process, and the distinction is the crux of this design (§3.1):

- **Inject** into an unmodified, running process (the bpftime model — `LD_PRELOAD`/ptrace, binary rewriting, a syscall-emulation shim). Powerful for instrumenting software you don't own, but brittle and invasive. **Evaluated and rejected** — see §3.1; a prototype confirmed the injection path is fragile in practice while the embedded path works.
- **Embed** the VM as a library and call it at designed-in hook points (the uBPF model). This is what Live Shield uses.

For a customer, userspace eBPF's headline benefit would be routing around a locked-down kernel. **For F5 as the vendor that benefit is irrelevant** — we can enable kernel eBPF in our own build, and we already ship kernel eBPF in BIG-IP eBPF Observability ("eob") for Kubernetes traffic on Cloud-Native Edition.

The reason F5 specifically wants an *embedded userspace* VM is the one thing kernel eBPF can never do regardless of privilege: **TMM is a userspace process that bypasses the kernel, so a VM embedded in TMM is the only mechanism that can place a shield (or a tracepoint) inside TMM's own execution.** This is the architectural justification and the product differentiator. Our kernel-eBPF "eob" proves the limitation by counterexample — it is kernel-level, so it sees kernel-mediated traffic, not TMM internals.

### 3.1 The vendor inversion: instrument by design, do not inject

Off-the-shelf userspace eBPF *injection* tooling (bpftime) attaches to processes the operator does not own, using ptrace/`LD_PRELOAD` injection and binary rewriting against stripped, symbol-less binaries at guessed offsets. That is brittle and invasive — and unnecessary for us. (A prototype bore this out: the injection runtime never reliably engaged, whereas embedding uBPF and calling it at a hook point worked directly.)

**We own TMM's source.** Therefore Live Shield does not inject into a running TMM. Instead:

- We build **first-class, sanctioned eBPF hook points** into TMM and the control-plane daemons as a designed-in instrumentation surface.
- The build pipeline emits a **hook-point map** for every TMOS build, naming stable attach points and their signatures.
- The uBPF VM is linked in as a designed-in component (the VM + its JIT, plus the PREVAIL verifier as the §9 load gate); shields are authored as ordinary eBPF C and compiled with the standard `clang -target bpf` toolchain. The VM is a **library call**, **not** a runtime intrusion technique.

This single decision eliminates the two worst objections to userspace eBPF in this context: the no-symbols/brittle-offset problem (we emit a per-build map and call a named hook) and most of the injection-safety risk (no runtime machine-code rewriting of a poll loop). The host calls `ubpf_exec(vm, ctx, …)` like any function and acts on the return.

## 4. Goals and non-goals

**Goals**
- Block a specific, known exploit path at runtime, on a running system, without reboot.
- Cover both planes: control-plane daemons and TMM internals.
- Vendor-authored, validated, and signed shields (SIRT-driven), not DIY runtime rules.
- Three operational modes (monitor / enforce / disable), full observability, and automatic retirement once the patched build is installed.
- Negligible steady-state performance impact.

**Non-goals**
- Replacing patches or lifecycle discipline. Shields are temporary.
- Protecting the applications *behind* the BIG-IP — that is already covered by Advanced WAF / Distributed Cloud virtual patching. Live Shield protects the **BIG-IP's own code**.
- Shielding TMM bugs that crash before any reachable hook point fires (see §10, residual dead zone).

## 5. Architecture

Four layers, mechanism-agnostic above the enforcement leaf.

```
            +-------------------------------------------------------+
            |  Shield Catalog (signed objects, CVE-keyed)           |  <- F5 SIRT authored
            +-------------------------------------------------------+
                              |
            +-------------------------------------------------------+
            |  Lifecycle Engine (modes, version-detect, auto-retire)|
            +-------------------------------------------------------+
                              |
   +-------------------+-------------------+-------------------------+
   | Enforcement Adapter: Enforcement Adapter:  Enforcement Adapter:|
   | iRules / WAF / AFM | ctrl-plane daemon | TMM hook points        |
   | (sanctioned today) | kernel eBPF/uprobe | (embedded userspace VM)|
   +-------------------+-------------------+-------------------------+
                              |
            +-------------------------------------------------------+
            |  Observability + Trust (hit evidence -> SIEM; signing) |
            +-------------------------------------------------------+
```

### 5.1 Enforcement adapters

Three adapters, in increasing order of audacity. Crucially, **two distinct eBPF execution engines are in play, chosen by what the kernel can see** — **kernel-space eBPF** for the control-plane daemons (adapter 2), an **embedded userspace VM** for TMM (adapter 3) — plus a JVM probe surface for iControl REST. They share one signed catalog and lifecycle; only the enforcement leaf differs (the layers above are mechanism-agnostic, §5).

1. **iRules / Advanced WAF / AFM** — already sanctioned, reaches traffic-shaped exploits at the proxy. This remains the **first-line** data-plane shield for anything an iRule event can observe. Deployed via AS3 / iControl REST. Lowest risk; no new runtime.
2. **Control-plane daemon hooks** — **kernel-space eBPF** attached via uprobes at function entry/exit in the native daemons (httpd front end, tmsh, MCPD and the other C config daemons). These are ordinary Linux processes the kernel *can* see, so this is the **true Cisco analog** (NX-OS uses kernel eBPF) and it reuses the kernel's own in-built BPF verifier — no embedded VM needed here. F5 already ships kernel eBPF in BIG-IP eBPF Observability ("eob"), so the engine is in-house. Low performance risk (these are not latency-critical), high CVE coverage (most disclosed TMOS CVEs are control-plane). **Note the iControl REST stack (`restjavad`/`icrd`) runs on the JVM:** neither kernel uprobes nor native hooks reach Java methods, so its shields use a distinct JVM instrumentation surface (JVMTI / USDT-style probes the runtime exposes). The designed-in hook-point philosophy is identical; the adapter implementation is separate (see §12, Phase 2).
3. **TMM hook points** — **embedded userspace eBPF VM** (uBPF + PREVAIL) attaching at sanctioned points inside TMM and its plugin processes (e.g. `bd`). Userspace precisely *because* TMM bypasses the kernel, so kernel eBPF is structurally blind to it (§2). The crown jewel: the only mechanism that reaches data-plane-engine internals. Highest care required (§9, §10).

### 5.2 The embedded eBPF VM

- **uBPF**, linked as a library (~150 KB, Apache-2.0): an in-process eBPF VM with x86-64/arm64 JIT. Shields are authored as ordinary eBPF C and compiled with `clang -target bpf`. On the hot path the JIT is used (a shield invocation is an indirect call into native code; the interpreter is a debug/portability fallback). uBPF is the engine in Microsoft's eBPF-for-Windows and underneath bpftime, so the execution core is proven.
- **PREVAIL** (`vbpf/ebpf-verifier`, the verifier in eBPF-for-Windows) statically verifies every shield **before** the VM is allowed to load it; nonzero verdict ⇒ reject (fail closed). The verifier is **load-bearing for safety** (§9). uBPF runs whatever bytecode it is given, so the verifier — not the VM — is what guarantees a shield can't read/write out of bounds or loop unbounded. (PREVAIL is the verifier for *this* userspace engine; the control-plane adapter rides the kernel's own in-tree BPF verifier instead — §5.1. Two engines, two verifiers, one catalog.)
- uBPF has no native maps; the host provides them. Mode, hit/enforce counters, and `observe`-mode telemetry live in host memory (per-CPU on hot paths) that the lifecycle engine reads and the shield updates via registered helpers.

### 5.3 Native hook-point API and build-pipeline integration

This is the make-or-break engineering item.

- TMM and the control-plane daemons expose named, versioned hook points (function entry/exit, plus a small number of arbitrary-offset points on exceptional paths).
- Every TMOS build emits a signed **hook-point map**: `{tmos_version, build_id, hook_points: [{name, addr/offset, arg_btf, attach_mode, path_class}]}` where `path_class ∈ {hot, warm, cold/exceptional}`, `attach_mode ∈ {observe, filter}` (§6.1), and `arg_btf` is BTF type information for the hook's argument structs.
- A shield declares the hook-point *name* it targets; the lifecycle engine resolves name → offset using the running build's map. Shields are therefore version-bound but not offset-fragile.
- **Argument layouts drift across builds just like addresses do.** Name→offset resolution fixes *where* a hook attaches but not the *layout of the structs it reads*. The build pipeline therefore emits **BTF for the TMM, `bd`, and control-plane-daemon argument structs** alongside the map, and shields are authored CO-RE-style so the loader relocates field accesses against the running build's BTF. A shield reading `ctx->field` stays correct across a build whose struct layout shifted, and **fails closed** — rejected at load — if a referenced field no longer exists. It never reads a stale offset silently.
- CI gate: a shield cannot ship for a build whose hook-point map lacks its target point.

## 6. Shield object schema

```json
{
  "shield_id": "LS-2026-22548-bd-01",
  "cve_id": "CVE-2026-22548",
  "title": "Prevent bd termination via crafted WAF-policy request",
  "affected": {
    "modules": ["asm", "awaf"],
    "tmos_versions": ["17.1.0-17.1.3", "17.5.0-17.5.1"],
    "conditions": "Advanced WAF/ASM policy bound to a virtual server"
  },
  "mechanism": "tmm_hook",            // irule | waf_policy | afm_rule | ctrl_uprobe | ctrl_jvm | tmm_hook
  "hook_point": "bd_request_eval_decision",
  "attach_mode": "filter",            // observe | filter  (see §6.1)
  "payload_ref": "blobs/LS-2026-22548-bd-01.bpf.o",
  "mode": "monitor",                  // monitor | enforce | disable
  "fixed_in_version": "17.5.2",
  "perf_class": "cold",
  "deploy_posture": "enforce-on-arrival",  // monitor-first | enforce-on-arrival  (see §7.1)
  "evidence": { "log_on_hit": true, "counter_map": "ls_hits" },
  "trust": {
    "author": "F5-SIRT",
    "validated_by": ["sirt-pipeline", "redteam"],
    "signature": "<F5 code-signing signature over canonicalized object + payload>"
  }
}
```

### 6.1 Enforcement contract and safe early-return

The schema says a shield *targets* a hook point; it does not by itself say how a shield *prevents* the vulnerable code from running. That mechanism is the safety-critical core of the design and is specified here, because a "verifier-safe" eBPF program proves only that the *probe* won't crash — it says nothing about whether short-circuiting the host function leaves TMM consistent.

**Two attach modes**, declared per hook point in the hook-point map:

- `observe` — the program runs at function entry/exit, may read arguments and update maps, but **cannot alter control flow**. All telemetry, monitor-only points, and evidence collection use this mode. It is always safe.
- `filter` — the program runs at a **designed-in decision point** and its return value selects among a *fixed, enumerated set of outcomes the host code already knows how to take* (`LS_PASS`, `LS_DROP`, `LS_RESET`). A `filter` point is not an arbitrary function entry; it is a location TMOS source explicitly compiles in, immediately before the vulnerable operation, at a place where each enumerated outcome leaves TMM in a consistent state.

**Why not arbitrary override.** Forcing an early return from an arbitrary function (kernel `bpf_override_return`-style) is explicitly **out of scope**: it synthesizes a return value the caller will consume while skipping the function body's side effects — cleanup, lock release, refcount and connection-state updates. On a poll-loop data plane that is a corruption vector, not a shield. The embedded VM does not expose it and Live Shield does not rely on it.

**The safe early-return contract.** For a `filter` hook point, the owning code path guarantees:

1. The decision point sits *before* the vulnerable operation and *before* any state an abort would have to unwind — so `LS_DROP`/`LS_RESET` is a clean branch the code already supports (typically the same path taken for a normal policy reject or malformed-input drop), not a synthesized unwind.
2. The enumerated outcomes are owned by TMOS source, not the shield. The shield only *chooses* among them; it cannot invent a new control-flow effect.
3. The verifier and the hook-point contract are **two independent safety obligations**: the verifier proves the program is safe to *run*; the `filter` contract proves the chosen outcome is safe to *take* (§9).

A CVE whose only viable interception point has no clean abort branch is, by this contract, **not shieldable by the TMM adapter** — it falls to the residual dead zone (§10) or an engineering hotfix. This is a deliberate limit: better to declare a CVE out of scope than ship a shield that returns into an inconsistent TMM.

## 7. Operational modes and auto-retirement

- **Monitor** — the shield's detection logic runs and logs hits, but takes no enforcement action. Lets operators confirm the threat and false-positive rate before enforcing. **This soak-then-promote posture is valid only for shields whose unmitigated exploit does not itself take the system down — see §7.1 for the crash-class exception.**
- **Enforce** — actively blocks/drops/sanitizes the exploit condition.
- **Disable** — deactivates the shield without uninstalling it (fast rollback).

**Auto-retirement.** The lifecycle engine polls the running TMOS version (iControl REST `sys/version`, corroborated by iHealth/QKView telemetry). When the running `tmos_version >= fixed_in_version`, the shield is auto-disabled and flagged for removal. A shield can never silently outlive the patch it stands in for.

### 7.1 Crash-class shields: monitor mode is not a safe soak

The monitor→enforce progression assumes the cost of *not* acting during the soak is only a logged miss. That holds for logic and auth-bypass CVEs. It does **not** hold for the crash/DoS class — `bd` termination, malformed-HTTP/2 TMM crashes — which §2 and §12 make the flagship use case.

For a crash-class shield the predicate fires immediately *before* the crash path, and monitor mode falls through (`LS_PASS`). So the first true positive in production both confirms the predicate **and crashes the box** — the very outcome the shield exists to prevent. Monitor mode cannot be soaked against live attack traffic for these CVEs.

The consequence, stated plainly so operators are not surprised:

- **False-positive validation for crash-class shields happens in F5's lab** (§8), against replayed/synthetic attack traffic and a representative legitimate-traffic corpus — *not* in the customer's production soak.
- Crash-class shields therefore carry `deploy_posture: enforce-on-arrival` and ship recommended-for-enforce. Monitor remains available as a diagnostic for operators who want hit telemetry, with the explicit caveat that a real hit may still crash the vulnerable process.
- Logic / auth-bypass shields keep the default `monitor`-first posture, where production soak is both safe and valuable.

This splits operational guidance by CVE class rather than pretending one posture fits both.

### 7.2 High availability, config-sync, and failover

A shield protects a device, but BIG-IP is deployed as HA pairs and device groups. Two failure modes follow if shields are not HA-aware:

- **Silent protection loss on failover.** A shield installed only on the active unit disappears when traffic fails over to a standby that lacks it. Shields must therefore be **device-group objects that propagate over the existing config-sync channel**, so every sync-group member carries the same shield set, mode, and version binding.
- **Enforce-mode shields vs. health monitoring.** An enforce-mode shield that drops or resets traffic can look like a failing service to a health monitor and induce flapping or an unnecessary failover. A `filter` outcome (`LS_DROP`/`LS_RESET`) is a deliberate mitigation, not a health signal, and must be classified distinctly from a genuine service fault — it must not by itself mark a pool member or virtual server down.

Mode and lifecycle state are part of the synced object: a monitor→enforce promotion, or an auto-retirement, applies group-wide as one change-controlled action rather than per-unit. Auto-retirement keys on the running version of *each* member, so a partially-upgraded group retires the shield per-unit as each member crosses `fixed_in_version`, never leaving a still-vulnerable member unshielded.

## 8. Trust and validation lifecycle

The enforcement primitive is the easy part; trust is the product. Shields are **not** DIY runtime rules. The lifecycle mirrors Cisco's Talos→validate→red-team→retire flow, mapped onto machinery F5 already operates:

1. **Author** — F5 SIRT analyzes the exploit path and writes the shield (this formalizes what the Kxxxxx mitigation articles already do informally).
2. **Validate** — internal SIRT pipeline checks targeting, false-positive rate, performance class, and that a clean auto-retirement path exists.
3. **Red-team** — independent validation that the shield actually blocks the exploit and cannot be trivially bypassed.
4. **Sign** — F5 code-signing over the canonicalized shield object + payload.
5. **Distribute** — existing update/advisory channels; the box verifies the signature before the verifier ever sees the bytecode.
6. **Retire** — automatic, on patched-version detection.

## 9. Safety and blast radius

Unlike Cisco's kernel-isolated shields, a Live Shield in the TMM adapter runs **in TMM's address space**. A faulty shield can crash the data plane. Mitigations:

- The **userspace verifier is mandatory** and runs before load; unverifiable bytecode is rejected.
- Signature verification precedes bytecode verification (§8); only F5-signed payloads load in production.
- Default deploy mode is **monitor** for logic/auth-bypass shields; crash-class shields ship **enforce-on-arrival** (§7.1). Promotion to enforce — whichever the default — is always an explicit, logged action.
- Shields default to **cold/exceptional `path_class` hook points** in TMM; **hot-path hooks are permitted under a measured perf budget + explicit sign-off** (§11), not banned.
- Per-TMM-instance watchdog: if a TMM instance restarts within N seconds of a shield load, the lifecycle engine auto-disables that shield and raises an alert.
- The **enforcement contract (§6.1) is a second, independent safety obligation**: the verifier proves the program is safe to *run*; the `filter` hook-point contract proves the chosen outcome is safe to *take*. A shield must satisfy both, and a hook point with no clean abort branch is simply not a `filter` point.

## 10. Residual dead zone (state honestly)

This is the right-hand-column residual from the §2.1 coverage map. A TMM bug that crashes **before** any reachable hook point fires — e.g. a fault deep in TLS record parsing ahead of the first instrumented function — cannot be shielded by this mechanism, just as it cannot be caught by an iRule (the event never fires) or by kernel eBPF (TMM bypasses the kernel). Those require an engineering hotfix. Live Shield narrows the window for most data-plane CVEs; it does not claim to close all of them. The hook-point map should be designed to push the earliest viable instrumentation point as close to TMM's ingress as performance allows, shrinking this zone over time.

## 11. Performance

Userspace eBPF is not free, but the embedded model is the cheap end of it. With the **JIT**, a shield invocation is an indirect call into native code plus the program's own handful of instructions — tens of nanoseconds, comparable to a C `if`. Crucially there is **no trampoline, no syscall, no kernel trap**: the VM is a direct in-process call, which is why this is far cheaper than injection/uprobe approaches (a kernel-uprobe sslsniff workload measured ~58% overhead vs ~12% for the equivalent userspace tool — and that userspace number still carried attach/trampoline indirection the embedded call does not). A hook point with no shield loaded costs one predictable branch.

Many CVE shields naturally target a **cold/exceptional** code path (the malformed-input handler, the crashing parser branch), so they cost ~nothing in steady state — that is the easy, default case. But it is **not** the only useful one: a CVE whose trigger appears in *ordinary* traffic, or per-flow telemetry/detection, is inherently **hot-path**, and that is legitimately valuable. Hot-path placement is therefore a **measured budget decision, not a prohibition**. Policy:

- `path_class` (`hot`/`warm`/`cold`) in the hook-point map makes placement **informed**, not banned: a `hot` hook is allowed when it carries a **measured per-invocation cost and a throughput/latency budget with explicit sign-off**. Cold/warm is the default; hot requires justification + numbers.
- Hot-path hooks **must** be JIT'd (interpreter is debug-only) and use **per-CPU** state (no cache-line contention across core-pinned TMM instances).
- Every shield/tracepoint carries a `perf_class` and a measured overhead figure from the validation pipeline; acceptance is "within the signed-off budget," not necessarily "indistinguishable from baseline."
- This cost is **intrinsic to any in-data-plane runtime, not specific to uBPF** — a WASM filter or an iRule on the same hot path pays the same kind of per-event tax (heavier, in WASM's case; see §2.3). The lever is the cost/value trade per hook, made explicit and measured — e.g. a few percent of throughput to close an actively-exploited CVE is an easy trade during the exposure window.

## 12. Phased delivery

**Phase 1 — MVP (control-plane-adjacent, real bug).**
Embed the userspace eBPF VM; add a native hook point in the `bd` enforcement process; ship a shield for **CVE-2026-22548** (crafted request terminating `bd` and disrupting traffic when an Advanced WAF/ASM policy is bound). Implement all three modes, signing, hit evidence to SIEM, and version-based auto-retirement. This proves the embedded-VM + lifecycle spine against a live, KEV-era-relevant bug **without touching TMM's hot path** — `bd` is a process we own and have symbols for.

**Phase 2 — control-plane daemons.**
Generalize hook points across the native daemons (httpd, tmsh, MCPD) using the **kernel-eBPF/uprobe adapter** (kernel-space, the Cisco analog — §5.1), and stand up the **separate JVM adapter** for the iControl REST stack (`restjavad`/`icrd`), since native uprobes cannot reach Java methods (§5.1). This is the clean Cisco analog and covers the bulk of historically disclosed TMOS CVEs (auth bypass, config-utility RCE, command injection) — many of which live precisely in the iControl REST surface, so the JVM adapter is not optional.

**Phase 3 — TMM internals (the prize).**
Sanctioned hook points inside TMM proper, on exceptional paths only, for the data-plane CVE classes nothing else can reach. Gated on Phase 1/2 proving the verifier, signing, and watchdog safety story.

## 13. Risks and open questions

- **VM-in-TMM stability** is the program's single biggest technical risk; the watchdog + verifier + cold-path policy are the controls, but Phase 3 should not start until they are proven in Phases 1–2.
- **Hook-point map drift** across builds — needs hard CI ownership so no build ships without a current map and no shield ships without a resolvable target.
- **Runtime maturity** — uBPF (the VM) and PREVAIL (the verifier) enter the trust path of critical infrastructure. Both are proven elsewhere (eBPF-for-Windows), permissively licensed, and small, but they must build against the TMOS base OS toolchain (a prototype built both on the RHEL-8 family) and be brought under F5's own maintenance/hardening. Note PREVAIL is C++23 — it needs a modern compiler in the build pipeline.
- **Overlap/positioning** with existing Advanced WAF virtual patching and EOB — messaging must be crisp: Live Shield protects the **BIG-IP's own code (incl. TMM)**, which neither of those does, and which Cisco's kernel-eBPF Live Protect also cannot do on their forwarding engine.
- **Mode-promotion governance** — who is authorized to promote monitor→enforce, and under what change control.
- **Two control-plane adapter implementations, not one** — the native-uprobe path and the JVM path (iControl REST) are separate implementations of the single control-plane adapter (§5.1), under one catalog and lifecycle. The JVM path is the less-trodden one and carries its own runtime-maturity and overhead questions.
- **Config-sync is now in the trust path** — shields propagate as device-group objects (§7.2), so the sync channel's integrity becomes part of the shield's integrity story, and a sync-group with mixed TMOS versions must resolve hook-point maps and auto-retirement per member.

## 14. Appendix — worked example (Phase 1, CVE-2026-22548)

> *Worked example. Confirm the advisory specifics against the published F5 notification before circulating this document; the identifier and details below are used illustratively.*

Per F5's February 2026 quarterly notification, CVE-2026-22548 allows an attacker to terminate the `bd` process — disrupting traffic — when an Advanced WAF/ASM policy is bound to a virtual server, via undisclosed requests under conditions outside the attacker's control.

**Shield concept (pseudocode):**

```c
// Sanctioned FILTER hook point: bd_request_eval_decision  (attach_mode: filter)
// Enumerated outcomes owned by bd:  LS_PASS | LS_DROP | LS_RESET
// path_class: cold  (only the specific malformed condition reaches here)
// The decision point sits before bd consumes the request and before any state
// LS_DROP would have to unwind — LS_DROP is bd's existing reject branch (§6.1).
SEC("filter/bd_request_eval_decision")
int ls_2026_22548(struct bd_req_ctx *ctx) {
    if (matches_crash_precondition(ctx)) {   // narrow, SIRT-derived predicate
        ls_count(&ls_hits);                   // evidence (always)
        if (ls_mode() == ENFORCE)
            return LS_DROP;                   // bd's sanctioned reject path, pre-crash
    }
    return LS_PASS;                           // fall through to normal processing
}
```

**Lifecycle** (note this is a **crash-class** shield, so it follows the §7.1 posture, *not* monitor-first):
1. Validated in F5's lab against replayed exploit traffic and a representative legitimate-traffic corpus (§7.1, §8); false-positive confidence is established before shipment, since a real hit in production would crash `bd`.
2. Ships with `deploy_posture: enforce-on-arrival`; recommended straight to `enforce`, where the crash precondition is dropped via `bd`'s sanctioned reject path before the vulnerable code runs. Monitor is available only as a diagnostic, with the caveat that a real hit may still terminate `bd`.
3. Propagates across the device group via config-sync (§7.2). Operator installs TMOS 17.5.2 on the normal schedule; the lifecycle engine detects `version >= fixed_in_version` per member and auto-disables the shield, queuing it for removal — never leaving a still-vulnerable member unshielded.

The predicate `matches_crash_precondition` is authored and validated by SIRT against the actual exploit path, kept as narrow as possible for an ultra-low false-positive rate — the same "that condition should never legitimately occur, so we block it" philosophy behind Cisco's pinpoint shields.
