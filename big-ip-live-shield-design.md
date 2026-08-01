# BIG-IP Runtime Compensating Controls ("Live Shield")
### Design proposal — embedded userspace eBPF for between-window CVE mitigation

**Status:** Draft for architecture review
**Audience:** TMOS architecture, F5 SIRT, BIG-IP security engineering
**Scope:** On-box, vendor-authored runtime shields for TMOS's *own* control-plane and data-plane code paths
**Companion:** `embedded-ebpf-substrate.md` (the broader substrate, programmability-spectrum, hook-point catalog & security model — Live Shield is its first instance) · `explainers/cve-shield-walkthrough.html` (the worked CVE example, end to end) · `development-scope.md` (build/reuse scoping) · `substrate/` (**candidate ABI artifacts + their checkers** — shield ABI header, hook-map schema and example map, budget/offset/gate checks; **not a running prototype** — no shield executes anywhere in this repo)

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

| Plane | What runs there | Exploit classes | Shieldable by kernel eBPF? |
|---|---|---|---|
| **Control plane** | Hardened RHEL-family Linux (CentOS → Rocky). **Three runtimes, not one:** native C daemons (httpd, MCPD, logging, SNMP), a **JVM** tier (Tomcat, `restjavad`/`icrd`), and a **Node** tier (`restnoded`, iControl LX). `tmsh` is a per-invocation shell, not a resident daemon. | iControl REST auth-bypass, Config-utility RCE, command injection, privilege escalation | Yes — normal Linux processes and syscalls |
| **Data plane** | TMM — F5's own microkernel. Own scheduler, own memory manager, own TCP/IP stacks. Core-pinned poll loop; bypasses the Linux kernel for all traffic. | Malformed-input crashes, parser bugs, `bd`/enforcement-process termination, traffic-borne RCE | **No** — a uprobe *attaches* today, but it costs a kernel trap per hit inside a run-to-completion loop, and the kernel forbids overriding a return from a uprobe. Attachable; neither affordable nor enforceable |

The consequence is the central design constraint:

> **Kernel eBPF can shield the control plane, but cannot shield TMM.** Not for lack of reach — a uprobe on `tmm` attaches today — but because it cannot afford the per-hit kernel trap inside a run-to-completion loop, and cannot enforce (the kernel forbids overriding a return from a uprobe). The most damaging data-plane CVEs live exactly where kernel-based instrumentation can watch, expensively, and never act.

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
| FastL4 / hardware-offload fast paths | (c) — flow bypasses the iRule VM | hook the *software* fast path; a flow accelerated end-to-end in ePVA/FPGA bypasses TMM software, so its **contents** are out of reach — but the **offload boundary itself is software and is hookable on both sides**, which also makes declining the offload a usable mitigation (§10) |
| Internal program state — connection-table internals, memory-pool pressure, parser state machines, inter-function latency, error-branch hit-counts | (b) — no iRule command exposes it | an `observe`-mode tracepoint (§6.1) reads it in-process |
| Code-level **crash mitigation** for a malformed condition not surfaced as a clean field | (b) — condition invisible in the data model | inspect the raw argument at the vulnerable function |

Two consequences worth making explicit:

- **One substrate, two missions.** The same embedded VM and hook-point machinery serve enforcement (`filter`-mode shields, §6.1) *and* observability (`observe`-mode tracepoints) — the latter reaching internal data-plane state that kernel-based eBPF observability ("eob") cannot reach *affordably* — a uprobe can read it, at a kernel trap per hit inside the poll loop. Enforcement and observability differ only in whether the host acts on the program's return value.
- **These are condition-scoped, not a per-packet firehose.** Every use case above fires on a *specific* code path or condition (the malformed-input branch, the error path, the plugin handoff), so in steady state they cost nothing, and none of this depends on sampling. But condition-scoped is not the same as cheap: when the condition is one an attacker supplies, its *rate* is theirs to set, and the hook carries a hot-path budget however cold it looks in the source (§11).

iRules remain the **first-line** control for anything an iRule event *can* observe (§5.1, adapter 1) — they are sanctioned, well-understood, and lowest-risk. The embedded VM is for the cases above, where no iRule event, data-model field, or reachable path exists.

### 2.3 Relationship to WASM data-plane programmability

As TMM gains a **WASM** runtime for data-plane programmability, the natural question is whether that subsumes the embedded eBPF VM. It does not — they are complementary, optimized for different jobs, and WASM arriving *clarifies* the split rather than eroding it.

| | **eBPF / uBPF** | **WASM** |
|---|---|---|
| Built for | tiny, bounded **probes / hooks** | general-purpose **extensions** |
| Safety model | **statically verified before run** — PREVAIL proves bounded memory. Termination only with `--termination`, which is **off by default**, and then to a ceiling of 100,000 loop iterations (~300 µs): a bound, not a budget | sandbox *confinement* — memory-isolated, no static bound on what it reads; execution time bounded by runtime fuel/epoch kills |
| Invocation cost | ~tens of ns (direct JIT call, tiny ctx) | heavier (runtime entry, linear-memory marshaling) |
| Footprint | ~150 KB | multi-MB runtime |
| Shape | attach-at-a-point → read ctx → return verdict the host acts on and counts | call rich logic written in a full language |

The decisive differentiator for a **shield or tracepoint running inline in the poll loop** is the verifier: eBPF gives a *static proof* that the program terminates and touches only what it should, **before** it ever runs. WASM gives isolation but no static guarantee about *what* a module reads. **What eBPF does not buy us is a time bound, and we should not pretend otherwise:** termination is not a WCET, so we need fuel as well. Saying so plainly matters — attacking WASM's fuel and then depending on it is an inconsistency a reviewer finds in one pass. The real difference is how many layers there are: eBPF gives a static memory-safety proof, **plus** an admission-time budget pass over the verified bytecode, **plus** runtime fuel. WASM gives confinement plus fuel alone. You cannot safely run unverified WASM on the TMM hot path the way you can a verified eBPF program.

On the hot path specifically: **WASM pays the same per-invocation tax as uBPF — in fact more** (heavier runtime entry). So WASM is not the lighter option for per-packet hooks; if anything the verified eBPF program is. The hot-path cost (§11) is intrinsic to *any* in-data-plane runtime, not a uBPF-specific objection.

**Where WASM genuinely wins** (the honest division of labor): rich, possibly customer- or partner-authored **data-plane extensions** — a full protocol transform, a complex custom filter, substantial logic in a real language. eBPF is the wrong tool for that, and Live Shield does not claim it.

So the architecture is **both**, with a clean line:

- **WASM** = the rich programmable-extension surface (expressive power, real languages).
- **Embedded eBPF / uBPF** = the **verified, near-zero-cost instrumentation + security surface** (CVE shields, tracepoints) — where you need *proof of safety* and *hot-path cheapness*, not expressiveness.

Doing safety-critical inline shields *in* WASM would mean reinventing eBPF's verifier — which is exactly why the uBPF investment is durable: its value is the verifier + cost profile, neither of which WASM provides.

### 2.4 How iRules and WASM handle the same two problems

Both questions a reviewer asks about per-packet work — *can the existing surfaces even reach that
level, and how do they survive a poll loop?* — have answers that are useful to state, because one
supports this proposal and the other names something we give up.

**Neither reaches the packet level in the sense that matters here.** iRules are *event-gated*: they run
at sanctioned proxy events, and the lowest-level access they offer is to **collected payload** at
data-ish events (`CLIENT_DATA` / `SERVER_DATA` after a `TCP::collect`), which is per-buffer rather than
per-packet. There is no event that fires on every ingress packet, and nothing that exposes fragment
reassembly, TCP option parsing, or TLS record-layer internals — which is precisely the pre-L7 hole in
§2.1, restated from the other side. F5's WASM surface is expected to be filter-shaped in the same way
(a request/stream/chunk model rather than an L3/L4 one), though **the specific ABI should be confirmed
against the shipping implementation rather than assumed from this document.** The consequence either
way: the pre-L7 CVE classes are not reachable from those surfaces at all, which is the gap the embedded
VM exists to close.

**They survive the poll loop by three means, and only the third is a bound — which is the honest
comparison.** First, **coarse placement**: an iRule runs at a boundary where the budget is microseconds,
not inside the tight path, so most rules are cheap by construction. Second, **suspend and resume**: a
rule that must block — a cross-blade `table` lookup, a sideband connection, `after` — is *suspended*
and its flow parked, so the loop keeps turning. Third, and the actual backstop, **a watchdog that
restarts TMM** when a rule spins anyway; a runaway iRule stalling TMM is a documented failure mode
rather than a theoretical one. WASM hosts add fuel or epoch interruption, which is the same shape:
a runtime kill, not a static bound.

So the existing surfaces manage this risk and **accept** what remains. This proposal adds a static
memory-safety proof, an admission-time cost bound, and fuel — a strictly stronger position, and worth
stating plainly next to the fact that the weaker position has been in production for years (§8.1).

**But name what eBPF gives up, because it is not small: a verified program cannot yield.** iRules can
suspend mid-rule and resume; an eBPF program must run to completion in a single invocation. There is no
blocking, no sideband call, no waiting on a cross-blade lookup — not deferred to a later tier, but
architecturally unavailable. That is the real reason the division of labour exists, and it is a better
explanation than "iRules see the data model and eBPF sees the code": **anything that needs to wait
belongs in an iRule or a WASM filter, and anything that must be provably bounded belongs here.** A
program that needs state it cannot compute in one pass gets it the only way the model allows — the host
pre-computes it into `ctx`.

## 3. Why userspace eBPF (and why F5 specifically wants it)

A userspace eBPF VM runs eBPF bytecode entirely in userspace — an interpreter plus a JIT — with no dependency on the kernel eBPF subsystem. The chosen engine is **uBPF**: a small (~150 KB), Apache-2.0, embeddable VM with x86-64 and arm64 JITs. It is the same userspace execution engine Microsoft ships in eBPF-for-Windows, and one of the VMs bpftime can use (bpftime defaults to its own LLVM-based JIT) — consumed here as a **library**, not a framework. **Be exact about which half is proven:** eBPF-for-Windows' production posture is the *interpreter* plus PREVAIL, and that is what its deployment attests. uBPF's **JIT** — the half we want on a hot path — is the less mature half, and our own register flags two specifics (no working instruction limit, an unprobed 4 KiB stack frame). Proven floor for the interpreter and the verifier; owned work for the JIT.

There are two ways to get userspace eBPF into a process, and the distinction is the crux of this design (§3.1):

- **Inject** into an unmodified, running process (the bpftime model — `LD_PRELOAD`/ptrace, binary rewriting, a syscall-emulation shim). Powerful for instrumenting software you don't own, but brittle and invasive. **Evaluated and rejected** — see §3.1, on documented grounds: the kernel forbids `bpf_override_return` on uprobes, and injection needs ptrace/`LD_PRELOAD` against stripped binaries at guessed offsets. (No empirical comparison is claimed — this repo ships no running prototype of either path.)
- **Embed** the VM as a library and call it at designed-in hook points — and, via compiler-reserved entry pads, at function boundaries the build already emitted (§5.3). This is what Live Shield uses. Both halves matter: the designed-in catalog covers what was anticipated, and the function boundaries are what make an *unforeseen* CVE shieldable without a pre-placed hook.

For a customer, userspace eBPF's headline benefit would be routing around a locked-down kernel. **For F5 as the vendor that benefit is irrelevant** — we can enable kernel eBPF in our own build, and we already ship kernel eBPF in BIG-IP eBPF Observability ("eob") for Kubernetes traffic on Cloud-Native Edition.

The reason F5 specifically wants an *embedded userspace* VM is the one thing kernel eBPF can never do regardless of privilege: **TMM is a userspace process that bypasses the kernel, so a VM embedded in TMM is the only mechanism that can *act* inside TMM's own execution — and the only one that can instrument it affordably.** Be precise here, because the sloppy version of this claim is easy to disprove: kernel eBPF *can* watch in-TMM state today via uprobe or USDT. What it cannot do is pay for it (a kernel trap per hit inside a poll loop) or act on it (the kernel forbids overriding a return from a uprobe). Our kernel-eBPF "eob" illustrates the boundary — it is kernel-level, so it sees kernel-mediated traffic rather than TMM internals.

**And the vendor position is what makes the proof a requirement rather than an ornament.** Where an
operator writes and runs their own dataplane extension, they own the crash risk and can rationally
accept it — native code, full speed, full expressiveness. F5 cannot ship a customer a mitigation
that *might* put the data plane into a crash-loop, which is why static verification is the precondition for the
artifact existing at all, not a safety feature layered on afterwards. The architectural
preconditions that make this fit TMM specifically — vendor-owned source, shipped appliance, an
expensive rebuild, and a run-to-completion loop rather than a vectorized pipeline — are set out in
[`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) §1.1.

### 3.1 The vendor inversion: instrument by design, do not inject

Off-the-shelf userspace eBPF *injection* tooling (bpftime) attaches to processes the operator does not own, using ptrace/`LD_PRELOAD` injection and binary rewriting against stripped, symbol-less binaries at guessed offsets. That is brittle and invasive — and unnecessary for us. The case against it rests on documented properties, not on an experiment we can show: injection depends on ptrace/`LD_PRELOAD` and offset-guessed rewriting of a binary whose symbols are stripped, and the *acting* half is foreclosed outright — the kernel does not permit `bpf_override_return` on a uprobe, so the model cannot change a return value even when attachment succeeds (§3). Embedding sidesteps both by construction: a named call site in our own source, and a return value the host reads. **Neither path is exercised by any artifact in this repo** — the argument is architectural.

**We own TMM's source.** Therefore Live Shield does not inject into a running TMM. Instead:

- We build **first-class, sanctioned eBPF hook points** into TMM and the control-plane daemons as a designed-in instrumentation surface.
- The build pipeline emits a **hook-point map** for every TMOS build, naming stable attach points and their signatures.
- The uBPF VM is linked in as a designed-in component — **the VM, its JIT, and the loader; the verifier is *not* in TMM.** PREVAIL runs in F5's admission pipeline before signing (§8); on the box the gate is the signature over the binding (§9). Shields are authored as ordinary eBPF C and compiled with the standard `clang -target bpf` toolchain. The VM is a **library call**, **not** a runtime intrusion technique.

This single decision eliminates the two worst objections to userspace eBPF in this context: the no-symbols/brittle-offset problem (we emit a per-build map and call a named hook) and most of the injection-safety risk (no *guessed-offset* rewriting of a foreign binary: arm/disarm touches only compiler-reserved pads at named symbols in our own build — the mechanism ftrace has used on live kernel text for years). The host calls the program like any function and acts on the return — `ubpf_exec()` for the interpreter, or an indirect call through the compiled `ubpf_jit_fn` on paths where the JIT is used. Two uBPF details that matter before "like any function" is literally true: `ubpf_compile`'s prologue does an unconditional `sub rsp, 4096` with **no stack probe**, so the JIT'd call needs `ubpf_compile_ex` against a per-core preallocated stack; and the interpreter is where `ubpf_set_instruction_limit` actually works (§11).

## 4. Goals and non-goals

**Goals**
- Block a specific, known exploit path at runtime, on a running system, without reboot.
- Cover both planes: control-plane daemons and TMM internals.
- Vendor-authored, validated, and signed shields (SIRT-driven), not DIY runtime rules.
- Three operational modes (monitor / enforce / disable), full observability, and automatic retirement once the patched build is installed.
- Steady-state performance impact inside a **measured, signed-off budget** — not "negligible" as an article of faith (§11).

**Non-goals**
- Replacing patches or lifecycle discipline. Shields are temporary.
- Protecting the applications *behind* the BIG-IP — that is already covered by Advanced WAF / Distributed Cloud virtual patching. Live Shield protects the **BIG-IP's own code**.
- Shielding TMM bugs where no reachable boundary exposes the condition in its arguments, or no safe outcome exists there (see §10, residual dead zone).

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
   +--------------------+--------------------+--------------------+
   | Enforcement        | Enforcement        | Enforcement        |
   | Adapter 1:         | Adapter 2:         | Adapter 3:         |
   | iRules / WAF / AFM | ctrl-plane runtime | TMM hook points    |
   | (sanctioned today) | kernel eBPF/uprobe | embedded userspace |
   |                    | + JVM + Node       | eBPF VM            |
   +--------------------+--------------------+--------------------+
                              |
            +-------------------------------------------------------+
            |  Observability + Trust (hit evidence -> SIEM; signing) |
            +-------------------------------------------------------+
```

Transport is reused: one message family (`LOAD · SET_MODE · STATUS · REVOKE`) on the existing
control-plane config channel, applied at a safe point between poll-loop iterations and fanned out per
core. **That safe point does not exist in TMM today** — it is a new per-iteration check in the poll
loop, and it is the most expensive and most politically sensitive item in the whole programme, not an
implementation detail of the transport (`engine-hard-problems.md`, item zero). It also cannot do the
work naively sketched here: an ELF parse plus a JIT compile inline at the safe point is milliseconds
of not polling, so load must be staged off-loop and only the *arm* happens at the safe point.
Everything else follows: every op audit-logged; `REVOKE` disarms every core. "Hit evidence -> SIEM" unpacks to: per-core
fire counters in both modes via `STATUS`, a rate-limited log line, and optional per-event egress-ring
records.

### 5.1 Enforcement adapters

Three adapters, in increasing order of audacity. Crucially, **two distinct eBPF execution engines are in play, chosen by what the kernel can see** — **kernel-space eBPF** for the control-plane daemons (adapter 2), an **embedded userspace VM** for TMM (adapter 3) — plus a JVM probe surface for iControl REST. They share one signed catalog and lifecycle; only the enforcement leaf differs (the layers above are mechanism-agnostic, §5).

1. **iRules / Advanced WAF / AFM** — already sanctioned, reaches traffic-shaped exploits at the proxy. This remains the **first-line** data-plane shield for anything an iRule event can observe. Deployed via AS3 / iControl REST. Lowest risk; no new runtime.
2. **Control-plane daemon hooks** — **kernel-space eBPF** attached via uprobes at function entry/exit in the resident native daemons (httpd front end, MCPD and the other C config daemons). **Not `tmsh`:** it is a shell that runs per command and exits, so an entry uprobe on it is a category error, not a shield — anything `tmsh` does that needs shielding is shielded in MCPD, where the change actually lands. These are ordinary Linux processes the kernel *can* see, so this is the **true Cisco analog** (NX-OS uses kernel eBPF) and it reuses the kernel's own in-built BPF verifier — no embedded VM needed here. F5 already ships kernel eBPF in BIG-IP eBPF Observability ("eob"), so the engine is in-house. Low performance risk (these are not latency-critical), high CVE coverage (most disclosed TMOS CVEs are control-plane). **Note that the control plane is three runtimes, so this adapter is three implementations.** The iControl REST stack (`restjavad`/`icrd`) runs on the **JVM** — neither kernel uprobes nor native hooks reach Java methods, so it needs a distinct surface (JVMTI / USDT-style probes the runtime exposes). iControl LX (`restnoded`) runs on **Node**, needing a third again (V8 inspector / async hooks). Neither is optional if the goal is coverage of historically disclosed CVEs, and both should be counted in the scope rather than discovered later. The designed-in hook-point philosophy is identical; the adapter implementation is separate (see §12, Phase 2).
3. **TMM hook points** — **embedded userspace eBPF VM** (uBPF + PREVAIL) attaching at sanctioned points inside TMM and its plugin processes (e.g. `bd`). Userspace precisely *because* kernel eBPF, though it can attach here, cannot afford the per-hit trap and cannot enforce (§2). The crown jewel: the only mechanism that reaches data-plane-engine internals. Highest care required (§9, §10).

### 5.2 The embedded eBPF VM

- **uBPF**, linked as a library (~150 KB, Apache-2.0): an in-process eBPF VM with x86-64/arm64 JIT. Shields are authored as ordinary eBPF C and compiled with `clang -target bpf`. On the hot path the JIT is used (a shield invocation is an indirect call into native code; the interpreter is a debug/portability fallback). uBPF is the engine in Microsoft's eBPF-for-Windows and one of the VMs bpftime can use — though what that deployment proves is the **interpreter** plus PREVAIL; the JIT is the half F5 would have to own and harden (§3, §11).
- **PREVAIL** (`vbpf/ebpf-verifier`, the verifier in eBPF-for-Windows) statically verifies every shield in F5's admission pipeline, **before** it is signed — nothing unverified is ever signed, and nothing unsigned ever loads; nonzero verdict ⇒ reject (fail closed). The verifier is **load-bearing for safety** (§9). uBPF runs whatever bytecode it is given, so the verifier — not the VM — is what guarantees a shield can't read out of bounds. Two precisions on that sentence, both load-bearing: **termination is proved only when `--termination` is passed**, which is off by default — so an admission pipeline that simply shells out to PREVAIL's defaults proves memory safety and *not* halting, and passing the flag is a deliberate choice the pipeline has to make; and PREVAIL does not express a read-only `ctx`, so out-of-bounds *writes* are bounded while writes **to `ctx` are not** — hence the mandatory per-core `ctx` copy above. (PREVAIL is the verifier for *this* userspace engine; the control-plane adapter rides the kernel's own in-tree BPF verifier instead — §5.1. Two engines, two verifiers, one catalog.)
- **No helpers, no verifier extension for the core.** Both `filter` shields and `observe` tracepoints are **pure functions of the context**: they read `ctx` and return a value (a verdict, or a telemetry sample). They call nothing. So mode, hit/enforce counters, and `observe`-mode telemetry live in host memory (per-CPU on hot paths) that the **host** reads and writes *around* the call — the lifecycle engine acts on the return value; the program never touches host state directly. Two consequences: (a) **no eBPF helper functions need to be defined, registered, or secured**, and (b) **no verifier *extension*** — a bounded predicate over a typed `ctx` is the canonical case any eBPF verifier already proves. But be precise about what "stock" means, because PREVAIL has **no `--program-type` flag**: it deduces the type from the ELF *section-name prefix* against a compiled-in table, falling back to `socket_filter`. So there are two honest options — (i) ride PREVAIL's existing **`tracing`** type unchanged, which is the Phase-1 choice and puts no fork in the trust path, or (ii) register a named TMM type, which is **a PREVAIL patch set carrying a per-release rebase cost**. Either way the `ctx` descriptor itself is real, bounded work (`engine-hard-problems.md` §2). Anything stateful is handled by the host pre-computing it into `ctx`. **And that `ctx` must be a per-core scratch *copy*, discarded on fall-through — never a live view of TMM state.** PREVAIL's context descriptor is four integers (`size`/`data`/`end`/`meta`); it does not express a read-only region, so a verified program **can write every byte of its `ctx`**. Handing it the live argument frame would turn the safety mechanism into an argument-injection primitive. Helpers — letting the program manipulate host maps directly — are an **optional later tier** for richer stateful programs, not a prerequisite for Live Shield or tracepoints.

### 5.3 Native hook-point API and build-pipeline integration

This is the make-or-break engineering item.

- TMM and the control-plane daemons expose named, versioned hook points at **function entry/exit**. Not "any named function": the hookable set is **whatever survived the build as its own out-of-line body**, and that is the optimiser's decision, not ours. `-fipa-icf` folds identical bodies, so arming one arms the other; `ipa-cp`/`ipa-sra` emit `foo.constprop.0` clones with different names *and* signatures; a fully-inlined static has no out-of-line copy and therefore no pad at all; a *partially* inlined one has a pad on the out-of-line copy only, so the fire counter still climbs while the inlined call sites run unshielded — **a false success, and the failure mode to design against.** Inlining pushes the hookable boundary *outward* to the caller, so the cost is a wider skip radius rather than lost reachability. `noinline` on a chosen hook is the only hard guarantee, and it is a source change — which dents the "no source modification" claim and should be said rather than finessed.
- Every TMOS build emits a signed **hook-point map**: `{tmos_version, build_id, hook_points: [{name, addr/offset, arg_btf, attach_mode, path_class}]}` where `path_class` is the **rate class** — `hot` = per packet, `warm` = per connection/request, `cold` = per exceptional event — read as **structure ∧ adversarial reachability** (§11), `attach_mode ∈ {observe, filter}` (§6.1), and `arg_btf` is BTF type information for the hook's argument structs.
- A shield declares the hook-point *name* it targets; the lifecycle engine resolves name → offset using the running build's map. Shields are therefore version-bound but not offset-fragile.
- **The program never reads a host struct.** This is the constraint that shapes the whole `ctx` design, and it is not a stylistic preference: in PREVAIL, a load out of `ctx` yields an unconstrained `T_NUM`, and **dereferencing a number is refused** regardless of how many NULL checks precede it. So the hook map declares a *bounded pointer walk* — restricted to the chain the hooked function is itself about to dereference — and the host's **generated ctx-builder** performs that walk in ordinary native C, NULL-checked at each step, handing the program **resolved scalars**. The program branches on scalars and nothing else.
- **Argument layouts drift across builds just like addresses do**, so the ctx-builder is per-build generated code. Name→offset resolution fixes *where* a hook attaches but not the *layout of the structs the builder walks*. The build pipeline therefore emits **BTF for the TMM, `bd`, and control-plane-daemon argument structs** alongside the map, from which the builder is generated; the argument contract is re-validated per build and the signature binds a build range (`build_min..max`) — CO-RE-style relocation is at most an authoring convenience, not the correctness story; the signed bytes are what load. A shield whose referenced field no longer exists **fails closed** — rejected at re-validation, never reading a stale offset silently.
- CI gate: a shield cannot ship for a build whose hook-point map lacks its target point.

## 6. Shield object schema

```json
{
  "shield_id": "LS-TMM-PTLOG-01",
  "advisory_ref": "<K-article / CVE id of the real advisory, filled in at authoring>",
  "title": "Prevent TMM crash on NULL protocol-transfer log profile",
  "affected": {
    "modules": ["ltm"],
    "tmos_versions": ["17.1.0-17.1.3", "17.5.0-17.5.1"],
    "conditions": "listener with no protocol-transfer log profile configured"
  },
  "mechanism": "tmm_hook",            // irule | waf_policy | afm_rule | ctrl_uprobe | ctrl_jvm | ctrl_node | tmm_hook
  "hook_point": "fw_log_prot_transfer_emit",
  "attach_mode": "filter",            // observe | filter  (see §6.1)
  "payload_ref": "blobs/LS-TMM-PTLOG-01.bpf.o",
  "mode": "monitor",                  // monitor | enforce | disable — the INITIAL mode.
                                      // A crash-class shield ships enforce-on-arrival
                                      // (§7.1); the load simply never arrives in
                                      // monitor for those. Both fields are present
                                      // because posture and current mode are distinct.
  "fixed_in_version": "17.5.2",
  "path_class": "warm",               // rate class; see §11. One name only — `perf_class`
                                      // was an earlier spelling and is retired.
  "deploy_posture": "enforce-on-arrival",  // monitor-first | enforce-on-arrival  (see §7.1)
  "evidence": { "log_on_hit": "rate-limited", "fire_counter": "per-core, host-maintained" },
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

- `observe` — the program runs at function entry/exit, may read arguments and **return a value the host aggregates**, but **cannot alter control flow**. All telemetry, monitor-only points, and evidence collection use this mode. It is always safe.
- `filter` — the program runs at a **designed-in decision point** and its return value selects among a *fixed, enumerated set of outcomes the host code already knows how to take*. That set is canonical and defined once in [`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) §2 — **PASS · DROP · RESET · SAFE-RETURN · STEER · SAMPLE** — and it is six, not three. `observe` is **not** a seventh member: it is the host declining to *apply* whichever outcome the program selected while still counting it, with the same program unchanged. A `filter` point is not an arbitrary function entry; it is a location TMOS source explicitly compiles in, immediately before the vulnerable operation, at a place where each enumerated outcome leaves TMM in a consistent state — either a designed-in call site, or a **patchable function entry** drawn from the build's signed hook map, where the enumerated outcome is that function's safe-return policy.

**Why not arbitrary override.** Out of scope is an *unpoliced* synthesized return at a guessed offset
in a foreign binary (the `bpf_override_return`-on-uprobes shape the kernel itself forbids): it fakes a
return value the caller will consume while skipping the function body's side effects — cleanup, lock
release, refcount and connection-state updates — a corruption vector on a poll-loop data plane. The
sanctioned form is different: a compiler-reserved **function entry** from the build's signed hook
map, whose enforce outcome is the **safe-return recorded in the per-build safe-return policy** (or an
upstream flow-reset where no safe return exists).

**What earns an entry in that policy — two gates, in this order.** The first gate is
**skippability**, and it is the one that matters: does *not running the body* leave TMM consistent?
That asks whether a lock is held across it, whether a refcount moves, whether flow state advances,
whether an input buffer is consumed, and whether anything downstream reads an out-param the body was
supposed to fill. Closed by default: a function whose body has not been analysed is **not**
safe-returnable, and "we could not find a problem" is not the same as "there is none." Only after
skippability passes does the second gate — what value to synthesize for the return type — even
apply.

Getting that order wrong inverts the difficulty. Classified by return type alone, `void` looks
trivially safe: there is no value to fake. In fact **`void` is the hardest case**, because a `void`
function is called *entirely* for its side effects, so skipping it discards all of them and the
signature tells you nothing about what they were. A function returning an error code is often easier:
the caller already has a handling path for the failure value.

A safe-return skips the *whole* body, so benign work the body did (e.g. a log record) is lost while
enforcing; a stand-in record can be synthesized out-of-band from egress-ring events.

**The safe early-return contract.** For a `filter` hook point, the owning code path guarantees:

1. The decision point sits *before* the vulnerable operation and *before* any state an abort would have to unwind — so `LS_DROP`/`LS_RESET` is a clean branch the code already supports (typically the same path taken for a normal policy reject or malformed-input drop), not a synthesized unwind.
2. The enumerated outcomes are owned by TMOS source, not the shield. The shield only *chooses* among them; it cannot invent a new control-flow effect.
3. The verifier and the hook-point contract are **two independent safety obligations**: the verifier proves the program is safe to *run*; the `filter` contract proves the chosen outcome is safe to *take* (§9).

A CVE whose only viable interception point has no clean abort branch is, by this contract, **not shieldable by the TMM adapter** — it falls to the residual dead zone (§10) or an engineering hotfix. This is a deliberate limit: better to declare a CVE out of scope than ship a shield that returns into an inconsistent TMM.

## 7. Operational modes and auto-retirement

- **Monitor** — the shield's detection logic runs and logs hits, but takes no enforcement action. Lets operators confirm the threat and false-positive rate before enforcing. **This soak-then-promote posture is valid only for shields whose unmitigated exploit does not itself take the system down — see §7.1 for the crash-class exception.**
- **Enforce** — actively drops, resets, or safe-returns past the exploit condition.
- **Disable** — deactivates the shield without uninstalling it (fast rollback).

**Auto-retirement.** The lifecycle engine reads the running TMOS version, build, and hotfix locally and re-checks at boot — this is a local version read plus a boot hook, not the iControl-REST polling subsystem an earlier draft implied, and it is cheaper than it sounds. When the running `tmos_version >= fixed_in_version`, the shield is auto-disabled and flagged for removal. A shield can never silently outlive the patch it stands in for.

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

1. **Author** — F5 SIRT analyzes the exploit path and writes the shield (this formalizes what the Kxxxxx mitigation articles already do informally). Authoring can be **AI-assisted**: a generative model drafts a bounded predicate that the verifier and an exploit-replay gate accept before a human signs — the verifier bounds a machine-authored draft's blast radius *by proof*, so the human reviews only candidates already proven safe and effective (substrate §8.5; a separate invention disclosure holds the method).
2. **Validate** — internal SIRT pipeline checks targeting, false-positive rate, performance class, and that a clean auto-retirement path exists.
3. **Red-team** — independent validation that the shield actually blocks the exploit and cannot be trivially bypassed.
4. **Sign** — F5 code-signing over the canonicalized shield object + payload. This is **HSM release
   signing**, the same gate a hotfix passes, and it is the step that sets the clock: it is a
   process, with approvers, not an API call.
5. **Distribute** — existing update/advisory channels; the box verifies the signature over the binding
   (program hash + hook + build range + mode ceiling + expiry); PREVAIL ran earlier, at F5 — the
   signature attests it.
6. **Retire** — automatic, on patched-version detection.

**How long this takes, honestly: days, not hours.** Author → verify → budget → red-team → HSM release
signing → distribute → monitor → enforce is a multi-day pipeline dominated by the human gates, and
against a patched-build cycle measured in weeks that is still the whole value. Anyone promising
same-day mitigation is describing a different process than this one.

**So the one process change that would matter most here is a pre-authorised shield-signing path** — a standing
approval for a bounded artifact class (verified, budget-passed, hook-bound, expiring bytecode) so that
signing is hours rather than days. That single process change is what converts "days, not hours" into
"hours," and it is worth more than any engineering optimisation available here.

### 8.1 Does the verifier remove the need for the pipeline?

**Asked plainly, because it is the first thing anyone will ask about "days, not hours": if a shield is
verified bytecode rather than a code change, does it still have to be tested, certified, and installed
on a maintenance window?** The answer is no, it does not remove the pipeline — but it **re-proportions**
it, and the compression lands almost entirely in one of those three steps. That distinction is worth
making carefully, because "the verifier makes this fast" is both wrong and easy to attack, while the
real answer is defensible.

| Step | Does bytecode + a verifier reduce it? | What actually does the work |
|---|---|---|
| **Test** | **Substantially, but not to zero** | Not the verifier alone — the **bounded outcome set**. A hotfix needs full-image regression because a hotfix *can break anything*; the burden scales with the image. A shield can only select an outcome the host already owns at a hook the build declared, so its blast radius is bounded **by construction**, which is what makes a proportionate test regime defensible rather than a corner cut. What remains is irreducible: does the predicate actually match the exploit, what is its false-positive rate against a legitimate-traffic corpus, and is the chosen outcome safe to *take* (§6.1's skippability gate — a separate obligation from memory safety that no verifier addresses). |
| **Certify** | **Barely, and it may add a problem** | The verifier is close to irrelevant here: evaluators care about *what code is inside the validated boundary*, and that answer now changes at runtime. What speaks to them is the **signature**, because signed code authenticity is an established construct. This is the program's likeliest productization gate (`engine-hard-problems.md` §5), and the failure mode is a forced dynamic-load-disabled certified mode rather than a refusal. |
| **Install** | **Yes — and this is where the value is** | Nothing about the artifact requires a reboot, a failover, or a maintenance window; `REVOKE` reverses it in seconds and expiry retires it unattended. The customer-side burden drops from "window + regression risk + rollback plan" to accepting a signed content update. **Note this is also the step a faster release train cannot help with at all**, because it sits on the customer's calendar rather than F5's. |

So: **the bounded outcome set buys a proportionate test surface; the signature buys the certification
argument; and being an artifact rather than an image buys the install window.** Three mechanisms doing
three different jobs — and it is worth keeping them distinct, because collapsing them into one claim
about the verifier is what makes the pitch sound like hand-waving.

**And the pipeline this belongs in already exists, which reframes the ask.** The instinct is to compare
a shield to a **hotfix**, and by that comparison every question above is hard. But F5 already operates a
vendor-authored, HSM-signed, proportionately-qualified, no-maintenance-window distribution channel for a
different artifact class: **attack-signature updates, WAF/ASM policy updates, threat feeds.** Those are
authored by F5, signed, shipped continuously, applied without a software upgrade, and qualified in
proportion to their blast radius rather than by re-testing TMOS. A shield is far more like one of those
than like a hotfix. **So the request is not "grant this an exception from the software-release process."
It is "this artifact class belongs in the content lane you already run"** — and what earns it the right
to be treated as content rather than as code is precisely the verifier plus the enumerated outcome set.
That is a much easier proposition to agree to, and it is the same argument the signing ask above rests
on.

**The precedent for running foreign logic in TMM is stronger still, because it is already customer
code.** BIG-IP lets *customers* write **iRules** — TCL executing inline on the data path — and is
gaining a **WASM** extension surface for the same purpose. Both run in TMM, on certified appliances,
authored by people F5 does not employ and cannot review. So *"this appliance executes logic that was not
in the validated image"* is not a new question here; it has an existing answer, from evaluators and from
support, and the sensible move is to find that answer and reuse it rather than re-litigate it.

Against that baseline the shield is the **more** constrained artifact on every axis that matters:

| | customer iRule | customer WASM | F5 shield |
|---|---|---|---|
| Author | the customer | the customer or a partner | **F5 SIRT** |
| Reviewed by F5 | no | no | **yes, plus red-team** |
| Static safety proof | none | none | **memory safety before it is signed** |
| Bound on what it may read | none — the whole exposed data model | sandbox boundary only | **a declared `ctx` of resolved scalars** |
| Bound on what it may do | any sanctioned iRule action | whatever its imports allow | **one host-owned outcome from a fixed set** |
| Cost bound | none; a runaway rule is a documented cause of a stalled TMM | fuel only | **admission budget pass + runtime fuel** |
| How time is ultimately bounded | coarse placement, suspend/resume for blocking work, and a **watchdog that restarts TMM** | a runtime fuel or epoch kill | **a static proof, an admission-time cost bound, *and* fuel** |
| Can it block or yield? | **yes** — suspend and resume, so a cross-blade lookup or sideband call is possible | host-dependent | **no, and this is architectural** — one invocation, run to completion. Anything that must wait belongs in an iRule or WASM filter, not here (§2.4) |
| Signed | no | no | **yes, over a binding that pins hook, build range, mode ceiling and expiry** |
| Expires by itself | no | no | **yes, on patched-build detection** |

Which **inverts the burden of proof**, and the proposal should say so rather than arguing purely
defensively. If the objection is "we cannot allow foreign logic to execute in the data plane," the
answer is that BIG-IP has allowed exactly that for years, with materially weaker controls, and that the
artifact under discussion is the most constrained thing ever proposed for that position.

**Two honest qualifications, because a good reviewer raises both immediately.**

**First, liability is the real disanalogy.** An iRule is the customer's code, on the customer's box, and
the crash risk is theirs to accept; a shield is F5's code and F5's liability. That asymmetry is genuine,
and it is not an argument against the comparison — it is the reason the proof is a *precondition* here
rather than a feature (§3). We are volunteering a higher standard than the surface next door, and the
right framing is that we hold ourselves to it because we are the author, not that we are exempt from
anything.

**Second, the precedent has a real hole, and it is exactly where the certification risk lives: the
JIT.** iRules are *interpreted*. WASM runs in a *sandboxed runtime*. Neither one **writes executable
native code into TMM's address space at runtime** — and that is different in kind, not degree, from
interpreting data. So the iRules/WASM precedent covers the interpreter path cleanly and does **not**
cover the JIT. That is an independent argument for the interpreter-only high-assurance build already
proposed as a mitigation (`engine-hard-problems.md` §1, §4): on a certified platform the interpreter is
the configuration with a precedent, and it is also the one where uBPF's instruction limit actually
works. The JIT is the part to argue for separately, with numbers.

**And one governance question this exposes that is not answered anywhere yet.** If the test regime is
proportionate rather than full-image, **who signs off that a shield is safe to ship — and is that the
same authority that signs off a hotfix, or a new one?** The comparison above suggests the answer should
look like the sign-off for a signature update rather than for a software release, but that is an
assertion, not a decision. It is a governance question rather than a technical one, and it is precisely
the kind of thing that stalls a programme in month nine if it is left until the engineering is done.
§13 lists mode-promotion governance as open; this belongs beside it.

## 9. Safety and blast radius

Unlike Cisco's kernel-isolated shields, a Live Shield in the TMM adapter runs **in TMM's address space**, so a faulty shield can fault TMM. State the harm precisely, because the imprecise version is both scarier and wrong: `sod` restarts TMM within seconds and an HA pair fails over, so a single fault is a blip. **The harm that matters is a repeatable crash-loop** — a shield that faults on a condition the traffic keeps supplying drops every flow on that TMM each time and can flap HA. That is worse than a one-shot crash, and it is what the watchdog below is actually for. Mitigations:

- The **userspace verifier is mandatory** and runs in F5's admission pipeline before signing; unverifiable bytecode is rejected.
- On the box, signature verification over the binding gates load (§8); only F5-signed payloads load in production — the signature, not an on-box verifier run, is the security perimeter.
- Default deploy mode is **monitor** for logic/auth-bypass shields; crash-class shields ship **enforce-on-arrival** (§7.1). Promotion to enforce — whichever the default — is always an explicit, logged action.
- Shields default to **`cold`/`warm` `path_class` hook points** (§11 — where `path_class` is structure ∧ adversarial reachability); **hot-path hooks are permitted under a measured per-invocation budget + explicit sign-off** (§11), not banned. Note that the default is about *structure*, and it does not exempt a hook from the budget: the worked example in §14 is a `warm` logging path that is nonetheless reachable by anyone who can open a flow, so it carries a measured budget and sign-off exactly as a `hot` hook would. **A cold-looking hook an attacker can pump is a budgeted hook** — the two questions are separate, and the second one is the one that decides cost.
- Per-TMM-instance watchdog: if a TMM instance restarts within N seconds of a shield load, the lifecycle engine auto-disables that shield and raises an alert.
- The **enforcement contract (§6.1) is a second, independent safety obligation**: the verifier proves the program is safe to *run*; the `filter` hook-point contract proves the chosen outcome is safe to *take*. A shield must satisfy both, and a hook point with no clean abort branch is simply not a `filter` point.

## 10. Residual dead zone (state honestly)

This is the right-hand-column residual from the §2.1 coverage map. Two things fall outside this mechanism, and both are shared by every *software* control surface (iRules, WASM) — they are not unique to it:

1. **No boundary exposes the condition, or no safe outcome exists there.** A TMM bug is unshieldable where no reachable boundary exposes the triggering condition in its arguments — e.g. a fault deep in TLS record parsing whose trigger is not visible at any earlier hook — or where the only interception point has no safe outcome (§6.1); an iRule (the event never fires) or kernel eBPF (TMM bypasses the kernel) cannot catch these either. For the flow-hook fallback, the hook-point map should push the earliest viable instrumentation point as close to ingress as performance allows, shrinking this zone over time.

2. **Traffic offloaded to hardware — but be precise, because this splits three ways and an earlier draft
   of this document got one of them wrong.** On appliances with **ePVA / FPGA (TurboFlex) / crypto
   offload**, some flows are switched or mitigated in silicon. An embedded userspace VM runs *in TMM
   software*, so:

   - **The flow's contents while it is in silicon are genuinely invisible.** A packet accelerated
     end-to-end never presents itself to a software hook. This is a hardware boundary, not a shortcoming
     of the mechanism, and it is the same FastL4/offload hole iRules and kernel eBPF have (§2.2).
   - **The offload *boundary* is not invisible at all — it is ordinary TMM software, and it is
     hookable on both sides.** Deciding to accelerate, escalate or reject; building the descriptor
     handed to the accelerator; receiving a flow back on escalation; and handling completions, errors
     and counters — all of that executes in TMM. So there are hook points **before the accelerator is
     invoked and after it returns**, and an earlier draft of this section was wrong to file *"a CVE in
     the offload/escalation decision"* alongside silicon bugs as needing a firmware fix. A bug in that
     decision, in descriptor construction, or on the escalation-return path is a **software** bug in
     code we own, reachable and shieldable like any other. Error and completion paths deserve
     particular attention, because that is where crash bugs concentrate.
   - **A bug *inside* the silicon, or in a pure-L4 vector that stays fully offloaded, does need a
     firmware/FPGA fix** — that part stands.

   **Two consequences worth taking, both of which improve the proposal.** First, **coverage stops being
   unknowable and becomes measured**: a hook at the offload decision is what tells you how many flows
   went to silicon, which resolves the ambiguity that otherwise makes a zero count useless — "no
   attempts", "attempts handled in hardware" and "wrong TMM instance" become distinguishable rather
   than conflated. Second, **declining the offload is itself a mitigation.** At a designed-in decision
   point, `STEER` can mean *do not accelerate this flow* — pushing it onto the software path where the
   rest of this mechanism applies. That buys reach into a class of flows the shield could not otherwise
   touch, at a real and bounded cost: matching flows lose acceleration for as long as the shield is
   armed. It is a throughput-for-coverage trade, made explicit, and available only because the decision
   was in software to begin with.

   The high-severity classes this design targets — L7/parser bugs, `bd`/WAF-plugin termination — execute
   in TMM software regardless, since a flow needing L7 inspection is escalated off the offload path
   anyway. So they were never in this dead zone.

### 10.1 What has to be true for a function-boundary probe to reach a given CVE

**The claim to be careful with is "an unforeseen CVE needs no pre-placed hook."** The defensible version
is narrower and worth stating precisely, because the loose version invites a demolition: **no
*bug-specific* tracepoint has to have been anticipated.** That is the real advance over a designed-in
catalog alone, and it is genuinely large. It is *not* the same as "any data-plane CVE is shieldable," and
four things still have to hold:

1. **A surviving boundary on the path, before the fault.** The hookable set is whatever the build emitted
   as its own out-of-line body (§5.3). Inlining does not remove reach, but it pushes the usable boundary
   *outward* to a caller — and the further out it goes, the more a safe-return discards along with the
   bug. Past some radius the only honest answer is that the boundary is too coarse to use.
2. **The condition has to be derivable from that boundary's arguments**, through the declared bounded
   walk the host's ctx-builder performs. **And note the timing, which is the constraint people miss:** an
   entry probe fires *before the body runs*, so a condition the body itself constructs is not visible to
   it. A malformed-frame state assembled inside a parser, or one accumulated across several earlier
   frames, is not reachable from the entry arguments of the function that faults. What you need is a
   boundary *downstream* of where the condition becomes determinable and *upstream* of the fault — and
   that window may contain no function boundary at all.
3. **A safe outcome has to exist there** — the skippability gate of §6.1, or a clean upstream flow reset.
   A boundary that exposes the condition perfectly but cannot be skipped or aborted is not a `filter`
   point.
4. **The budget has to allow it** at that boundary's rate class, read as structure ∧ adversarial
   reachability (§11). This one is a policy block rather than an impossibility, but it is a real block.

Two whole classes sit outside regardless: **hardware-offloaded flows** (item 2 below), and anything at
all before **the enabling build ships** — the mechanism itself rides one release train, once.

**And the honest position on coverage is that we do not know the fraction.** Nobody has taken a set of
real, published F5 data-plane advisories and asked, per CVE, whether conditions 1–4 hold. Until that is
done, any statement about how many data-plane CVEs this would have caught is an assertion. **That study
is cheap, it needs no engineering, and it is the single most decisive artifact this proposal could
acquire** — it either establishes the coverage claim with evidence or right-sizes the whole programme
early. If the answer turns out to be "a minority, and mostly in one subsystem," that is a smaller and
still-worthwhile project, and far better learned now.

**Form-factor consequence.** The *mechanism* (an embedded VM at designed-in hooks) is identical across appliance, VE, and BIG-IP Next for Kubernetes, because all three run the same TMM data plane. **Coverage** is not: **BIG-IP VE** (pure software, no offload) is the best case — the VM sees the entire data path; an **appliance** carries the offload dead zone above; **BNK** on a DPU depends on how much traffic the DPU steers versus lands in the containerized TMM. Coverage scales inversely with how much the platform offloads to hardware.

Live Shield narrows the window for most data-plane CVEs; it does not claim to close all of them. Those in the residual zone require an engineering hotfix.

## 11. Performance

Userspace eBPF is not free, but the embedded model is the cheap end of it. With the **JIT**, a shield invocation is an indirect call into native code plus the program's own handful of instructions. Order **tens of nanoseconds** — which is emphatically *not* "comparable to a C `if`" (that is sub-nanosecond); the invocation overhead, not the program, is what costs. The repo's budget pass makes the point concretely: the three worked predicates price at **6–17 cycles**, far under any plausible hook budget, so the thing to measure first is the trampoline's register save/restore. Crucially there is no syscall and no kernel trap: a designed-in call site is a direct call, and a patched function entry costs one jump into F5's own in-process trampoline — which is why this is far cheaper than injection/uprobe approaches (a published bpftime comparison of an `sslsniff` workload put kernel-uprobe overhead around 58% against roughly 12% for the userspace equivalent — cite the source before using the figure, note it is *that* workload rather than TMM, and note the userspace number still carried attach/trampoline indirection an embedded call does not). A hook point with no shield loaded costs one predictable branch **at runtime** — but the pads are not free in the build: `-fpatchable-function-entry` adds 5–8 bytes to every emitted function, and across O(10^5) functions that is a plausible 3–8% text inflation carried as unconditional i-cache and i-TLB pressure by every customer forever, whether or not a shield ever loads. **Free at runtime; a measured build-time footprint cost** — and measuring it is the first deliverable of the feasibility phase (§12), not an assumption.

**First, what `path_class` actually means.** The budget is **per invocation**; what makes an invocation affordable is the *rate* at which it fires, so `path_class` **is** the rate class — `hot` = per packet, `warm` = per connection or request, `cold` = per exceptional event. And it has to be read as **structure ∧ adversarial reachability**, not structure alone. A malformed-input handler is structurally cold and in steady state costs nothing; it is also the branch an attacker drives, and at line rate it is the hottest code on the box. **Anything reachable from unauthenticated input at attacker-controlled rate is budgeted `hot`, wherever it sits in the source.** That correction is what makes the rest of this section honest: the genuinely cheap case is a cold path *an attacker cannot pump*, and it is narrower than "cold" alone suggests. It is also not the only useful case — a CVE whose trigger appears in *ordinary* traffic, and per-flow telemetry or detection, are inherently **hot-path**, and both are legitimately valuable. Hot-path placement is therefore a **measured budget decision, not a prohibition**. Policy:

- `path_class` (`hot`/`warm`/`cold`) in the hook-point map makes placement **informed**, not banned: a `hot` hook is allowed when it carries a **measured per-invocation cost and a throughput/latency budget with explicit sign-off**. Cold/warm is the default; hot requires justification + numbers.
- Hot-path hooks use **per-CPU** state (no cache-line contention across core-pinned TMM instances). **The JIT carries a tension to resolve, not to gloss:** `ubpf_set_instruction_limit` "has no effect on JIT'd programs," so the fuel guard a hot hook depends on requires **a uBPF JIT patch F5 owns** — the limit *does* work in the interpreter, which is the one place it is least needed. Wall-clock is reporting rather than enforcement, since `CNTVCT_EL0` ticks at 10–40 ns against a hot-hook budget of tens of ns. See `engine-hard-problems.md` §1.
- **A per-hook budget is necessary and not sufficient.** The admission pass gates one program against one hook's allowance, which says nothing about many hooks armed together — and hooks on the same flow's path are not independent, so **a flow pays the sum of every armed hook it traverses**, not the maximum. That needs a global armed-cost ceiling in the loader, and it is one of four things that only appear once more than one program is armed (`engine-hard-problems.md` §3.1 — the others being one-program-per-hook enforcement, cross-hook masking, and mutual re-entrancy).
- Every shield/tracepoint carries a `path_class` and a measured overhead figure from the validation pipeline; acceptance is "within the signed-off budget," not necessarily "indistinguishable from baseline." **Every number in this section is currently an estimate** — no measurement exists yet, which is precisely why §12 asks for one before anything else.
- This cost is **intrinsic to any in-data-plane runtime, not specific to uBPF** — a WASM filter or an iRule on the same hot path pays the same kind of per-event tax (heavier, in WASM's case; see §2.3). The lever is the cost/value trade per hook, made explicit and measured — e.g. a few percent of throughput to close an actively-exploited CVE is an easy trade during the exposure window.

## 12. Phased delivery

**Phase 1 — MVP (in TMM, on a non-hot path, against a real bug).**
Embed the userspace eBPF VM and ship one shield against **a designed-in call site on a `warm`/`cold` TMM path** — the worked example in §14. Note that non-hot is a claim about *structure*, and §14's hook is still attacker-reachable, so it carries a measured budget like any other (§9). Implement all three modes, signing, hit evidence to SIEM, and version-based auto-retirement.

**Not `bd`, despite the temptation.** `bd` looks like the safe first target because it sits off the hot path, but it is the *hardest* one. It is multi-threaded C++ with no poll loop and therefore **no defined safe point** for delivery — which §5 requires — plus mangled names, references and by-value structs in its signatures, and RAII destructors that a skipped body silently fails to run. A designed-in TMM call site is both easier and a better proof, because it exercises the in-TMM spine (the VM, the safe point, the trampoline, per-core fan-out) that Phases 2–3 depend on. `bd` follows once that spine exists.

**Phase 2 — control-plane daemons.**
Generalize hook points across the resident native daemons (httpd, MCPD, and the other C config daemons — not `tmsh`, which is a per-invocation shell) using the **kernel-eBPF/uprobe adapter** (kernel-space, the Cisco analog — §5.1), and stand up the **separate JVM adapter** for the iControl REST stack (`restjavad`/`icrd`) plus a **Node adapter** for iControl LX (`restnoded`), since native uprobes reach neither (§5.1). Three runtimes, three implementations — that is the honest scope of "the control-plane adapter." This is the clean Cisco analog and covers the bulk of historically disclosed TMOS CVEs (auth bypass, config-utility RCE, command injection) — many of which live precisely in the iControl REST surface, so the JVM adapter is not optional.

**Phase 3 — TMM internals (the prize).**
Sanctioned hook points inside TMM proper for the data-plane CVE classes nothing else can reach. Default `cold`/`warm`; a `hot` hook is permitted under a measured per-invocation budget with explicit sign-off (§9, §11) rather than banned outright. Gated on Phase 1/2 proving the spine: the safe point, signing, the fuel guard, and the crash-loop watchdog.

**Scope, so the phases are not read as equal or small.** A defensible v1 across both supported
architectures is **subsystem-scale work, not a feature** — the reframe that matters is that the
subsystem being added is not the VM but a code-patching, live-text, dynamic-code-loading facility
inside the crown-jewel process, with its own build-pipeline toolchain and a permanent per-build ABI.
The TMA and certification engagement are gating prerequisites rather than paperwork. Per-item scope is
in [`engine-hard-problems.md`](engine-hard-problems.md) §6.1 and
[`design-review-findings.md`](design-review-findings.md) §5; **neither offers a month figure, on
purpose** — this is a proposal, not a plan.

**None of which has to be committed to in order to evaluate this.** Three questions decide whether the
rest is worth designing, and the first is a *measurement* rather than a feature: the dark cost of
building TMM with `-fpatchable-function-entry` (throughput, latency distribution, text size, i-cache
behaviour). **Kill criterion, stated up front: if the padding flag costs more than ~1% of pps, the
function-boundary half of this proposal is dead** and only designed-in call sites survive. The other
two are a `ctx` model that actually verifies against real TMM debug info, and one hook armed end-to-end
in a lab TMM with core dumps still readable. Naming the number that would kill this is what makes the
rest of it worth taking seriously.

## 13. Risks and open questions

- **VM-in-TMM stability** is the program's single biggest technical risk; the watchdog + verifier + cold-path policy are the controls, but Phase 3 should not start until they are proven in Phases 1–2.
- **Hook-point map drift** across builds — needs hard CI ownership so no build ships without a current map and no shield ships without a resolvable target.
- **Runtime maturity** — uBPF (the VM) and PREVAIL (the verifier) enter the trust path of critical infrastructure. Both are proven elsewhere (eBPF-for-Windows — for the interpreter and the verifier; **not** for the JIT), permissively licensed, and small, but they must build against the TMOS base OS toolchain — **unverified here; no build of either against a TMOS-family toolchain is demonstrated in this repo** — and be brought under F5's own maintenance/hardening. Note PREVAIL is C++23 — it needs a modern compiler in the build pipeline. **This risk is bounded by the no-helpers/pure-predicate model (§5.2): the core defines *no* custom helpers and rides PREVAIL's existing `tracing` program type, so there is no verifier fork in the trust path and no helper ABI to secure — the maturity work is "consume and harden," not "extend."** A *named* TMM program type would be a PREVAIL patch set with a per-release rebase cost, and Phase 1 deliberately does not take it. The helper tier, if pursued later, is what would reintroduce verifier-integration surface.
- **Licensing & OSS posture — an enabler, not a blocker.** Both core components are **permissively licensed and safe to statically link into a proprietary appliance**: uBPF is **Apache-2.0** (with an express patent grant — net-positive alongside the parallel invention disclosure), PREVAIL is **MIT**, and PREVAIL's build dependency Boost is under the permissive **Boost Software License**. Nothing in the primary path is copyleft, so there is **no source-disclosure obligation** — only routine NOTICE/attribution preservation, already handled for other TMOS OSS. This is *enabling*, not merely acceptable: the counterfactual verifier is the Linux kernel's in-tree eBPF verifier, which is **GPLv2 and cannot be lifted into a userspace product** — permissive PREVAIL is precisely what makes an embeddable, shippable verifier possible, and what makes the "consume and harden" posture above legally real. Two items to close:
  - **OSPO action (the only real risk):** abstract-interpretation verifiers sometimes link **copyleft numeric-domain libraries** — PPL is GPLv3; APRON and parts of ELINA are LGPL. Current PREVAIL appears to use its own vendored domains (CRAB heritage, Apache-2.0) rather than PPL/APRON, but the transitive dependency tree drifts by version. **Pin the PREVAIL commit and run an SBOM + license scan** (`syft` / Scancode / FOSSA) to confirm no GPL/LGPL in the shipping path. A small, bounded task that converts "probably clean" into "verified clean," and it should gate Phase 1.
  - **For patent counsel (FTO note):** MIT (PREVAIL) carries **no patent grant**; Apache-2.0 (uBPF) does. A low-but-nonzero freedom-to-operate consideration worth one line alongside the filing — some verification technique in PREVAIL could in principle be third-party patented.
- **Overlap/positioning** with existing Advanced WAF virtual patching and EOB — messaging must be crisp: Live Shield protects the **BIG-IP's own code (incl. TMM)**, which neither of those does. Resist the temptation to extend that into a claim about Cisco's silicon: Live Protect covers **NX-OS**, and asserting what it cannot do on their forwarding engine is unverifiable and invites a correction. The defensible statement is about the technique — runtime patching of live text is well established (ftrace, kernel livepatch, kernel error injection); what no vendor ships is that technique **inside a proxy data plane**.
- **Mode-promotion governance** — who is authorized to promote monitor→enforce, and under what change control.
- **Shipping authority for a proportionately-tested artifact** (§8.1) — if a shield is qualified in proportion to its blast radius rather than by re-testing TMOS, **who signs off that it is safe to ship?** The same authority as a hotfix, or the one that releases attack-signature content? The comparison in §8.1 argues for the latter, but that is an assertion and not a decision, and it is a governance question rather than a technical one. Settle it early: it is the class of item that stalls a programme once the engineering is finished.
- **Two control-plane adapter implementations, not one** — the native-uprobe path and the JVM path (iControl REST) are separate implementations of the single control-plane adapter (§5.1), under one catalog and lifecycle. The JVM path is the less-trodden one and carries its own runtime-maturity and overhead questions.
- **Config-sync is now in the trust path** — shields propagate as device-group objects (§7.2), so the sync channel's integrity becomes part of the shield's integrity story, and a sync-group with mixed TMOS versions must resolve hook-point maps and auto-retirement per member.

## 14. Appendix — worked example

> *This example is deliberately **not** attached to a CVE identifier.* The bug is real and the shield
> is the one worked end to end in [`explainers/cve-shield-walkthrough.html`](explainers/cve-shield-walkthrough.html);
> what is missing is a published advisory to anchor it to. **Before this document circulates, rework
> it against a specific published, closed F5 advisory and its actual patch diff** — which is worth
> doing on its own merits, because a retrospective "would this have been shieldable?" study over the
> last several quarters of real advisories is the single most persuasive artifact this proposal could
> carry, and it is cheap to produce. A plausible-looking but invented CVE number is the opposite: SIRT
> will look it up inside five minutes and the rest of the document inherits the doubt.

**The bug.** TMM's protocol-transfer logging path fetches a listener's log profile and reads its name
with no NULL check:

```c
struct fw_log_profile_protocol_transfer *ptlp =
    flow_get_listener(cf)->prot_transfer_log_profile;
const char *str = ptlp->name;      // ptlp is NULL when no profile is configured
```

When a flow's listener has no protocol-transfer log profile, `prot_transfer_log_profile` is NULL, the
read faults, and the data-plane process dies. Anyone who can open a flow to such a listener can
trigger it, so it is remotely reachable without authentication.

**Shield concept (pseudocode):**

```c
// Sanctioned FILTER hook point: fw_log_prot_transfer_emit  (attach_mode: filter)
// Enumerated outcomes owned by the host:  LS_PASS | LS_SAFE_RETURN
// path_class: warm  (once per request on this listener — structurally the
//   logging path, but reachable by anyone who can open a flow, so it is
//   budgeted by rate, not by how exceptional the source looks)
// The function returns void and its body's only effect is emitting a log
// record, so the skip is analysable: no lock is held across it, no refcount
// moves, no flow state advances, nothing downstream consumes an out-param.
// That is what earns it a safe-return entry — not the fact that it is void.
SEC("tracing/fw_log_prot_transfer_emit")
int ls_ptlog_nullderef(struct ctx *c) {
    /* The program does NOT consult the mode. It always selects the outcome its
       predicate implies; the host applies it in enforce and merely counts it in
       observe (substrate §2 — observe is not a seventh outcome). Gating mode
       inside the program would make a monitor-mode hit indistinguishable from
       a miss, which is exactly what the fire counters exist to tell apart.

       Two scalar loads, one branch, no call, no loop, no pointer chase. The
       host's generated ctx-builder already walked cf -> listener -> profile in
       native C, NULL-checked at each step; the program sees what that resolved. */
    if (!c->listener_present || !c->log_profile_present)
        return LS_SAFE_RETURN;                // skip the body that would deref NULL
    return LS_PASS;                           // fall through to normal processing
}
```

**What the shield does and does not restore.** It stops the crash. It does **not** reproduce the
corrected behaviour: the real fix substitutes a placeholder string for the NULL and still emits the
log record, whereas a safe-return skips the whole body, so **while the shield is enforcing, affected
flows produce no protocol-transfer log record at all.** That is a real, and acceptable, trade against
a crash — but it has to be stated to operators rather than discovered by them. The shield's own
per-core fire counter is the evidence that it is working; the missing log line is the cost.

**Lifecycle** (a **crash-class** shield, so it follows the §7.1 posture, *not* monitor-first):
1. Validated in F5's lab against replayed trigger traffic and a representative legitimate-traffic
   corpus (§7.1, §8); false-positive confidence is established before shipment, because a real hit in
   production would crash TMM.
2. Ships `deploy_posture: enforce-on-arrival`, recommended straight to `enforce`. Monitor is
   available only as a diagnostic, with the caveat that a real hit still crashes the process.
3. Propagates across the device group via config-sync (§7.2). The operator installs the patched build
   on their normal schedule; the lifecycle engine detects `version >= fixed_in_version` per member and
   auto-disables the shield, queuing it for removal — never leaving a still-vulnerable member
   unshielded.

Note that the predicate is written inline above rather than as a call: eBPF permits no arbitrary function calls, so any helper factored out of a predicate has to be `static inline` / `__always_inline` or the program will not compile. The predicate is authored and validated by SIRT against the actual crash path and kept as narrow as
possible, for an ultra-low false-positive rate — the same "that condition should never legitimately
occur, so we block it" philosophy behind Cisco's pinpoint shields.
