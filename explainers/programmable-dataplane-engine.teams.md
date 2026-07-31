**THE PROGRAMMABLE DATA PLANE — a verified eBPF engine for TMM**
_A design proposal. (Teams-pasteable companion to the visual explainer; same content, no HTML.)_

The whole thing in three terms: **runtime · programmable · provably safe.**

---

**00 · Machine speed — the hook**

In the generative-AI world, everything ships at machine speed — a config push, a hot reload, a redeploy, a security mitigation, a new capability in minutes. The data plane already flexes at its edges (config, traffic logic), but changing its **own code and behavior** still waits on a release train.

**The fix:** give TMM its own eBPF engine — a verified VM at designed-in hook points — so its code and behavior can change at runtime, provably safely. Load a program, prove it safe, run it in-process: no rebuild, no reboot, no release train.

---

**01 · The holdout**

TMM is fast because it left the kernel behind — and that's exactly why it's hard to change. It's a kernel-bypass microkernel: its own network stack, its own memory manager, its own scheduler (a core-pinned poll loop that never syscalls for traffic). That's **why it's fast** — and **why it's opaque and rigid.**

The industry's answer to safely changing a running system is eBPF *in the kernel*. But TMM bypassed the kernel, so kernel eBPF is structurally blind to everything TMM does with traffic. Changing TMM today means the slow lane:

```
change today:  C source → rebuild → re-qualify → release train   (weeks–quarters)
```

Two planes:
- **Control plane** — Linux daemons (httpd, tmsh, MCPD, iControl REST). Kernel eBPF reaches this. ✓
- **Data plane** — the TMM microkernel: own stack, poll loop, plugin processes, kernel-bypassed. Nothing outside can see in. ✗

**Say it plainly: TMM is its own kernel.** It plays every role Linux plays for the traffic it carries. Linux earned an eBPF VM inside it for exactly this job — a kernel of TMM's standing and maturity deserves its own eBPF hosting VM.

**And TMM's shape is the favorable one.** DPDK and VPP extend their data planes with native-code plugins, which is right for a *toolkit* — the third party's code *is* the data plane, its author owns the crash risk, and a rebuild is cheap. TMM is a **shipped appliance**: F5 owns the source (so designed-in hooks exist at all), can't ship a mitigation that might take the data plane down (so the proof is the requirement), and a rebuild costs a maintenance window. Even the execution model favors us — eBPF takes one `ctx` at a time and can't express a vector, which is fatal inside VPP's vector-graph node and a non-issue in a **run-to-completion poll loop**.

---

**02 · The move**

Give TMM — a microkernel — its own eBPF. (F5 has a long history of extending programmability into the runtime data plane; this is the next step.)

It's buildable because what makes kernel eBPF safe was never the kernel — it's a **static verifier** + a **small sandboxed VM**, both libraries. The verifier proves, *before* the program runs, that it is **bounded** (every path terminates; it can't loop forever) and **memory-safe** (every load/store stays inside the bytes it was handed). Note: termination isn't the whole of hot-path safety — a per-hook time budget handles the rest (see §5.4). The verifier is the floor, not the ceiling.

Bring them inside: embed a small userspace eBPF VM (**uBPF**, ~150 KB, JIT-compiled) inside TMM's own address space, at designed-in hook points, gated by a stock verifier (**PREVAIL**). Now behavior arrives as bytecode, proven safe before it loads — a fast lane:

```
the proposal:  author → clang → PREVAIL verify → budget pass → sign → load   (hours)
```

**The mechanism exists; what's missing is the proof.** Every mature userspace data plane hit this same need and answered it with **native-code plugins** — VPP's graph nodes, DPDK applications — accepting the cost that a bad plugin takes the process down with it. That is the trade we're proposing to change, and **eBPF-for-Windows** shows the exact stack working in production: **uBPF verified by PREVAIL**, inside a shipping OS. **DPDK** also carries a userspace eBPF VM in mainline — `librte_bpf`, its *own* in-tree VM and validator, since 2018 — though honestly: still an **experimental API**, attachable only via software RX/TX callbacks, and never DPDK's headline programmability story. *The interesting part is where it's going* — it recently gained a debuggable **abstract-interpretation** validator, independently converging on PREVAIL's technique. The direction of travel in userspace data planes is toward verified bytecode, not away from it.

The hooks map onto structures TMM **already has — and new ones it will define** — so the surface starts from what's in the code today and grows with it. A candidate catalog of **USDT tracepoints** (userland statically-defined tracing — named probe points designed into the source) rides alongside the engine: L3/L4 ingress + the connection table, the TLS record layer, the L7 parsers, the plugin processes, the poll loop itself.

Nothing else brings all three properties (runtime · programmable · provably safe) in-process:
- **iRules** — runtime, but not provably safe
- **DynaD** — runtime too (an earlier scripting-based swing at exactly this, since deprecated)
- **WASM** — programmable, but bounded by a runtime kill, not a proof
- **kernel eBPF** — provably safe, but in the wrong kernel (a USDT lets it *watch* TMM, not act inside it, and traps on every hit)

**An embedded eBPF engine is the only surface that is all three, in-process** — reaching the data plane's own code and state.

Complementary, not a replacement: iRules stays the first line for traffic logic, WASM the home for rich extensions. This reaches the layer none of them can.

---

**03 · One shape — observe · act**

Observe and act are the same machinery; only the last step differs.

**What a program is:** not a process that runs on its own — a small **event handler / callback** the engine invokes at a hook, triggered by the very thing it's watching. Execution reaches that point in the code, the program fires, and it's handed a **curated context (`ctx`)**. In its simplest shape it reads `ctx` and returns a value. What the host does with that value — **record it as a metric**, use it to **stream a window of live internal state out to userspace** (discovery, RCA, debugging), or treat it as **a decision to act on** — is the host's choice, not a different mechanism.

**How you'd write one:** you write a few lines of C and compile with `clang -target bpf` — or, for one-line probes, **tmmtrace**, a proposed authoring front-end that emits the same bytecode (*bpftrace for TMM*): describe the probe in a small, familiar language and it does the rest — compile → verify → (once signed) attach at the named hook. It spans both planes from one grammar — a data-plane hook runs in the embedded VM, a control-plane hook rides kernel eBPF.

Each probe is three parts:

```
tmm:<stage>:<event>      /predicate/        { action }
  which hook              when it fires       what to do
  (tmm: or ctl:)
```

The **action** is the only part that decides observe vs. act. Same hook, same predicate — flip the verb:

```
observe:  tmm:lb:select  /args.member_load > 80/  { snapshot() }   → host records a sample
act:      tmm:lb:select  /args.member_load > 80/  { steer() }      → host steers the flow to a cooler member
```

Nothing about the VM, the verifier, or the context changed — only what the host does with the answer. That symmetry *is* the thesis: one verified surface, observation and control as equals. And read-ctx/return-value is just the floor — the hook surface is designed to grow: a widening catalog of designed-in USDTs, plus every named function the build's signed hook map already exposes.

---

**04 · What the engine unlocks**

A general-purpose programmability platform for the data plane. One engine — a verified program running at a hook — covers a wide span:
- **Deep observability** — counters, latency histograms, a flight recorder from inside a kernel-bypassed data plane; summarized with **tmmtrace** (*bpftrace for TMM*) or captured byte-for-byte with **tmmdump** (*tcpdump for TMM*).
- **New logic, telemetry & tuning** — behavior and metrics shipped as bytecode, no TMOS rev.
- **In-path control** — steer, sample, rate-limit, or gate a flow on an internal signal, decided right at the hook, inline.
- **Field diagnostics** — ship a signed probe to characterize a production issue in situ, then pull it. No debug build, no core-dump archaeology.
- **AI-authored programs** — because safety is a *proof, not trust*, a model can draft one and the verifier is a fail-closed acceptance gate; blast radius bounded before a human signs.

Every one of these is the same engine — a verified program at a hook — differing only in what the host does with the result. A new capability ships as verified bytecode, on demand, then retires — not as a TMOS release.

---

**05 · Under the hood (for engineers)**

Everything above rests on one small, in-process call, gated by a static proof.

**5.1 — The engine & its hook points.** A full in-process eBPF engine (a JIT VM running arbitrary *verified* bytecode), not a single-purpose gate. **Two kinds of hook, and the difference matters most for shields:**
- **Designed-in tracepoint (USDT)** — F5 places a named, versioned point exposing a *curated* `ctx`, a stable contract in a per-build map. The planned surface: observability, and CVEs that land where one sits. But F5 can't pre-place a tracepoint for every future bug.
- **Function-boundary probe** — attach the verified VM at the *entry/return of an existing named function* (the one that would crash, or one on its path), reading its arguments and reachable state as the `ctx`. It rides the code's existing structure, so you can hook a spot nobody instrumented ahead of time — that's how you shield an unforeseen CVE: hook the vulnerable function, read the pointer from its args, decide. No bespoke tracepoint required. (Mechanism = the kernel's own `fentry`/ftrace trampoline model, applied to TMM's own functions. See the worked example — `cve-shield-walkthrough` — shielding a real TMM CVE.)

Both stay **designed-in, not injected**: F5 owns the source and symbol table, compiles the hook capability in (patchable function entries), and attaches at a *named symbol* — never fragile offsets guessed at in a foreign process. Dark until lit. The honest trade is **stability**: a tracepoint's `ctx` is a curated, versioned contract; a function-boundary probe's is *build-specific* (function X's signature at build Y) — more reach, looser contract, re-validated per build. Either way: verified, signed, budgeted before it runs.

```c
// at a hook point: pack a curated snapshot, run the VM
struct l7_ctx ctx = { .opcode = f->opcode, .len = f->len };
ubpf_exec(vm, &ctx, sizeof ctx, &ret);
// ret is the result; the host decides what it means:
//   summarize → recorded as a counter, histogram, or ring
//   capture   → a window of state streamed out to userspace (RCA, debug)
//   act       → a decision applied — e.g. steer / rate-limit / gate
```

Base tier: programs are **pure functions of `ctx`** (read fields, return a number, call nothing). Two consequences erase the hardest parts: **no custom helpers** to secure, and **stock PREVAIL** — a bounded predicate over a typed context is its canonical case, so there's no fork in the trust path.

**5.2 — Placement: two planes, two engines, one catalog.**
- **Control plane** — Linux daemons (httpd, tmsh, MCPD; iControl REST on the JVM). Engine: kernel eBPF / uprobe (+ JVMTI for Java).
- **Data plane** — TMM microkernel + plugin processes, kernel-bypassed. Engine: **embedded uBPF (+ PREVAIL)** — the only thing that can reach inside TMM's own execution.
One front-end (**tmmtrace**) drives both; the hook namespace picks the engine (`ctl:` → kernel eBPF; `tmm:` → embedded uBPF). One DSL, two engines, one trust path.

**5.3 — Three form factors, honest coverage** (coverage scales inversely with hardware offload):
- **BIG-IP VE** — pure software, no offload → **full** coverage; the VM sees the entire path.
- **Appliance** — ePVA / FPGA / TurboFlex offload → software path only; offloaded flows are a hardware boundary.
- **BIG-IP Next (BNK)** — containerized TMM, DPU-dependent → depends on how much the DPU steers vs. lands in TMM.
Honest boundary: a flow handled entirely in silicon never enters TMM software, so an in-TMM hook can't see it (the same limit iRules and kernel eBPF already have). The L7/parser stages and plugin internals worth reaching run in software regardless.

**5.4 — Why it's safe to run inline.** Every claim leans on the verifier being right; three reasons that's a strong bet:
- **Provenance** — PREVAIL is Microsoft's eBPF-for-Windows verifier: abstract interpretation (a formal method), publicly maintained, hardened in production.
- **Narrow envelope** — used at its best-proven case: a bounded predicate over a small typed struct, no helpers, no maps.
- **Depth (the load-bearing point)** — the JIT emits native code inside TMM, and the verifier gates what reaches it — PREVAIL itself runs off-box at build/control-plane time — so an unsound verifier would still mean arbitrary code in the data plane. **But only F5-signed bytecode ever reaches the verifier or JIT** — attacker input never touches them — so a soundness bug is **not a traffic-borne RCE**; it's a supply-chain concern, gated by signing-key protection. (The load-bearing problems are catalogued in the engineering register — `engine-hard-problems`.)

**Verified ≠ secure, and verified ≠ correct.** The governance around the VM:
- **Proven before load** — bounded memory + termination, or rejected (fail closed).
- **Bounded in time, not just in steps** — termination is not a **worst-case execution time (WCET)**. Each hook adds an instruction-budget ceiling at load and a runtime deadline, so a provably-terminating program still can't overrun the poll loop's per-packet budget.
- **Signed & authorized** — signature checked before the verifier sees bytecode; a program that *acts* needs stricter authz than one that only observes; RBAC-gated.
- **Host-owned outcomes** — a program only returns a value; the host applies it, choosing among outcomes it already owns (steer / rate-limit / gate). A program can't invent control flow.
- **Context minimization** — the signed hook map declares, per hook, exactly which `ctx` fields are exposed; secrets and PII withheld by default.
- **One-way egress** — no helpers → no I/O of its own; it returns to a host-owned, schema-checked sink; only host-approved *derived* output leaves, never raw memory.
- **Governed lifecycle** — attestation/inventory, tamper-evident audit, instant kill-switch + revocation, a per-hook perf budget + watchdog, and a **control-plane canary that auto-unloads on a health signal** (a verified, signed program can still be *wrong* — black-hole or misroute traffic; the proof bounds crashes, the canary bounds bad-but-valid programs).

**5.5 — Lifecycle: nothing outlives its purpose.**

```
author → clang → PREVAIL verify → budget pass → sign → load / run → auto-retire
```

Every program can carry an expiry (a diagnostic probe when its window closes; a temporary control when it's no longer needed). No zombies.

**5.6 — The surface is built to grow.**
- **More hooks, cheaply.** Each release adds USDTs (define a `ctx`, place a hook, publish it in the signed map — each rides a build), and function-boundary hooks come with the compiler flag — no VM, verifier, or helper work either way. Every new field widens what can be observed *and* acted on.
- **Helpers — if and when needed.** Richer, stateful programs (host-map access, cross-flow state) via an *optional* helper tier later. The honest trade: helpers reintroduce an ABI to secure and verifier surface to manage — which is why the base ships without them, on stock PREVAIL.

---

**06 · The direction**

Make the data plane **runtime, programmable, and provably safe.**

The whole story, one line per beat:
- **00** — everything ships at machine speed now, but the data plane's own code still waits on a release train.
- **01** — TMM is a kernel that bypassed the kernel; nothing outside can reach inside it.
- **02** — so give it its own eBPF: verifier + VM, in-process, at designed-in hooks — complementing iRules and WASM.
- **03** — one program shape: read a context, return a value — observe it or act on it, the host decides.
- **04** — a general-purpose platform (observability, diagnostics, steering, tuning) — new capability shipped as bytecode, not a TMOS release.
- **05** — every change proven safe before it runs: signed, governed, self-retiring.

This isn't a feature request — it's a direction: give TMM the one in-process surface that is runtime, programmable, and provably safe. The parts are proven libraries; the hooks are ours to place; the safety is **a proof, not a promise.**

_A design proposal. Detailed method & claims are held in a separate invention disclosure._
