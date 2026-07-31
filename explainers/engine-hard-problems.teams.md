**ENGINE HARD PROBLEMS — an engineering register**
_A design proposal. (Teams-pasteable companion to the visual explainer; same content, no HTML.)_

The load-bearing problems building the engine actually raises — **time · the interface · shared state · the trust surface** — plus smaller concerns and sequencing. Engineering as much as security. **None is a show-stopper**; each has a known mitigation and a clear day-one path.

---

**00 · The frame**

The proposal says a verified eBPF engine is safe to run inside TMM. True — as far as it goes. This is the other half: the problems a serious engineering + security review will raise, surfaced up front. They are **the work to do, not a verdict against doing it.**

Four load-bearing themes: **time · the interface · shared state · the trust surface** — plus a set of smaller ones and a note on sequencing.

---

**01 · Time**

A proof that a program *terminates* is not a promise it fits the budget. The verifier proves every program halts (it bounds loop iterations) — that is **not** a **worst-case execution time (WCET)**: the longest it can actually take on the hardware.

_Claim to retire:_ "it's verified as bounded, so it can't hang the poll loop."

The resource is unforgiving: TMM's poll loop is **single-threaded, un-preemptible, run-to-completion** — no OS underneath to preempt an overrunning hook. Every hook borrows cycles from the same loop; one misjudged hook starves every flow on that core.

The fix is **two layers — and only one is free** (static analysis can bound how *many* instructions run, not how *long* they take):

- **① at admission · static · once, off-box — the budget pass.** Cost the worst-case path through the program's control-flow graph (finite; loops proven-bounded), compare to the hook's budget (tight on hot per-packet hooks, looser on cold paths), reject over-budget / fail closed. Bounds **instruction count**. *Runtime cost: none — a build artifact.*
- **② at runtime · every execution — the wall-clock deadline.** Instruction count is not time (warm vs. cold cache). A **deadline + watchdog** on each run is what actually stops a slow execution from stalling the loop. **Irreducible**; small per-execution cost.

Why both: ① proves the program is *small* (static, provable); ② proves it's *fast this time* (only knowable as it runs). **Size settles statically; timing does not.** (The instruction "fuel" counter is optional — redundant with ①; the wall-clock deadline is the one you can't skip.) None of this needs helpers or a verifier change — the pass, budget table, cost model, and deadline are new **F5 build work**.

Layer ①, on one program:

```
[ entry: prologue, 8 instr ] → [ loop body: 10 instr ]  ↺ ≤ 64× (proven) → [ exit: epilogue, 4 instr ]

worst case = 8 + 10×64 + 4 = 652 instr ≈ 800 cycles
   ≤ hook budget → load ✓        > hook budget → reject (fail closed) ✗
```

Build pipeline — where each step runs, what it emits, and what touches the hot path:

```
 dev / CI     F5 build + sign  (off-box, per program)     control plane   data plane
[compile] → [verify] → [budget pass] → [sign]        →     [load]      →   [run]
 bytecode    verified   +budget bound   signed program      on a hook       per packet
|————————— amortized: once per program / per build · off the data path —————————|  |— per packet · poll loop —|
```
Plus, once per **TMOS build**: the signed hook-point map, the ctx/BTF descriptors, the per-hook budget table, and the cost model.

**And the budgets are measurable, not guessed — the value prop arriving mid-problem.** Setting a per-hook budget, and catching one at risk, is itself an observability task — exactly what a few **designed-in USDTs** would expose: per-iteration poll-loop duration (`tmm:rt:poll_iter`), per-hook execution cost, and a stall/overrun tripwire (`tmm:rt:poll_stall`). The engine ends up **instrumenting the very loop it runs in**, so the same surface that makes this problem tractable *is* the observability the engine exists to provide.

---

**02 · The interface**

The VM is the easy 10%; the interface is the other 90%. What a program *sees* (the `ctx`: which fields of the flow, buffer, profile), the verified **helper surface**, and the **map model** — that is the real design, and it's a **permanent, versioned ABI** you carry once you ship it.

_Claim to retire:_ "the base tier is a trivial pure function of `ctx`."

The good news, stated precisely: this is **"write the program-type descriptor"** the verifier consumes, **not "modify the verifier"** — the no-verifier-fork claim survives, but the effort estimate doesn't.

**Put concretely, the designed-in half of that interface *is* a catalog of well-defined USDTs** — one per hook, each a curated `ctx` — and the other half is the per-build typed-argument map that **function-boundary probes** read. Getting them right isn't incidental; it *is* the project: together they are the **ceiling on what the engine can observe or enforce** — the catalog bounds the *anticipated* surface; function-boundary probes reach any named function whose arguments expose the fault — and it's the permanent ABI — the difference between a toy and a platform.

- **Day one:** a minimal, read-only `ctx` per hook + its program-type descriptor. Genuine work, but **not a blank page** — TMM's code already holds the state these USDTs expose (the connection table, the TLS record layer, the L7 parser state, the `bd`/plugin internals, the poll-loop counters), so the first USDTs are a curated window onto structures that already exist; the surface can begin the day the engine lands.
- **Deferred:** helpers — each is a new ABI to secure and a new verifier prototype. `ctx`-first, helpers-later.

---

**03 · Shared state**

TMM is not one kernel — it's **N core-pinned kernels with their own state fabric.** Multiple TMM instances per box (**CMP**) plus connection **mirroring** to an HA peer make map/state semantics *harder* than Linux's single-kernel case.

_Claim to retire:_ "maps work like they do in Linux."

- **Day one:** per-CPU maps only — no cross-TMM sharing (matches the core-pinned model; no locking). State that must survive failover **rides TMM's existing mirroring channel** — don't reinvent HA replication in the map layer.
- **Deferred:** shared, writable maps across TMMs — they need an explicit concurrency + reconciliation model.

---

**04 · The trust surface**

The JIT emits native code into **the crown-jewel process**, and the verifier decides what reaches it — PREVAIL itself runs off-box, at build/control-plane time (§05) — so an unsound verifier or a buggy JIT still means arbitrary native code in the data plane. This is the one a review will press hardest. †

**The load-bearing point: the perimeter is the signing gate, not the verifier.** Only F5-signed bytecode ever reaches the verifier or JIT — attacker-controlled input never touches them — so a soundness bug is **not a traffic-borne RCE**; it's a supply-chain concern, gated by signing-key protection.

_We're not alone on this — and that's new information._ DPDK's `librte_bpf` recently added a **validation debugging API** built to unit-test its verifier by stepping through **the abstract interpretation** — independently converging on PREVAIL's technique inside a userspace data plane. Two things follow: userspace dataplane bytecode is clearly not a dead end (someone is investing in a verifier for it *now*), and **step-through tooling is what makes a verifier auditable** — the only real answer to "how do you know it's sound?" Worth tracking as prior art for evidencing PREVAIL's soundness to a TMA.

```
attacker-controlled bytecode → signing gate            → ✗ rejected
F5-signed bytecode           → verify → JIT            → ✓ runs
```

And **verified ≠ correct**: a verified, signed program can still black-hole traffic. Day one:
- **Signing gate + HSM-backed key protection** — the real perimeter.
- **JIT hardening** (W^X, guard pages) and an **interpreter-only high-assurance build** option.
- A **control-plane canary** that auto-unloads on a health signal — the proof bounds crashes; the canary bounds a bad-but-valid program.

_† Sharper still given the source-code exposure — an adversary holding the code can hunt verifier/JIT soundness bugs directly. Which is exactly the point: secrecy was never the defense; the signing gate is — the perimeter holds whether or not the source is public._

---

**05 · Further concerns** (smaller, but real — each has a stance; the first two shape the first shippable form)

- **Certification (FIPS / Common Criteria)** — a certified appliance that loads code into its data plane at runtime is a certification problem; may force a **dynamic-load-disabled certified mode**. Likely the biggest productization gate — raise it early.
- **Keep the verifier out of TMM** — PREVAIL (heavy C++/Boost) verifies at build/control-plane time; only the small runtime + a signature check live in TMM's address space. Shrinks the §04 surface.
- **Boundary-probe ctx is build-specific.** A function-boundary probe's contract (function X's typed args at build Y) is regenerated and re-validated every build — more reach than a versioned USDT ctx, looser contract; the signed hook map and the binding's build range are what keep it honest.
- **uBPF JIT maturity** — §04 is really "the verifier *and this JIT*." uBPF's JIT is far less battle-tested than the kernel's — audit / harden / fork it, or default to the interpreter on high-assurance builds.
- **Multi-tenancy (partitions, route domains, vCMP)** — BIG-IP is deeply multi-tenant; vCMP guests each run their own TMM. A program's scope, authorization, and blast radius must be tenant-aware from day one.
- **ISSU + failover** — zero-downtime upgrades and HA failover need defined behavior: loaded programs re-verify and reload on the new TMM, with explicit map-state handling.
- **Invocation granularity — per-packet vs. batched** — eBPF's calling convention takes **one `ctx`, once**; it cannot express "here is a vector of 256 packets." That is the structural reason bytecode never displaced native plugins in **VPP**, whose whole premise is a graph node seeing the entire vector. **TMM is the favorable case**: run-to-completion and core-pinned, per-flow rather than per-vector, so the mismatch that blocks VPP largely doesn't apply. What remains is per-invocation overhead on hot hooks — DPDK's `rte_bpf_exec_burst()` is the precedent to copy, with §01's budget pass reasoning **per burst**.
- **Jitter-sensitive deployments** — trading, 5G UPF and the like won't tolerate *any* added per-packet jitter, even budgeted — expect a per-hook / per-deployment opt-out.

---

**06 · Sequencing — day-one vs. deferred**

Most of the risk retires on day one; the rest is governed and deferred.
- **Time safety** — day one: instruction-budget ceiling + watchdog · deferred: tuned per-hook budgets from field data.
- **Interface** — day one: read-only `ctx` + program-type descriptor · deferred: helper tier.
- **State** — day one: per-CPU maps, failover via existing mirroring · deferred: shared writable cross-TMM maps.
- **Execution** — day one: interpreter or hardened JIT (W^X) · deferred: —.
- **Trust perimeter** — day one: signing gate + HSM key protection · deferred: —.
- **Blast radius** — day one: canary auto-unload + kill-switch + revocation · deferred: automated health-driven rollback.

---

**07 · The reality**

The verifier is the **floor, not the building.** It gives you memory-safety and termination — **not** WCET, **not** correctness, and **not** immunity from its own bugs. The engine is defensible because the **signing gate** keeps attacker input away from the verifier and JIT, a **budget + watchdog** bounds execution time, and a **canary** bounds the blast radius of a valid-but-bad program. Verification is one layer of several.

**This design is not self-certifying.** Everything here is the engineering input to a formal **Threat Model Analysis (TMA)** by F5 security — a **gating prerequisite** before implementation, not a formality. The trust surface (§04) in particular must be threat-modeled and signed off.

The whole register, one line per problem:
- **01 Time** — termination isn't WCET; a per-hook budget + wall-clock deadline protect the un-preemptible poll loop.
- **02 Interface** — the `ctx`/ABI is the real 90%; write the program-type descriptor, don't fork the verifier.
- **03 State** — per-CPU first; failover rides TMM's existing mirroring, not a bolted-on map sync.
- **04 Trust** — the signing gate, not the verifier, is the perimeter; a canary catches bad-but-valid programs.
- **05 Further** — certification, verifier-placement, boundary-probe ctx, uBPF-JIT maturity, invocation granularity, multi-tenancy, ISSU, jitter — each addressable.
- **06 Sequencing** — the conservative half ships first; the powerful half is deferred and governed.

_A design proposal — the engineering register behind the engine explainer. Detailed method & claims are held in a separate invention disclosure._
