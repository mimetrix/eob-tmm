# Embedded eBPF Engine — Hard Problems & Engineering Register

### The load-bearing problems the explainers gloss — real-time, interface & scope, distributed state, security, certification, operations. What building this actually entails, surfaced up front: what's day-one vs. deferred, and the honest mitigations

**Status:** Proposal / engineering rigor · **Companions:** [`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) (the substrate + security model), [`big-ip-live-shield-design.md`](big-ip-live-shield-design.md) (lifecycle, signing, OSS posture), [`data-plane-egress-primitives.md`](data-plane-egress-primitives.md) (the SPSC egress ring), [`development-scope.md`](development-scope.md) (what F5 actually builds), [`explainers/cve-shield-walkthrough.html`](explainers/cve-shield-walkthrough.html) (the worked example)
**Audience:** TMM core engineering, architecture, F5 SIRT / security review, product & certification

---

The pitch is "verified ⇒ safe, stock PREVAIL, no helpers." That is true as far as it goes, and
it is the right *floor* — but the hard parts of actually *building* it span several places the
explainers understate: real-time behavior, interface and scope, shared state, the trust surface,
and productization — **engineering as much as security.** This is the honest register — surfaced
up front, not waiting for a review to reveal it — with where each problem lands. **None is a show-stopper** — each has a known
mitigation and a clear day-one/deferred path. They are the work to do, not a verdict against
doing it.

> **This design is not self-certifying.** Everything here is the engineering input to a **formal
> Threat Model Analysis (TMA)** by F5 security — a **gating prerequisite** before implementation,
> not a formality. The verifier/JIT-in-the-data-plane surface (§4) in particular must be
> threat-modeled and signed off. Read this register as *what to bring to that review*, not a
> substitute for it.

## 1. Termination is not WCET

**The claim to retire:** "PREVAIL proves the program is bounded, so it can't hang the poll loop."

PREVAIL proves **halting** — it bounds loop iterations via abstract interpretation, so it
*handles* loops (unlike the original kernel verifier's unroll-or-reject rule) and guarantees the
program terminates. That is safety + termination. It is **not** a **worst-case execution time
(WCET)** — the longest wall-clock time the program can actually take on the hardware.
"Halts in a finite number of steps" says nothing about fitting the budget at the hook it runs on, and even
a static **instruction-count** bound is not WCET (memory stalls, JIT variance, cache effects all
dominate).

And the resource being protected is unforgiving. TMM's poll loop is **single-threaded,
un-preemptible, run-to-completion** — there is no OS underneath to preempt an overrunning hook.
Every hook borrows cycles from the *same* loop, so a hook that cannot be preempted must be
*provably short*, and the budget is a **first-class scheduler concern**, not an afterthought:
one misjudged hook starves every flow on that core. Poll loops are managed carefully or not at all.

**Day-one mitigations — and note: no helpers, no verifier change.** Time-safety is enforced
*around* the verifier, not inside it: PREVAIL's job is unchanged, and nothing here needs a new
helper (helpers add capability, not time-safety — a helper call only adds cost). The work is
**two layers** — a static **post-verifier step** at admission (free at runtime) and a live
**runtime guardian** (small cost) — because *how many* instructions a program runs is provable
ahead of time, but *how long* they take is not.

- **A post-verifier budget pass — work to be done.** After PREVAIL clears a program (safety +
  termination), a load-time pass — running out-of-band with verification, never in TMM — bounds
  the program's cost and gates on the hook's budget:
  1. The program is already verified, so its control-flow graph is finite and every loop carries a
     proven iteration bound — which makes a **longest-path instruction count** over the CFG
     computable (WCET-*lite*, tractable precisely because unbounded code was already rejected).
     PREVAIL's loop bounds are *reused* here, not recomputed.
  2. Map that count to a conservative **cycle estimate** via a per-target cost model (most eBPF
     ops ≈ 1 cycle; loads/stores more) and compare to the hook's **budget** — a cycle allowance
     per hook and path class. **The budget is per *invocation*, and what makes an invocation affordable is
     its rate**: cost-per-invocation × invocations-per-unit-of-work must fit the loop's headroom for
     that unit of work. `path_class` *is* the rate class — `hot` fires per packet, `warm` per
     connection or per request, `cold` per exceptional event. So the same 100 ns program is noise on
     a request the proxy spends 50 µs on, significant on a packet forwarded in 200 ns, and a problem
     if it was budgeted per request and turns out to fire per packet. (Which is precisely the
     adversarial case in §5: an attacker changes a hook's *rate* without touching a line of code.)
  3. Over budget → **reject, fail closed.**
  The pass, the per-hook budget table, and the cost model are **new build work** — a stage added
  to the load pipeline (`author → clang → PREVAIL → budget pass → sign → load`), F5-owned.
- **A runtime guard — also new work, and irreducible.** A static instruction count
  is *not* wall-clock time (cache, memory stalls, JIT variance) — bounding *how many* instructions
  run cannot bound *how long* they take. So something must stop a slow run from stalling the poll
  loop as it executes — bounded-cost preemption for a loop with no OS to preempt it. *Which* mechanism
  is the trilemma below, not a settled matter. This layer has a small runtime cost and **cannot be moved to admission time.**
  Runtime/JIT engineering, not verifier or helper.
- **And the trilemma — the hardest open question in this register.** With **no preemption**, three
  mechanisms could enforce a time bound, and each costs something claimed elsewhere. **Fuel** (a
  counter at loop back-edges) is cheap and deterministic — but uBPF's own API states it *"has no
  effect on JIT'd programs,"* so fuel means **patching uBPF's JIT**, which costs the
  "reused as-is" claim on one of the three reused components. **Wall-clock** reads a clock at
  back-edges — but on aarch64 the counter ticks at tens of MHz (10–40 ns granularity) against a hot
  hook's budget of tens of nanoseconds, so it is **not measurable at the granularity that matters**
  on half the platforms. **Signals/timers** cost a syscall per invocation plus delivery jitter — a
  non-starter in this loop. So the honest position is that **fuel is the mechanism, not the optional
  extra**, and the wall-clock deadline is better understood as *reporting* than enforcement (earlier
  drafts of this register had that backwards). Decide in the room, not in month nine: which do we
  give up — the run-to-completion loop, the unmodified uBPF, or enforce on hot hooks? The available
  good answer is to fork uBPF's JIT for back-edge fuel, own it, and upstream it. One known corner worth
  keeping: uBPF's instruction limit *does* work in the **interpreter** — only the JIT ignores it — so an
  interpreter-only high-assurance build (§4) has enforceable fuel today, with no fork.
- **Budget by rate class** — a `hot` (per-packet) hook gets a tight, *measured* budget; `warm`
  (per-connection/per-request) hooks get the proxy's much larger per-unit headroom; `cold`
  (exceptional-branch) hooks are looser still. Read §5's adversarial note before trusting `cold`.
- **The budget pass is also a placement decision, not just a gate.** Once a program's cost is
  estimated at admission, "over budget" need not mean "rejected outright" — it can mean *not here*.
  The same analysis that protects the poll loop can **route**: a program that fits runs inline at
  the hot hook it asked for; one that doesn't can be admitted at a looser cold/warm hook, admitted
  only where there is headroom (a VE deployment rather than a loaded appliance), or declined in
  favour of doing that work somewhere else entirely — including capable hardware, where an
  offload path exists. Worth building the pass with that in mind: a reject/accept boolean is a
  smaller idea than a cost estimate that tells you *where* a given program belongs.
- **`path_class` is an assumption an adversary can break.** A hook's rate class is a claim about code
  structure, not about traffic. An attacker who can drive the malformed input that reaches a `cold`
  error branch turns it into the hottest path on the box — same program, same hook, a rate class it was
  never budgeted for. So for anything reachable from unauthenticated input, read `path_class` as
  **structure ∧ adversarial reachability**, and treat it as `hot` regardless of where it sits in the
  code. This is why the runtime guard is gating for attacker-reachable hooks rather than staged.
- **Interpreter mode** for the most sensitive builds makes per-instruction cost predictable (and
  see §4 — it also shrinks the native-code surface).

**And the budgets are measurable, not guessed — which is the value proposition arriving mid-problem.**
Setting a per-hook budget, and catching one at risk, is itself an *observability* task, and it's exactly what a
few **designed-in USDTs** would expose: per-iteration poll-loop duration (`tmm:rt:poll_iter`), per-hook execution
cost, and a stall/overrun tripwire (`tmm:rt:poll_stall`). The engine ends up **instrumenting the very loop it runs
in** — so the same surface that makes this problem tractable *is* the observability capability the engine exists
to provide. Describing the problem and demonstrating the payoff turn out to be one move.

## 2. The context / helper / program-type ABI is the actual project

**The claim to retire:** "the base tier is a trivial pure function of `ctx`."

The VM is the easy ~10%. The 90% is **interface design**: TMM's **`ctx`** (what a program sees —
which fields of the flow, the buffer, the profile), the **verified helper surface** (map access,
connection-table lookup, pool select, header rewrite), and the **map model**. For a designed-in
USDT, that `ctx` is a *permanent, versioned* interface — ship it in the per-build hook-point map
+ BTF and you carry it forever. For a function-boundary probe, the `ctx` is the function's typed
arguments — **build-specific, regenerated and re-validated every build** from the signed hook
map; more reach, a looser contract. Getting either wrong is expensive. Even the base-tier
read-only `ctx` is real design work.

**The good news, stated precisely:** this work is exactly the input PREVAIL is designed to
consume. The verifier task is **"write the program-type descriptor"** (`ctx` layout + memory
regions + helper prototypes), **not "modify the verifier."** So the *no-verifier-fork* claim
survives — but the effort estimate in the explainers does not.

**Put concretely, the designed-in half of that interface *is* a catalog of well-defined USDTs** — one per hook,
each a curated `ctx` — and the other half is the per-build typed-argument map that **function-boundary probes**
read. Together they are the ceiling on what the engine can observe or enforce: the USDT catalog bounds the
*anticipated* surface; function-boundary probes extend reach to any named function whose arguments expose the
fault. Getting both right isn't incidental to the project; it *is* the project. This is where the design effort
earns its keep — the difference between a toy and a platform.

**Day-one vs. deferred:**

- **Day-one:** a minimal, **read-only `ctx` per hook** (curated fields, no helpers) + its
  program-type descriptor for PREVAIL, plus the auto-generated typed-arg `ctx` for
  function-boundary probes (from the signed per-build hook map). Genuine work — but **not a blank page**: TMM's code already holds the state
  these USDTs expose (the connection table, the TLS record layer, the L7 parser state, the `bd`/plugin internals,
  the poll-loop counters), so the first USDTs are a *curated window onto structures that already exist* and the
  surface can begin the day the engine lands.
- **Deferred, per use case:** every helper is a new ABI to secure, a new verifier prototype, and
  a new soundness surface. Add helpers only when a use case forces it; `ctx`-first, helpers-later.

## 3. Maps under CMP and connection mirroring

**The claim to retire:** "maps work like they do in Linux."

TMM is not one kernel — it is **N core-pinned instances per box (CMP)**, plus **connection
mirroring to an HA peer**. So map/state semantics (per-CPU vs. shared, and reconciliation with
TMM's *existing* flow-state sync) are a harder concurrency problem than the Linux single-kernel
case, not an easier one.

**Day-one vs. deferred:**

- **With the helper tier (deferred): per-CPU maps only**, no cross-TMM sharing — the base tier
  has no map access at all. Per-CPU matches TMM's core-pinned model — no locking — and aligns
  with the SPSC-per-core egress rings already specified in
  [`data-plane-egress-primitives.md`](data-plane-egress-primitives.md).
- **Failover state rides TMM's existing mirroring channel**, not a bolted-on eBPF-map sync.
  Do not reinvent HA state replication inside the map layer.
- **Deferred / governed:** shared *writable* maps across TMMs need an explicit concurrency +
  reconciliation model. Read-mostly *config* maps (published from the control plane, RCU-style)
  are the easier first step if sharing is ever required.

**The trap:** treating eBPF maps as if TMM were a single Linux kernel. It is N kernels with their
own state-sync fabric; the map model must defer to that fabric, not compete with it.

## 4. Verifier soundness is a data-plane RCE surface

**This is the one a security review will (correctly) fixate on.** uBPF JITs native code into
TMM's address space — the crown-jewel process of a security appliance. An **unsound PREVAIL** or
a **buggy JIT** is arbitrary execution inside TMM. Linux has burned through many verifier CVEs;
embedding the mechanism relocates eBPF's single biggest risk class into the data plane.[^src]

**The perimeter is the signing gate, not the verifier — and the design already implies it.**
Only **F5-signed bytecode ever reaches the in-TMM JIT** — PREVAIL runs earlier, inside F5's
admission pipeline, never on attacker-supplied input. Therefore a verifier-soundness bug is
**not remotely triggerable by traffic** — exploiting it *also* requires compromising the signing
key. That collapses the risk from **traffic-borne RCE** to **supply-chain / insider**, a
different and much smaller tier. This is the strongest argument in the whole design and it must
be made explicitly: *the signing gate keeps attacker-controlled input away from the JIT
entirely, and the verifier never runs on-box at all.*

**Defense-in-depth residual (because the signing gate is now load-bearing):**

- **Signing-key protection** — HSM-backed, F5 root of trust. This is the real perimeter now;
  treat it accordingly.
- **JIT hardening** — W^X, guard pages; consider validating JIT output before execution.
- **Interpreter-only high-assurance build** — trade JIT speed for a smaller (or zero) native-code
  surface on the most sensitive deployments.
- **Tracked CVE surface** — keep PREVAIL/uBPF current; carry both in the SBOM (ties to the OSS
  posture in the shield design §13).

**The open ask: make the verifier auditable, not just trusted.** "How do you know the verifier is
sound?" has no satisfying answer of the form *"it's widely used."* The answer that does work is
**inspectability** — tooling that steps through the abstract interpretation so a reviewer can see
why a program was accepted, and so the verifier itself can be unit-tested against adversarial
inputs. That is the form soundness evidence has to take for a TMA, and it is worth establishing
early whether PREVAIL offers it, whether it can be built alongside, and what a soundness-evidence
package would actually contain. Treat it as a deliverable of the trust story, not an afterthought:
the signing gate bounds *who* can exploit a soundness bug, but only auditability reduces the
chance there is one.

**Verified ≠ correct.** A verified, signed program can still **black-hole all traffic** — drop
everything, misroute, degrade — because the proof is about memory-safety and termination, not
intent or correctness. The design needs a **control-plane canary / watchdog that auto-unloads on
a health signal** (traffic-drop, latency, error-rate), on top of the instant kill-switch and
revocation. The safety proof bounds the blast radius from *crashes*; the canary bounds it from
*bad-but-valid* programs.

**This is squarely a TMA item.** The threat model must center on verifier and JIT soundness,
the signing key as the real perimeter (and its protection), and the interpreter-vs-JIT trade for
high-assurance builds — with F5 SIRT sign-off gating implementation, not following it.

## 5. Further TMM-specific concerns

- **Item zero — the safe point itself.** Every in-TMM item above assumes "a safe point between
  poll-loop iterations that dequeues and processes a load request." That does not exist in TMM today.
  Building it means a per-instance message queue reachable from the config channel, **a new check in
  the poll loop** (one load and branch per iteration, on the loop this organisation guards hardest),
  and a bounded work budget for the handler — because as first sketched, `do_load` performs an ELF
  parse and a **JIT compile** *at* the safe point, which is milliseconds during which the loop is not
  polling: a latency spike, possibly a dropped heartbeat. Move compile and page population off the
  safe point; leave it publishing a pointer and patching a few bytes. **This is the most expensive
  item on the list and it was previously not on the list.**

The four above are load-bearing. These are the next tier — each has a stance and none changes
the day-one posture, but the safe point and certification are the most likely to shape the first shippable form.

- **Certification (FIPS 140-2/3, Common Criteria).** A certified security appliance that can load
  code into its data plane at runtime is a certification problem — evaluators may not accept
  "it's signed" as sufficient, and it can force a **dynamic-load-disabled certified mode** for
  gov/finance deployments. Possibly the biggest *productization* gate; take it to certification
  early, not late.
- **Keep the verifier out of TMM.** PREVAIL is heavy C++/Boost; it should verify at **build/sign
  or control-plane time**, so only the small uBPF runtime (+ a signature check) lives in TMM's
  address space. Stated, this shrinks the §4 surface; left unstated, a reviewer assumes a large
  dependency in the crown-jewel process.
- **uBPF JIT maturity.** §4 is really "the verifier *and this JIT*." uBPF's arm64/x86-64 JIT is
  far less battle-tested than the kernel's, and here a JIT bug is the RCE. Plan to
  **audit/harden/fork it**, or default to the **interpreter** on high-assurance builds.
- **The optimiser decides the hookable set, not us.** `-fpatchable-function-entry` pads the entries of
  functions the build actually emits out-of-line. At `-O2` that is a *subset* of the source: an
  inlined function has no entry of its own; `-fipa-icf` **folds identical functions**, so one pad may
  serve two source names and arming "A" also arms "B"; and `ipa-cp`/`ipa-sra` emit **clones**
  (`foo.constprop.0`, `foo.isra.0`) whose symbol name *and argument list* differ from the source, so a
  `ctx` derived from the source signature would be wrong. Three consequences worth stating before
  anyone promises reach: the hook map must be generated from the **emitted** symbols and must reject
  or disambiguate folded ones (the generator's `DW_AT_low_pc` test silently drops inlined statics —
  see `development-scope-code.md` item 5); the hookable set is knowable **per build** but is not the
  set of functions an engineer can name from reading the code; and guaranteeing a *specific* function
  stays hookable across releases means marking it `noinline`, which is a **source change** with a
  perf cost — so "no source modification" holds for the mechanism, not for a guarantee about any
  particular target. Day one: publish the hookable set as a build artifact and treat it as the
  contract, rather than implying every named function qualifies.
- **Invocation granularity — per-packet bytecode on a partly batched data plane.** eBPF's calling
  convention takes **one `ctx`, once**: it cannot express "here is a vector of 256 packets." A data
  plane whose performance comes from a stage seeing an entire batch at once — so it can loop and
  prefetch across the batch — would therefore be a poor host for bytecode, because a per-packet
  callback inside such a stage forfeits its whole premise. **TMM is the favorable case, and it is
  worth stating plainly:** run-to-completion and core-pinned, processing per-flow/per-packet through
  a stack rather than as a vector through a graph, so a per-invocation hook fits the existing
  control flow. What remains is per-invocation overhead where TMM *does* batch — burst receive on
  hot paths. The answer there is a **burst-capable invocation form**, with §1's budget pass
  reasoning **per burst** rather than per packet. Note honestly what a burst form does *not* buy:
  it amortizes call overhead while still running one invocation per packet with its own `ctx`; the
  program still cannot reason across the batch. If a future hook ever needs cross-packet reasoning,
  that is a different program model, not a tuning exercise.
- **Patching live text, and safe-return correctness.** The function-boundary mechanism arms by
  atomically overwriting a compiler-reserved nop pad in live text (the ftrace discipline: atomic
  patch + i-cache flush) — proven in kernels, but new inside TMM and per-CPU-architecture work
  that must be exactly right. And a safe-return skips the hooked function's *whole body*:
  deciding what a skipped body may safely not do (and what it must hand back) is a per-function
  judgment recorded in the signed safe-return policy — the reason a sane v1 restricts
  enforce-capable boundaries to functions with trivial returns.
- **Multi-tenancy — partitions, route domains, vCMP.** BIG-IP is deeply multi-tenant, and vCMP
  guests each run their own TMM. A program's **scope** (global vs. per-virtual-server /
  per-partition), its **authorization**, and its **blast radius** must be tenant-aware from day
  one — the governance model cannot be single-tenant.
- **ISSU / hitless upgrade + failover.** F5 sells zero-downtime upgrades. Loaded programs need
  defined behavior across an in-service upgrade and HA failover — **re-verify and reload on the
  new TMM**, with explicit map-state handling. (Extends §3.)
- **Jitter-sensitive deployments.** Trading, 5G UPF, and similar won't tolerate *any* added
  per-packet jitter, even budgeted. Expect a **per-hook / per-deployment opt-out**; "dark until
  lit" is ~a branch, but a populated hot hook costs real cycles.

## 6. Sequencing — day-one vs. deferred

| Concern | Day-one | Deferred / governed |
|---|---|---|
| **Time safety** | instruction-budget ceiling; runtime deadline/watchdog gates hot-path hooks (may trail for cold-path-only) | tuned per-hook budgets from field data |
| **Interface** | read-only `ctx` per hook + program-type descriptor | helper tier (map access, rewrite, lookup) |
| **State** | no maps (base tier); when helpers land: per-CPU maps, failover via TMM's existing mirroring | shared writable cross-TMM maps |
| **Execution** | interpreter or hardened JIT; W^X | — |
| **Trust perimeter** | signing gate + HSM key protection | — |
| **Blast radius** | canary/watchdog auto-unload + kill-switch + revocation | automated health-driven rollback policies |

## 6.1 The honest size of it

An earlier draft of the scope described this as "hundreds of lines, not subsystems." Reviewed against
what each item actually requires, a defensible v1 on two CPU architectures is **50–80
senior-engineer-months**, staffed as five to six people over ten to fourteen months, plus the TMA and
certification engagement. The items that grew most: the safe point (§5, previously unlisted), the
trampoline (a page of assembly, then months of ABI edge cases), arm/disarm (live-text patching,
possibly a memory-manager change), and the hook-map generator — a parameter classifier over DWARF
implementing the platform calling conventions, against an optimised build.

The reframe that matters: **the subsystem being added is not the VM.** It is a code-patching,
live-text, dynamic-code-loading facility inside the crown-jewel process, with its own build-pipeline
toolchain and a permanent per-build ABI. That is worth building — but describing it as smaller than it
is doesn't make it easier to fund, it makes the funding collapse in month nine. Hence the ask: a
**one-quarter feasibility phase**, not the whole register — measure the always-on cost of the padding
flag (kill criterion ~1% pps), settle a `ctx` model that verifies, and arm one hook end-to-end in a
lab TMM with core dumps still readable.

## 7. The honest one-liner

> The verifier gives you memory-safety and termination — **not** WCET, **not** correctness, and
> **not** immunity from its own bugs. The engine is defensible because the **signing gate** keeps
> attacker input away from the JIT (the verifier never runs on-box), a **budget + watchdog**
> bounds execution time, and a **canary** bounds the blast radius of a valid-but-bad program. Verification is one layer
> of several — the floor, not the whole building.

---

> **IP note.** Novel method & claims are held in a separate invention disclosure (gitignored),
> per policy; this document is engineering rigor only.

[^src]: Sharper still given the source-code exposure — an adversary holding the code can hunt
    verifier/JIT soundness bugs directly. Which is exactly the point: secrecy was never the
    defense; the signing gate is. The perimeter holds whether or not the source is public.
