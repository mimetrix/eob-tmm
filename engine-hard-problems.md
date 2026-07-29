# Embedded eBPF Engine — Hard Problems & Engineering Register

### The load-bearing problems the explainers gloss — real-time, interface & scope, distributed state, security, certification, operations. What building this actually entails, surfaced up front: what's day-one vs. deferred, and the honest mitigations

**Status:** Proposal / engineering rigor · **Companions:** [`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) (the substrate + security model), [`big-ip-live-shield-design.md`](big-ip-live-shield-design.md) (lifecycle, signing, OSS posture), [`data-plane-egress-primitives.md`](data-plane-egress-primitives.md) (the SPSC egress ring)
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
"Halts in a finite number of steps" says nothing about fitting TMM's per-packet budget, and even
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
     per hook and path class, derived from the poll loop's per-packet headroom.
  3. Over budget → **reject, fail closed.**
  The pass, the per-hook budget table, and the cost model are **new build work** — a stage added
  to the load pipeline (`author → clang → PREVAIL → budget pass → sign → load`), F5-owned.
- **A runtime wall-clock deadline — also new work, and irreducible.** A static instruction count
  is *not* wall-clock time (cache, memory stalls, JIT variance) — bounding *how many* instructions
  run cannot bound *how long* they take. So a per-execution **deadline + watchdog** — bounded-cost
  preemption for a loop with no OS to preempt it — is what actually stops a slow run from stalling
  the poll loop. This layer has a small runtime cost and **cannot be moved to admission time.** (An
  instruction **fuel** counter is *optional* here — redundant with the admission bound; the
  wall-clock deadline is the piece you can't skip.) Runtime/JIT engineering, not verifier or helper.
- **Budget by path class** — hot hooks (per-packet) on a tight measured budget; cold/error-path
  hooks looser.
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
connection-table lookup, pool select, header rewrite), and the **map model**. That `ctx` is a
*permanent, versioned* interface — ship it in the per-build hook-point map + BTF and you carry it
forever; getting it wrong is expensive. Even the base-tier read-only `ctx` is real design work.

**The good news, stated precisely:** this work is exactly the input PREVAIL is designed to
consume. The verifier task is **"write the program-type descriptor"** (`ctx` layout + memory
regions + helper prototypes), **not "modify the verifier."** So the *no-verifier-fork* claim
survives — but the effort estimate in the explainers does not.

**Put concretely, that interface *is* a catalog of well-defined USDTs** — one per hook, each a curated `ctx`.
Getting them right isn't incidental to the project; it *is* the project: the USDT set is the **ceiling on
everything the engine can ever observe or enforce** (a hook can only act on what its `ctx` exposes), and it is the
permanent ABI. This is where the design effort earns its keep — the difference between a toy and a platform.

**Day-one vs. deferred:**

- **Day-one:** a minimal, **read-only `ctx` per hook** (curated fields, no helpers) + its
  program-type descriptor for PREVAIL. Genuine work — but **not a blank page**: TMM's code already holds the state
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

- **Day-one: per-CPU maps only**, no cross-TMM sharing. This matches TMM's core-pinned model —
  no locking — and aligns with the SPSC-per-core egress rings already specified in
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
Only **F5-signed bytecode ever reaches the verifier/JIT.** Therefore a verifier-soundness bug is
**not remotely triggerable by traffic** — exploiting it *also* requires compromising the signing
key. That collapses the risk from **traffic-borne RCE** to **supply-chain / insider**, a
different and much smaller tier. This is the strongest argument in the whole design and it must
be made explicitly: *the signing gate keeps attacker-controlled input away from the verifier and
JIT entirely.*

**Defense-in-depth residual (because the signing gate is now load-bearing):**

- **Signing-key protection** — HSM-backed, F5 root of trust. This is the real perimeter now;
  treat it accordingly.
- **JIT hardening** — W^X, guard pages; consider validating JIT output before execution.
- **Interpreter-only high-assurance build** — trade JIT speed for a smaller (or zero) native-code
  surface on the most sensitive deployments.
- **Tracked CVE surface** — keep PREVAIL/uBPF current; carry both in the SBOM (ties to the OSS
  posture in the shield design §13).

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

The four above are load-bearing. These are the next tier — each has a stance and none changes
the day-one posture, but the first two are the most likely to shape the first shippable form.

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
| **Time safety** | instruction-budget ceiling + runtime deadline/watchdog | tuned per-hook budgets from field data |
| **Interface** | read-only `ctx` per hook + program-type descriptor | helper tier (map access, rewrite, lookup) |
| **State** | per-CPU maps; failover via TMM's existing mirroring | shared writable cross-TMM maps |
| **Execution** | interpreter or hardened JIT; W^X | — |
| **Trust perimeter** | signing gate + HSM key protection | — |
| **Blast radius** | canary/watchdog auto-unload + kill-switch + revocation | automated health-driven rollback policies |

## 7. The honest one-liner

> The verifier gives you memory-safety and termination — **not** WCET, **not** correctness, and
> **not** immunity from its own bugs. The engine is defensible because the **signing gate** keeps
> attacker input away from the verifier and JIT, a **budget + watchdog** bounds execution time,
> and a **canary** bounds the blast radius of a valid-but-bad program. Verification is one layer
> of several — the floor, not the whole building.

---

> **IP note.** Novel method & claims are held in a separate invention disclosure (gitignored),
> per policy; this document is engineering rigor only.

[^src]: Sharper still given the source-code exposure — an adversary holding the code can hunt
    verifier/JIT soundness bugs directly. Which is exactly the point: secrecy was never the
    defense; the signing gate is. The perimeter holds whether or not the source is public.
