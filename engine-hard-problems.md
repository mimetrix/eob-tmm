# Embedded eBPF Engine — Hard Problems & Security-Review Register

### The load-bearing problems the explainers gloss: what a TMM engineer and a security review will ask first, what's day-one vs. deferred, and the honest mitigations

**Status:** Proposal / engineering rigor · **Companions:** [`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) (the substrate + security model), [`big-ip-live-shield-design.md`](big-ip-live-shield-design.md) (lifecycle, signing, OSS posture), [`data-plane-egress-primitives.md`](data-plane-egress-primitives.md) (the SPSC egress ring)
**Audience:** TMM core engineering, F5 SIRT / security review, architecture

---

The pitch is "verified ⇒ safe, stock PREVAIL, no helpers." That is true as far as it goes, and
it is the right *floor* — but the real engineering and the real security exposure live in four
places the explainers understate. This is the honest register: the questions that will be
asked first, with where each one actually lands. **None is a show-stopper** — each has a known
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

**Day-one mitigations (verification is necessary, not sufficient, for hot-path safety):**

- A **per-hook instruction-budget ceiling** enforced at load — reject bytecode whose static
  bound exceeds the hook's budget. PREVAIL's iteration bounds can *seed* this ceiling, but treat
  it as a floor on the real cost, not WCET.
- A **runtime deadline / watchdog** that short-circuits or unloads a program that overruns, with
  run-to-completion accounting the program cannot starve.
- **Budget by path class** — hot hooks (per-packet) on a tight measured budget; cold/error-path
  hooks looser.
- **Interpreter mode** for the most sensitive builds makes per-instruction cost predictable (and
  see §4 — it also shrinks the native-code surface).

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

**Day-one vs. deferred:**

- **Day-one:** a minimal, **read-only `ctx` per hook** (curated fields, no helpers) + its
  program-type descriptor for PREVAIL. This is the base tier — and it is genuine work, not free.
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
embedding the mechanism relocates eBPF's single biggest risk class into the data plane. It is
**sharper given the source-code exposure**: an adversary with the source can hunt soundness bugs
directly.

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

## 5. Sequencing — day-one vs. deferred

| Concern | Day-one | Deferred / governed |
|---|---|---|
| **Time safety** | instruction-budget ceiling + runtime deadline/watchdog | tuned per-hook budgets from field data |
| **Interface** | read-only `ctx` per hook + program-type descriptor | helper tier (map access, rewrite, lookup) |
| **State** | per-CPU maps; failover via TMM's existing mirroring | shared writable cross-TMM maps |
| **Execution** | interpreter or hardened JIT; W^X | — |
| **Trust perimeter** | signing gate + HSM key protection | — |
| **Blast radius** | canary/watchdog auto-unload + kill-switch + revocation | automated health-driven rollback policies |

## 6. The honest one-liner

> The verifier gives you memory-safety and termination — **not** WCET, **not** correctness, and
> **not** immunity from its own bugs. The engine is defensible because the **signing gate** keeps
> attacker input away from the verifier and JIT, a **budget + watchdog** bounds execution time,
> and a **canary** bounds the blast radius of a valid-but-bad program. Verification is one layer
> of several — the floor, not the whole building.

---

> **IP note.** Novel method & claims are held in a separate invention disclosure (gitignored),
> per policy; this document is engineering rigor only.
