# Development scope — what F5 actually builds

Everything the embedded-eBPF substrate needs **beyond what is reused as-is** (compile, verify,
execute — clang, PREVAIL, uBPF). Derived from the worked example
([`explainers/cve-shield-walkthrough.html`](explainers/cve-shield-walkthrough.html)); step numbers
below refer to that walkthrough. Companion to
[`engine-hard-problems.md`](engine-hard-problems.md), which covers *why* the flagged items are
hard — this doc covers *what gets written, where it runs, and how often*.

The organizing fact: **nothing on this list recurs per CVE except the shield program itself** (a
few lines of C). Everything else is written once or generated automatically per build.

---

## 0. Reused as-is — explicitly *not* developed

| Component | Role | License | Status |
|---|---|---|---|
| **uBPF** | the VM + JIT (~150 KB) | Apache-2.0 | proven in the prototype (`ubpf_create/load/compile/exec`) |
| **PREVAIL** | the static verifier | MIT | proven in the prototype's verify-gate track |
| **clang** | C → eBPF bytecode | — | standard toolchain |

Nobody at F5 writes a VM, a verifier, or a compiler. The prototype (`prototype/minimm`) already
demonstrates the load-and-run half of the loader with the real uBPF API.

---

## 1. In-TMM data-plane code — ships in the substrate build

The genuinely delicate systems work: small, but must be exactly right.

1. **The trampoline** *(walkthrough step 2)* — per CPU architecture: save the hooked function's
   argument registers per the ABI, build the `ctx`, call the JIT'd program, bump the fire
   counter, apply the verdict (safe-return vs. fall-through), restore. ≈ a page of code per
   architecture, generic across all functions.
2. **Arm/disarm routine** *(step 2)* — atomic nop-pad patch + instruction-cache flush,
   coordinated across cores at the safe point. Same discipline the kernel's ftrace has used on
   live text for years — proven pattern, not research.
3. **The safe-point loader handler** *(steps 4, 10)* — processes `shield_msg`
   (`LOAD · SET_MODE · STATUS · REVOKE`): signature check → `ubpf_create/load/compile` →
   hook-map lookup → arm. Plus the unglamorous rest that is real work: **all error paths
   fail-dark** (no partial arm), expiry enforcement (auto-retire on build match), per-shield
   state (per-core fire counters, mode flags, VM teardown on unload).
4. **Signature verification in TMM** *(steps 3, 10)* — checking the signed binding against the
   baked-in public key before any bytecode is touched. Possibly reusable from F5's existing
   signed-artifact verification; net-new integration either way.

## 2. Build-pipeline tooling — runs at F5, per TMOS build

Written once; their *outputs* regenerate automatically every build (maintenance-free artifacts).

5. **Hook-map generator** *(step 3)* — from the build's debug info (DWARF/BTF): named symbol →
   entry address + typed argument layout. Output is signed and shipped with the build.
6. **ctx-descriptor emission for PREVAIL** *(steps 3, 7)* — turning those typed layouts into the
   program-type descriptor stock PREVAIL verifies against. **Flagged honestly: this is
   hard-problems §2 — "the ctx/helper/program-type ABI is the real 90%."** Mechanically simple
   per hook; the discipline and versioning around it is the substrate's biggest ongoing
   engineering surface.
7. **Safe-return policy table** *(steps 3, 12)* — per hookable function: what a skipped body
   hands back. Partly tooling, partly one-time human annotation — which is why a sane v1 scopes
   enforce-capable hooks to functions with trivial (`void`/benign) returns.

*(The `-fpatchable-function-entry` flag itself is build-system configuration, not code.)*

## 3. Control-plane / F5-infrastructure code

Conventional engineering — no novel machinery.

8. **Budget pass** *(step 8; hard-problems §1)* — admission-time cost estimator + gate: CFG
   longest-path over the verified bytecode → cycle bound, compared against the hook's
   per-invocation budget. A build artifact, off the data path; fail-closed.
9. **Signing-service integration** *(step 9)* — the binding format
   (`prog hash · hook · build range · mode ceiling · expiry`) wired into F5's existing
   HSM-backed release-signing flow. New manifest, existing infrastructure.
10. **Loader daemon side** *(steps 4, 10)* — pushing `shield_msg` over the **existing**
    control-plane config channel (the path profiles/iRules already ride), per-core fan-out,
    status/counter collection.
11. **Operator front-end** *(steps 10, 12)* — a thin `tmsh` subcommand / iControl endpoint on
    the existing management surface (illustrated as `shieldctl` in the walkthrough — **not** a
    new standalone tool). Fills the struct; reads the counters.
12. **Audit trail** *(step 4)* — every op logged: who loaded/flipped/revoked what, when.

## 4. Optional / staged tiers — not needed for the worked example

13. **Rate-limited per-firing log line** in the trampoline (evidence tier 2).
14. **Egress ring + drain agent** — per-core SPSC shared-memory ring for per-event records
    (flow tuple + timestamp), drained off the hot path; enables out-of-band synthesis of a
    suppressed log entry. Already designed:
    [`data-plane-egress-primitives.md`](data-plane-egress-primitives.md).
15. **Runtime watchdog / wall-clock deadline** — the second time-safety layer (hard-problems
    §1). A must-have before hot-path packet hooks; optional for cold-path sites like the worked
    example's log function.
16. **Canary auto-unload** — health-metric-driven auto-revoke (verified ≠ correct;
    hard-problems §4).
17. **tmmtrace** — the bpftrace-style authoring DSL. Convenience front-end only; emits the same
    bytecode the C path produces.

## 5. Recurring cost — per CVE, forever

**The shield program: a few lines of C** *(step 6)*. That is the entire marginal cost of each
new mitigation. Nothing else on this list is ever written again.

---

## 6. Shape summary

| # | Item | Runs | Written | Size class |
|---|---|---|---|---|
| 1 | trampoline | TMM hot path (when armed) | once per arch | ~1 page |
| 2 | arm/disarm | TMM, safe point | once | small |
| 3 | loader handler | TMM, safe point | once | hundreds of lines |
| 4 | sig verify in TMM | TMM, at load | once (or reused) | small |
| 5 | hook-map generator | build pipeline | once | tool |
| 6 | ctx descriptors for PREVAIL | build pipeline | once + **ongoing discipline** (§2) | tool + process |
| 7 | safe-return table | build pipeline | once + annotations | tool + process |
| 8 | budget pass | admission (at F5) | once | tool |
| 9 | signing integration | F5 infra | once | integration |
| 10 | loader daemon side | control plane | once | conventional |
| 11 | operator front-end | control plane | once | thin |
| 12 | audit trail | control plane | once | conventional |
| 13–17 | optional tiers | various | staged | staged |
| — | **shield program** | TMM, via VM | **per CVE** | **a few lines of C** |

Items 1–4: delicate, small, must be exactly right. Items 5–7: tooling with one hard design
decision (§2). Items 8–12: conventional control-plane engineering. Items 13–17: staged
follow-ons. Nothing is a subsystem on the scale of "write a VM or a verifier" — that is
precisely what the reuse buys.

---

*A design proposal. Security-review-worthy items feed the formal TMA (Threat Model Analysis),
a gating prerequisite. Detailed method & claims are held in a separate invention disclosure.*
