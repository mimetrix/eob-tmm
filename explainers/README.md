# Explainers — index

| Page | What it covers | Read |
|---|---|---|
| [`programmable-dataplane-engine.html`](programmable-dataplane-engine.html) | The engine as a general capability — hooks, the `ctx` model, safety, form-factor coverage | 15 min |
| [`cve-mitigation.html`](cve-mitigation.html) | The CVE-mitigation case in plain language, with the perimeter argument and coverage limits | 8 min |
| [`cve-shield-walkthrough.html`](cve-shield-walkthrough.html) | A real TMM NULL-deref crash class end to end: 4 build steps, 9 runtime steps, the eBPF program line by line | 20 min |
| [`engine-hard-problems.html`](engine-hard-problems.html) | The engineering register — time safety, the `ctx` ABI, shared state, the trust surface, thirteen further concerns, day-one vs. deferred sequencing, honest scope | 20 min |
| [`post-build-report.html`](post-build-report.html) | **Post-build.** The state after building the mechanism: four seams (patch own code · trampoline+VM · safe swap · joined) run and measured on the bench, the numbers, the current toolchain, and the honest last mile to a live TMM | 10 min |

Order: engine → cve-mitigation → walkthrough → hard-problems. The engine page is
generic on purpose; **if** read after the CVE pages, it reads as a security feature rather than the
programmability surface it is.

## Elsewhere in the repo

- [`../development-scope.md`](../development-scope.md) — what F5 builds, item by item, and what is reused as-is.
- [`../development-scope-code.md`](../development-scope-code.md) — a candidate code skeleton per item, with real/stubbed/TODO marked.
- [`../design-review-findings.md`](../design-review-findings.md) — the author's own adversarial review and its dispositions, including the findings that changed the design.
- [`../engine-hard-problems.md`](../engine-hard-problems.md) · [`../embedded-ebpf-substrate.md`](../embedded-ebpf-substrate.md) · [`../big-ip-live-shield-design.md`](../big-ip-live-shield-design.md) — the long-form docs these pages are distilled from.
- [`../substrate/`](../substrate/) — the candidate ABI artifacts and their checkers: a header whose `_Static_assert`s pin the loader message's wire layout, a hook-map schema, an admission-time budget pass with a self-test, and a check that fails the build if the safe-return two-gate rule regresses, plus harnesses that arm the real trampoline and run verified shields on a dev box. **Bench artifacts, not a shipping prototype — no shield runs inside a live TMM.**

## Canonical sources

Where a fact is defined once and referenced everywhere else. An explainer that disagrees with one of
these is the thing that's wrong.

| Fact | Defined in |
|---|---|
| **What the proposal assumes** — split into known, controlled, and assumed, with the two that end the case if false | [`../big-ip-live-shield-design.md`](../big-ip-live-shield-design.md) §1.1 |
| The host-owned outcome set | [`../embedded-ebpf-substrate.md`](../embedded-ebpf-substrate.md) §2 |
| What must be true for a hook to reach a given CVE, and that the fraction of real advisories clearing those bars is unknown | [`../big-ip-live-shield-design.md`](../big-ip-live-shield-design.md) §10.1 |
| `path_class` as the rate class, read as structure ∧ adversarial reachability | [`../engine-hard-problems.md`](../engine-hard-problems.md) §1 |
| What is and is not supported when several programs are armed or running | [`../engine-hard-problems.md`](../engine-hard-problems.md) §3.1 · §3.2 |
| The first experiment, and the three forms the mechanism can take depending on its result | [`../design-review-findings.md`](../design-review-findings.md) §4 |
| Hook-map schema | [`../substrate/hook_map.schema.json`](../substrate/hook_map.schema.json) |
| Loader ABI + wire layout | [`../substrate/shield_abi.h`](../substrate/shield_abi.h) (compiles; asserts its own offsets) |
| Per-item scope, ranked by how far the original sizing was off | [`../design-review-findings.md`](../design-review-findings.md) §5 |
| Scope of the whole (subsystem, not a feature) | [`../engine-hard-problems.md`](../engine-hard-problems.md) §6.1 · [`../design-review-findings.md`](../design-review-findings.md) §5 |

## Open — and now partly measured on a bench

The first experiment specified in [`../design-review-findings.md`](../design-review-findings.md) §4 —
can a process patch its own running code so that *execution* sees the change — has been **run and
answered yes**. [`post-build-report.html`](post-build-report.html) carries that result and the other
bench measurements: VM per-call cost (~10 ns JIT / ~48 ns interpreter), code footprint, and the
safe-swap soaks (billions of calls, zero corrupt returns). These are **bench numbers from candidate
artifacts on a dev box**, not a shipping TMM under production load — the entry-padding cost *at rate*
and behaviour inside TMM's real poll loop remain open. Nothing runs a shield inside a shipping TMM.
