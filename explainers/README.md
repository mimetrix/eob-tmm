# Explainers — index

> **Accuracy note (2026-08-13).** These pages were written when this was a proposal. The data-plane
> mechanism now **runs on a live TMM** — load, arm, disarm, no restart — and designed-in call sites
> have been **removed** in favour of patched function entries. Any page still written in
> "embed this and you get…" voice about *those* parts is describing something that now exists, and is
> being corrected page by page. Two things are still genuinely unproven and must stay in the
> conditional: **no CVE has been mitigated on live traffic**, and **per-call hook cost is
> unmeasured** ([`../load-path-scope.md`](../load-path-scope.md) §7).

| Page | What it covers | Read |
|---|---|---|
| [`programmable-dataplane-engine.html`](programmable-dataplane-engine.html) | The engine as a general capability — hooks, the `ctx` model, safety, form-factor coverage | 15 min |
| [`cve-mitigation.html`](cve-mitigation.html) | The CVE-mitigation case in plain language, with the perimeter argument and coverage limits | 8 min |
| [`cve-shield-walkthrough.html`](cve-shield-walkthrough.html) | A real TMM NULL-deref crash class end to end: 4 build steps, 9 runtime steps, the eBPF program line by line | 20 min |
| [`engine-hard-problems.html`](engine-hard-problems.html) | The engineering register — time safety, the `ctx` ABI, shared state, the trust surface, thirteen further concerns, day-one vs. deferred sequencing, honest scope | 20 min |

Order: engine → cve-mitigation → walkthrough → hard-problems. The engine page is
generic on purpose; **if** read after the CVE pages, it reads as a security feature rather than the
programmability surface it is.

## Elsewhere in the repo

- [`../development-scope.md`](../development-scope.md) — what F5 builds, item by item, with a per-item status column. uBPF is **no longer reused as-is**: F5 carries a patch (`../substrate/ubpf-patches/`).
- [`../development-scope-code.md`](../development-scope-code.md) — a candidate code skeleton per item, with real/stubbed/TODO marked.
- [`../design-review-findings.md`](../design-review-findings.md) — the author's own adversarial review and its dispositions, including the findings that changed the design.
- [`../engine-hard-problems.md`](../engine-hard-problems.md) · [`../embedded-ebpf-substrate.md`](../embedded-ebpf-substrate.md) · [`../big-ip-live-surface-design.md`](../big-ip-live-surface-design.md) — the long-form docs these pages are distilled from.
- [`../substrate/`](../substrate/) — the candidate ABI artifacts and their checkers: a header whose `_Static_assert`s pin the loader message's wire layout, a hook-map schema, an admission-time budget pass with a self-test, and a check that fails the build if the safe-return two-gate rule regresses. **These check themselves** (`make -C substrate check`). The same sources are compiled into TMM, where the mechanism has run: loaded over a socket into an already-running process, armed while traffic flowed, disarmed. That part is not reproducible from this repo alone — it needs the TMM build tree and the cluster.

## Canonical sources

Where a fact is defined once and referenced everywhere else. An explainer that disagrees with one of
these is the thing that's wrong.

| Fact | Defined in |
|---|---|
| **What the proposal assumes** — split into known, controlled, and assumed, with the two that end the case if false | [`../big-ip-live-surface-design.md`](../big-ip-live-surface-design.md) §1.1 |
| The host-owned outcome set | [`../embedded-ebpf-substrate.md`](../embedded-ebpf-substrate.md) §2 |
| What must be true for a hook to reach a given CVE, and that the fraction of real advisories clearing those bars is unknown | [`../big-ip-live-surface-design.md`](../big-ip-live-surface-design.md) §10.1 |
| `path_class` as the rate class, read as structure ∧ adversarial reachability | [`../engine-hard-problems.md`](../engine-hard-problems.md) §1 |
| What is and is not supported when several programs are armed or running | [`../engine-hard-problems.md`](../engine-hard-problems.md) §3.1 · §3.2 |
| ~~The first experiment, and the three forms the mechanism can take~~ — **run, and decided: form B, patched function entries. Designed-in call sites were removed from the TMM tree 2026-08-13.** Kept as the record of why | [`../design-review-findings.md`](../design-review-findings.md) §4 · [`../mechanism-tradeoff.md`](../mechanism-tradeoff.md) |
| Hook-map schema | [`../substrate/hook_map.schema.json`](../substrate/hook_map.schema.json) |
| Loader ABI + wire layout | [`../substrate/shield_abi.h`](../substrate/shield_abi.h) (compiles; asserts its own offsets) |
| Per-item scope, ranked by how far the original sizing was off | [`../design-review-findings.md`](../design-review-findings.md) §5 |
| Scope of the whole (subsystem, not a feature) | [`../engine-hard-problems.md`](../engine-hard-problems.md) §6.1 · [`../design-review-findings.md`](../design-review-findings.md) §5 |

## Open

No performance numbers exist yet. Every cost claim — "free when dark," "tens of nanoseconds is
noise" — is an estimate, which is why the first thing to settle is a measurement.
The experiment is specified in [`../design-review-findings.md`](../design-review-findings.md) §4, together
with the three forms the mechanism can take depending on what it returns.
