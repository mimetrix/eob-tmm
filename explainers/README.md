# Explainers — index

| Page | What it covers | Read |
|---|---|---|
| [`one-pager.html`](one-pager.html) | The whole proposal, one printable sheet, ending on the ask | 3 min |
| [`programmable-dataplane-engine.html`](programmable-dataplane-engine.html) | The engine as a general capability — hooks, the `ctx` model, safety, form-factor coverage | 15 min |
| [`cve-mitigation.html`](cve-mitigation.html) | The CVE-mitigation case in plain language, with the perimeter argument and coverage limits | 8 min |
| [`cve-shield-walkthrough.html`](cve-shield-walkthrough.html) | A real TMM NULL-deref crash class end to end: 4 build steps, 9 runtime steps, the eBPF program line by line | 20 min |
| [`engine-hard-problems.html`](engine-hard-problems.html) | The engineering register — time safety, the `ctx` ABI, shared state, the trust surface, twelve further concerns, day-one vs. deferred sequencing, honest scope | 20 min |

Order: one-pager → engine → cve-mitigation → walkthrough → hard-problems. The engine page is
generic on purpose; **if** read after the CVE pages, it reads as a security feature rather than the
programmability surface it is.

## Elsewhere in the repo

- [`../development-scope.md`](../development-scope.md) — what F5 builds, item by item, and what is reused as-is.
- [`../development-scope-code.md`](../development-scope-code.md) — a candidate code skeleton per item, with real/stubbed/TODO marked.
- [`../design-review-findings.md`](../design-review-findings.md) — three architect reviews and their dispositions, including the findings that changed the design.
- [`../engine-hard-problems.md`](../engine-hard-problems.md) · [`../embedded-ebpf-substrate.md`](../embedded-ebpf-substrate.md) · [`../big-ip-live-shield-design.md`](../big-ip-live-shield-design.md) — the long-form docs these pages are distilled from.
- [`../substrate/`](../substrate/) — the candidate ABI artifacts and their checkers: a header whose `_Static_assert`s pin the loader message's wire layout, a hook-map schema, an admission-time budget pass with a self-test, and a check that fails the build if the safe-return two-gate rule regresses. **Not a running prototype — nothing in this repo executes a shield.**

## Canonical sources

Where a fact is defined once and referenced everywhere else. An explainer that disagrees with one of
these is the thing that's wrong.

| Fact | Defined in |
|---|---|
| The host-owned outcome set | [`../embedded-ebpf-substrate.md`](../embedded-ebpf-substrate.md) §2 |
| Hook-map schema | [`../substrate/hook_map.schema.json`](../substrate/hook_map.schema.json) |
| Loader ABI + wire layout | [`../substrate/shield_abi.h`](../substrate/shield_abi.h) (compiles; asserts its own offsets) |
| Per-item scope, ranked by how far the original sizing was off | [`../design-review-findings.md`](../design-review-findings.md) §5 |
| Scope of the whole (subsystem, not a feature) | [`../engine-hard-problems.md`](../engine-hard-problems.md) §6.1 · [`../design-review-findings.md`](../design-review-findings.md) §5 |

## Open

No performance numbers exist yet. Every cost claim — "free when dark," "tens of nanoseconds is
noise" — is an estimate, which is why the first thing to settle is a
measurement.
