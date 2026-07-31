# Explainers — index

Each HTML page has a `.teams.md` twin with the same content as pasteable text.

| Page | What it covers | Read |
|---|---|---|
| [`one-pager.html`](one-pager.html) | The whole proposal, one printable sheet, ending on the ask | 3 min |
| [`programmable-dataplane-engine.html`](programmable-dataplane-engine.html) | The engine as a general capability — hooks, the `ctx` model, safety, form-factor coverage | 15 min |
| [`cve-mitigation.html`](cve-mitigation.html) | The CVE-mitigation case in plain language, with the perimeter argument and coverage limits | 8 min |
| [`cve-shield-walkthrough.html`](cve-shield-walkthrough.html) | A real TMM NULL-deref CVE end to end: 4 build steps, 9 runtime steps, the eBPF program line by line | 20 min |
| [`engine-hard-problems.html`](engine-hard-problems.html) | The engineering register — time safety, the `ctx` ABI, shared state, the trust surface, nine further concerns, effort figure | 20 min |

Order: one-pager → engine → cve-mitigation → walkthrough → hard-problems. The engine page is
generic on purpose; read after the CVE pages it reads as a security feature rather than a
programmability surface.

## Elsewhere in the repo

- [`../development-scope.md`](../development-scope.md) — what F5 builds, item by item, and what is reused as-is.
- [`../development-scope-code.md`](../development-scope-code.md) — a candidate code skeleton per item, with real/stubbed/TODO marked.
- [`../design-review-findings.md`](../design-review-findings.md) — three architect reviews and their dispositions, including the findings that changed the design.
- [`../engine-hard-problems.md`](../engine-hard-problems.md) · [`../embedded-ebpf-substrate.md`](../embedded-ebpf-substrate.md) · [`../big-ip-live-shield-design.md`](../big-ip-live-shield-design.md) — the long-form docs these pages are distilled from.
- [`../prototype/`](../prototype/) — a working relay with a synthetic CVE, a designed-in hook, and a PREVAIL gate that rejects a deliberately-unsafe program.

## Canonical sources

Where a fact is defined once and referenced everywhere else. An explainer that disagrees with one of
these is the thing that's wrong.

| Fact | Defined in |
|---|---|
| The host-owned outcome set | [`../embedded-ebpf-substrate.md`](../embedded-ebpf-substrate.md) §2 |
| Hook-map schema | [`../prototype/substrate/hook_map.schema.json`](../prototype/substrate/hook_map.schema.json) |
| Loader ABI + wire layout | [`../prototype/substrate/shield_abi.h`](../prototype/substrate/shield_abi.h) (compiles; asserts its own offsets) |
| Per-item effort | [`../engine-hard-problems.md`](../engine-hard-problems.md) §7 |

## Open

No performance numbers exist yet. Every cost claim — "free when dark," "tens of nanoseconds is
noise" — is an estimate, which is why the ask is a feasibility phase with a measurement as its first
deliverable.
