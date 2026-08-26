# Explainers — index

> **Accuracy note (2026-08-13).** These pages were written when this was a proposal. The data-plane
> mechanism now **runs on a live TMM** — load, arm, disarm, no restart — and designed-in call sites
> have been **removed** as the shield mechanism in favour of patched function entries. (They returned
> for *tracepoints*, which are a different thing: a chosen structure at a chosen point, and the one
> place an F5 source file is edited.)
>
> **Ordering correction (2026-08-16).** These pages lead with CVE mitigation. That ordering is wrong
> and the pages have not yet been rewritten to match. What is proven today is **debugging/RCA** and
> the **data probe** — both work, both need none of the hard machinery. **Five CVE candidates were
> screened against a live TMM and all five failed on reachability**, not on the mechanism. Read the
> CVE pages as *the hardest case the surface was designed against*, not as the thing it demonstrably
> does. Full constraint list: [`../substrate/LIMITATIONS.md`](../substrate/LIMITATIONS.md).
>
> **Signature verification is built, 2026-08-20.** The pages describe it as part of the proposal;
> it now runs. An Ed25519 signature over the program's binding — which commits to the program by
> hash and carries its hook, build range, mode ceiling and expiry — is checked inside TMM before
> admission, and unsigned, re-signed and altered programs are refused
> ([`../GROUND_TRUTH.md`](../GROUND_TRUTH.md), 16 of 16 in
> [`../env/scripts/bnk-test-signatures.sh`](../env/scripts/bnk-test-signatures.sh)). **What this does
> not do is authenticate the caller** — the program is signed, the asker is anonymous, the verifying
> key is compiled in with no revocation path. **Every operation is now recorded** (2026-08-20):
> one line per control-plane operation with the op, target, program hash, the binary's build id,
> and the verdict the caller received verbatim, attributed to the pid/uid the kernel reports for
> the connecting process --- which is a process, not a person. Where a page names
> signature verification, the safe-return policy table and a runtime budget guard together, only the
> first exists.
>
> **The shield is now shown to prevent the NULL-deref crash (2026-08-24)** — enforce returns a safe
> value and TMM survives, monitor falls through and the same binary dies — against a **synthesised**
> condition, since no CRD can create the real one. That is the mechanism preventing a crash, which is
> a different claim from a reachable attack path being closed. See
> `../cve-selftest.md` for exactly where the boundary sits.
>
> Still genuinely unproven and must stay conditional: **no CVE has been mitigated on live traffic**,
> and the **per-call cost of an armed hook on the data path is unmeasured**. A floor is now measured
> — ≤ 11 ns for a small program on the compiled path — and it is bounded by the timer rather than by
> the program, so it excludes the trampoline, the call and return, and cache effects under traffic.
> Quote it as a floor and nothing as a per-packet cost (`../load-path-scope.md` §7).

| Page | What it covers | Read |
|---|---|---|
| [`programmable-dataplane-engine.html`](programmable-dataplane-engine.html) | The engine as a general capability — hooks, the `ctx` model, safety, form-factor coverage | 15 min |
| [`cve-mitigation.html`](cve-mitigation.html) | The CVE-mitigation case in plain language, with the perimeter argument and coverage limits | 8 min |
| [`cve-shield-walkthrough.html`](cve-shield-walkthrough.html) | A real TMM NULL-deref crash class end to end: 4 build steps, 9 runtime steps, the eBPF program line by line | 20 min |
| [`substrate-as-built.html`](substrate-as-built.html) | **What exists and what it measures** — the only page in this set that is a record rather than a proposal: the five-byte patch with real bytes either side, reach counted from the binary, the seven-stage pipeline with what each stage checks, the perimeter's honest edge, and every claim tiered including the ones that are not claims | 8 min |
| [`engine-hard-problems.html`](engine-hard-problems.html) | The engineering register — time safety, the `ctx` ABI, shared state, the trust surface, thirteen further concerns, day-one vs. deferred sequencing, honest scope | 20 min |

Order: **as-built → engine → hard-problems → cve-mitigation → walkthrough.** The as-built page
goes first now: it is the only one written after the mechanism ran, so it says what is true before
the design-era pages say what was intended. Hand a skeptic that one.

Older order, still the right sequence for the four proposals: **engine → hard-problems →
cve-mitigation → walkthrough.** The engine page is generic on
purpose; read after the CVE pages it reads as a security feature rather than the programmability
surface it is. The CVE pages moved to the end on 2026-08-16 — they describe the least demonstrable
use case, and putting them second made the whole set look like a security proposal whose central
claim has not been shown.

## Elsewhere in the repo

- `../development-scope.md` — what F5 builds, item by item, with a per-item status column. uBPF is **no longer reused as-is**: F5 carries a patch (`../substrate/ubpf-patches/`).
- `../development-scope-code.md` — a candidate code skeleton per item, with real/stubbed/TODO marked.
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
