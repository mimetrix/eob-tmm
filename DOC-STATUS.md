# Which documents are current, and which describe a system that did not exist yet

This repository accumulated design documents before the mechanism ran, and measurement
documents after. Both are useful and they do not agree, because the second set falsified
parts of the first. **This page says which is which**, so a reader knows whether a document
describes intent or observation.

The governing rule, from `CLAUDE.md`: *replace a claim when it is falsified rather than
letting it stand, and add the new limit in the same edit.* This page is the index for that
rule, not a substitute for it.

---

## Start here

| if you want | read |
|---|---|
| **What the engine does, has done, and could do** — the current state, with evidence | [`tmm-bpf-engine-architect-brief.md`](tmm-bpf-engine-architect-brief.md) |
| Every axis in flat form: hook types, maps, helpers, ceilings | [`vm-capability-inventory.md`](vm-capability-inventory.md) |
| The three customer requests, answered — including where the answer is no | [`ebpf-requests-capability-map.md`](ebpf-requests-capability-map.md) |
| How to reproduce any of it | [`REPRODUCING.md`](REPRODUCING.md), [`env/bnk-dev-runbook.md`](env/bnk-dev-runbook.md) |

**One thing to know before reading anything older than 2026-08-13.** The repository's
earlier convention was *"there is deliberately no prototype; nothing in this repo executes a
shield."* That was true when written. It is now false: programs load into a running TMM,
arm at function entries, fire under traffic, and produce records. Documents still carrying
that sentence are marked below.

---

## Classification

**CURRENT** — written or revised after the mechanism ran; claims are measured.
**DESIGN** — written before it ran. The design intent stands; specific claims about what is
built, reachable, or costly have in places been superseded by measurement.
**RECORD** — the account of a particular investigation or run. Still accurate *as a record
of that run*, and not a description of the present state.
**PROCEDURE** — how to do something. Ages with the tooling rather than with the design.

### Current

| document | covers |
|---|---|
| [`tmm-bpf-engine-architect-brief.md`](tmm-bpf-engine-architect-brief.md) | The entry point. Mechanism, results with evidence, limits, ranked extensions |
| [`vm-capability-inventory.md`](vm-capability-inventory.md) | Hook types, context shapes and the measured 96-byte ceiling, maps, helpers, verdicts, egress, admission gates |
| [`ebpf-requests-capability-map.md`](ebpf-requests-capability-map.md) | Attack-surface reduction, threat observability, defence in depth — what fits and what does not |
| [`cve-survey-bnk.md`](cve-survey-bnk.md) | The Bugzilla survey. **Supersedes** any earlier CVE framing in this repo |
| [`demo-options.md`](demo-options.md) | What can be demonstrated, and the four-part structure |
| [`rst-why-feed.md`](rst-why-feed.md) | The reset feed, its record format, and its measured triggers |
| [`hook-types.md`](hook-types.md) · [`hook-types-plan.md`](hook-types-plan.md) | What the VM can attach to, and how to add to it |

### Design — pre-build intent

Read these for *why the system is shaped as it is*. Where they state what exists, what is
reachable, or what something costs, prefer the current documents.

| document | what has been superseded since |
|---|---|
| [`big-ip-live-surface-design.md`](big-ip-live-surface-design.md) | The threat model and lifecycle stand. The worked CVE example is not a real advisory (see `design-review-findings.md` T4), and the cost discussion predates any measurement |
| [`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) | **Still says nothing executes.** The programmability spectrum and hook-point catalogue stand |
| [`development-scope.md`](development-scope.md) · [`development-scope-code.md`](development-scope-code.md) | The 17-item scope stands as a map. Items 1, 2, 3, 5 and much of 6 are now built; items 4 (signing) and 12 (audit) are not, and remain the gate on customer use |
| [`engine-hard-problems.md`](engine-hard-problems.md) | The register of hard problems is still the right register. Several entries now have measurements attached |
| [`data-plane-egress-primitives.md`](data-plane-egress-primitives.md) | The egress ring is built and running; the design's contract sketch predates it |
| [`data-plane-intelligence.md`](data-plane-intelligence.md) | Unchanged by the build — it is a product argument, not a mechanism claim |
| [`tmm-usdt-tracepoints.md`](tmm-usdt-tracepoints.md) | The catalogue stands. The designed-in HTTP tracepoint it proposes **was built and rolled back** — iRules already saw every field it captured |
| [`hook-point-catalog.md`](hook-point-catalog.md) | Superseded in practice by the generated index: ~71k entries produced per build (71,157 then 71,169 across two builds of identical source), rather than a hand-maintained list |
| [`safe-swap-plan.md`](safe-swap-plan.md) | Built. Live arm and disarm with byte-identical restore is now routine |
| [`cve-mitigation-plan.md`](cve-mitigation-plan.md) | **Substantially superseded.** See `cve-survey-bnk.md`: a shield does not change a package version, so it does not clear a scan. CVE work moved off BNK |
| [`widening-plan.md`](widening-plan.md) | Its assertion that a third-party inline hooker could not work inside TMM was **tested and disproved**. The library was declined on provenance, not capability |
| [`mechanism-tradeoff.md`](mechanism-tradeoff.md) | The scope discipline it sets out — never quote whole-binary padding reach — is still the rule and is worth reading for that alone |

### Record — accounts of specific investigations

| document | what it records |
|---|---|
| [`tmm-integration-findings.md`](tmm-integration-findings.md) | The first integration into the TMM tree |
| [`design-review-findings.md`](design-review-findings.md) | An adversarial review of the design. Several findings are now closed; **T4 remains open** — the worked CVE example is not a real published advisory |
| [`probe-a-function.md`](probe-a-function.md) | **CURRENT, and every command was run.** The reverse-engineering procedure as a command sequence, walked end to end on build 03c6f0e0 |
| [`build-pipeline.md`](build-pipeline.md) | **CURRENT, and measured.** The build-time artifact pipeline: what is generated per build, the forced ordering, where each stage runs, the gates, and the defect the gates caught while it was being written (two debug binaries in one package, differing in 3,132 functions) |
| [`load-path-scope.md`](load-path-scope.md) | The runtime load path, and why the per-call cost figure in it must not be quoted |
| [`bnk-integration-map.md`](bnk-integration-map.md) | What BNK exposes and what it does not |
| [`env/tmm-build-environment.md`](env/tmm-build-environment.md) | The padding measurement. Source of the 48.9% whole-binary figure — which is **correctly scoped there** and routinely misquoted elsewhere as "coverage" |

### Procedure

| document | |
|---|---|
| [`REPRODUCING.md`](REPRODUCING.md) | Reproduce the results |
| [`env/bnk-dev-runbook.md`](env/bnk-dev-runbook.md) | Build and deploy environment, end to end |
| [`live-patch-runbook.md`](live-patch-runbook.md) | Arming a live TMM |

---

## The specific claims the build falsified

Listed so a reader who has already absorbed the older documents knows what to unlearn.

| claim, as it appears in older text | what is true now |
|---|---|
| "There is deliberately no prototype; nothing in this repo executes a shield" | Programs load into a running TMM, arm at function entries, fire under traffic, and emit records |
| "Candidate artifact. It compiles. Nothing calls it" (on `ls_tramp.c` and others) | These are the live dispatch path. `ls_tramp_dispatch` is reached from patched entries on every armed hook |
| "Arming is item 2 and would be what writes the jump" | Arming is built, gated on build identity, and refuses unknown, ambiguous and unpadded targets |
| "Maps are not implemented" | Per-thread hash maps, plus a clock and an event-output helper. A program does its own rate limiting |
| "CVE mitigation is the BNK story" | It is not. A shield does not change a package version. The BNK story is decisions no other surface exposes |
| "39 CVEs tracked against BNK" | 3,068. The earlier figure came from a truncated query |
| The record's `"tmm"` field | Always carried the **slot** number. Renamed to `"slot"`; the byte layout did not change |
| "uBPF and PREVAIL are vendored unmodified — zero forks" | **uBPF carries one patch.** `vm/ubpf_jit_support.c` is modified by `0001-jit-scratch-rightsize.patch`, preserved in `substrate/ubpf-patches/`, whose own README says plainly that "a fork was always coming". A second patch (JIT back-edge fuel, scope item 15) is anticipated. PREVAIL is unmodified |
| uBPF pin cited as `c900ed9` / PREVAIL as `v0.2.5` | **Neither matches what is installed.** The vendored uBPF has no version-control history, so its upstream revision cannot be stated; it differs from the `508d5e4b` checkout on the build box. The PREVAIL binary in use reports `v0.2.6`. A reproducer following the documented pins gets different code |
| "The substrate modifies no F5 source file" | Technically narrow and misleading. **39 new files and 7,174 lines are added into `src/base/` and `src/modules/hudfilter/ssl/`**, three build-configuration files are edited, and `Makefile.overrides` replaces `CFLAGS_OPTIMIZE` for the whole build. What is true is smaller: no existing F5 *function body* is edited, because initialisation goes through `INIT_FUNC(INIT_LATE, …)`. The phrase appears in ten files and should be retired in favour of the delta |
| "Entry-padding reach is 48.9%" quoted as *coverage* | 48.9% is whole-binary and correct as such. The shield's scope is the TMM core, where reach is 82–97%. The whole-binary figure averages in components that were never in scope |

---

## What has not changed

Worth stating, because a long list of corrections can imply the foundations moved. They did
not:

- The mechanism is the same one the design proposed: a verified program, run from a patched
  function entry, with the host applying the verdict.
- The safety argument is the same: nothing is displaced, so disarm restores the original
  bytes exactly.
- The scoping discipline is the same: build-time versus run-time, proven versus bounded,
  reused versus built.
- The two gaps that block customer use are the two the scope document named at the start —
  program signing and an audit trail. Neither has been built, and neither has been
  reclassified as less important.
