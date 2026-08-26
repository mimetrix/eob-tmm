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

**These six were written for the architecture review of 2026-08-18** and are the set to hand
someone cold, in that order. They are kept current rather than frozen: everything above was
re-checked against the build on 2026-08-20, which moved three claims — signature verification
from *unbuilt* to *measured*, per-call cost from *unmeasured* to *a floor, stated as a floor*, and
hardware watchpoints from *absent, needs signal delivery* to *prototyped, and the signal-delivery
objection falsified*.

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
**PRESENTED** — a self-contained page written to be shown and circulated. Design-era by
construction, kept that way on purpose, and carrying its own dated accuracy note in the hero.

### Current

| document | covers |
|---|---|
| [`tmm-bpf-engine-architect-brief.md`](tmm-bpf-engine-architect-brief.md) | The entry point. Mechanism, results with evidence, limits, ranked extensions |
| [`vm-capability-inventory.md`](vm-capability-inventory.md) | Hook types, context shapes and the measured 96-byte ceiling, maps, helpers, verdicts, egress, admission gates |
| [`ebpf-requests-capability-map.md`](ebpf-requests-capability-map.md) | Attack-surface reduction, threat observability, defence in depth — what fits and what does not |
| [`rst-why-feed.md`](rst-why-feed.md) | The reset feed, its record format, and its measured triggers |

### Design — pre-build intent

Read these for *why the system is shaped as it is*. Where they state what exists, what is
reachable, or what something costs, prefer the current documents.

| document | what has been superseded since |
|---|---|
| [`big-ip-live-surface-design.md`](big-ip-live-surface-design.md) | The threat model and lifecycle stand. The worked CVE example is not a real advisory (see `design-review-findings.md` T4), and the cost discussion predates any measurement |
| [`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) | **Still says nothing executes.** The programmability spectrum and hook-point catalogue stand |
| [`engine-hard-problems.md`](engine-hard-problems.md) | The register of hard problems is still the right register. Several entries now have measurements attached |
| [`data-plane-egress-primitives.md`](data-plane-egress-primitives.md) | The egress ring is built and running; the design's contract sketch predates it |
| [`data-plane-intelligence.md`](data-plane-intelligence.md) | Unchanged by the build — it is a product argument, not a mechanism claim |
| [`tmm-usdt-tracepoints.md`](tmm-usdt-tracepoints.md) | The catalogue stands. The designed-in HTTP tracepoint it proposes **was built and rolled back** — iRules already saw every field it captured |
| [`mechanism-tradeoff.md`](mechanism-tradeoff.md) | The scope discipline it sets out — never quote whole-binary padding reach — is still the rule and is worth reading for that alone |

### Record — accounts of specific investigations

| document | what it records |
|---|---|
| [`tmm-integration-findings.md`](tmm-integration-findings.md) | The first integration into the TMM tree |
| [`design-review-findings.md`](design-review-findings.md) | An adversarial review of the design. Several findings are now closed; **T4 remains open** — the worked CVE example is not a real published advisory |
| [`probe-a-function.md`](probe-a-function.md) | **CURRENT, and every command was run.** The reverse-engineering procedure as a command sequence, walked end to end on build 03c6f0e0 |
| [`bnk-integration-map.md`](bnk-integration-map.md) | What BNK exposes and what it does not |
| [`env/tmm-build-environment.md`](env/tmm-build-environment.md) | The padding measurement. Source of the 48.9% whole-binary figure — which is **correctly scoped there** and routinely misquoted elsewhere as "coverage" |

### Procedure

| document | |
|---|---|
| [`REPRODUCING.md`](REPRODUCING.md) | Reproduce the results |
| [`env/bnk-dev-runbook.md`](env/bnk-dev-runbook.md) | Build and deploy environment, end to end |

### Explainers — a fifth category, and this page did not classify them until 2026-08-20

The four pages in [`explainers/`](explainers/) are **presented artifacts**: self-contained HTML
written to be shown and circulated, not read as status. They belong to the design era and are
deliberately not rewritten each time the build moves — a proposal rewritten into a status report
stops being either. Each therefore carries an **accuracy note in its own hero**, updated in place,
and that note is the authority for which of its claims have since been built.

| page | era | what its accuracy note now says |
|---|---|---|
| [`explainers/substrate-as-built.html`](explainers/substrate-as-built.html) | **CURRENT** — written after the mechanism ran, so it is a record and not a proposal. Needs no accuracy note: every number in it is dated and tiered inline, and what is not established says so in the same table |
| [`explainers/programmable-dataplane-engine.html`](explainers/programmable-dataplane-engine.html) | design, mechanism since built | mechanism runs live; signature verification and the per-build hook index built since; data-path per-call cost unmeasured, floor only |
| [`explainers/engine-hard-problems.html`](explainers/engine-hard-problems.html) | design | same note; several register entries now have measurements rather than estimates |

**They were omitted from this page for a week.** DOC-STATUS exists so a reader knows which era a
document belongs to before acting on it, and the four most *circulated* documents in the repo were
the ones it did not classify. Anything published from them to an external artifact host is a
separate copy that this repo cannot update — retiring or repointing those is a manual step, and
needs the owner's approval per [`CLAUDE.md`](CLAUDE.md) §1.

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
| uBPF pin cited as `c900ed9` / PREVAIL as `v0.2.5` | **CORRECTED 2026-08-20 — the pins were right and this row was wrong.** The vendored copies in this repo *do* carry git history: uBPF is `c900ed9f`, PREVAIL is `06769f7b` (tag `v0.2.5`), and the binary reports `v0.2.5`, not `v0.2.6`. The "cannot be stated" claim was true of a different copy — the build box's git-less `~/code/tmm/.ubpf` extract — and had been generalised to the repo. See `CONTESTED-PREMISES.md` #6 |
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

---

## Removed as obsolete (2026-08-26)

21 documents were deleted in a cleanup: superseded planning (`development-scope*`, `*-plan`, `hook-point-catalog`, `load-path-scope`, `build-pipeline`, `live-patch-runbook`), the set-aside CVE-on-BNK thread (`cve-*`, `substrate/VULNERABLE-BUILD.md`), and the pre-BNK BIG-IP-VE environment notes (`env/archive-eob-bigip/`, `env/bigip-*`, `env/openstack-cli-reference.md`). The current story lives in `docs/TMM-BUILD.md`, `docs/BYTECODE-BUILD.md`, and `co-re-plan.md`; the design record is the remaining root docs.
