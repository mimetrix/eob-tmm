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

**2026-09-30 program ownership:** [PROGRAMS.md](substrate/PROGRAMS.md) is the
current contract and native/socket/build/live record. Independent programs with
multiple entry attachments pass pinned native checks. The new sources compile
into TMM build `5784e768…`; linked functions, TLS, globals and trampolines pass
inspection. Packaged build `2ab960fa…` passes 18 exchanges across eight ownership
phases, with 594 records. Hooks are restored and the isolated fixture is removed.
Scope is two owners, two hooks and one worker; sustained cost remains unmeasured.

**2026-09-30 combined activity:** [ACTIVITY-COMBINED.md](env/ai-traffic/ACTIVITY-COMBINED.md)
is the current exchange contract, measured result and export procedure.
[ACTIVITY-PROGRAM.md](env/ai-traffic/ACTIVITY-PROGRAM.md) records the one-ELF,
two-entry build. Ten live exchanges produce combined records, including keep-alive
and concurrent equal IDs. Both hooks were restored and the fixture was removed.
Scope is one worker and non-pipelined HTTP/1. Identity binding, silent missed hooks
and sustained data-path cost remain unqualified.

**2026-09-30 activity export:** [AGENT-ACTIVITY.md](env/ai-traffic/AGENT-ACTIVITY.md)
is the current format and procedure for identity-ready JSON observations. Archived
replay and collector API checks pass. Authenticated identity binding remains open.

**2026-09-29 correction:** the old zero-unwind-import admission premise is false
for both re-examined packaged binaries. Full-width inspection now refuses them.
[ENTRY-SNAPSHOT.md](env/ai-traffic/ENTRY-SNAPSHOT.md) is the current native/build
record and live-admission limit. Earlier successful return observations remain
records; they do not establish exception-path qualification. See
[`CONTESTED-PREMISES.md` §39](CONTESTED-PREMISES.md#39--no-unwind-imports-means-return-hook-admission-is-clear--falsified-check).

| if you want | read |
|---|---|
| Build TMM and matching bytecode from a source-tree path | [`docs/BUILD-FROM-SOURCE.md`](docs/BUILD-FROM-SOURCE.md) — PROCEDURE; explicit inputs and known gaps, not yet tested on a fresh host |
| A starting program with configuration, maps, field reads and metadata output | [`docs/EBPF-TUTORIAL.md`](docs/EBPF-TUTORIAL.md), [`substrate/template.c`](substrate/template.c) — PROCEDURE; unsampled entry/exit and map replacement pass on the repaired isolated TMM; cost remains unmeasured |
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
| [`substrate/PROGRAMS.md`](substrate/PROGRAMS.md) | **MEASURED native/socket tests, package and isolated live TMM, 2026-09-30.** Two owners, two shared entry hooks, 18 exchanges, 594 records; separate maps/configuration, independent detach/revoke and replacement. Restored hooks and removed fixture. Multiple workers and sustained cost remain unqualified. |
| [`env/ai-traffic/VOID-COMPLETION.md`](env/ai-traffic/VOID-COMPLETION.md) | **MEASURED native fixture only, 2026-09-29.** Both pinned compilers pass 24 cases and 1,100 observed returns. Tests a frame-bound entry snapshot with the unchanged return machinery. Production entry capture and live initialization remain unvalidated. |
| [`env/ai-traffic/JSON-INITIALIZATION.md`](env/ai-traffic/JSON-INITIALIZATION.md) | **MEASURED source/compiled/admission qualification only, 2026-09-29.** Handler/reset void-return refusals, admitted control and rejected forwarding shortcut. Build-box verifier checks 48 source snapshots and 15 instruction locations. No live probe; completed initialization and lifecycle remain unqualified. |
| [`env/ai-traffic/ID-FLOW.md`](env/ai-traffic/ID-FLOW.md) | **Measured same-record ID and flow side, 2026-09-29.** Pinned PREVAIL, 224 native invocations, 12 decoder rejections and 44 live exchanges yielding 88 records. Keep-alive and concurrent equal IDs; exact replay, archive and cleanup. Local lifecycle, message role and request/reply association remain unqualified. |
| [`env/ai-traffic/GAPS.md`](env/ai-traffic/GAPS.md) | **Measured controlled-gap tests, 2026-09-28.** Four-VM native falsifier; five live windows, 150 accepted requests and 1,023 calls/records. Reported gaps and capacity invalidate a whole window. Full reload recovers fresh-request matching; retained connection stays unknown. Silent-gap detection, multiple workers and cost remain open. |
| [`env/ai-traffic/CORRELATION.md`](env/ai-traffic/CORRELATION.md) | **Measured bounded live join, 2026-09-28.** Four hooks, 313 calls/records; 51 completed header observations yield 42 accepted-operation matches, one authenticated rejection and eight unknowns. Trusted fixture ledger, canonical HTTP/1, 512-byte bound and lifetimes 1–127. General request identity, native AI-filter visibility and cost remain open. |
| [`env/ai-traffic/LIFETIME.md`](env/ai-traffic/LIFETIME.md) | **Measured parser-interval gate, 2026-09-28.** Three hooks, 204 calls/records, 71 closed lifetimes and 66 address-reuse pairs. Late/missed initialization remains unknown. The later correlation record adds a bounded authenticated join; general request identity and cost remain unvalidated. |
| [`configuration-snapshots.md`](configuration-snapshots.md) | **Implemented interface + bench and isolated live validation, 2026-09-25.** Controller-published versioned configuration ARRAY, invocation-copy semantics, CLI/wire contract and signed-load/update/withdrawal/reload/revoke lifecycle. 52 exact HTTP responses; 48 armed calls/events, zero reported drops; kernel binary/patch witnesses. Live pressure, cross-UID rejection and cost remain unvalidated. |
| [`env/ai-traffic/README.md`](env/ai-traffic/README.md) | **Measured fixture/procedure, 2026-09-24.** P19 synthetic MCP/A2A/inference flows through the HTTP proxy, independent client/backend records, paced SSE, replay/cleanup and next-phase metadata candidates. Native AI filters disabled. |
| [`env/ai-traffic/ATTRIBUTION.md`](env/ai-traffic/ATTRIBUTION.md) | **Measured fixture, consumer checks and live scope falsifiers, updated 2026-09-28.** Original 23-outcome ledger and 21 synthetic consumer checks remain recorded. Scope probe falsifies call/address shortcuts; later lifetime and correlation records qualify a bounded HTTP/1 join. General request identity, unique visibility and cost remain open. |
| [`env/ai-traffic/INSPECTION.md`](env/ai-traffic/INSPECTION.md) | **Measured source/configuration preflight + bounded unarmed outcomes, updated 2026-09-25.** Delayed allow, denial and inspector-silence cases pass in isolated SSA; prior failed attempts retained. ICAP monitor compiled, relocated, verified and signed but unarmed. Supporting experiment after attribution became primary; unique-state and cost results remain unrun. |
| [`embedded-traversal-validation.md`](embedded-traversal-validation.md) | **Measured record, 2026-09-24.** P17 named embedded traversal: native execution fixtures, independent real-TMM relocations, installed authoring catalog and live HTTP/1 probes; failed network preflights and explicit limits. |
| [`catalog-free-deployment.md`](catalog-free-deployment.md) | **Measured record, 2026-09-24.** Catalog-free TMM image, authenticated build-resolved targets, full-layer audit and live signed entry/exit validation under P18. Defined metadata scope and one-function/one-pod limits. |
| [`env/k8s/h2-trailer-backend.yaml`](env/k8s/h2-trailer-backend.yaml) | **current — half of the CVE demonstration.** ConfigMap + Pod: an h2c origin whose every response ends in a trailer with an empty header block, which is the only shape that reaches CVE-2025-41414. Was a scratch-directory script until 2026-09-05, which is why the demo could not be re-run |
| [`substrate/shields/h2_trailer_guard.bpf.c`](substrate/shields/h2_trailer_guard.bpf.c) | **current — the other half.** The shield that prevents it. PREVAIL-verified, ~74 cycles, signed at `enforce`. Its comment states the predicate is a deliberate over-approximation and that 0/10 false positives is measured, not proven-zero |
| [`substrate/ls_build_gate.h`](substrate/ls_build_gate.h) | **current.** The decision that refuses a program signed for a different build — header-only and pure, so `check_build_gate.c` asserts every branch off-TMM |
| Checks added with the sign-time-relocation work | `substrate/check_relo_baked.py` (baked offsets vs an independent implementation), `substrate/check_prevail_after_relo.sh` (does PREVAIL's verdict survive relocation), `env/scripts/bnk-test-build-gate.sh` (the gate, live), `env/scripts/bnk-test-btfless.sh` (a shield loads, arms and runs on a binary with no type information) |
| [`cve-41414-demonstration.md`](cve-41414-demonstration.md) | **current — the evidence record.** CVE-2025-41414 crashed by one client request and prevented by a selective shield (2026-09-03). Read this before any claim about CVE mitigation; it supersedes every "no CVE has been mitigated" line elsewhere |
| [`cve-to-shield-process.md`](cve-to-shield-process.md) | **current — procedure.** The nine steps from a CVE description to a verified shield, which two actually kill attempts, and the v0→v1→v2 predicate derivation. Read with the demonstration record |
| [`tmm-bpf-engine-architect-brief.md`](tmm-bpf-engine-architect-brief.md) | The entry point. Mechanism, results with evidence, limits, ranked extensions |
| [`vm-capability-inventory.md`](vm-capability-inventory.md) | Hook types, context shapes and the measured 96-byte ceiling, maps, helpers, verdicts, egress, admission gates |
| [`ebpf-requests-capability-map.md`](ebpf-requests-capability-map.md) | Attack-surface reduction, threat observability, defence in depth — what fits and what does not |
| [`rst-why-feed.md`](rst-why-feed.md) | The reset feed, its record format, and its measured triggers |

### Design — pre-build intent

Read these for *why the system is shaped as it is*. Where they state what exists, what is
reachable, or what something costs, prefer the current documents.

| document | what has been superseded since |
|---|---|
| [`env/ai-traffic/JSON-LIFECYCLE.md`](env/ai-traffic/JSON-LIFECYCLE.md) | **CURRENT, 2026-09-29: measured boundary subset, lifecycle unknown.** Three probes; 312 native records and 306 live records from 13 exchanges. Eleven unavailable-context records invalidate the full consumer window. Late attachment, malformed JSON, keep-alive and concurrency are tested. Other required live paths remain unvalidated. Both attempts are archived and fixtures removed. |
| [`env/ai-traffic/MESSAGE-SCOPE.md`](env/ai-traffic/MESSAGE-SCOPE.md) | **MEASURED source/compiled qualification only, 2026-09-29.** Build-box check covers 16 embedded files and 11 instruction locations. Rejects reused JSON context as request/shared-connection identity. Qualifies flow-side and handler/reset candidates; runtime scope and common owner lifetime remain unvalidated. |
| [`env/ai-traffic/MESSAGE-ID.md`](env/ai-traffic/MESSAGE-ID.md) | **MEASURED bounded message-ID extraction, 2026-09-29.** Pinned PREVAIL and 194 native invocations; 35 live exchanges and 70 records. Exact types and raw bytes, including large numbers, with explicit missing/ambiguous/limited states. Reused and mismatched IDs stay as observations. Saved-evidence verifier checks fields, replay, archive and cleanup. General request association, protocol equality and caller identity remain unqualified. |
| [`env/ai-traffic/REPLY-METADATA.md`](env/ai-traffic/REPLY-METADATA.md) | **MEASURED bounded reported reply fields, 2026-09-29.** Pinned PREVAIL and 106 native invocations; 38 live exchanges and 76 records. Exact presence, integer/Boolean values and explicit missing/ambiguous states. Saved-evidence verifier checks replay, both archives and cleanup. Retains pre-arm fixture failures. Reported fields do not prove remote success, caller identity or request association. |
| [`env/ai-traffic/OPERATION-TARGET.md`](env/ai-traffic/OPERATION-TARGET.md) | **MEASURED bounded requested tool/resource extraction, 2026-09-29.** Pinned PREVAIL and 74 native invocations; 28 live requests and 56 records. Exact bytes, nested exclusions, duplicate rules, truncation, replay and cleanup pass. This adds requested activity for proposed identity profiles, not authenticated identity or authorized/successful access. |
| [`env/ai-traffic/RESPONSE-METADATA.md`](env/ai-traffic/RESPONSE-METADATA.md) | **MEASURED bounded HTTP status and local transfer completion, 2026-09-29.** Pinned PREVAIL and 80 native invocations; nine live requests and 201 handler records, including paced, chunked, SSE and interrupted bodies. Saved-evidence verifier/export checks fields, journal, replay and cleanup. Retains failed cache-validity rule and layout assertion. No general request identity, remote-operation success, HTTP/2 coverage or data-path cost claim. |
| [`env/ai-traffic/SESSION-ROUTING.md`](env/ai-traffic/SESSION-ROUTING.md) | **MEASURED bounded session-header and selected-route extraction, 2026-09-29.** Pinned PREVAIL and 80 native invocations; seven live requests, five session records and seven routing records through the existing collector. Exact bytes, replay, restored hooks and archived fixture removal. Retains three failed attempts. Identity profiles and blast-radius assessment remain IDEA consumer goals; successful persistence decoding, authenticated identity and data-path cost remain unvalidated. |
| [`env/ai-traffic/COVERAGE.md`](env/ai-traffic/COVERAGE.md) | **IDEA probe-first discovery plan, corrected 2026-09-28.** Metadata extraction comes first; representative usage tests and analytics follow observations. Retains both the withdrawn fixed-concurrency proposal and the correction to requiring a real deployment before probe design. |
| [`env/ai-traffic/METADATA.md`](env/ai-traffic/METADATA.md) | **MEASURED handler events and bounded root-object method extraction, 2026-09-28.** Retains the event-only limitation and failed stack-limit build. Pinned interpreter/JIT and live byte comparisons pass, including unfamiliar/escaped values and explicit truncation. Four-member walk and getter reachability limit coverage; the AIMCP input produced no getter observation. The token-cache and session/routing results supply separate measured paths. Broader fields and collector-side ZeroMQ publication remain pending/IDEA. |
| [`env/ai-traffic/TOKEN-METHOD.md`](env/ai-traffic/TOKEN-METHOD.md) | **MEASURED bounded AIMCP/JSON method extraction, 2026-09-28.** Completion-hook program passes pinned PREVAIL, 68 native invocations and a 13-request live gate. The separate collector retains 26 cache records in 28 journal events. Exact values, replay, restored hook and archive/removal are checked. Initial helper-hook coverage failure remains recorded. Requires JSON filtering, literal root keys and bounded traversal; no protocol/request identity or data-path cost claim. |
| [`env/ai-traffic/EXTRACTED-METADATA.md`](env/ai-traffic/EXTRACTED-METADATA.md) | **MEASURED source results, readable exports, 2026-09-28.** Actual method bytes and status records from the saved getter and token-cache runs. `metadata_export.py` and `token_method_verify.py --export` decode captured bytes. Authored fixture data, not production-agent observations. |
| [`env/ai-traffic/PRODUCTION-STREAM.md`](env/ai-traffic/PRODUCTION-STREAM.md) | **IDEA production service contract, 2026-09-28.** The local collector subset below is measured. Multiworker identity, attachment/health history, power-loss durability, authenticated off-box transport and sustained cost remain unvalidated. |
| [`env/ai-traffic/COLLECTOR.md`](env/ai-traffic/COLLECTOR.md) | **MEASURED bounded local handoff/replay, 2026-09-28.** Ten native checks and one successful live method run. Commit-before-ACK reader, finite SQLite journal, independent HTTP cursors, explicit retention gaps. Eight method records reach both live consumers. Retains the old drain's false delivery claim and the failed eager-start assumption; source qualification and production limits remain explicit. |
| [`env/ai-traffic/COLLECTOR-CONTAINER.md`](env/ai-traffic/COLLECTOR-CONTAINER.md) | **MEASURED bounded container replacement, 2026-09-28.** Eleven native checks; separate image, journal/API volumes and resource limits. Normal stop and SIGKILL followed by replacement; requests during outages forward and their queued values reach two separate consumer containers. Stable TMM, archived journal and fixture removal. Retains AppArmor and controller-check failures; operational separation, not strong security isolation. |
| [`broader-coverage-roadmap.md`](broader-coverage-roadmap.md) | **Working roadmap, 2026-09-24.** Six coverage dimensions, function discovery without embedded BTF, and the first DSL state-access slice (named embedded structs), with P17 acceptance criteria. Implementation/validation status is recorded separately from the proposed backlog. |
| [`ai-gateway-tracepoints.md`](ai-gateway-tracepoints.md) | **Design / IDEA, updated 2026-09-25 — collaborator working paper.** Proposed semantic tracepoints, correlation/provenance and host-owned decision gates (P13–P16). §8.1 defines continuous-feed validation (P20); §8.2 now prioritizes agent attribution, requiring a specific iRules/WASM visibility gap and measured poll-loop cost. Destination authentication and bounded ICAP prerequisites have measured receipts; TMM-internal AI metadata experiments remain unrun. |
| [`docs/pipeline.svg`](docs/pipeline.svg) | **Historical pipeline diagram.** Predates catalog-free delivery and authenticated targets. Use `catalog-free-deployment.md` and `docs/BYTECODE-BUILD.md` for the current flow. |
| [`big-ip-live-surface-design.md`](big-ip-live-surface-design.md) | The threat model and lifecycle stand. The worked CVE example is not a real advisory (see `design-review-findings.md` T4), and the cost discussion predates any measurement |
| [`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) | **Still says nothing executes.** The programmability spectrum and hook-point catalogue stand |
| [`engine-hard-problems.md`](engine-hard-problems.md) | The register of hard problems is still the right register. Several entries now have measurements attached |
| [`data-plane-egress-primitives.md`](data-plane-egress-primitives.md) | The egress ring is built and running; the design's contract sketch predates it |
| [`data-plane-intelligence.md`](data-plane-intelligence.md) | Unchanged by the build — it is a product argument, not a mechanism claim |
| [`tmm-usdt-tracepoints.md`](tmm-usdt-tracepoints.md) | The catalogue stands. The designed-in HTTP tracepoint it proposes **was built and rolled back** — iRules already saw every field it captured |
| [`cross-plane-intent-binding.md`](cross-plane-intent-binding.md) | **Design, 2026-09-21, and the newest thing here — nothing in it has been run.** Binding a model's authorized intent to what a host actually executed, using the TMM plane as an off-host witness and stock host-kernel eBPF as the enforcement point. Read §9 before §4: the cheapest falsifier (P10 — is a tool call even separable at the syscall layer) can kill the whole programme in an afternoon, off-substrate. Its §7 concedes that an iRule may cover the proxy side of enforcement, so the substrate's role is narrower than the document's title suggests |
| [`idea.md`](idea.md) | **Design, 2026-09-21.** TLS-record-shape leakage on streaming inference, rewritten against the as-built substrate after a first draft re-proposed four things that were already shipped or already retired. Its §0 keeps that draft's errors on the record; its §2 concedes that the observation half is available to a span port, leaving labels and enforcement as the value |
| [`mechanism-tradeoff.md`](mechanism-tradeoff.md) | The scope discipline it sets out — never quote whole-binary padding reach — is still the rule and is worth reading for that alone |

### Record — accounts of specific investigations

| document | what it records |
|---|---|
| [`env/ai-traffic/CLEANUP-20260928.md`](env/ai-traffic/CLEANUP-20260928.md) | **2026-09-28:** three build fixture projects and five deployment jig resources removed; 177 evidence files archived and verified. Shared TMM identity is stable. Stopped attempts and corrections retained. Recreate fixtures before another live run. |
| [`explainers/agent-attribution-evidence.html`](explainers/agent-attribution-evidence.html) | **2026-09-25, frozen evidence view.** Actual destination-side attribution records, A→B delegation IDs, all 23 outcomes and implementation/receipt links. Source is the registered `attribution-01` snapshot; not a live dashboard or a TMM-internal attribution result. |
| [`ctx-contract-validation.md`](ctx-contract-validation.md) | **2026-09-23:** 96-byte entry/exit context fix rebuilt and deployed as `5c76bc3a`; signed live JIT probes, process-memory disarm witnesses, cached receipts, and test failures/corrections. Added hook cost remains unmeasured |
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
| "The substrate modifies no F5 source file" | Technically narrow and misleading. **39 new files and 7,174 lines are added into `src/base/` and `src/modules/hudfilter/ssl/`**, three build-configuration files are edited, and `Makefile.overrides` replaces `CFLAGS_OPTIMIZE` for the whole build. What is true is smaller: no existing F5 *function body* is edited **by the substrate**, because initialisation goes through `INIT_FUNC(INIT_LATE, …)`. The phrase appears in ten files and should be retired in favour of the delta. **Narrowed again 2026-09-04:** the tree also carries the CVE-2025-41414 revert in `http2.c`, which edits an F5 function body, so even the smaller claim needs "by the substrate" attached — `CONTESTED-PREMISES.md` §16 |
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

Documents were deleted in a cleanup: superseded planning (`*-plan`, `hook-point-catalog`, `load-path-scope`, `build-pipeline`, `live-patch-runbook`), the set-aside CVE-on-BNK thread (`cve-*`, `substrate/VULNERABLE-BUILD.md`), and the pre-BNK BIG-IP-VE environment notes (`env/archive-eob-bigip/`, `env/bigip-*`, `env/openstack-cli-reference.md`). The current story lives in `docs/TMM-BUILD.md`, `docs/BYTECODE-BUILD.md`, and `co-re-plan.md`; the design record is the remaining root docs.

**Correction (2026-08-26).** Two docs were **over-deleted** in that pass and have been restored: `development-scope.md` (the canonical "what F5 builds, item by item" scope — cited ~30× across the design docs by `item N`) was not obsolete. Its per-item code-skeleton companion `development-scope-code.md` **is** retired — the real substrate sources supersede the illustrative sketches — along with its `check_skeletons.py` checker, the `check-skeletons` make target, and the orphaned `platform_stub.h`. `make check` no longer runs a skeletons target.

**Also restored (2026-08-27):** `substrate/example_hook_ctx.h` — a `check-offsets` oracle (declarations only, never compiled into TMM), over-deleted in the bespoke-ctx retirement; its removal had silently broken `make check-offsets`, now green again. And **`TMM-TREE-DELTA.md` was (re)created** — the symbol-level record of the substrate's filelist/whitelist/flag delta that `substrate/.tree-expected-delta` points at; it was referenced but absent from the repo.

## Published artifacts diverge from the repo (2026-09-03)

`explainers/cve-mitigation.html` and `presentations/cve-mitigation-demo.html` were written when the
CVE story was **injected-condition only**. They therefore understate the result: a named CVE is now
crashed by traffic and prevented by a selective shield. `explainers/engine-hard-problems.html` and
`explainers/programmable-dataplane-engine.html` carried a *"No CVE has been mitigated on live
traffic"* line and have been corrected in-repo.

**Anything already published as a claude.ai Artifact still shows the old text** — editing the repo
file does not change a published page, and republishing needs the owner's explicit per-item approval
(convention 1). Treat the hosted copies as stale until that approval is given.

### Retired 2026-09-05

`dtls-tx-shield-demo.md` — **deleted**, and it is the surviving half of the retirement below.
`presentations/shield-live-demo.html` went on 2026-09-04 for having a `dtls_tx` spine and no CVE id;
this was its markdown twin. Its own headline conceded the demo never landed: *"the `dtls_tx` shield
is verified but **not yet armed live**, blocked on a relocator bug."* The evidence-event pipeline it
recorded is not lost — it is a MEASURED row in `GROUND_TRUTH.md`, and the shield story it was
standing in for is now `cve-41414-demonstration.md`.

`cve-mitigation-milestone.md` — **deleted.** It described itself as *"thesis + milestone plan …
what is MEASURED today vs. the **milestone that isn't reached yet**"*. That milestone has been
reached twice: CVE-2025-41414 crashed by one client request and prevented by a selective shield
(2026-09-03), then reproduced on a binary carrying **no type information at all** (2026-09-05). A
plan for a completed milestone is the clearest case of overcome-by-events in the repo. Its two jobs
are now split cleanly: `cve-41414-demonstration.md` holds the evidence, `cve-to-shield-process.md`
the procedure. Seven citations in `SYMPTOMS.md` plus four elsewhere were repointed rather than left
dangling.

**What was deliberately NOT deleted in the same pass**, because the bar here is *wrong and useless*
rather than merely old: `cve-shield-capability-matrix.md` (a forward map, still the roadmap input),
`cve-hunt-runbook.md` (the procedure for sourcing the next target), `reachability-survey.md` (a
measurement record — records age but stay true), and every design-era document, which this page
already classifies and which is kept because the reasoning explains the system's shape.

### Retired 2026-09-04

`presentations/shield-live-demo.html` — **deleted.** Its entire spine was `dtls_tx`, a
fragment-length overflow that is an internal finding with **no CVE id**, and there is a standing
rule here that a target without a CVE id is not a business claim. Superseded by
`presentations/cve-mitigation-demo.html`, whose subject is a published CVE demonstrated end to end.
The mechanism content it carried (verifier, trampoline, two-compile path) is not lost — it lives in
`explainers/programmable-dataplane-engine.html` and `substrate-as-built.html`.

**Deleting the repo file does not remove anything already published.** Any hosted Artifact made from
it still exists and still shows `dtls_tx` as the worked example; removal from the claude.ai gallery
is manual and cannot be done from tooling.
