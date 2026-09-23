# Programmable tracepoints for an F5 AI gateway

## A working paper for collaborators: MCP, agent-to-agent, and inference traffic

**Status:** Work in progress · **Evidence tier: IDEA** for the proposed AI-specific interfaces and
actions · **Draft date:** 2026-09-23

**Audience:** TMM, AI gateway, protocol-adapter, observability, performance, and security engineers.

**Planning premise:** the TMM + embedded eBPF engine will underpin an F5 AI gateway proxying Model
Context Protocol (MCP), agent-to-agent (A2A), and inference traffic. This paper proposes what to
instrument as that gateway is built; it is not a statement that those protocol integrations exist
today. Event names and fields below are candidate interfaces, not protocol-standard definitions.

## 1. The opportunity

Add tracepoints at the gateway's semantic decisions: when a tool call is understood, an agent
delegates work, a model is selected, a stream advances, and an action becomes irreversible. This
would turn the embedded engine into a way to deploy new AI-gateway telemetry and narrowly scoped
controls without rebuilding TMM for each new program.

The key investment is a **stable, versioned AI-event interface**. Function-entry and function-exit
hooks remain useful for diagnosis. Designed-in semantic tracepoints can expose the exact state a
policy needs at the moment it can still influence the outcome, without making every program
depend on the internal layout and timing of a protocol implementation.

The intended product value is a gateway whose decisions are **explainable, correlatable, and
selectively programmable**. A collaborator should be able to ask:

- Why was this tool call allowed, denied, retried, or sent to this destination?
- Was this response slow because of the model, a tool, gateway admission, inspection, or the client?
- Which delegation or upstream attempt consumed the time and reported usage?
- When the caller disconnected, what cancellation did the gateway propagate, and what did it
  observe afterward?
- Can we deploy a new observation or a narrow dispatch restriction while traffic continues?

Adding a semantic tracepoint or a new host action requires gateway engineering and a build.
Once that interface exists, compatible probes and predicates can use the live-program lifecycle.

## 2. What we can build on, and what this paper adds

| Foundation | Evidence and limit |
|---|---|
| Live entry/exit instrumentation, signed loading, and clean disarming | **MEASURED.** See [GROUND_TRUTH.md](GROUND_TRUTH.md). These are function hooks, not the AI-event catalog proposed here. |
| DSL-authored field predicates and selective early-return enforcement | **MEASURED.** Multi-hop reads and live enforcement are recorded in [GROUND_TRUTH.md](GROUND_TRUTH.md). A function early return is not a generic cancellation, rerouting, or stream-termination API. |
| Structured record draining and build-specific program delivery | **MEASURED.** The current pipeline resolves field offsets before verification/signing and can deliver to a TMM without embedded BTF type information. See [GROUND_TRUTH.md](GROUND_TRUTH.md). |
| Entry/exit contexts consistent with PREVAIL's 96-byte tracing region | **MEASURED, 2026-09-23.** [Context-contract validation](ctx-contract-validation.md) covers live entry/exit probes on one HTTP function. Added initialization cost remains unmeasured. |
| AI-specific semantic events, cross-operation correlation, and protocol-aware actions | **IDEA.** Proposed in this paper; no implementation or live validation is claimed. |

These foundations establish a mechanism, not general safety or production readiness. Known
armed-status bookkeeping and broader runtime-lifecycle limitations remain in
[GROUND_TRUTH.md](GROUND_TRUTH.md) and [CONTESTED-PREMISES.md](CONTESTED-PREMISES.md).
Performance results from earlier probes do not establish the cost of this proposed workload.

## 3. Candidate semantic tracepoint catalog

Names are illustrative. Protocol adapters would normalize their own messages into these events;
an adapter must explicitly report when a field or transition is unavailable.

| Candidate tracepoint | Placement and candidate fields | Payoff |
|---|---|---|
| **`ai:request:admit`** | After identity and request classification, before expensive processing. Tenant, authenticated principal, protocol, requested model/service, deadline, policy revision, admission outcome. | Explain admission failures; selectively observe a tenant or workload; apply bounded admission predicates at an associated decision gate. |
| **`ai:policy:decision`** | At a policy decision. Rule and revision, inputs-present flags, verdict, reason, evaluation duration, timeout/fallback outcome. | Explain why traffic was allowed or denied; compare a monitor-mode candidate with the active decision. |
| **`mcp:operation:dispatch`** | After parsing and authorization, immediately before forwarding. Server, operation class, tool/resource identifier, catalog revision, argument size/schema result, authorization scope and verdict. | Tool-level audit; calls inconsistent with authorized scope; temporary restrictions on an operation without disabling the entire server. |
| **`mcp:operation:complete`** | On result, error, timeout, or cancellation. Correlation ID, duration, result size, normalized outcome, cancellation state. | Tool reliability, unexpectedly large results, slow dependencies, and activity observed after cancellation. |
| **`agent:delegation:dispatch`** | Before forwarding a delegation. Parent operation, target agent, task, authenticated delegation scope, remaining budget/deadline, known lineage depth. | Constrain delegation boundaries; investigate fan-out and repeated delegation; attribute downstream work to an initiating request where lineage is available. |
| **`agent:task:transition`** | At a gateway-observed task transition. Previous/new state, source, task ID, sequence, result/artifact size, cancellation state. | Diagnose stuck tasks, duplicate or out-of-order transitions, and cancellation failures. |
| **`inference:route:commit`** | After choosing an upstream, before sending. Requested/selected model, endpoint, route reason, policy revision, retry attempt, fallback reason, queue duration. | Explain model selection; identify unexpected fallback or destination changes; measure routing experiments. |
| **`inference:stream:progress`** | At first semantic output and sampled progress milestones. Elapsed time, output bytes, semantic-event count, inter-event gap, buffering, downstream write pressure. | Distinguish upstream production delay, gateway buffering, and a slow consumer; investigate first-output latency and streaming stalls. |
| **`inference:request:complete`** | On every terminal outcome, including disconnect and timeout. Timing breakdown, attempts, finish reason, reported usage, usage source/completeness, cancellation outcome. | Model-service reliability, usage attribution, retry amplification, incomplete accounting. |
| **`ai:content:release`** | Before a buffered message or defined content window becomes visible downstream. Content class, inspection verdict, inspected range, completeness, policy revision, prior bytes released. | Apply an available inspection decision at the actual release boundary; explain exactly what had already left the gateway. |

### Semantic distinctions that must survive normalization

- **Chunks are not tokens.** Track transport bytes, semantic events, provider-reported token usage,
  and estimates separately. Define whether first output means a protocol event or user-visible
  content; a transport byte alone does not establish either.
- **Lineage is not automatically authenticated.** A supplied parent ID or claimed delegation depth
  is a claim. Expose its source and trust status. Enforcement on a task-wide budget needs trusted
  accounting beyond an individual trace event.
- **Forwarding is not execution.** The gateway can witness what it forwarded and received. Proving
  that a remote tool executed an action, or that computation stopped, needs an additional witness.
- **Completion has multiple scopes.** An upstream attempt can finish while a logical request
  continues through a retry; a task can outlive a transport connection. Do not merge those states.
- **Release cannot be undone.** Inspection of a later window cannot protect bytes already sent.
  The event must identify its protected boundary and how much content preceded it.

## 4. Trace the gaps between semantic events

The differentiating diagnostic value comes from joining semantic decisions to the gateway's
internal behavior. Add a small companion set:

| Candidate tracepoint | Candidate fields and purpose |
|---|---|
| **`ai:queue:enter` / `ai:queue:leave`** | Queue identity/reason, depth, elapsed wait, deadline remaining. Separate queueing from upstream execution. |
| **`ai:upstream:attempt`** | Attempt identity/phase, connection reuse, connect/TLS timing, failure stage, retry eligibility. Explain retries and establishment delays. |
| **`ai:stream:backpressure`** | Which side is blocked, buffered bytes, duration, action taken. Separate slow production from slow consumption. |
| **`ai:cancel:propagate`** | Cancellation received, forwarded, locally completed, and upstream acknowledgment where observable. Preserve each as a distinct fact. |
| **`ai:parser:reject`** | Parser state, rejection reason, bounded size/depth counters, adapter version. Localize malformed-input failures. |
| **`ai:probe:health`** | Invocations, errors, dropped records, sampling configuration, program generation. Make missing or degraded observation visible. |

Timing intervals need defined start/end points and overlap semantics. Summing overlapping tool,
upstream, and queue intervals would overstate request duration. Monotonic clocks support local
durations; cross-instance joins require clock metadata or explicit uncertainty.

## 5. A compact, versioned event contract

Each event should have a common logical envelope plus an event-specific payload:

- Schema version and event kind.
- Gateway-generated request/operation ID, scoped to a gateway-instance epoch.
- Parent operation and upstream-attempt IDs, when known.
- Tenant and authenticated-principal references.
- Monotonic timestamp and sequence.
- Policy revision and probe generation.
- Validity/provenance flags distinguishing **observed, authenticated, reported, estimated, and
  unavailable** values.

Use opaque references and fixed-size fields for inline programs. The list above is a logical
schema, **not a claim that every field fits in the current 96-byte context**. Define layouts and
sizes before freezing the application binary interface (ABI); place export-only metadata in the
host record envelope where appropriate. Richer accessors would need their own verifier/runtime
contract. Do not expose an unbounded JSON document as the tracing context.

Identity references should resolve off the poll loop. Raw credentials, prompts, tool arguments,
and response bodies are not needed for the baseline catalog. Content inspection can expose
bounded classification results and inspected ranges; content capture would be a separate interface.

Keep high-cardinality correlation IDs in event records rather than default metric labels. A
consumer must be able to distinguish sampled-away events from missing terminal events and dropped
records. Sequence and drop counters expose incompleteness; they do not make a record tamper-evident.

## 6. Observation and enforcement are different contracts

A tracepoint observes a fact. A decision gate accepts a bounded predicate result and lets the
host apply one of a defined set of actions. Pair them where intervention is useful, without
giving every observation hook arbitrary control over the protocol state machine.

```text
AUTHORING / ADMISSION — off the traffic path
  Program source
    -> compile and build-specific field resolution
    -> verify -> sign
    -> signed program artifact -> live loader

GATEWAY / INLINE — the poll loop
  Protocol adapter -> normalized operation -> authorization
    -> semantic tracepoint / bounded eBPF predicate
    -> host-owned action -> forwarding or protocol-correct rejection
    -> bounded event publication

OBSERVATION / ANALYSIS — off the poll loop
  Event drain -> correlation and aggregation
    -> dashboards / investigations / policy evaluation
```

Candidate actions:

| Boundary | Initial action contract to investigate |
|---|---|
| Admission or dispatch | Continue, or reject with a protocol-correct error before any protected upstream write. |
| Routing commit | Observe the chosen route first. Rerouting would require a separate host-owned selection contract. |
| Content release / streaming | Continue, or terminate through the host's defined cleanup path. Whole-message withholding requires an explicit buffering policy. |
| Cancellation | Request the host's cancellation path; record propagation separately from acknowledgment or remote completion. |

The current safe-return mechanism does not implement these actions by itself. Each requires
placement analysis, state-machine integration, cleanup semantics, and caller-visible behavior.
Parser normalization and semantic inspection belong in gateway components. The eBPF predicate
consumes bounded facts or inspection results; it should not run a model or parse arbitrary
content in the poll loop.

Similarly, local probe state is not a distributed quota service. Exact tenant-wide budgets,
cross-agent totals, and admission reservations require host/control-plane accounting. A tracepoint
can expose that accounting's result and version.

## 7. Runtime and tooling implications

**Rate classification.** Admission and completion are per-operation events; progress and
backpressure can fire much more frequently. Parser rejects may be driven at attacker rate.
Use first/last events plus sampled or thresholded progress, bounded publication, and explicit
dropped-record counters. Consumer pressure must not stall forwarding.

**DSL and discovery.** `tmmtrace` should become the principal authoring and operating interface for
these events. Section 7.1 describes the extension; existing `fentry/` and `fexit/` expressions remain
implementation-level tools. The proposed semantic-event syntax is not supported today.

**Performance.** Verification is not a wall-clock execution-time guarantee. Measure adapter
normalization, context assembly, predicate execution, record publication, and drain pressure as
separate costs, then measure their combined effect. Test idle/unarmed cost as well as armed cost.
No existing floor establishes packet-path overhead for these events.

**Coverage.** Specify which adapters, retries, resumed sessions, and protocol versions pass through
each gate. A bypass that forwards protected traffic without the gate is an enforcement defect,
even if normal-path counters look correct.

### 7.1 How `tmmtrace` and the DSL would support this

The intended workflow is **discover an event, inspect its contract, write a predicate, verify and
sign it, observe its matches, and optionally apply an admitted host action**. The domain-specific
language (DSL) should make that workflow concise without hiding field validity, event coverage, or
the meaning of an enforcement action.

#### Reuse the existing language layer; add a semantic event target

Today, [`substrate/tmmtrace.py`](substrate/tmmtrace.py) accepts `fentry/<function>` and
`fexit/<function>` targets, scalar comparisons, homogeneous `&&` or `||` predicates, field access,
`count()`, histogram-oriented values, and entry shielding with `shield(safe_value)`. It generates
C for compilation to eBPF and PREVAIL verification. Its type/signature catalogs resolve fields;
multi-hop pointer access has live evidence in `GROUND_TRUTH.md`.

Extend the parser with a semantic target such as `event/<name>`. Resolve it through a versioned
event catalog into an explicit hook, context layout, and permitted action set. This is an
authoring-level name: it need not become a new PREVAIL program type. The generated object must
still use a verifier-recognized section and a context contract matched by the actual dispatcher.
An implementation choice remains between dedicated adapter hook functions and a new typed-event
dispatcher; neither is supplied merely by accepting the new syntax.

**Illustrative proposed syntax — these are design examples, not runnable commands:**

```text
# Count calls to a selected tool for one tenant.
event/mcp:operation:dispatch
  /args.tenant_id == 17 && args.tool_id == 42/ { count() }

# Observe queue delay on the selected route.
event/inference:route:commit
  /args.route_id == 7/ { hist(args.queue_ns) }

# Count upstream cancellation acknowledgments, not just cancellation forwarding.
event/ai:cancel:propagate
  /args.phase == CANCEL_UPSTREAM_ACK/ { count() }

# Proposed host-owned dispatch rejection, after monitor-mode validation.
event/mcp:operation:dispatch
  /args.tenant_id == 17 && args.tool_id == 42/ { reject(TOOL_DISABLED) }
```

The examples are formatted across lines for readability. Semantic target names, symbolic enum
constants, and `reject()` are new language work. Numeric tenant/tool IDs illustrate opaque
references; their namespace and catalog revision must be known, not guessed. The compiler should
resolve symbolic values against the selected schema and reject unknown or ambiguous names.
Existing restrictions on mixed boolean operators should remain explicit until precedence or
parentheses are deliberately implemented and tested.

#### Make the event contract discoverable

Proposed `tmmtrace list` extensions and a new `describe` operation should expose:

- Event name, schema version, supported adapter/build, and coverage limitations.
- Field names, types, units, availability, and provenance; enum values and reference namespaces.
- Event timing: before dispatch, after completion, before release, or sampled progress.
- Supported modes/actions, including whether the event is observation-only.
- Rate class, context size, sampling capabilities, and correlation fields.

For example, a **proposed** `tmmtrace describe 'mcp:operation:dispatch'` should tell the operator
that `reject()` is meaningful there, identify the host error/cleanup contract, and state which
forwarding paths are covered. It must refuse an action at a hook that cannot implement it.
The event catalog becomes part of the build artifacts, alongside the existing symbol/type catalogs.

#### Keep compilation, admission, and runtime responsibilities separate

| Stage | Required extension or reused behavior |
|---|---|
| Parse and type-check | Resolve event, schema, fields, enum constants, units, validity requirements, and allowed action. Refuse incompatible combinations before generating C. |
| Generate and compile | Emit a bounded predicate against the event's actual context. Reuse the C-to-eBPF path; use build-specific relocation where needed. A stable semantic name does not remove binary compatibility checks. |
| Verify and package | Use the pinned build toolchain and PREVAIL on the final program bytes. Record target event/schema and action requirements in program metadata. |
| Sign and admit | Reuse signing/build checks; define how event/schema/action metadata is cryptographically bound and checked at load/arm. Any new binding fields require a versioned format change, not an unsigned sidecar trusted by convention. |
| Observe | Load in monitor mode, show hook hits versus predicate matches and candidate actions, and report program generation, sampling, and lost records. |
| Enforce | Admit only actions implemented by that event's host gate. The host performs protocol error construction, cleanup, or cancellation; the program returns a bounded decision. |
| Remove and verify | Disarm and verify attachment removal. Do not rely solely on the current `armed` status field, whose bookkeeping limitation is recorded in `GROUND_TRUTH.md`. |

The existing toolbox wrapper is not yet this complete workflow. It needs alignment with the
current **compile → relocate → strip → verify → sign** build-specific pipeline and with the
proposed event metadata. Authoring may be initiated from a toolbox, but compilation/signing belong
in the authoritative build/admission environment; forwarding never waits for them.

#### Define what counts and histograms actually mean

`count()` currently uses the host's match tally; histogram-oriented expressions return values for
consumer-side bucketing. That does not automatically provide exact per-tenant histogram maps or
complete delivery of every value. The extension must state whether each output is an exact local
counter, a sampled distribution, or an off-loop aggregate, and report loss/sampling with it.

Initially, host-computed durations and scalar fields are enough for useful DSL predicates.
Request/attempt joins, cross-event timing reconstruction, high-cardinality aggregation, and
cross-agent analysis should run in the drain/analysis layer. A `hist(args.queue_ns)` expression
requires the host to expose that duration; it is not a hidden stateful join inside the VM.
Task-wide quotas likewise consume an authoritative host accounting decision rather than relying
on a small local probe map.

Correlated records can feed the same operational view as `tmmtop`-style rates and JSON output,
but semantic labels and event ownership must come from attachment metadata, not guesses about
slot numbers. Cost reporting should distinguish static program properties, measured floors,
and workload results; it must not label a verifier pass as a wall-clock budget proof.

#### Deliver the language extension in three increments

1. **Discovery and observation:** versioned catalog, `event/` resolution, field checking,
   `count()`/value output, and correlated event draining. Preserve existing function-hook syntax.
2. **Operational usability:** describe schemas, resolve symbolic constants, show monitor deltas,
   sample/loss metadata, and join events off-loop. Validate generated predicates against known
   positive and negative inputs, not just successful compilation.
3. **Protocol-aware actions:** add `reject()` at one dispatch gate, bind its metadata at admission,
   and prove P14 before expanding the action set. Stream termination and cancellation follow only
   when their host contracts exist.

Acceptance must cover both the language and its meaning: a generated predicate must select the
same events as an independent fixture ledger; unsupported fields/actions must be refused; schema
mismatch must fail admission; and monitor mode must leave forwarding unchanged. These checks
support P13–P16 below rather than replacing live semantic-placement tests.

## 8. First implementation and demonstration

Start with one correlated tool-call and inference lifecycle:

1. Request admission.
2. MCP operation dispatch and completion.
3. Inference route commit.
4. First semantic output.
5. Request completion.
6. Cancellation propagation.

Build the IDs and terminal-state rules with this slice, rather than adding correlation after
independent event feeds already exist. Extend to delegation/task transitions and content release
once the first lifecycle is coherent.

The first demonstrations should be:

1. **Explain a slow request end to end:** tool time, routing, first output, and downstream pressure,
   with injected delays whose location is independently known.
2. **Change a narrow policy live:** load a monitor predicate, show known-positive matches, then
   exercise a protocol-correct dispatch restriction. Verify the denied operation never reaches
   the test upstream, and unrelated traffic continues.
3. **Follow cancellation:** distinguish receipt, forwarding, local cleanup, upstream acknowledgment,
   and any later observed output. Do not label forwarding alone as successful remote cancellation.

## 9. Validation questions and falsifiers

These questions are pre-registered as **P13–P16** in
[02-RESEARCH-PARAMETERS.md](02-RESEARCH-PARAMETERS.md). All are unrun.

| Question | Experiment and falsifier |
|---|---|
| **P13 — Does correlation survive real request lifecycles?** | Exercise concurrent multiplexed requests, retries, disconnects, and task continuation. Falsified if events join the wrong operation/tenant or ambiguous lineage is reported as known. Compare with an independently recorded test-client/upstream ledger. |
| **P14 — Is the dispatch gate before every protected write?** | Deny known-positive operations while exercising normal and retry paths. Falsified if any protected operation bytes reach the upstream before or despite denial, or rejection corrupts unrelated traffic. |
| **P15 — Are cancellation states truthful?** | Use upstreams that acknowledge, delay, or ignore cancellation. Falsified if forwarding is reported as acknowledgment/completion, or continued output is hidden by premature terminal accounting. |
| **P16 — Is inline work bounded and affordable under pressure?** | Compare unarmed/armed latency and throughput under representative streams, high event rates, and a slow/stopped drainer. Falsified if publication waits on the consumer, resource use escapes configured bounds, or agreed performance budgets are exceeded. Set workload and numeric budgets before running. |

Build-sensitive checks must use the pinned build toolchain. Live findings require an identified
binary and stable deployment, with independent traffic/endpoint witnesses where possible. A
passing record-format harness alone cannot establish correct semantic placement.

## 10. Decisions requested from collaborators

- **Protocol owners:** Which normalized facts already exist, and precisely where is the last
  reversible boundary before dispatch or content release?
- **TMM/runtime owners:** What is the smallest stable context and host action contract for that
  boundary? How are cancellation, cleanup, and concurrent probe replacement handled?
- **Observability owners:** Which questions require new internal state rather than fields already
  available in ordinary gateway logs? Define identity, timing, sampling, and terminal-event rules.
- **Performance owners:** Set the first workload matrix and budgets, including slow consumers,
  retries, long streams, and bursty malformed traffic.
- **Security reviewers:** Review provenance, action authority, exposed fields, and bypass paths as
  part of the Threat Model Analysis (TMA) before production enforcement.

**Working recommendation:** prioritize the correlated lifecycle and a single protocol-correct
dispatch gate. They provide a concrete test of the premise: stable semantic events plus live,
signed predicates can make the gateway more explainable and adaptable without moving complex
protocol logic into the embedded VM.

## Related work in this repository

- [GROUND_TRUTH.md](GROUND_TRUTH.md) — measured capabilities and their limits.
- [Context-contract validation](ctx-contract-validation.md) — the latest runtime-context fix.
- [TMM tracepoint catalog](tmm-usdt-tracepoints.md) — earlier design rationale; use
  [DOC-STATUS.md](DOC-STATUS.md) to distinguish design-era claims from current results.
- [Data-plane egress primitives](data-plane-egress-primitives.md) — design rationale for bounded,
  off-loop export; the current record-draining evidence is in `GROUND_TRUTH.md`.
- [Cross-plane intent binding](cross-plane-intent-binding.md) — a separate, unvalidated proposal
  for joining gateway authorization to host execution. The events here could supply gateway-side
  evidence; they do not establish that cross-plane join.
