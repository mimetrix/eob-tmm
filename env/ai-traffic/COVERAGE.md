# Agent activity: probe first, coverage from observations

**2026-09-28 — IDEA discovery plan; existing fixture results are separate.**
Owner correction: first design the probe and establish which application metadata
it can extract. Preserve variants without an assumed agent workflow. Downstream
analytics can follow. The immediate work is the [metadata probe](METADATA.md),
not identity matching or a representative workload test. No overall coverage
percentage is established.

**MEASURED extraction subset:** the [getter probe](METADATA.md) supplies root-method
values on the A2A path. The [token-cache probe](TOKEN-METHOD.md) also supplies
`tools/list` on the configured AIMCP/JSON path. These fixture results do not give
an overall coverage percentage, authenticated identity or session relationships.

The earlier version of this page proposed a fixed concurrency test too soon.
That proposal is withdrawn below, with the reason retained. The questions in
the register are prompts for investigation, not a model of how agents must work.

**Second correction, retained:** the next response made a real agent deployment
the prerequisite and an activity report the first deliverable. That also moved
too far downstream. Source and binary inspection, probe design and extraction
checks can proceed now. Real traffic will later establish which variants these
observation points expose and which they miss.

## What coverage means

Investigate these questions without assuming the answers or the units of work:

1. **Observation:** Did the relevant traffic pass through the instrumented TMM?
   Which request, response or stream boundaries were actually observed?
2. **Identity:** What authenticated the actor? Can the evidence distinguish the
   running instance, or only the shared agent identity?
3. **Work relationships:** What proves a retry, delegation or parent operation?
   Caller labels and nearby timestamps do not establish those relationships.
4. **Outcome:** Was the operation accepted, rejected, completed or interrupted?
   Header completion and destination acceptance do not prove tool completion.
5. **Evidence health:** Were observation, controller history and output complete?
   Missing evidence must be visible, with a reason for each unknown result.

An actor can be known while its running instance or parent remains unknown.
Keep those distinctions in the contract for future records. Do not treat an
instance name as authenticated merely because a request contains it.

## Existing evidence and discovery questions

**MEASURED** below means only the stated fixture case. Proposed tests and failure
conditions below are **IDEA / unrun**, not a selected representative test set.
**Outside current scope** means the TMM observer cannot
claim coverage of that work; it is not a test waiting to be marked passed.

| ID | Area to investigate | Evidence today | Discovery questions and later failure conditions |
|---|---|---|---|
| C01 | One agent sends many queries at once | No qualified same-agent, multi-request fan-out result. The current concurrent clients each send their own requests in sequence. [Correlation](CORRELATION.md) | Issue overlapping requests with deliberately reordered completions. Fail on merged attempts, wrong actors, or an assumed completion order. |
| C02 | Many agents operate at once | **MEASURED:** A/B concurrency and shared-connection alternation in the bounded HTTP/1 fixture. [Correlation](CORRELATION.md) | Increase distinct agents and mix concurrent and reused connections. Fail if connection identity substitutes for actor identity. |
| C03 | Several deployed copies of one agent | No qualified authenticated instance identity | Test distinct instance credentials and shared credentials. Fail if two copies merge when evidence distinguishes them, or if shared credentials acquire a guessed instance. |
| C04 | Delegation and work split across agents | **MEASURED:** one-level fixture delegation, actor/originator/parent retention and selected invalid-grant cases. [Attribution](ATTRIBUTION.md), [correlation](CORRELATION.md) | Test several children, nested delegation and results returning out of order. Fail on an invented parent, changed executing actor, expanded authority or an inferred completed task. |
| C05 | Retries, replay and duplicate work | **MEASURED:** replay, fresh-nonce retry and ambiguous marker refusal in fixture tests. [Attribution](ATTRIBUTION.md), [correlation](CORRELATION.md) | Test timeout after acceptance, overlapping retries, speculative requests and cancellation. Fail if attempts collapse into one operation or cancellation is reported as proof that work stopped. |
| C06 | Long responses and streams | **MEASURED:** paced synthetic stream forwarding; fragmented request headers and paced bodies. This is not attributed stream completion. [Traffic fixture](README.md), [correlation](CORRELATION.md) | Attribute stream boundaries, partial output, disconnect and reconnect separately. Fail if chunks become separate requests or partial output becomes a completed operation. |
| C07 | Protocol and transport changes | **MEASURED:** canonical fixture HTTP/1 header extraction, bounded to 512 bytes. Subsequent native-filter tests add handler events and bounded A2A/AIMCP method values. These do not validate native-filter attribution or general protocol coverage. [Correlation](CORRELATION.md), [metadata](METADATA.md), [token cache](TOKEN-METHOD.md) | Different contracts are necessary for native Model Context Protocol (MCP), Agent-to-Agent (A2A), HTTP/2, WebSocket and gRPC paths. Reject a result if unsupported syntax or multiplexed streams receive a guessed HTTP/1 identity. |
| C08 | Identity providers, tenants and credential changes | **MEASURED:** two fixture identities with per-run request-proof keys. Production identity integration is unvalidated. [Attribution](ATTRIBUTION.md) | Test credential rotation, expiry/revocation and identical actor labels under different authorities or tenants. Fail on stale authorization or cross-tenant identity merging. |
| C09 | Observation gaps and restarts | **MEASURED:** reported detach, capacity refusal, full reload and retained-connection refusal. [Gaps](GAPS.md) | Test lost controller history, collector restart, mixed old/new records and independent detection of attachment changes. Fail if absent history is treated as continuous coverage. Silent breaks remain unvalidated. |
| C10 | Workers, scale and output pressure | **MEASURED:** one-worker bounded joins and tracking-limit refusal. No data-path cost result. [Correlation](CORRELATION.md), [gaps](GAPS.md) | Test multiple TMM workers, instance rollout and slow/stopped consumers against registered budgets. Fail on cross-worker joins, hidden loss, unbounded waits or exceeded budgets. |
| C11 | Deferred work and work outside the proxy path | **Outside current scope:** local execution or traffic that does not reach this observer. No qualified queued-work attribution | Inventory the actual path and obtain a separate execution/queue witness where needed. Fail if no TMM record is presented as proof that no work occurred. |
| C12 | Useful internal security facts | Request-to-actor matching is bounded and measured; distinctive internal visibility is still open | Select a routing, rebinding or policy fact and audit existing interfaces. Fail if the observation cannot distinguish the condition or adds no visibility beyond the relevant existing surface. See P20. |

Measured claims above refer to the [ground-truth record](../../GROUND_TRUTH.md)
and its registered source receipts. Authored client, authority and collector
checks are SELF witnesses, not independent authentication audits.

## Later step: use the probe to observe a real deployment

**IDEA / not yet run.** This follows the probe extraction work in [METADATA.md](METADATA.md).
The recorded agent-attribution traffic is synthetic. Select the deployment and
observation point before collecting its activity, not before designing the probe.

1. **Establish the observation boundary.** Record the actual deployment, versions,
   traffic path and available observation points. State which activity reaches
   TMM, which is encrypted at the chosen point, and which is outside that path.
   Do not claim visibility from configuration alone.
2. **Collect observable facts.** Select instrumentation from the actual reachable
   code and traffic. Record supported connection, parser, request, response and
   stream events only where their meaning is established. Include timestamps,
   process/worker identity, instrumentation identity, attachment history and loss
   information where available. Name unavailable fields explicitly.
3. **Preserve observations before interpretation.** Do not require the fixture's
   `X-Proof-Nonce`, a recognized agent protocol, or a known actor to retain an
   activity record. An unfamiliar exchange is still evidence. A parser call is
   not automatically a request; a request is not automatically an agent query,
   tool call or task. Keep inferred meanings separate from observed facts.
4. **Compare with an independent account of the work.** Where available, use the
   real deployment's authenticated records, application traces or controlled user
   actions to establish relationships. Record provenance and uncertainty. Do not
   infer retries, delegation, completion or identity from timing or shared labels.
   If no comparison witness is available, leave those meanings unknown.
5. **Derive tests from the evidence.** Retain observed sequences and unexplained
   cases. Determine what the instrument missed, conflated or could not interpret.
   Then register reproducible tests for those cases and for known failure modes.
   State the deployment/version scope of each result. Revisit it when new activity
   appears; a passing test set is not proof of complete coverage.

That later discovery deliverable is an activity record and a visibility report.
It must distinguish:

- activity observed directly;
- meaning supported by a separate witness;
- observed activity whose meaning is unknown;
- activity outside the observation boundary;
- intervals where loss or missing history prevents a coverage claim.

**Discovery falsifiers:** unfamiliar traffic silently excluded; absence of events
reported as absence of work; parser calls relabeled as logical operations without
evidence; identity or causal links invented; or incomplete observation described
as complete. Existing fixture tests remain regression tests for their mechanisms.
They do not establish that the selected observation points cover real agent use.

### Withdrawn fixed-workload proposal

Earlier on 2026-09-28, this page selected three agents, two simulated instances
each and four simultaneous requests per instance: a 24-request wave. No such test
was implemented or run. The owner corrected the approach: we had not observed a
real workload that justified those assumptions. C01–C03 remain useful questions,
but that fixed workload is not the next experiment. Discovery comes first.

## Keep the register current

For each observed integration, record its deployed protocol/version, identity source,
request boundaries, transport and traffic path before claiming support. Add a
missing behavior or interaction to this register before implementing its test.
Do not infer support for a new combination from separate passing component tests.

Promote only the tested combination to MEASURED, with pinned artifacts, receipts,
scope, witness and a stated failure condition. Retain failed attempts and update
the limits in the same change. Review the register when the workload or integration
changes. No claim of complete agent coverage follows from this checklist.
