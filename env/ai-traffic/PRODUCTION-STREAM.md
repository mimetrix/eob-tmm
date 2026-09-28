# Production metadata stream

**2026-09-28 — IDEA service contract.** The owner requires streaming analytics
workflows. A production output service must run continuously and support independent
consumers. A saved test receipt is not that service.

**MEASURED foundation:** the [method probe](METADATA.md) extracts bounded values
and emits records through the local ring in the one-worker fixture. See the
[actual values](EXTRACTED-METADATA.md) and
[evidence index](../../SOURCES.md#root-object-method-extraction-2026-09-28).
Multiworker collection, sustained throughput, durable delivery and consumer
recovery are not established by that result.

**Later measured subset:** the [local collector](COLLECTOR.md) now commits before
ring acknowledgement and exposes independent HTTP replay cursors. Ten native
checks and a one-worker live field comparison pass. The journal and exact values
are archived. This adds bounded handoff/recovery evidence; production ownership,
complete attachment/health history, power-loss durability and sustained cost
remain open. [Receipts](../../SOURCES.md#continuous-metadata-collector-2026-09-28).

**Separate-container subset:** [collector replacement](COLLECTOR-CONTAINER.md)
now passes a bounded live test after normal stop and SIGKILL. Requests during both
outages forward and their queued values are recovered. Two separate consumers use
only the Unix API volume. TMM stays unchanged. The collector still shares TMM's PID
namespace and needs process-inspection access; strong security isolation is open.

## 1. Where each step runs

```text
BUILD / CONTROL PLANE — off the traffic path
  Qualify fields + verify/sign probe
    -> program + field manifest + schema
  Load / configure / attach / detach
    -> attachment history and source identity

TMM WORKERS — traffic path
  Application hook -> bounded field reads -> one record attempt
    -> producer-owned local ring
  No wait for network publication, disk storage or analytics consumers

LOCAL COLLECTOR — separate container
  Own the drain cursor for each producer ring
    -> raw records + source identity + collection health
  Validate/decode -> versioned metadata envelope
    -> bounded output queue / durable local journal

STREAM SERVICE — outside TMM
  Publish and retain events according to the delivery contract
    -> independent consumer positions and replay

ANALYTICS WORKFLOWS
  Subscribe -> process windows / join qualified events -> persist results
    -> acknowledge progress independently
```

Use one coordinated reader for each local ring. Consumers must not compete for
that ring's drain cursor. Distribution to multiple consumers happens after the
collector. The proposed per-worker ring ownership and discovery protocol still
need validation against the production TMM process model.

## 2. What consumers receive

Consumers subscribe to a versioned event family, such as application-method
observations. They receive values and extraction status, not only aggregates.
Keep raw record bytes available for a different decoder or later interpretation.

| Envelope component | Required content and source |
|---|---|
| Source identity | Device/process epoch and worker identity, obtained from a verified producer registration; production mechanism pending |
| Probe identity | Loaded instance, program hash, binary build ID, hook/phase and schema manifest |
| Event identity | Source epoch + worker + loaded probe instance + nonzero sequence; valid only within the declared sequence scope |
| Time | Producer monotonic timestamp and its clock domain; collector receipt time separately |
| Fields | Field identifier, exact bytes/representation, original/copied lengths where known, complete/truncated/read-failed/unavailable status |
| Health | Output refusals, ring loss, collector loss, publication loss and known observation gaps, each identified by layer |
| Configuration | Probe config revision, extraction limits and relevant attachment history |

Do not fabricate missing source identity. A replacement process or ring starts a
new source epoch. A sequence reset or saturated sequence must not reuse an event ID.
The current probe's loaded-instance identity is not, by itself, a worker identity.
Here an epoch identifies one source lifetime. Carry 64-bit identities and clocks
as lossless integer fields or strings; do not convert them to floating-point values.

Publish source-start, source-stop, attach, detach, schema-change and gap events
alongside field events. A separate health report must work when the data ring is
full or silent. Its source information and failure behavior require validation.
No events can mean idle traffic, an unused hook or a broken source; it does not
establish that an application field was absent.

Preserve per-source order where available. Do not infer a global order across
workers from arrival time or compare unrelated monotonic clocks directly.
Analytics windows must define late-arrival behavior and carry observation quality.
Contiguous event numbers alone do not prove continuous hook coverage; see [GAPS.md](GAPS.md).

## 3. Delivery and slow consumers

The proposed default for stateful analytics is a **replayable stream**. A consumer
acknowledges its own progress. One slow or failed consumer must not stop the other
consumers or make TMM wait. The guarantee has a boundary:

- **Before durable acceptance:** TMM output is bounded and can lose records.
  Ring pressure, collector failure or producer failure can leave a gap. A crash
  can leave an unknown tail; do not invent an exact lost-record count.
- **After durable acceptance:** design for retry and at-least-once delivery within
  a declared retention window. Duplicates are possible. Consumers deduplicate
  using the event identity and save progress with their state.
- **Beyond retention or storage capacity:** report an explicit gap. Finite storage
  cannot retain an unlimited outage. Do not silently resume as if history were complete.

If the local journal is the acceptance boundary, retain the ring record until the
journal has durably accepted it. Specify batch and sync policy. A collector crash
between journal acceptance and cursor advance can cause replay duplicates.
Disk delay can fill the ring; the producer must still follow its nonblocking loss
policy. This ordering and recovery behavior are proposed, not tested here.

Use bounded queues with explicit overflow rules at each stage. Keep source-read
and output-loss counters even when downstream consumers are unavailable. Do not
introduce silent sampling to recover capacity: the probe contract attempts output
on every invocation. An explicit change in capture scope needs a new config
revision and a visible observation boundary.

## 4. Where ZeroMQ fits

A ZeroMQ publisher can be a collector-side transport adapter. A publisher inside
TMM is not required. Selecting that adapter does not specify this service's
retention, acknowledgements, replay or consumer recovery contract.

Provide a live-only endpoint only for consumers that accept gaps and no replay.
For stateful workflows, require the replayable service above. Both can receive
the same metadata envelope. The choice of an existing stream platform or a new
service is open; no transport integration is implemented by this document.

## 5. Which analytics are supported by the fields?

| Workflow | Field requirement / current limit |
|---|---|
| Distribution of observed method values; detection of unfamiliar values | Current method values can supply input. Counts are getter observations, not proven request counts. A production stream remains pending. |
| Per-request latency and outcome | Needs qualified request/response association and completion fields. The current method record does not supply them. |
| MCP tool activity | Needs a reachable MCP method/tool extraction path. The live AIMCP input did not call the current getter. |
| Agent/session activity graph | Needs qualified identities and relationships. Do not substitute pointer, connection or method identity. |

Preserve unfamiliar values and status-only records. Do not require a recognized
workflow before accepting an observation. Publication cannot supply fields that
the probe did not extract.

## 6. Production acceptance gates

Register these before implementing the service:

1. Run multiple producers. Establish one reader per ring and unique source epochs.
   Replace a producer. Old records must not acquire the replacement's identity.
2. Kill the collector before and after durable acceptance. Account for replay,
   duplicates, cursor recovery and unknown tails.
3. Disconnect publication and slow one consumer. Fill bounded queues and storage.
   Verify other consumers' behavior, loss reports and unchanged forwarding behavior.
4. Change schemas/probes during traffic. Retain old schemas and attachment
   boundaries. Unknown schemas must not be silently decoded as the current one.
5. Test replay, late events, duplicates and a missing source. Verify that
   workflow results expose incomplete observation windows.
6. Measure hook/read/output cost, collector drain rate and end-to-end latency at
   sustained and burst loads. Size rings and retention from these results.

**Falsifiers:** a blocked traffic worker; an unbounded queue; incorrect source or
field identity; undetected loss presented as complete history; replay events with
new identities; or analytics output that treats unavailable fields as absent.

Per-call cost remains unmeasured. Production release also requires the repo's
Threat Model Analysis (TMA) gate. Neither this design nor the one-worker field
test completes that gate.
