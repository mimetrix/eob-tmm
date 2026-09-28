# Continuous metadata collector

**2026-09-28 — MEASURED local handoff and replay.** The collector now runs
continuously outside TMM. It commits records to a local journal before advancing
the ring cursor. Two HTTP consumers receive the same live method values.
[Receipts and hashes](../../SOURCES.md#continuous-metadata-collector-2026-09-28).

**Deployment update:** the first live test used separate processes inside TMM's
container. The [separate-container gate](COLLECTOR-CONTAINER.md) now places the
reader, writer and replay service in their own container. It measures replacement
after normal stop and SIGKILL, with two API-only consumer containers and stable TMM.

The gate below was registered as IDEA before implementation. The original text
is retained in the build receipts. This completes a bounded subset of
[PRODUCTION-STREAM.md](PRODUCTION-STREAM.md).

The first reader is a separate C process. It maps the existing STREAM segment,
copies one record, and waits for a matching acknowledgement. It advances the ring
cursor only after the Python collector commits that record to a local SQLite
journal with synchronous durability enabled. No producer or TMM change is required.

The journal has one writer, a record-retention limit and a database-page limit.
A separate HTTP service exposes bounded replay pages and independent
client-held cursors. Old cursors receive explicit retention-gap responses. No
consumer controls the ring cursor. A failed database commit must produce no ACK.
The initial service uses loopback TCP. The container deployment uses HTTP over a
Unix socket; consumers mount only its API volume.

## Source and delivery scope

The reader checks a pinned producer PID/start time, executable identity, boot/PID
namespace and segment inode. This describes the current source, not an agent.
Ring index identifies a producer ring, not a verified TMM worker ID. Reuse/reset
of a segment within the same producer lifetime remains a qualification gap; cursor
regression or conflicting bytes at an existing position must stop the collector.
The reader also requires a shared writable mapping of the segment in the pinned
process. It checks executable device/inode, not a signed executable manifest.
The container supervisor additionally checks a controller-supplied executable hash
before starting either service. This does not replace program-binding verification.

Deduplicate by source identity, ring and byte position, with a payload comparison.
Use a distinct journal identity in replay cursors. Keep unknown payloads as raw
records; decode the measured method record only when its schema and shape match.
The decoded view is labelled `binding: not_verified_by_collector`. Matching bytes
does not prove which loaded program produced them. The live test separately checks
the signed program, loaded instance, configuration revision and run token.
The legacy drain must not run beside the new reader. Cooperative locks cannot
exclude a reader that ignores them.

## Pre-registered checks

- Reproduce whether the old consuming helper advances the cursor before output.
- Stop the reader before ACK: cursor unchanged and the same record is replayed.
- Stop after durable commit but before ACK: restart yields one journal record,
  then acknowledges the duplicate without assigning a new event identity.
- Refuse a competing reader/writer. Reject malformed ACKs and corrupt geometry.
- Fill the ring while the reader waits: producer returns, drops are observable.
- Fill/expire journal retention: old replay cursors get a gap, not silent skipping.
- Use two independent consumers. Slow/disconnect one and verify the other advances.
- Replace the source, use a cursor from another journal, or replay conflicting bytes:
  retain source boundaries and refuse false continuity.
- Run the collector against the live method probe in the isolated fixture, if the
  native gate passes. Compare exact values and restore the hook before cleanup.

**Falsifiers:** ACK before durable acceptance, duplicate journal events after the
commit/ACK crash window, unbounded storage/queues, silent retention loss, false
source identity, blocked producer, or loss presented as complete extraction.

This first service does not establish production throughput, multiworker TMM
ownership, power-loss durability, authenticated off-box transport or arbitrary
stream-broker integration. These remain production gates.

## Measured result

Pinned GCC 13.3.0 builds the separate reader. Build 03 passes ten process/native
checks. They cover pre-ACK replay, the commit/ACK crash window, locks, source
replacement, full-ring drops, finite retention, database-page exhaustion, two
HTTP consumers, parent death and lazy source startup. Test sources and assertions
are SELF witnesses. Kernel interfaces supply mappings, file identity and locks.

The legacy drain test sends stdout to `/dev/full`. It consumes a record, fails
to store output, and still returns zero. Its old at-least-once claim was false.
The source comments are corrected; the original comments and failure remain in
[CONTESTED-PREMISES.md §30](../../CONTESTED-PREMISES.md#30--legacy-drain-at-least-once-delivery--falsified).

Live attempt 01 stopped before attachment. It expected a segment before TMM's
first output. The corrected collector can wait for a bounded startup interval.
A ready journal can still have no registered source. The test records this state.

Live attempt 02 uses the pinned `ca69b84f…` TMM and signed method build 02.
Ten client requests produce eight getter calls and eight method records:

| Extracted bytes or result | Status |
|---|---|
| `SendMessage` | Complete |
| `future.variant` | Complete; request arrived in fragments |
| Empty string | Complete |
| Literal `future\u002evariant` | Complete; escaped bytes preserved |
| 64 `x` bytes | Complete |
| First 64 of 65 `y` bytes | Truncated |
| No value; getter return 29 | Getter error |
| No value; four-member scan exhausted | Budget exhausted |

Nested-only and AIMCP requests did not call this getter. These are measured
coverage limits, not evidence that those requests had no method.

Both consumers receive identical bytes, event identities and cursors. One consumer
waits until the first has advanced, then replays from its own earlier cursor.
The journal has ten events: source boundary, ring health and eight method records.
No reported drops, new VM errors or TMM restart occurred. The collector stopped
cleanly. The hook was restored, the journal was archived, and the fixture was removed.

## Run the local service

Compile `substrate/drain/ls_stream.c` as a separate Linux executable. For the
recorded build-box gate, stage the current collector sources, then run:

```sh
python3 /home/starin/eob-config-20260925/collector_build.py \
  --output /home/starin/eob-config-20260925/collector-build-NEXT
```

Use a new output directory for each attempt. The builder records compiler output,
exact sources, binary hashes and every check. It does not build TMM.

For a qualified source, set `PID` and `START_TICKS` from its checked process record.
Use an existing journal directory. The reader must see that PID and its segment
mapping in `/proc`. Run the writer in one process:

```sh
python3 env/ai-traffic/stream_collector.py collect \
  --reader /path/to/ls_stream \
  --segment /run/ls-stream/ls_tp_ring \
  --pid "$PID" --start "$START_TICKS" \
  --journal "$JOURNAL_DIR/journal.sqlite" \
  --wait-segment 120 --retain 10000 --max-pages 32768
```

Run the replay service in another process. Both processes must see the same journal:

```sh
python3 env/ai-traffic/stream_collector.py serve \
  --journal "$JOURNAL_DIR/journal.sqlite" --port 18096
curl 'http://127.0.0.1:18096/events?limit=100'
```

Each consumer saves its own returned `next_cursor`. Supply it as `after` on the
next call. `wait_ms` enables bounded long polling:

```sh
curl "http://127.0.0.1:18096/events?after=$CURSOR&limit=100&wait_ms=10000"
```

An expired cursor gets HTTP 409 with `error: retention_gap` and the retained
boundaries. A cursor from another journal gets `wrong_journal`. Starting without
a cursor selects the oldest retained event; it does not request earlier history.
An empty page does not prove that observation or the writer is healthy.

Events retain raw payload hex and source/ring positions. Recognized method records
also have `decoded.record.value_hex`, extraction status and copied/original lengths.
Their representation is escaped JSON string bytes. Large identities and clocks
are decimal strings. Transport `ts_ns` is a real-time clock; the method record's
`monotonic_ns` is a monotonic clock. Do not join requests by either timestamp.

The journal uses SQLite `synchronous=FULL` and rollback-journal mode. Its page
limit bounds database growth; a transaction journal also needs disk space.
Retention and source checkpoints commit together. Failed commits produce no ACK.
Pages contain at most 128 events. The HTTP service accepts at most eight concurrent
requests and releases each database read transaction before network output.

## Verify the saved result

```sh
python3 env/ai-traffic/collector_verify.py
```

This checks saved source hashes, exact consumer records and archived SQLite journals
for both deployments. It does not generate more live traffic. The original
same-container archive has eight files; the separate-container archive has nine.
The live runner supports `--suite collector --collector-dir collector-build-03`
with `--artifact-dir method-build-02`, after fixture creation. Use a new run name.

## Remaining limits

- Records can be lost before commit, including during ring overflow or producer
  death. Last loss counts can also be unavailable. No exactly-once claim is made.
- Source boundaries, observed drop changes and retention gaps are explicit.
  Complete attachment history and silent-gap detection remain unvalidated.
- A cooperative lock prevents another cooperating reader. The legacy drain can
  ignore that lock. Source reset/reuse within one process lifetime remains open.
- Each record requires a local commit. Sustained throughput, storage latency and
  per-call TMM cost are unmeasured. Disk pressure can stop collection and fill rings.
- Loopback TCP and Unix-socket HTTP are local interfaces. Production authentication, multiworker
  ownership and Threat Model Analysis remain release gates. No off-box broker
  adapter is included in this result.
