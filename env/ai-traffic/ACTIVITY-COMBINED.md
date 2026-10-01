# Combined activity records

**2026-09-30 — MEASURED: ten combined exchanges in isolated live TMM.** One
bytecode file in Executable and Linkable Format (ELF) supplies both entry programs.
They run at JSON completion and the HTTP handler. The bytecode
adds an explicit exchange key to their records. The exporter combines method,
target, message ID, reported reply and HTTP fields by that key.
[Evidence and checksums](../../SOURCES.md#combined-activity-records-2026-09-30).

The contract was registered before implementation. The first live attempt
falsified its event-order assumption; the correction and failed run remain below.
Identity is still unknown. This result covers one worker and non-pipelined HTTP/1.

## Exchange contract

**Revised after live attempt 01.** The original header-first candidate is
[falsified](../../CONTESTED-PREMISES.md#40--aimcp-sees-request-headers-before-client-json-completion--falsified).
Start at the first reader of a client JSON-completion invocation. Allocate
a new number on every such invocation, including a reused connection or message ID.
Use the JSON program instance and run token with that number. Require a later
HTTP request-header confirmation before accepting server JSON. Store the current
number in a bounded map keyed by the client flow address. The address stays
private; it is not the exchange number or an identity.

For a server-side observation, require a current, symmetric peer link to a
client-side connection flow. Look up that client's active exchange. End the
exchange on the client-side response-done event. Initialization, abort, teardown,
overlap, invalid input and capacity failure must not retain a usable old key.
Neither handler entry nor a reported result proves successful execution.

This implementation supports one worker, connection-flow storage and non-pipelined
HTTP/1 request/reply exchanges. A second request while an exchange is active must
invalidate the association. Streaming multiple JSON messages, HTTP/2, multiple
workers and silent missed hooks remain outside this first qualification.

The exporter needs one client JSON observation, a request-header confirmation,
one server JSON observation and an observed response end. It checks exact ID type
and spelling, record completeness,
instance/run consistency, sequence continuity and reported loss. Missing, duplicate,
conflicting or ambiguous inputs stay explicit. Identity remains unknown.

## Falsifiers and checks

- Reject wrong peers, unobserved starts, cross-instance state and duplicate starts.
- Equal IDs on concurrent connections must remain separate.
- Keep-alive and address reuse must allocate fresh exchange numbers.
- Missing/duplicate parts, output loss, truncation and collector page boundaries
  must not yield a falsely complete record.
- Reject unsupported storage and malformed frames; retain their diagnostics.
- The host HASH evicts on full. A reserved counter must stop new address
  admission at 127 retained addresses. Verify zero evictions. Completion, abort,
  teardown and initialization release the address and decrement the counter.
- Verify both entry sections with pinned PREVAIL. Test interpreter and
  just-in-time (JIT) execution.
- Use the isolated fixture for exact request/reply comparisons and hook witnesses.
  Archive it before removal. Retain failed attempts.

The frame uses version 2 of the application binary interface (ABI).

| Where | Step | Output | On the data path? |
|---|---|---|---|
| TMM worker | Two entries in one ELF read bounded fields and maintain exchange state | ABI 2 frames in the ring | Yes; no wait for a consumer |
| Collector process | Commit ring records to the journal, then expose replay pages | Raw records and cursors | No |
| Exporter process | Check the key, required fields, boundaries and reported gaps across pages | Combined JSON or explicit incomplete/diagnostic output | No |

The grouping key is `(source_id, ring, run, owner_instance, exchange)`. Exact
message-ID type and raw bytes are consistency checks, not lookup keys. The
48-byte ABI 2 prefix also carries side, status, phase and invocation. ABI 1 is
refused because it described the falsified header-first contract.

## Measured result

Live attempt 03 uses the [182,056-byte artifact](ACTIVITY-PROGRAM.md) at both
entry hooks in build `f9a1ed8c8c54192e76e54bf7f1c59921b8a774c9`.

| Check | Result |
|---|---|
| Three individual exchanges | Exact methods, tool/resource targets, IDs and reported replies |
| Three requests on one keep-alive connection | Three different exchange keys despite the same message ID |
| Four concurrent connections | All four requests reach the backend before replies; equal IDs remain separate |
| Probe output | 20 JSON calls / 80 field records; 184 HTTP calls / 184 records |
| Combined output | Ten `observed_exchange` records; HTTP 200 and local transfer completion in each |
| Replay | Second consumer and one-row pages reproduce the combined records |
| Kernel witness | Both hook patches and restorations observed; same process, zero restarts |
| Cleanup | All three attempts archived in 24 files; isolated fixture removed |

SELF witnesses cover traffic, fields, counters and replay. KERNEL witnesses cover
the process, executable and hook bytes. TOOL witnesses cover source/layout and
compilers. INDEPENDENT PREVAIL checks both entries with the pinned 256-byte stack
limit. GCC and clang native harnesses pass interpreter and JIT execution.

Current-exporter check 02 adds the explicit reply-before-header-confirmation
check after live attempt 03. Six tests pass against that measured journal and the
real Unix-socket API. They cover page sizes 1, 2, 3, 7, 17, 127 and 128;
38 missing-record/discard mutations; changed keys, producers, runs, invocation,
ABI and side; output failures; truncation; mismatched IDs; and bounded capacity.
The six legacy observation-export tests also pass.

### Corrections retained

- Live attempt 01: client JSON arrives before the AIMCP request-header event.
  Request-kind bits must also be checked as request bits. ABI 2 starts at client
  JSON and requires the later header confirmation.
- Native check 05: the host HASH evicts on full. A reserved admission counter
  now prevents eviction. Check 06 tests refusal, deletion and fresh admission,
  with zero evictions. The host map policy is unchanged.
- Live attempt 02: DISCARD at ring wrap is padding, so unconditional group
  invalidation was wrong. The exporter keeps the diagnostic and checks producer
  sequences and required fields. Missing-record/discard mutations still prevent
  complete results.

## Export combined JSON

**Timestamp correction — MEASURED saved-journal/API replay.** The first combined
format omitted source timestamps. The correction was registered before its check.
It adds `timing.started_at`, `ended_at` and `last_observed_at` from the source
ring's `ts_ns` (`CLOCK_REALTIME`). Format them as
UTC with nine fractional digits. Start means the first client JSON observation;
end means the observed client response-done boundary. These are observation
times, not the start and end of remote tool execution.

Calculate `timing.duration_ns` from the start/end probe `monotonic_ns` values,
using `CLOCK_MONOTONIC`, not wall-clock subtraction. Keep it as a decimal string. Missing/invalid source
time stays null; an unfinished exchange has no end or duration. `timing.status`
is `complete`, `incomplete` or `invalid`. Reject the change if replay changes
timestamps, nanoseconds are rounded, a wall-clock adjustment changes duration,
or an unfinished exchange gains an end time. Test the saved live journal and API.

All eight exporter tests pass on the build box in `activity-timestamps-check-01.json`.
They compare timestamps with all ten measured exchanges and test missing/invalid
time, unfinished exchanges, a backward wall-clock adjustment and a regressed
monotonic clock. Timing status is separate from field-correlation status. A
regressed monotonic clock gives `invalid` timing with no duration. No export-time
clock is substituted for source time. This is replay of the existing live journal.

Run beside the mounted collector socket:

```sh
python3 env/ai-traffic/activity_combine.py --socket /collector-api/events.sock --follow
```

Output is one JSON object per line. It includes combined records and diagnostics.
For a saved journal, use `--journal PATH_TO_EVENTS_SQLITE`. Without `--follow`,
the command stops at the current end and reports unfinished groups as incomplete.
Wrong-journal and expired cursors return an error; they do not silently restart.

The exporter retains at most 128 pending groups and 128 records per group. Its
pending state is in memory. A restart needs replay from before the earliest
unfinished exchange. `--after` skips earlier records; it does not restore state.
Consumers can use the deterministic `activity_id` to remove replay duplicates.

### Measured example, shortened

This is a subset of the first combined record in `activity-timestamps-check-01.json`.
The full record includes raw field bytes and per-field source cursors.

```json
{
  "schema_version": 1,
  "event_type": "agent.activity.combined",
  "identity_binding": "unknown",
  "identity": null,
  "correlation": {
    "status": "observed_exchange",
    "scope": "single_worker_nonpipelined_http1",
    "issues": []
  },
  "activity": {
    "method": {"status": "complete", "value": "tools/call"},
    "target": {"status": "complete", "kind": "tool_name", "value": "sum"},
    "message_id": {"status": "complete", "kind": "string", "value": "one"}
  },
  "reported_outcome": {
    "result_present": true,
    "error_present": false,
    "tool_error": {"status": "complete", "value": false},
    "http_status": {"status": "complete", "value": 200},
    "local_transfer_complete": {"status": "complete", "value": true}
  },
  "timing": {
    "started_at": "2026-09-30T14:32:07.456368731Z",
    "ended_at": "2026-09-30T14:32:07.463149243Z",
    "last_observed_at": "2026-09-30T14:32:07.463149243Z",
    "duration_ns": "6786271",
    "status": "complete"
  },
  "evidence": {
    "source_id": "49d8a96ac86746599c61ec2b62bc8bab",
    "ring": 0,
    "run": "12761957049485156178",
    "owner_instance": "9223372036854776139",
    "exchange": "1",
    "record_count": 18,
    "program_binding": "not_verified_by_exporter",
    "continuity": "observed_records_only"
  }
}
```

## Reproduce on the prepared build box

Use the pinned build procedure in [ACTIVITY-PROGRAM.md](ACTIVITY-PROGRAM.md).
For the current exporter/API tests, stage the checked repo scripts and run:

```sh
R=/home/starin/eob-config-20260925
python3 "$R/activity-timestamps-01/check_activity_combine.py" \
  --live "$R/activity-group-live-03.json" \
  --journal "$R/activity-group-collector-03/events.sqlite" \
  --report "$R/activity-timestamps-check-NEW.json"
```

The isolated fixture is removed. To repeat live qualification, recreate it with
both collector arguments as described in [ACTIVITY-PROGRAM.md](ACTIVITY-PROGRAM.md).
Use fresh run, collector-source and receipt paths:

```sh
python3 "$R/json_initialization_live.py" --combined \
  --run activity-group-NEW --artifact-dir activity-group-check-06 \
  --image-build "$R/collector-image-02/image-build.json" \
  --source-dir "$R/activity-group-collector-NEW" \
  --output "$R/activity-group-live-NEW.json"
```

Finish with `json_initialization_fixture.py archive-cleanup`, using the recorded
package, collector image/source, live receipt and a fresh archive path. The cached
creation, live and cleanup receipts contain the exact commands and source snapshots.

## Remaining limits

`observed_exchange` is bounded correlation of observed records. The exporter
does not verify the signed producer binding. It does not establish authenticated
agent identity, issuer, tenant, delegation or successful remote execution.
HTTP/2, pipelining, multiple workers, streamed JSON and silent missed hooks need
separate qualification. Arming both hooks is not atomic. Sustained data-path cost,
secure off-box delivery and power-loss durability remain unmeasured.

Earlier [message-scope](MESSAGE-SCOPE.md) and [JSON-boundary](JSON-LIFECYCLE.md)
results still reject address or ID equality as sufficient association keys.
This result qualifies the explicit exchange contract above, not a general
JSON-context storage lifetime.
