# Agent activity events

**2026-09-30 — MEASURED archived-record export and collector API tests.**
The contract below was written before implementation checks.
[Evidence](../../SOURCES.md#agent-activity-export-2026-09-30).

**Live source added later the same day:** [ACTIVITY-PROGRAM.md](ACTIVITY-PROGRAM.md)
records one bytecode ELF at both required entry hooks. The original live check
exported and replayed 87 records. The current artifact also emits exchange keys.
[ACTIVITY-COMBINED.md](ACTIVITY-COMBINED.md) describes the stateful exporter that
uses those keys to combine ten live exchanges. The one-row observation format
below still keeps correlation unknown. Both formats keep identity unknown.

Publish a versioned JSON view of the existing collector replay stream. Each input
row produces one output row with the same cursor. This first version supplies
observed activity and reported outcome fields. Identity binding stays `unknown`;
there is no authenticated identity source attached to these records yet.

## Contract

- Use `schema_version: 1` and `event_type: agent.activity` for supported records.
- Keep method, tool/resource, message ID, flow side and reported outcome as
  separate observations. Do not join them by address, ID, time or record order.
- Include source/event references, extraction status, program instance/revision,
  monotonic observation time and reported output errors. Large counters and IDs
  remain strings where numeric conversion would lose precision.
- Preserve raw JSON field bytes. Supply decoded string text only for complete,
  valid strings. Truncated values remain explicitly truncated.
- Keep source boundaries, discarded records, ring health and reported gaps.
  Malformed or unsupported payloads produce diagnostic observations.
- Set identity binding and correlation to `unknown`. Trace/span IDs are optional
  fields, absent until there is a qualified source. Do not accept identity or
  trace claims from arbitrary fields added to a collector record.
- Export one replay page at a time. Preserve retention errors and `next_cursor`.
  The consumer advances its cursor only after it accepts the output page.

Reject the implementation if it invents identity or association, loses a gap or
cursor, labels a reported result as proven success, rounds an ID, or treats a
partial field as complete. Check it against saved live journals and focused
negative cases. This is an off-data-path format change, not a new TMM probe.

## Export a page

Run the exporter where the existing collector socket is mounted:

```sh
python3 env/ai-traffic/activity_export.py --socket /collector-api/events.sock
```

The output is one JSON page with `format: agent_activity/v1`, an `events` array
and the original `next_cursor`. Each array item retains its collector cursor.
After your consumer accepts the page, supply that cursor with `--after`:

```sh
python3 env/ai-traffic/activity_export.py --socket /collector-api/events.sock \
  --after JOURNAL_ID:OFFSET --limit 128
```

For archived evidence, use `--journal PATH_TO_EVENTS_SQLITE` or
`--page PATH_TO_SAVED_REPLAY_JSON`. Journal access is read-only. An expired cursor
returns an error; the exporter does not silently restart at a newer record.
Transport failures return a nonzero exit code and do not advance a cursor.

## Example observation

The checked tool-target example contains the following fields. The full event
also carries the source, raw record, program instance and extraction details:

```json
{
  "schema_version": 1,
  "event_type": "agent.activity",
  "identity_binding": "unknown",
  "identity": null,
  "correlation": {"status": "unknown"},
  "activity": {
    "target": {
      "kind": "tool_name",
      "status": "complete",
      "value": "inventory.lookup",
      "raw_hex": "696e76656e746f72792e6c6f6f6b7570",
      "representation": "json_string_escaped_bytes",
      "original_length": 16
    }
  },
  "reported_outcome": {}
}
```

Supported observations are method, tool/resource target, message ID, connection
flow side, reported reply fields, HTTP status and local transfer completion.
Each comes from its own record. A result field or HTTP 200 is not relabeled as
successful agent activity. Flow side is not message role. Numeric message IDs
keep their original spelling as strings. Invalid string encoding keeps its raw
bytes and a `text_error`; it has no decoded `value`.

`evidence.program_binding` is `not_verified_by_exporter`. Decoding a known wire
format does not authenticate its producer. `evidence.continuity` remains
`not_established`; gaps, source boundaries and output-failure counts remain visible.
Diagnostic and unsupported records use `agent.observation` or a specific event
type such as `agent.observation_gap` instead of disappearing from the page.

## Checks and remaining work

```sh
python3 env/ai-traffic/check_activity_export.py
```

Six tests pass on the build box. Five saved journals supply 468 metadata records
and ten diagnostic rows. The tests also exercise the collector's actual replay
socket, cursor pagination and retention errors. They check malformed records,
truncation, large numeric IDs and attempts to inject identity/trace claims.

The local workspace rejects the existing collector's socket permission change;
that failure is retained. The API test passes on the build box. No collector or
TMM rebuild is required for this exporter.

Regression check 04 repeats all six tests after grouped-frame support was added.
It passes on the same 478 saved rows. ABI 2 frames retain their raw record and
add `evidence.group`; legacy records keep their original decoding.
[Regression receipt](../../SOURCES.md#agent-activity-export-2026-09-30).

The next identity step is to supply a qualified authenticated binding for a
supported request path. This exporter does not yet attach an agent subject,
issuer, tenant or delegated authority. Trace/span fields also await a source.
