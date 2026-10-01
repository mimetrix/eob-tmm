# Message scope qualification

**2026-09-29 — MEASURED source and compiled-code inspection only.** The check now
identifies the flow-side field and the JSON filter's reset and lifecycle paths.
It rejects the JSON context address as a request ID or a shared connection ID.
Runtime scope and message association remain unvalidated.
[Receipts and checksums](../../SOURCES.md#message-scope-qualification-2026-09-29).

The original IDEA contract is retained in both discovery receipts. It qualifies
the scope needed to use [observed message IDs](MESSAGE-ID.md) in a later
request/reply association. Equal IDs alone do not establish a shared request,
connection, session or caller.

## First gate: source and binary qualification

Inspect the JSON filter's completion, initialization, reset and cleanup paths on
the pinned build box. Save source, debug layouts, compiled calls and binary
identity before selecting a probe. Identify what each object actually represents:
one direction, one message, one stream, one connection, or temporary storage.

Require evidence for each proposed scope component:

- Direction comes from qualified application state, not JSON member names,
  arrival order, addresses or a test interval.
- A lifecycle number requires an observed birth and end. Address reuse must not
  reuse the old number. Late attachment must remain unknown.
- A message boundary must account for cache resets, keep-alive, fragmented bodies,
  streaming, errors and cleanup. Parser completion is not operation success.
- A relationship between request and reply must have a qualified common owner.
  A client-side object and a server-side object cannot be joined by proximity.
- Observed session-header bytes and message IDs remain untrusted field values.
  Neither supplies authenticated caller identity.

The first deliverable is an executable qualification check and an evidence-backed
candidate decision. Build a runtime probe only when that decision supplies a
bounded contract. A source/disassembly result alone must not be called live scope.

## Falsifiers

Reject a candidate if a reset changes its meaning without a visible boundary;
if direction has more than one meaning on the selected path; if an object is
temporary but is called a connection; or if request and reply have no qualified
shared owner. A readable pointer or a padded function does not satisfy these tests.

For a later runtime gate, reject invented births, stale state after reuse, guessed
associations after loss, and valid-looking state after capacity or counter limits.
Test interleaved connections with equal IDs and multiple messages on one connection.
Keep complete source/worker identity and explicit unavailable states in each result.

## Existing limits that still apply

[LIFETIME.md](LIFETIME.md) measures HTTP parser intervals, not connection IDs.
[CORRELATION.md](CORRELATION.md) measures a bounded synthetic ledger join.
[GAPS.md](GAPS.md) records stale lifetime state after missed boundaries. Reported
loss can invalidate an observation window; silent missed boundaries remain open.
None of those results qualifies the JSON filter's object lifecycle or a native
message-ID association. General request scope remains unvalidated.

```text
BUILD BOX — off the data path
  pinned source + debug layouts + compiled paths -> scope qualification receipt

REPOSITORY — off the data path
  checked receipt -> candidate decision and explicit missing evidence

LATER TMM GATE — not implemented by this qualification
  observed boundaries + direction + fields -> bounded records -> collector

LATER CONSUMER — outside TMM
  complete qualified scope + ID equality rules -> association or unknown
```

## Qualification result

Discovery 01 captured the JSON filter and its compiled entries. Discovery 02 adds
the flow-side definitions, stream/node sources and complete handler ranges.
Check 01 passes on the build box. It checks 16 embedded files, source references,
11 instruction locations, debug offsets and the pinned binary identity.
These are TOOL and SELF witnesses. There is no runtime scope probe in this result.

| Candidate | Source and compiled evidence | Decision |
|---|---|---|
| Flow side at JSON completion | Argument 3 is `union uflow *`. The successful path reads byte 37 and masks `0x40`, matching `uflow_is_clientside` and `FLOW_CLIENTSIDE`. | A source-qualified field candidate. It describes the flow side, not the JSON message's request/reply role or authenticated caller. |
| JSON context as request ID | `json_filter_reset_ingress_for_reuse` releases the message/cache and clears fields in the same context. | Rejected. One context can process successive messages. |
| JSON context as shared connection ID | The filter declares both connection and stream context sizes. The stream API explicitly separates stream state from connection state. | Rejected. Qualify the actual object and its lifetime before naming it. |
| Initialization and cleanup function hooks | The index has no individual entries for `hud_json_init_scb` or `hud_json_uninit_scb`. The handler contains the initialization zeroing and cleanup release operations. | Use the compiled handler as a candidate observation point. Do not assume a source-level call has a hook. |
| Handler entry as completed initialization | The source handles `HUDEVT_FLOW_INIT`, abort and teardown, but checks disabled state before its switch. | Entry observes an event before its effects. A later runtime contract must distinguish event arrival from completed initialization. |
| Reset as operation completion | Reset follows normal and message-mode paths. Rule execution can defer it through `f_done` or `f_msg_done`. | A local storage boundary, not proof of delivery or successful execution. |
| Current peer as shared lifetime | `uflow_clientside` selects the current flow or its peer. This capture does not establish peer lifetime or continuous binding. | Insufficient for request/reply association. |

The flow representation also matters. The source represents a stream flow as its
address minus 33. Its leading padding is not allocated object storage. The source
has a separate assertion for the shared flow-type offset. This does not authorize
reading other connection fields through a stream-flow pointer. Start a later
runtime gate with an explicit supported storage form and reject other forms.

### Pinned locations

Build ID: `ca69b84f4f5c9e225813b2ed3997c59f18ba2a31`.
Executable SHA-256: `05d17517531d99b26eb9e8f00f5b5326f660b5bef492226c9555368b887a9611`.
The inspected TMM source files have no local modifications. This is not a claim
that the whole TMM build tree has no modifications.

| Function | Entry | Patch site | Pad offset |
|---|---|---|---:|
| `json_filter_handle_json_complete` | `0xd93540` | `0xd93540` | 0 |
| `json_filter_reset_ingress_for_reuse` | `0xd927c0` | `0xd927c0` | 0 |
| `hud_json_handler` | `0xd94100` | `0xd94104` | 4 |

The completion function receives node, JSON context and flow as its first three
arguments. The JSON cache pointer is at context offset 24. Message mode is bit 4
of byte 89. The HUD node context starts at offset 64; its size field is at 44.
The verifier exports exact source lines and instruction bytes behind these checks.
Requalify these locations for any different binary.

## Next runtime gate

The [ID/flow-side gate](ID-FLOW.md) now measures both fields in one record:
44 exchanges and 88 records, including keep-alive and concurrent equal IDs.
This separate live result does not establish lifecycle or request scope.

**Separate boundary result:** [JSON-LIFECYCLE.md](JSON-LIFECYCLE.md) now records
306 entry observations from 13 exchanges. Late attachment, malformed JSON,
keep-alive and concurrent equal IDs are tested. Eleven unavailable-context records
invalidate the full consumer window. Entry still does not prove completed
initialization. Disabled, deferred and other listed live paths remain unvalidated.
Keep any later lifecycle number local to its qualified object; it is not a
connection ID.

A common request/reply owner and its binding lifetime still need separate
qualification. Protocol equality rules and message role also remain open.
`runtime_scope_validated`, `request_scope_validated`,
`message_association_validated` and `authenticated_identity_validated` all remain
false. Source qualification does not measure data-path cost.

## Verify the saved result

From the repository root:

```sh
python3 env/ai-traffic/message_scope_verify.py
python3 env/ai-traffic/message_scope_verify.py --export
```

This checks the immutable discovery-02 receipt. It does not run TMM. Check 01
retains the verifier source and the same result from the authoritative build box.
The checksum index also covers the original discovery and check receipts.

For a new capture, stage `message_scope_discover.py` and this document in the
prepared build-box directory. Use an unused name:

```sh
ROOT=/home/starin/eob-config-20260925
python3 "$ROOT/message_scope_discover.py" --output "$ROOT/message-scope-discovery-NEXT.json"
```

`completed=true` means capture completed. Review the new source and compiled
evidence before updating verifier pins or accepting a new candidate. The saved
verifier intentionally does not accept an arbitrary new receipt as qualified.
