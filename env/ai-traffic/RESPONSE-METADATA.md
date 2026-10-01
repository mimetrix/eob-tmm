# Response status and completion metadata

**2026-09-29 — MEASURED in the bounded one-worker fixture.** The loaded program
extracts HTTP status and local transfer-completion fields from existing TMM filter
state. Nine requests produce 201 handler records through the separate collector.
The saved journal, replay, hook restoration and fixture removal are verified.
The original contract was registered as IDEA before implementation. The
[session/routing result](SESSION-ROUTING.md) is a separate measured subset.

## Measured result

Build 03 passes pinned PREVAIL with a 256-byte stack limit and 80 native
interpreter/JIT invocations. Live attempt 02 passes all nine cases:

| Fixture case | HTTP status | Status records | Done records | Local transfer complete |
|---|---|---|---|---|
| Normal body | 200 | 2 | 2 | 1 |
| Bodyless | 204 | 2 | 2 | 1 |
| Not found | 404 | 2 | 2 | 1 |
| Service unavailable | 503 | 2 | 2 | 1 |
| Unfamiliar status | 777 | 2 | 2 | 1 |
| Paced body | 200 | 2 | 2 | 1, after release |
| Chunked body | 200 | 2 | 2 | 1 |
| Server-Sent Events (SSE) stream | 200 | 2 | 2 | 1 |
| Interrupted body | 200 | 2 | 2 | 0 |

The paced origin waits for the test to inspect the header observations before it
releases the remaining body. At that point, status is present and no done field
has been observed. The interrupted origin advertises 25 bytes and sends five.
The client receives `short`, and both done observations report zero. A complete
transfer can carry HTTP 404 or 503; it does not mean the operation succeeded.

Each ordinary case produces 21 handler records; the SSE case produces 33. The
201 records include 18 status and 18 done observations. Other handler messages
carry their event code with these fields marked not applicable. Case labels are
controlled fixture intervals, not exported request identities or a general join.

All records are 96 bytes. A status extraction uses at most two application-memory
reads and five source bytes. Done extraction uses no application-memory read.
These are read bounds, not measurements of execution time or per-packet cost.

The final journal has 224 events: 23 from the first attempt and 201 new records.
Replay agrees with the captured records. Counters reconcile; no drops, observation
gaps, output failures or new VM errors are reported. The process and binary stay
stable. Kernel reads show the armed call and restored five NOP bytes. Cleanup
checks all 12 slots inactive, verifies the 14-file archive, and removes the isolated
containers, networks and volumes. Other Docker identities and state are unchanged.

**Witnesses:** SELF for authored traffic, fields, counters and journal comparisons;
INDEPENDENT for PREVAIL; KERNEL for hook bytes and process identity; TOOL for
source and container inspection. [Receipts and checksums](../../SOURCES.md#response-metadata-qualification-2026-09-29).

## Meanings and limits

- HTTP status describes the response at the selected filter boundary. It does
  not prove that the client received the response or that a remote tool succeeded.
- A response-done message describes a local protocol boundary. Qualify its data
  argument before interpreting it as a transfer-complete flag.
- Preserve incomplete, unavailable and unsupported outcomes. An absent done
  message does not by itself establish an incomplete transfer.
- Do not join records to requests, sessions or identities by time or sequence.
  Authenticated identity, remote task completion and request association need
  separate evidence.

The first candidate is an entry probe on `hud_aimcp_handler`. Retain every
invocation's event code. Read HTTP fields only for qualified response messages.
For done messages, accept only the documented scalar argument representation.
Do not dereference it as an object pointer.

**Registered budgets:** at most four application-memory reads, 16 source bytes
and one record of at most 128 bytes per invocation. No text fields, body content,
credential values or object addresses. Use the existing output ring and separate
collector. TMM must not wait for storage or consumers. Give the state map a unique
name. No application accessor calls or writes to application state.

## Qualification and tests

**Source qualification — MEASURED.** The cached build-box
[receipt](../../SOURCES.md#response-metadata-qualification-2026-09-29) confirms the
handler's patch address `0xbbd304` (entry `0xbbd300`, pad offset 4). Its fourth
argument is `http_data` for response messages 28/144. The parser flags are at
offset 28 and the signed status at 36.
Require a non-request, non-trailer parser state.
Preserve status values 100–999, including unfamiliar values; other values are
outside this contract.

**Correction after live attempt 01:** the first program also required a clear
`f_invalid_status` flag. That rule rejected the normal HTTP 200 response. This
flag invalidates an HTTP/2 cached pseudo-header; it does not invalidate the parsed
numeric status. The source's cache reset sets it, and the HTTP/2 serializer uses
it to select a different header source. Keep discovery/build/live attempt 01 as
the failed record. The corrected program ignores this cache flag and needs at
most two reads and five source bytes for a status observation. Native tests check
that setting the flag does not suppress a valid numeric status.

For done messages 29/145, retain only scalar zero or one with explicit field
status. HTTP/1 `http_send_done_message` computes this flag from expected-body and
body-complete state. The HTTP proxy forwards the argument. It is a local transfer
flag, not proof of client delivery or remote task completion. Other message types
retain their event code with both fields marked not applicable. No field value is
retained from an earlier invocation.

1. On the pinned build, cache the source, debug types, event numbers and compiled
   hook/call paths. Establish when response fields are valid and what done means.
2. Run pinned PREVAIL and interpreter/JIT checks. Include familiar and unfamiliar
   status values, wrong message types, missing/unreadable memory, invalid parser
   state, both Boolean values and unsupported done arguments. Check unchanged
   input, output refusal, sequence saturation and instance replacement.
3. Use the isolated AIMCP fixture with the existing collector. Compare exact
   numeric fields for normal, error, unfamiliar, bodyless, streamed and interrupted
   responses. Include a paced body so a header observation cannot stand for body
   completion. Keep fixture interval labels outside the exported schema.
4. Check counters, journal/replay, reported loss, stable process and restored
   hook bytes. Save successful and failed receipts before fixture removal.

**Falsifiers:** a status read from a request or stale parser state; unrelated
memory exported; a done flag invented from pointer presence; a partial body
reported as complete; a modified application input; mismatched native/live values;
or response status/done relabeled as remote-operation success.

The result will be limited to its configured protocol path. HTTP/2, generalized
stream completion, cancellation acknowledgment, identity profiles, full blast
radius and data-path cost require separate qualification.

## Decode and reproduce

The [ABI](../../substrate/surfaces/response_metadata_abi.h) uses magic
`0x5253504d`, version 1 and layout `<II6Q10I>`.
The [consumer decoder](response_metadata_decode.py) validates field states,
message types, numeric ranges and read bounds. `complete` is a field-availability
state. Read `transfer_complete` separately for the local transfer result.
Instance, revision and run identify the observation source; sequence is local to
that program instance. They do not identify a request, session or authenticated actor.
The collector stores the new schema as raw records; the consumer decodes it.

Verify the saved sources, native records, live fields, archive and journal without
new traffic. Add `--export` to include all 201 decoded observations:

```sh
python3 env/ai-traffic/response_metadata_verify.py
python3 env/ai-traffic/response_metadata_verify.py --export
```

For a new live run, use the prepared build box and the pinned toolchain recorded
in the receipts. Stage the response scripts and C sources at the same locations
as [the session/routing procedure](SESSION-ROUTING.md#verify-or-reproduce). Use fresh names
for every receipt, source directory and run. No TMM rebuild is needed.

```sh
ROOT=/home/starin/eob-config-20260925
IMAGE=sha256:26f3184a4e3fe96b61f780761497933facc385f3d62d6f1cf66f04e56abd5054
python3 "$ROOT/response_metadata_discover.py" --output "$ROOT/response-metadata-discovery-NEXT.json"
python3 "$ROOT/response_metadata_build.py" \
  --discovery "$ROOT/response-metadata-discovery-NEXT.json" --output "$ROOT/response-metadata-build-NEXT"
mkdir "$ROOT/response-metadata-source-NEXT"
python3 "$ROOT/lifetime_fixture.py" create --collector-image "$IMAGE" \
  --collector-source "$ROOT/response-metadata-source-NEXT" --output "$ROOT/response-metadata-create-NEXT.json"
python3 "$ROOT/response_metadata_live.py" --run response-metadata-live-NEXT \
  --artifact-dir response-metadata-build-NEXT --image-build "$ROOT/collector-image-02/image-build.json" \
  --source-dir "$ROOT/response-metadata-source-NEXT" --output "$ROOT/response-metadata-live-NEXT.json"
python3 "$ROOT/lifetime_fixture.py" archive-cleanup --collector-image "$IMAGE" \
  --collector-source "$ROOT/response-metadata-source-NEXT" --live "$ROOT/response-metadata-live-NEXT.json" \
  --output "$ROOT/response-metadata-cleanup-NEXT.json" --archive "$ROOT/response-metadata-evidence-NEXT.tar.gz"
```

## Pipeline

```text
BUILD BOX: source + debug layout + compiled paths
  -> field manifest -> bounded program -> PREVAIL + native checks -> signature
TMM DATA PATH: qualified response/done invocation
  -> status or completion field + availability -> one ring record attempt
SEPARATE COLLECTOR: ring -> journal -> cursor-based replay
CONSUMER: raw record -> typed fields, provenance and explicit limits
```
