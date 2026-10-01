# Reported result and error fields

**2026-09-29 — MEASURED, bounded one-worker fixture.** The probe extracts literal
root `result` and `error`, integer `error.code`, and Boolean `result.isError`.
The field contract was registered before implementation. Its original IDEA status
and text remain in the [discovery receipt](../../SOURCES.md#reported-reply-fields-2026-09-29).

These fields describe what a message reports. A result is not proof that a tool
completed its work. An absent `isError` field must remain absent, not become false.
HTTP status and local transfer completion remain separate observations.

## Field contract and bounds

- Scan at most four direct root members. Recognize literal `result`, `error`
  and `method` keys. Both result and error, repeated relevant keys, or a method
  combined with a reply field are ambiguous. Do not select an arbitrary outcome.
- With one reply field and no method, report its presence. Inspect at most four
  direct members of its object for `code` or `isError`. Reject duplicate selected
  members as ambiguous. Nested decoys are not direct members.
- Accept signed 32-bit decimal integer error codes. Preserve zero and unfamiliar
  codes. Fractions, exponents, overflow and nonnumeric values have explicit status.
- Accept only literal Boolean `true` or `false` for `isError`. Missing, wrong-type,
  ambiguous and unreadable values remain distinct. No result body, error message,
  error data, credential contents or object addresses are exported.
- Literal keys only; no escape decoding or protocol validation. The hook observes
  JSON caches, not authenticated protocol identity or proven response direction.
- At most 80 application-memory reads, 2,048 source bytes, four fragments per
  selected byte read, and one 104-byte record per invocation. No application
  accessor calls or application writes. Use a private state-map name and the
  existing collector. TMM must not wait for storage or consumers.

## Checks and falsifiers

Recheck the pinned source, debug layout and compiled completion path. Run PREVAIL
and native interpreter/JIT tests before the isolated live gate. Check result-only,
error-only, tool true/false/missing, zero/negative/unfamiliar/boundary error codes,
wrong types, overflow, conflicting/duplicate fields, nested decoys, escaped keys,
member/fragment limits, unreadable memory and unchanged input. Live comparisons
must check exact fields, client response bytes, counters, journal/replay, stable
process and restored hook bytes. Archive evidence before fixture removal.

**Falsifiers:** missing becomes false; a result is labeled successful execution;
an error code is rounded or wrapped; a nested or duplicate field supplies a guessed
value; unrelated text escapes; stale values survive failure; or a bound is exceeded
without explicit status. Malformed JSON that never reaches a qualified completion
cache is outside this hook's observation coverage.

```text
BUILD BOX: qualify parsed fields -> bounded probe -> verify/sign
TMM: JSON completion -> reply shape and typed fields -> one ring record attempt
COLLECTOR: ring -> acknowledged journal -> cursor replay
CONSUMER: decode reported fields; retain unknowns and source provenance
```

Trusted caller identity, request/response association and remote-operation success
remain separate requirements for an identity profile.

## Measured result

Pinned clang 18.1.3 and PREVAIL pass with the 256-byte stack limit. Build 03 passes
106 native interpreter/JIT invocations. Live attempt 03 passes 38 exchanges through
the AIMCP/JSON fixture. Each exchange yields one request-cache observation and one
reply-cache observation: **76 records**. All client response bodies match the
authored bodies exactly, including two paced replies. All HTTP responses are 200;
the reported error fields remain separate from that transport status.

| Authored reply | Observed field |
|---|---|
| `result: {}` | Result present; `isError` unavailable |
| `result.isError: true` or `false` | Exact Boolean, with complete field state |
| `error.code: -32601`, `0`, `7654321` | Exact signed integer |
| `error.code: -2147483648` or `2147483647` | Exact signed 32-bit boundary |
| Numeric overflow, fraction or exponent | Out of scope; no numeric value |
| Missing or nested-only selected field | Unavailable; no guessed value |
| Duplicate selected field | Ambiguous; no guessed value |
| Both result and error, repeated root reply key, or method plus result | Ambiguous root; presence fields unqualified |
| More than four root or selected-object members | Budget exhausted at that level |

The 76 root states are 29 complete, 41 not applicable, four ambiguous, one budget
exhausted and one wrong type. “Complete” means the root observation is qualified;
the selected field has its own state. It does not mean successful execution.
The 41 not-applicable observations include all 38 authored request messages.

The live maximum is 25 application-memory reads and 419 source bytes. These are
counts, not execution-time measurements. Native checks also cover guarded partial
reads, invalid cache fields, fragment limits, unchanged input and output refusal.
The stream contains no reported gaps, drops, output failures or new VM errors.
The 78-event journal and cursor replay agree. There are no replay retries.

Kernel witnesses show a stable process and restored hook bytes. All 12 slots are
inactive at cleanup. Seven successful-run files were archived before removal.
Eight files from the pre-arm failures were archived separately. Other container
identities and state stayed unchanged during each scoped removal.

**Witnesses:** SELF for fixtures, field comparisons, counters and replay;
INDEPENDENT for PREVAIL; KERNEL for process/hook bytes; TOOL for source and container
inspection. [All receipts and SHA-256 values](../../SOURCES.md#reported-reply-fields-2026-09-29).

## Retained failures and corrections

1. Build 01 passed. Build 02 added the empty `event_names` field required by the
   inherited fixture and changed test formatting. Build 03 applies the remaining
   formatter changes. All three pass 106 native checks; the probe is unchanged.
2. Creation 01 omitted the collector Compose layer. Live 01 stopped at
   `collector socket not ready`, before loading the probe. Inspection showed the
   test container lacked `/collector-api`. The collector itself logged a listening
   socket. Mount repair 01 restored that read-only mount.
3. Live 02 then timed out in `get_conf_svr()`, before configuration or probe load.
   Its root cause is not established. A fresh fixture, created with the collector
   layer, passed live 03. Do not turn that recovery into a diagnosis of the timeout.
4. Reset 01 wrongly required `sha256` in every witness row; the initial row carries
   that field. Reset 02 matched the guard text `PRIVATE KEY-----` inside a saved
   source snapshot. The revised check tests full private-key start markers.
   Both attempts stopped before removal. Reset 03 checked the failure archive and
   inactive slots, then removed only the isolated fixture.

The live driver now checks the API mount before starting the collector. It creates
the evidence directory early and records bounded readiness errors. The original
receipts are unchanged. [Failure register](../../CONTESTED-PREMISES.md#35--a-live-fixture-already-has-the-collector-mount--falsified).

## ABI and consumer rules

The [ABI](../../substrate/surfaces/reply_metadata_abi.h) uses magic `0x52504c59`,
version 1 and 104 bytes: `<II6Q7Ii4I>`. The private map is
`reply_metadata_state`. Slot 11 runs at `json_filter_handle_json_complete`, patch
address `0xd93540`, pad zero, in build
`ca69b84f4f5c9e225813b2ed3997c59f18ba2a31`.

The [decoder](reply_metadata_decode.py) rejects invalid sizes, reserved fields,
status/value combinations and exceeded counters. Numeric state 0 means not
applicable; 1 complete; 3 read failure; 4 out of scope; 5 budget exhausted;
7 unavailable; 9 invalid cache; 10 wrong type; 11 ambiguous. A numeric value is
usable only when its field state is complete. Zero-filled fields at other states
are not observations of zero, false or absence. Nonnumeric primitive error codes
such as `null` are out of scope; string/object/array codes have wrong-type state.

The hook does not prove response direction, JSON-RPC conformance, remote-operation
success, authenticated identity or request association. Keys remain literal.
HTTP/2, multiworker ownership, sustained cost, secure off-box delivery and full
identity profiles remain separate work. The separate collector gives lifecycle
and storage separation, not strong security isolation: see [its limits](COLLECTOR-CONTAINER.md).

## Verify or reproduce

From the repo root, check saved evidence without traffic:

```sh
python3 env/ai-traffic/reply_metadata_verify.py
python3 env/ai-traffic/reply_metadata_verify.py --export
```

The verifier checks 141 embedded source snapshots, exact native/live fields,
failed attempts, archive hashes, replay, journal integrity, process and hook
witnesses, inactive slots and scoped removal.

For a new run, use the prepared build box and fresh names. Stage the new sources
beside the existing fixture scripts. Recheck the remote TMM instructions and
protected infrastructure before running these commands. The signing key stays
on the build box. `NEXT` below must be an unused attempt name.

```sh
ROOT=/home/starin/eob-config-20260925
IMAGE=sha256:26f3184a4e3fe96b61f780761497933facc385f3d62d6f1cf66f04e56abd5054
python3 "$ROOT/reply_metadata_discover.py" --output "$ROOT/reply-metadata-discovery-NEXT.json"
python3 "$ROOT/reply_metadata_build.py" \
  --discovery "$ROOT/reply-metadata-discovery-NEXT.json" --output "$ROOT/reply-metadata-build-NEXT"
mkdir "$ROOT/reply-metadata-source-NEXT"
python3 "$ROOT/lifetime_fixture.py" create --collector-image "$IMAGE" \
  --collector-source "$ROOT/reply-metadata-source-NEXT" --output "$ROOT/reply-metadata-create-NEXT.json"
python3 "$ROOT/reply_metadata_live.py" --run reply-metadata-live-NEXT \
  --artifact-dir reply-metadata-build-NEXT --image-build "$ROOT/collector-image-02/image-build.json" \
  --source-dir "$ROOT/reply-metadata-source-NEXT" --output "$ROOT/reply-metadata-live-NEXT.json"
python3 "$ROOT/lifetime_fixture.py" archive-cleanup --collector-image "$IMAGE" \
  --collector-source "$ROOT/reply-metadata-source-NEXT" --live "$ROOT/reply-metadata-live-NEXT.json" \
  --output "$ROOT/reply-metadata-cleanup-NEXT.json" --archive "$ROOT/reply-metadata-evidence-NEXT.tar.gz"
```
