# Observed message IDs

**2026-09-29 — MEASURED, bounded one-worker fixture.** The probe extracts a literal
direct root `id` from the JSON completion cache. It preserves type and raw bytes.
The original IDEA contract is retained in the discovery receipt. This is an input
to a later request/reply association, not that association itself.
[Receipts and checksums](../../SOURCES.md#observed-message-ids-2026-09-29).

**Later qualification:** [MESSAGE-SCOPE.md](MESSAGE-SCOPE.md) checks the pinned
flow-side and lifecycle paths. It rejects the reused JSON context as a request
or shared-connection ID. That source/compiled result does not add runtime scope
to the ID records described here.

The separate [ID/flow-side gate](ID-FLOW.md) now measures both fields in one record.
It includes keep-alive and concurrent equal-ID traffic. Local context lifecycle
remains the [next registered test](JSON-LIFECYCLE.md).

## Field contract

- Inspect at most four direct root members. Scan the whole bounded object before
  accepting an ID. Reject repeated literal `id` keys, even with equal values.
- Distinguish string, number, explicit `null`, missing ID, wrong type, ambiguity,
  invalid cache, unavailable memory and exceeded bounds. Nested `id` fields do not
  supply the root ID. Escaped key names are not decoded.
- Preserve up to 64 raw string bytes, without JSON escape decoding. An empty
  string is present. Longer strings have truncated status and cannot be used as
  complete matching keys.
- Preserve JSON number spelling up to 64 bytes. Validate the bounded number
  grammar; do not convert to floating point or integers. Large integers remain
  exact. Fractions and exponents retain their spelling. Longer numbers are out of
  scope, with no value. Different spellings are not normalized or declared equal.
- Explicit `null` retains type null and the four bytes `null`. It is not a usable
  request key. Boolean, object and array IDs have wrong-type status and no value.
- Use at most 80 application-memory reads, 2,048 source bytes, four fragments per
  byte read, and one 144-byte output attempt per invocation. Use a private state
  map and the existing collector. TMM must not wait for a consumer.

No unrelated member values, credentials or object addresses are exported. No
application accessors or application-memory writes are permitted. The hook does
not establish message direction, protocol conformance, authenticated identity,
ID uniqueness, connection/session scope or request/reply association.

## Checks and falsifiers

Requalify source, layout and compiled hook on the pinned build box. Require PREVAIL
at the 256-byte stack limit and native interpreter/JIT checks before live testing.
Compare exact bytes and types in both request and reply cache observations.
Test missing/null/empty IDs; string versus number; large integers; decimals and
exponents; escaped values and keys; duplicates; nested decoys; length/member/
fragment limits; corrupt cache fields; unreadable and partial reads; unchanged
input; and output refusal. Test reused IDs and mismatched request/reply values
without producing an association claim.

**Falsifiers:** a type is lost; a number is rounded; missing or null becomes a
matching key; partial bytes are marked complete; a nested or duplicate ID is
selected; unrelated bytes escape; or an ID receives a guessed caller or request
scope. Native malformed number fixtures must not acquire numeric-value status.

Live evidence must include exact client/origin bodies, positive configuration
acknowledgements, counters, journal/replay, stable process, restored hook, archive
and scoped fixture removal. Include the collector layer at fixture creation.

```text
BUILD BOX: qualify JSON cache -> bounded ID probe -> verify/sign
TMM: completion cache -> literal ID/type/status -> one ring output attempt
COLLECTOR: ring -> acknowledged journal -> cursor replay
CONSUMER: preserve raw ID and unknown scope; qualify associations separately
```

## Measured result

Pinned clang 18.1.3 and PREVAIL pass with the 256-byte stack limit. Build 01 passes
194 native interpreter/JIT invocations. Live attempt 01 passes **35 exchanges and
70 records**: one request-cache observation and one reply-cache observation per
authored exchange. Request and response bodies match the authored bytes exactly.
Two replies and one request use paced fragments.

| Input | Observation |
|---|---|
| Numeric `1` and string `"1"` | Same value byte `31`, distinct number/string types |
| `9007199254740993` | Exact numeric spelling; no floating-point rounding |
| `-0`, `0.125`, `1e+3`, `-2.5E-30` | Exact numeric spelling; no normalization |
| 64-digit number | Complete, exact bytes |
| 65-digit number | Out of scope, no value |
| Empty string | Complete string, zero value bytes |
| `"future\u002eid"` and UTF-8 `"資料"` | Exact raw string bytes |
| 65-byte string | Truncated to 64 bytes, not a complete matching key |
| Explicit `null` | Null type and bytes `null`, distinct from missing |
| Repeated root ID, including equal values | Ambiguous, no selected value |
| Nested-only or escaped-key ID | Missing literal root ID |
| Boolean, object or array ID | Wrong type, no value |

Two exchanges reuse the string `shared`. Other cases deliberately give the reply
a different value or type. The probe preserves those observations. The fixture
compares them within its controlled intervals; it does not produce an ID-based
join or prove uniqueness across requests, connections or sessions.

There are 44 complete records, two truncated, four out of scope, eight wrong type,
six missing, four ambiguous and two budget exhausted. Native tests also check 12
malformed number spellings in each execution mode, guarded partial reads, invalid
cache fields, fragment limits, unchanged input and output refusal.

The live maximum is 20 application-memory reads and 386 source bytes. These are
counts, not time measurements. All 70 records agree with the journal and replay.
The 72-event journal has no reported drops or gaps. There are no replay retries,
output failures or new VM errors. Kernel witnesses show one attachment interval,
a stable process and restored hook bytes. All 12 slots are inactive at cleanup.
Seven files were archived before scoped fixture removal. Other container
identities and state stayed unchanged. Build and live attempt 01 both passed.

**Witnesses:** SELF for fixtures, values, counters and replay; INDEPENDENT for
PREVAIL; KERNEL for process/hook bytes; TOOL for source and container inspection.
[All evidence](../../SOURCES.md#observed-message-ids-2026-09-29).

## ABI and consumer rules

The [ABI](../../substrate/surfaces/message_id_abi.h) uses magic `0x4d534749`,
version 1 and the existing 144-byte layout `<II6Q4IHHI64s>`. In this schema, the C
word `getter_result` means `id_kind`: zero unknown, one string, two number, three
null. The private state map is `message_id_state`. The collector retains raw
records; the [consumer decoder](message_id_decode.py) checks their types, lengths,
number grammar, padding and counter bounds.

States: 1 complete, 2 truncated, 3 read failed, 4 out of scope, 5 budget exhausted,
7 unavailable, 8 missing, 9 invalid cache, 10 wrong type, 11 ambiguous. Value bytes
are available only in complete/truncated records. An observed length or type on a
failed read does not make its zero-filled value available. A long primitive token
has out-of-scope status and unknown type because its full grammar was not checked.

The hook is `json_filter_handle_json_complete`, patch `0xd93540`, pad zero, in
build `ca69b84f4f5c9e225813b2ed3997c59f18ba2a31`. This isolated run uses slot 11,
after removal of the earlier reply fixture. The result does not establish that
these separate probes can run together at this hook.

String escapes and number spellings are not normalized. A consumer must qualify
protocol equality and connection/session lifetime before making associations.
Equal raw IDs do not prove the same request or caller. Missing, null, ambiguous,
truncated and unavailable fields must not become guessed matches. Full protocol
coverage, trusted identity, general request association and data-path cost remain
open. The [separate collector's security limits](COLLECTOR-CONTAINER.md) still apply.

## Verify or reproduce

From the repo root, verify saved evidence without traffic:

```sh
python3 env/ai-traffic/message_id_verify.py
python3 env/ai-traffic/message_id_verify.py --export
```

The verifier checks 60 embedded source snapshots, native/live fields, exact fixture
bodies, journal/replay, archive hashes, process/hook witnesses and scoped cleanup.

For a new live run, use the prepared build box and fresh names. Stage the new
sources beside the existing fixture scripts. Keep the signing key on the build
box. Check the remote TMM instructions and protected infrastructure first.
`NEXT` below must be an unused attempt name. Include the collector layer when
creating the fixture; the live driver checks its socket mount before proceeding.

```sh
ROOT=/home/starin/eob-config-20260925
IMAGE=sha256:26f3184a4e3fe96b61f780761497933facc385f3d62d6f1cf66f04e56abd5054
python3 "$ROOT/message_id_discover.py" --output "$ROOT/message-id-discovery-NEXT.json"
python3 "$ROOT/message_id_build.py" \
  --discovery "$ROOT/message-id-discovery-NEXT.json" --output "$ROOT/message-id-build-NEXT"
mkdir "$ROOT/message-id-source-NEXT"
python3 "$ROOT/lifetime_fixture.py" create --collector-image "$IMAGE" \
  --collector-source "$ROOT/message-id-source-NEXT" --output "$ROOT/message-id-create-NEXT.json"
python3 "$ROOT/message_id_live.py" --run message-id-live-NEXT \
  --artifact-dir message-id-build-NEXT --image-build "$ROOT/collector-image-02/image-build.json" \
  --source-dir "$ROOT/message-id-source-NEXT" --output "$ROOT/message-id-live-NEXT.json"
python3 "$ROOT/lifetime_fixture.py" archive-cleanup --collector-image "$IMAGE" \
  --collector-source "$ROOT/message-id-source-NEXT" --live "$ROOT/message-id-live-NEXT.json" \
  --output "$ROOT/message-id-cleanup-NEXT.json" --archive "$ROOT/message-id-evidence-NEXT.tar.gz"
```
