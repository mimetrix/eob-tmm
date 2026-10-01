# Message ID and flow side in one record

**2026-09-29 — MEASURED in the bounded one-worker fixture.** Each record now contains
the literal message ID and the observed connection-flow side. The live test gives
88 records from 44 exchanges. Both fields come from one invocation and one output
attempt. Request/reply association, connection lifetime and authenticated identity
remain unvalidated. [Receipts and checksums](../../SOURCES.md#message-id-and-flow-side-2026-09-29).

Build 01 and live 01 retain the original IDEA contract from before implementation.

## Contract

Use the pinned completion hook and source qualification in
[MESSAGE-SCOPE.md](MESSAGE-SCOPE.md). Preserve the existing ID reader and its limits.
Read at most one additional source byte: `flow_type` at offset 37 of argument 3.
Support only nonzero, 64-byte-aligned connection-flow pointers. Odd stream-flow
representations are out of scope; other misaligned values are invalid.

Require exactly one side bit: `0x40` for client side or `0x80` for server side.
Both bits or neither bit produce invalid status. A missing pointer, read failure,
unsupported storage or exhausted budget has no side value. ID status and side
status stay independent. Missing configuration permits no application-memory read.

Keep the total limits at 80 source reads, 2,048 source bytes and one 144-byte
record. If the ID reader consumes the budget, leave flow side unavailable with
budget-exhausted status. No accessors, application-memory writes or object addresses
are permitted. Use a private state map, `id_flow_state`, and the existing collector.

The new schema has magic `0x4944464c`, version 1, and the existing 144-byte layout.
The flags word retains diagnostic bits 0–3. Bits 4–5 contain side: 0 unknown,
1 client side, 2 server side. Bits 8–10 contain side status: 0 unavailable,
1 complete, 2 out of scope, 3 read failed, 4 invalid, 5 budget exhausted.
All other flag bits are reserved. A complete side requires value 1 or 2; every
other status requires zero. Old decoders must reject the new magic.

## Checks and falsifiers

- Require pinned PREVAIL with the 256-byte stack limit and real interpreter/JIT
  checks. Retain all existing ID checks. Add both side values, missing/unreadable
  pointers, stream/misaligned storage, conflicting bits, unchanged input and
  output refusal. The consumer must reject malformed side encodings.
- Live tests compare exact bodies, ID fields and sides through journal/replay.
  Test numeric/string/null/missing/duplicate IDs, paced bodies, reused IDs,
  multiple messages on one connection and concurrent connections with equal IDs.
- Send result-shaped JSON from the client and method-shaped JSON from the server.
  Side must follow the qualified flow state, not the JSON member names.
- Compare concurrent output as a multiset. Do not assign request identity from
  record order, timestamps or fixture labels.
- Require exact counters, no reported loss or new VM errors, a stable process,
  restored hook bytes, archive verification and scoped fixture removal.

Reject the candidate if a side is guessed after a failed read, if side failure
changes a valid ID, if ID failure invents a side, if limits increase silently,
or if same-record fields are presented as a cross-record association.

```text
BUILD BOX: source/compiled qualification -> bounded combined probe -> verify/sign
TMM: ID cache + flow-side byte -> one 144-byte output attempt
COLLECTOR: ring -> retained journal -> cursor replay
CONSUMER: ID status/value + side status/value; lifetime and association unknown
```

The [separate JSON-boundary gate](JSON-LIFECYCLE.md) now measures 306 entry records
from 13 exchanges. Unavailable context invalidates its full consumer window.
Completed initialization and a qualified local lifecycle remain open.
Flow side is not the message's request/reply role. Common owner lifetime, protocol
equality, trusted identity and data-path cost remain open.

## Measured result

Build 01 uses the unchanged ID reader and a private state map. Pinned PREVAIL passes
with the 256-byte stack limit. The interpreter and just-in-time compiler tests
produce 224 records: all 194 earlier ID checks plus 30 side-field checks.
They test missing configuration, both sides, invalid bits, missing or unreadable
pointers, unsupported storage, independent ID failure, unchanged inputs and output
refusal/recovery. Twelve malformed or incompatible consumer inputs are refused.

Live 01 passes 44 exchanges:

- The 35 earlier exact-ID cases, including large numbers and paced bodies.
- Two cases with result-shaped client JSON or method-shaped server JSON.
- Three exchanges with the same ID on one client connection.
- Four concurrent connections with the same ID. The origin receives all four
  requests before it releases replies. Field checks use a multiset, not a join.

The 88 records contain 44 client-side and 44 server-side observations. Every side
has complete status. ID states are 62 complete, four out of scope, two truncated,
eight wrong type, six missing, four ambiguous and two budget exhausted.
Thus a failed ID extraction can still contain an independently observed side.
The maximum observed extraction is 21 reads and 387 source bytes.
The contract remains 80 reads, 2,048 bytes and one 144-byte output attempt.

Exact bodies, fields, counters and cursor replay agree. The journal has 90 events,
with no earlier events, reported gaps or drops. There are no replay retries or new
VM errors. Kernel witnesses show stable process identity and restored hook bytes.
Cleanup checks all 12 slots inactive, archives seven files, then removes the
isolated fixture. Other recorded Docker containers retain their identity and state.

Values, fixture boundaries and counters are SELF witnesses. PREVAIL is INDEPENDENT.
Process and hook bytes are KERNEL witnesses. Source/container inspection is TOOL.
The fixture's connection labels are test evidence; they are not exported request
or connection identities. Stream-flow storage and multiple TMM workers remain
outside this result. Separate probes at the same hook were not tested together.

### Retained check stops

Black first requested two line-wrap changes in the new suite. These were applied
before the live run. After cleanup, the saved-evidence verifier initially lacked
`message_id_verify.py` on the build box. Import stopped before it opened an output
file. Staging that unchanged dependency allowed check 01 to pass. The authored
failure summary is separate from the automatic build and live receipts.

## Verify and reproduce

From the repository root:

```sh
python3 env/ai-traffic/id_flow_verify.py
python3 env/ai-traffic/id_flow_verify.py --export
```

The saved-evidence check needs no TMM process. It verifies 54 source snapshots,
native and live fields, malformed decoding, exact fixture bodies, replay, archive
contents and cleanup. Check 01 retains the same verifier result from the build box.

For another live run, use the prepared build-box procedure in
[MESSAGE-ID.md](MESSAGE-ID.md). Stage the new `id_flow_*.py`, `id-flow-run.sh` and
`ID-FLOW.md` files with all inherited message-ID, configuration and collector
dependencies. Include `message_id_verify.py` for the saved-evidence check. Stage
the new probe, ABI header and native test with their unchanged included sources.
Use unused build, run, source-directory, receipt and archive names.

```sh
ROOT=/home/starin/eob-config-20260925
python3 "$ROOT/id_flow_build.py" --output "$ROOT/id-flow-build-NEXT" \
  --discovery "$ROOT/message-id-discovery-01.json" \
  --scope "$ROOT/message-scope-discovery-02.json"
```

Create the fixture with both collector options before invoking `id_flow_live.py`.
Its arguments match `message_id_live.py`: select the new artifact directory, the
pinned collector image receipt and a fresh source directory. Archive with
`lifetime_fixture.py archive-cleanup` before removal. Preserve failed attempts.
Requalify source, layouts and hook addresses for any different TMM binary.
