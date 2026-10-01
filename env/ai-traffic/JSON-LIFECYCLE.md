# JSON-context boundary test

**2026-09-29 — MEASURED boundary observations, lifecycle unknown.** Three probes
produced 306 records during 13 live HTTP exchanges. Initialization-event arrival,
JSON completion entry, reset entry and teardown-event arrival are observable in
this bounded fixture. Entry does not prove the completed effect of a function.
Eleven handler records lack qualified context fields. The consumer rejects the
full window. No local lifecycle or common request/reply owner is established.

The contract below was registered before implementation. Immutable source snapshots
retain that version. [Receipts and checksums](../../SOURCES.md#json-context-boundary-observations-2026-09-29).
SELF: authored traffic, fields, counters and replay. INDEPENDENT: PREVAIL.
KERNEL: hook bytes and process identity. TOOL: source, layouts and container state.

**Follow-up:** [Initialization-completion qualification](JSON-INITIALIZATION.md)
rejects the tested return and forwarding candidates. This source/compiled/admission
result adds no live lifecycle claim. A completion-only return contract needs separate
qualification.

## Measured result

Build 03 passes the pinned PREVAIL checks at a 256-byte stack limit. The native
interpreter and just-in-time compiler tests produce 312 records. They challenge
shared maps, unchanged inputs, read failures, late observation, reused addresses,
capacity, output refusal, run-token changes and counter overflow.

Live 02 uses one TMM worker, connection-flow storage and the configured AIMCP/JSON
HTTP/1 path. It uses the unchanged separate collector.

| Observation | Saved result |
|---|---|
| Traffic | 13 exact request/reply body checks, all HTTP 200 |
| Probe entries | 255 handler, 25 JSON completion, 26 reset |
| States | 269 observed, 26 address-only reset, 11 unavailable |
| Handler event codes | 21 initialization arrivals, 22 teardown arrivals; no abort arrival |
| Opaque storage tags | 19 nonzero tags; no lifetime meaning |
| Late attachment | Client completion has seen-mask 2: completion seen, initialization not seen |
| Malformed request | One server-side completion, no client-side completion; two resets |
| Keep-alive | Three exchanges on one client connection, six completions |
| Concurrent equal IDs | Four client connections; origin receives all four before replying; eight completions |
| Per-call bounds | At most four reads, 29 source bytes, one 112-byte output attempt |
| Journal and replay | 308 journal events; all 306 records reconcile with counters and replay |
| Diagnostics | No reported ring loss, output failures, new VM errors or replay retries |
| Cleanup | Three restored hooks, stable process, all 12 slots inactive, nine-file archive, scoped removal |

The 11 unavailable records carry `HUDCTL_CONNECT` (code 2). They carry no context
tag, side or source reads. They remain in the journal and invalidate the full
consumer window. `diagnostic_or_gap` is the consumer's general rejection reason;
here it means unavailable context, not measured transport loss.

Paced request and reply bodies are included. Fixture intervals group observations
for these checks. They do not create a production request/reply association.
The ID/side probe was not loaded beside this probe set.

**Limits:** interrupted transfer, a live disabled path, deferred rule completion,
live omitted boundaries, live capacity and live reload remain unvalidated. Native
and consumer checks cover some corresponding failure states, not those live paths.
The known-detach check is an offline consumer challenge, not a performed live detach.
Collector replacement was not tested with this probe set. Silent missed boundaries,
stream-flow coverage, multiworker ownership, trusted identity and data-path cost
remain open. A completed-initialization witness is still required before any local
lifecycle claim.

## Retained failures

- Build 01 fails because the reset variant does not use `read_field`. Build 02
  compiles that helper only for handler/completion variants. Reset still reads no
  application memory. Build 03 adds stricter consumer source-change checks.
- The first suite format check finds an indented `publish_tests` definition.
  Correction and line wrapping precede probe load; both live receipts retain
  passing format and lint checks.
- Live 01 stops because the test accepts only observed, address-only or disabled
  states. It rejects a valid unavailable-state record. Live 02 preserves unavailable
  and unsupported states while keeping the consumer window invalid. The first
  attempt's nine-file archive was checked before fixture removal and recreation.
- Saved-evidence check 01 expects `stat` in every hook-change row. Only the initial
  and final witness rows contain it. Check 02 checks process start time there and
  hook-byte changes across the interval. The original failed check is retained.

Each literal symptom lookup returned `NO RECORD`.
[Contested premise](../../CONTESTED-PREMISES.md#37--every-json-handler-entry-has-qualified-context--falsified).

## Starting evidence

[MESSAGE-SCOPE.md](MESSAGE-SCOPE.md) records the pinned source and compiled paths.
The context is reused between messages and has connection and stream forms.
Initialization and cleanup operations are inside `hud_json_handler`. Handler entry
precedes those operations and can take a disabled-state path. Reset can follow
deferred rule execution. These facts exclude entry alone as proof of initialization.
[Source receipts](../../SOURCES.md#message-scope-qualification-2026-09-29).

[ID-FLOW.md](ID-FLOW.md) now measures ID and flow side in one record. It supplies
neither local lifecycle nor common owner lifetime. Earlier parser-lifetime and
[gap tests](GAPS.md) also cannot supply JSON-context coverage.

## First deliverable: boundary observations

Recheck the source, argument layouts, event constants and compiled branches before
building. Start with the pinned handler, JSON completion and reset entries. Retain
each event's actual meaning: initialization event seen, completion entry seen,
reset entry seen, abort event seen or teardown event seen. Do not rename an entry
observation as the completed effect of that function.

Use connection-flow storage only. Reject stream representations, invalid pointers,
unreadable fields and disabled or unsupported paths explicitly. Preserve source,
worker, program instance, revision, sequence and output-failure diagnostics.
Application pointers may serve as private map keys; do not export them as identity.
An opaque context tag means only observed storage, including possible address reuse.

Initial limits for this gate are four source reads, 128 source bytes and one
128-byte output attempt per invocation. Use at most 128 tracked contexts and the
existing host map limits. Define the exact ABI and state table before compilation.
Use private map names; explicitly document any state shared by the three programs.
No eviction may silently replace a tracked context. Capacity, counter overflow,
map failure or output refusal must invalidate the affected result window.

This is a separate probe set. Do not load it beside the existing ID/flow program
at the same completion hook. Use the unchanged collector and a fresh run token.
No application-memory writes, application accessor calls or TMM function edits
are part of the test.

## Required challenges

### First probe contract, registered before compilation

Use three entry probes: handler (kind 1), completion (kind 2), reset (kind 3).
Slots 8, 9 and 10 are reserved for this isolated test. Every invocation attempts
one 112-byte record. Handler codes retain their numeric value. Completion and
reset have code zero; their kind identifies the function entry.

For handler/completion, read the node's four-byte size/flags field at offset 44.
Require at least 96 context bytes, active/context bits and no stream bit. Require
an aligned connection-flow pointer and one valid side bit. Completion argument 2
must equal node plus 64. Read the context's 16-byte tail at offset 80 and its
eight-byte cache pointer at offset 24. Export only cache presence, payload length
and the low 14 context flag bits. Maximum: four reads and 29 source bytes.
Disabled context status describes the observed bit, not a completed handler action.

Reset has only a context argument. It cannot requalify the node or flow storage.
Therefore it reads no application memory and exports no side or context fields.
It may report an existing opaque storage tag, with `address_only` status. An
unseen reset address has tag zero. This is an explicit limit of the first gate.

Three shared maps hold output, run counters and at most 128 distinct context
addresses. Tags identify observed storage only; they are not lifecycle numbers.
An existing tag survives address reuse, deliberately exposing that ambiguity.
A monotonic seen-mask records initialization entry, completion entry, reset entry
and abort/teardown entry. It never grants a valid lifecycle. No map eviction is
permitted. A different run token with retained state is refused, not reset silently.

The record layout is: magic/version; seven 64-bit fields (instance, revision, run,
clock, global sequence, output failures, storage tag); twelve 32-bit fields
(kind, event code, status, diagnostics, side, context flags, cache presence,
seen-mask, read count, source-byte count, payload length, reserved zero).
Magic is `0x4a4c4244`, version 1. Status values are 0 unavailable, 1 observed,
2 address only, 3 unsupported, 4 read failed, 5 disabled, 6 capacity,
7 overflow, 8 map failed, 9 run mismatch. Diagnostic bits 0–3 retain the existing
configuration/map/overflow/clock meanings. Any diagnostic, refusal or known
attachment break invalidates the consumer's entire window.

The native state tests must show that reset cannot invent a tag or initialization,
equal addresses retain storage tags after reuse, and a gap invalidates the consumer
even when the record sequence has no hole. A handler entry remains only an entry.

| Challenge | Required decision |
|---|---|
| Fresh context and normal teardown | Distinguish event arrival from completed initialization and cleanup. If no qualified completion witness exists, lifecycle remains unknown. |
| Three messages on one client connection | Record local completion/reset boundaries without calling the context a request or shared connection. |
| Concurrent connections with equal IDs | Keep context observations separate. ID equality and record order must not create a shared owner. |
| Paced body, parse error and interrupted transfer | Distinguish parser completion, reset and abort. None proves remote operation success. |
| Disabled JSON path or deferred rule completion | Record the actual observed path. An unreachable challenge stays unvalidated; it is not a passing test. |
| Attach after initialization | Subsequent completion/reset events cannot invent a birth. |
| Omit both end and next initialization during address reuse | Show that an apparently continuous record sequence can retain stale state. Reported detach invalidates the entire window. Silent omission remains a coverage limit. |
| Tracking capacity and counter limits | Emit an explicit limit when possible; reject affected scope even when later events look complete. |
| Collector restart or program reload | Preserve journal source boundaries. Require new validated coverage before accepting any lifecycle. |

Native interpreter and just-in-time compiler tests must challenge the state table,
read failures, unchanged input and output refusal. Pinned PREVAIL must pass with
the 256-byte stack limit. Live challenges must use the isolated, stable fixture.
Record exact traffic outcomes, hook counters, replay and kernel witnesses.
Archive the evidence before scoped removal.

## Decision and falsifiers

Reject a lifecycle candidate if it invents initialization, survives a known gap,
reuses an old number after a qualified end, hides a capacity failure, or uses a
reset as proof of request completion. A source-level helper name without a
compiled hook is not an observation point.

The first possible result is **measured boundary observations, lifecycle unknown**.
Promote a local lifecycle only after a qualified initialization witness, explicit
end/reuse rules and the required coverage checks pass. Preserve any failed shortcut
in `CONTESTED-PREMISES.md`. Keep general request scope and message association false.

```text
BUILD BOX — source + compiled branches -> event/ABI/state-table contract -> verify/sign
TMM — handler/completion/reset entries -> bounded boundary records
COLLECTOR — ring -> retained journal -> cursor replay and source boundaries
CONSUMER — coverage checks -> local boundary observations, or unknown
LATER QUALIFICATION — common owner + binding lifetime + ID equality -> possible association
```

Flow side still does not specify JSON message role. Trusted caller identity,
multiworker ownership, stream-flow coverage, silent boundary loss and data-path
cost remain separate work.

## Verify and reproduce

From the repository root:

```sh
python3 env/ai-traffic/json_lifecycle_verify.py
python3 env/ai-traffic/json_lifecycle_verify.py --export
```

The verifier checks receipt hashes, 125 source snapshots, the 312 native records,
14 malformed decoder inputs, exact traffic bodies, record accounting, replay,
kernel witnesses and both archives. It does not run TMM. Check 02 saves the same
verification from the build box. Source snapshots from failed attempts are checked
as history; current non-Markdown sources are checked against the successful build
and run.

For another live run, use the prepared build box and the pins in
[ID-FLOW.md](ID-FLOW.md#reproduce-on-the-prepared-build-box). Stage the new
`json_lifecycle_*.py`, `json-lifecycle-run.sh`, this contract, the two substrate
surface files and `check_json_lifecycle.c`. Retain the inherited configuration,
traffic, loader and collector files. Run these commands from
`/home/starin/eob-config-20260925`, with unused output names:

```sh
python3 json_lifecycle_discover.py --scope message-scope-discovery-02.json --output json-lifecycle-discovery-02.json
python3 json_lifecycle_build.py --output json-lifecycle-build-04 --discovery json-lifecycle-discovery-02.json
mkdir json-lifecycle-source-03
python3 lifetime_fixture.py create --collector-image sha256:26f3184a4e3fe96b61f780761497933facc385f3d62d6f1cf66f04e56abd5054 --collector-source json-lifecycle-source-03 --output json-lifecycle-create-03.json
python3 json_lifecycle_live.py --run json-lifecycle-live-03 --artifact-dir json-lifecycle-build-04 --image-build collector-image-02/image-build.json --source-dir json-lifecycle-source-03 --output json-lifecycle-live-03.json
python3 lifetime_fixture.py archive-cleanup --collector-image sha256:26f3184a4e3fe96b61f780761497933facc385f3d62d6f1cf66f04e56abd5054 --collector-source json-lifecycle-source-03 --live json-lifecycle-live-03.json --archive json-lifecycle-evidence-02.tar.gz --output json-lifecycle-cleanup-02.json
```

The final command requires a passing live receipt. For a failed run, preserve its
receipt and journal, then use `json_lifecycle_reset.py` with `--live`, `--source-dir`,
`--archive` and `--output`. That path checks disarm and archives before removal.
Do not export signed objects or signing keys. A new result needs new evidence
index rows and explicit review; the saved verifier above checks the recorded run.
