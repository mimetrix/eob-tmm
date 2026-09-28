# Bounded request-correlation experiment

**MEASURED, 2026-09-28: bounded live join in one synthetic HTTP/1 fixture.**
Of 51 completed header observations, 42 match accepted operations, one matches an
authenticated rejection, and eight remain unknown. The fixture has been removed
after evidence collection. [Receipts and hashes](../../SOURCES.md#bounded-request-correlation-2026-09-28).

Registered as IDEA before implementation. The build and live receipts retain the
original contract. The method and falsifiers below are that experiment's scope.

**Later follow-up:** [GAPS.md](GAPS.md) tests reported observation breaks, capacity
and fresh recovery. It adds a collector guard for those cases. Silent, unreported
breaks remain outside the validated scope.

Test whether the observer can read a request path and `X-Proof-Nonce`, then find
a unique authenticated record in the fixture's destination ledger. These values
are untrusted. Authentication comes only from the authority's checked request proof.
The existing [parser-lifetime result](LIFETIME.md) is a prerequisite, not identity proof.

## Method

Keep the initialization, client-parser exit and cleanup programs. Add an entry
observer on the internal byte-input parser. Check its machine-code argument use
against the pinned source before arming. Use the fault-contained read helper.
Read at most 512 bytes of headers per attempt. Read no bytes after the header end.
Export only a recognized fixture path, a complete 32-character hexadecimal nonce,
the observed parser interval/attempt and diagnostics. Never export raw headers,
request proofs, credentials or bodies. Every invocation attempts output.

Accept only canonical fixture request lines for `/mcp`, `/a2a` and `/delegate`.
Unsupported syntax, missing/duplicate/invalid nonce, exhausted bounds, a failed
read, missing initialization, or incomplete headers must remain unavailable.
Do not infer a candidate from a previous request or memory occupant.

Join only after a successful client-header parse and a checked interval closure.
Require complete stream/counter accounting before enabling any matches. Match
`(path, nonce)` without using arrival order, addresses or nearest timestamps.
Duplicate candidates on either side remain ambiguous. A rejected authority record
must not become an accepted operation. An unavailable candidate stays unknown.

## Falsifiers and tests

- Pinned PREVAIL and native interpreter/JIT tests must accept the final program.
  Test fragmented bytes, exact bounds, missing/duplicate/invalid nonce, responses,
  unreadable pointers, output refusal and stale state on a new attempt/lifetime.
- Live requests must include alternating agents on one connection, concurrency,
  memory reuse, fragmented headers, paced bodies, an aborted header, late attachment
  and a missed initialization. Reuse the same nonce for A, B and an A replay.
  Also test a short nonce, a forged request proof, an authenticated rejection,
  a false claimed actor, grant issuance and a delegated downstream request.
- For unique valid candidates, independently compare extraction with client and
  authority data. Reordered ledger input must give the same result. Deliberately
  removed or duplicated records, bad sequence numbers and reported loss must stop
  attribution. No ambiguous candidate may acquire an actor.
- Reconcile every hook call and output record. Require restored hook bytes,
  stable process/binary and no new errors, verdict selections or reported drops.
- Retain failed attempts. Archive all fixture evidence before removing the fixture.

## Scope limit

A pass qualifies a bounded join in this synthetic HTTP/1 fixture. It does
not prove general request identity, native AI-protocol attribution, production
identity-provider integration, HTTP/2, multiple-worker scope, missing-boundary
recovery, sustained output capacity or per-call cost. Header completion still does
not prove body completion or accepted execution. Record these limits with any pass.

## Result

Build attempt 01 passed PREVAIL but failed the native extraction test. The program
requested five maps; the pinned host permits four across the shared registry.
The failed build receipt is retained. Build attempt 02 corrects the storage:
it shares the existing lifetime counter/output maps and uses two rows in one new map
per lifetime. This limits extraction to lifetimes 1–127 in a fresh registry.
Higher lifetime numbers emit an unavailable diagnostic. The reader still
uses a 512-byte header bound. The native test now also checks loader-map errors.

Build 02 passes pinned clang-18, PREVAIL, monitor signing, and native interpreter
and just-in-time (JIT) execution tests. The native reader test uses one VM with
seeded lifetime state. It is not a four-program integration test. The live test
below runs all four programs together.

### Where each step runs

```text
BUILD VM — off the data path
  Compile → bind to the packaged binary → verify → sign four monitor programs
                                                     │
TMM — data path                                      ▼
  Initialization + byte-input reader + client-parser return + cleanup
       │ bounded candidate and lifetime records; one output attempt per call
       │
       │                FIXTURE DESTINATION
       │                  Validate request proof → authority ledger
       │                                             │
       ▼                                             ▼
COLLECTOR — off the TMM data path
  Check complete accounting and closed intervals → match unique (path, nonce)
  → accepted-operation match / authenticated rejection / unknown
```

The header values remain untrusted. The collector receives the ledger directly
from the fixture authority. This test does not validate a production ledger
transport or accept an arbitrary caller-supplied ledger as authentication proof.

### Live attempt 02

| Check | Observed result |
|---|---|
| HTTP responses | 53 total: 50 accepted and three intended rejections; two accepted requests are outside the armed window |
| Four-hook accounting | 313 calls and 313 records: 71 initializations, 109 byte-input calls, 58 client-parser returns, 75 cleanups |
| Lifetimes | All 71 observed positive intervals close; 66 address-reuse pairs |
| Header attempts | 51 completed, including three with no observed initialization; seven partial returns |
| Candidate reader | 47 complete values, seven partial records, 48 unsupported-input records, six missing-initialization records and one invalid-nonce record |
| Accepted-operation matches | 42; includes grant issuance and a delegated operation by A with originator B and B's accepted parent operation |
| Authenticated rejection | One denied method; it is not recorded as accepted execution |
| Unknown results | Three missing initializations; three colliding nonce candidates (A, B, A replay); one short nonce; one forged proof |
| Hostile actor claim | A's false claim to be B does not change authenticated actor A |
| Extraction check | Complete extracted values match the client/authority values, including concurrent requests; no match is assigned by arrival order |
| Evidence checks | Reversing the ledger preserves all results. Removed output, removed ledger record, added duplicate ledger record, reported loss and a boolean sequence number each stop all attribution |
| Runtime | No reported output loss/refusal, new VM error or verdict selection; stable binary/process and zero restarts |
| Hooks | Kernel reads show two CALL/NOP cycles at initialization and one at each other site; all original bytes restored |

The candidate hook is `http_parse_headers`, entry `0xcc8240`, with its patch at
offset zero. The other sites are the three recorded in [LIFETIME.md](LIFETIME.md).
All four programs are signed for monitor mode on build
`ca69b84f4f5c9e225813b2ed3997c59f18ba2a31`.

Witnesses: **SELF** for authored clients, authority decisions, program records and
native assertions; **INDEPENDENT** for PREVAIL; **KERNEL** for process identity and
hook bytes. The separate client checks are not an independent authentication audit.

### Remaining limits

- `bounded_join_validated=true`; **`request_scope_validated=false`**. This is a
  closed-window result for the tested fixture, not a general streaming identity feed.
- Only canonical `POST` request lines for the three fixture paths are supported.
  The reader admits at most 512 header bytes and lifetimes 1–127 in a fresh registry.
  Lifetime numbers include other parser uses; this is not a 127-request capacity.
- Native tests check every-byte fragmentation, header bounds 511/512/513, body
  exclusion, missing/duplicate/invalid nonce, response input, read/output failures,
  absent/ended/reused lifetimes, fresh attempts and refusal at lifetime 128.
  These native cases are separate from the live cases in the table.
- The late/missed-initialization tests do not cover losing both cleanup and
  initialization while stale active state remains. Run-token reuse, map rollover,
  alternate parser paths and arbitrary buffer partitioning remain unvalidated.
- Header completion precedes body completion. Identity and accepted-operation
  evidence are available only after the destination checks the complete request.
- Native AI filters, production identity providers, HTTP/2, multiple workers,
  sustained output pressure and per-call data-path cost remain unvalidated.
  Reading these headers does not establish visibility unavailable through iRules.

### Final checks and cleanup

The first lint check found a mismatched subclass method signature. It was
corrected. Live attempt 01 then stopped at Black before attaching any hook.
Both failures remain cached. Live attempt 02 passes Black and pylint with
convention/refactor rules excluded. Snapshot 01 checks exact live-source hashes,
Python/shell syntax and the lifetime suite's scoped lint rules. All four slots
are disabled, and all four configuration-status requests are refused.

Cleanup checks the same process/binary, four restored hook sites and all 12
inactive loader slots. Nine fixture evidence files are archived with checked
hashes. Two containers, two networks and four volumes are removed. The toolchain
container retains its identity and state. See [cleanup](CLEANUP-20260928.md#later-correlation-run).

## Repeat this bounded test

Use the pinned build VM, repaired image and staging paths from
[LIFETIME.md](LIFETIME.md#repeat-this-bounded-test). Keep all imported fixture
modules together. Stage the new correlation scripts and BPF/native sources.
`correlation_build.py` also requires the retained, checked `lifetime-build-01`
artifacts. This repository alone cannot reproduce the live result.

Choose unused output names. Run these on the build VM:

```sh
python3 /home/starin/eob-config-20260925/correlation_build.py \
  --output /home/starin/eob-config-20260925/correlation-build-next
python3 /home/starin/eob-config-20260925/lifetime_fixture.py create \
  --output /home/starin/eob-config-20260925/correlation-create-next.json
python3 /home/starin/eob-config-20260925/lifetime_live_run.py \
  --run correlation-live-next --artifact-dir correlation-build-next --suite correlation \
  --output /home/starin/eob-config-20260925/correlation-live-next.json
python3 /home/starin/eob-config-20260925/lifetime_snapshot.py \
  --live /home/starin/eob-config-20260925/correlation-live-next.json \
  --output /home/starin/eob-config-20260925/correlation-snapshot-next.json
python3 /home/starin/eob-config-20260925/lifetime_fixture.py archive-cleanup \
  --live /home/starin/eob-config-20260925/correlation-live-next.json \
  --archive /home/starin/eob-config-20260925/correlation-evidence-next.tar.gz \
  --output /home/starin/eob-config-20260925/correlation-cleanup-next.json
```

Run each step only after the previous required checks pass. Retain a failed
receipt, investigate its literal error through `env/scripts/ask`, and use a new
attempt name. The cleanup driver requires a successful live receipt for the
same fixture identity.
