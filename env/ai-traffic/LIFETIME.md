# Parser lifetime experiment

**Registered 2026-09-28, before implementation: IDEA / unrun.**
The bounded live result below is now **MEASURED**. The build and live receipts
retain the exact pre-run contract.
Test whether initialization and cleanup can bound the parser observations that
the earlier address-tag experiment could not separate.

## Source boundary

[Authoritative source](../../SOURCES.md#parser-lifetime-2026-09-28) shows two
flow-based users (`http.c`, `http1x.c`) and temporary parser contexts in offbox,
FPS, HTTP API and risk code. ADM uses the string parser after initialization.
Thus a parser context is not necessarily a connection. The init/fini hooks also
see contexts used for responses and trailers.

The parser returns to `PARSE_BEGIN` after successful headers. On the next call,
the client wrapper resets its per-header fields. `http_reset_http_context` and
`http_reset_scb_context` clear HTTP state without creating a new parser context.
The observer will not read the parser's bitfield state or dereference exit
arguments. String parsing, trailers, alternate filters and HTTP/2 remain outside
the live test's request-count claim.

## Method and falsifiers

Use three monitor programs: entry to `http_parse_ctx_init`, exit from
`http_parse_client_headers`, and entry to `http_parse_ctx_fini`. Share bounded
per-thread maps under an explicit run token. Emit on every call, including errors.
Keep addresses in the maps. Export an observed lifetime number and a parser-attempt
sequence, not an authenticated request ID.

- Each observed initialization assigns a new lifetime. Reinitialization at the
  same address must not reuse an old lifetime. Record the previous lifetime.
- A parser call without a current observed initialization must stay unknown.
  Test late attachment and a deliberately omitted initialization hook.
- Partial returns retain one attempt sequence. Success finishes that header
  attempt. The next attempt gets a new sequence without changing the lifetime.
- Cleanup ends the lifetime. An incomplete header must be visible at cleanup.
  Calls after cleanup must not inherit its identity.
- Duplicate initialization, duplicate cleanup, parse errors, capacity exhaustion,
  counter overflow and missing configuration must produce diagnostics. They must
  not silently assign a valid request identity.
- Native tests use three real interpreter/JIT programs sharing the actual map
  helpers. Challenge unreadable addresses, reuse, missing boundaries, output
  refusals, capacity and run-token changes.
- Live tests include keep-alive, fragmented headers, a paced body, an aborted
  header, concurrency, repeated connection creation and late/missed initialization.
  Reconcile every hook counter with output. Require zero reported drops and no
  new errors or verdict selections. Retain diagnostics in the negative cases.
- Check every observed positive lifetime's initialization/cleanup pair. A missing
  end prevents a closed-lifetime result. A reused address must have a new lifetime.
- Require the same executing binary/process, restored pads and disabled programs
  after the run. Archive the evidence before removing the isolated fixture.

Even a successful result qualifies only observed parser lifetimes and header
attempts in this HTTP/1 fixture. It does not prove body completion, authenticated
acceptance, or a correlation value shared with the authority ledger.
`request_scope_validated` remains false for the attribution consumer.

## Result

**MEASURED, 2026-09-28 — `lifetime-live-01`.** The three programs pass pinned
clang-18/PREVAIL verification, monitor signing and native interpreter/JIT checks.
The live JSON result and Tao XML both pass on repaired build
`ca69b84f4f5c9e225813b2ed3997c59f18ba2a31`.

| Check | Observed result |
|---|---|
| Unsampled output | 204 calls and 204 records: 71 initializations, 58 parser exits, 75 cleanups |
| Positive lifetimes | All 71 observed initializations have a matching cleanup |
| Reused addresses | 66 old/new lifetime pairs; the old lifetime is closed before the new initialization |
| Completed headers | 48 known attempts and three unknown attempts |
| Late/missed initialization | One late-attachment attempt and two attempts on the deliberately unobserved connection remain unknown; restoring the init hook does not invent a birth for that connection |
| Shared keep-alive connection | Eight completed header attempts retain one lifetime while actors and disposition change |
| Fragmented headers | Three attempts each retain one attempt number across `17,17,0` parser results |
| Paced body | Header completion is observed before the body is sent or the authority records an operation |
| Aborted header | One partial return, followed by cleanup with `PARTIAL_END`; no destination operation |
| Missing births at cleanup | Four cleanup diagnostics; no lifetime is invented |
| Client/authority reconciliation | 53 responses: 52 accepted fixture operations and one intended replay rejection; includes two unarmed responses |
| Runtime state | No reported drops, output refusals, new VM errors or verdict selections; stable executable/process, zero restarts |
| Hook bytes | Init has two CALL/NOP cycles; parser and cleanup each have one. All three sites return to their original bytes |
| Attribution | `request_scope_validated=false`; no authenticated request join is claimed |

Program records, counters and the authored client/authority are **SELF** witnesses.
PREVAIL is **INDEPENDENT**. Process-memory reads are **KERNEL** witnesses. Separate
client and authority checks do not constitute an independent security audit.
[Receipts and hashes](../../SOURCES.md#parser-lifetime-2026-09-28).

The native tests also cover duplicate initialization/cleanup, calls after cleanup,
parse errors, missing configuration, unreadable argument addresses, capacity,
output refusals, stale objects after a token change and call-counter saturation.
Those cases are bench results; the table above states the live cases.

### Limits after this result

- These numbers identify observed parser intervals in one HTTP/1 worker. They are
  not connection IDs, authenticated request IDs or accepted-operation IDs.
- The missing-initialization tests start without an active stored lifetime for
  that address. They do not cover losing both cleanup and initialization while
  an old entry remains active. General gap detection and recovery remain open.
- The live run starts with fresh maps, uses one unchanged run token and stays
  below the 256-birth bound. A new token alone is not a validated reset protocol.
  Capacity-safe rollover across retained maps remains unvalidated.
- This lifetime-only run joins no header value to the authority ledger. The later
  [registered correlation test](CORRELATION.md) measures that bounded join, with
  collision, replay, ambiguity and missing-evidence cases. General request identity
  remains unvalidated.
- Other parser callers, alternate filters, trailers, HTTP/2, multiple workers,
  sustained output pressure and per-call data-path cost remain unvalidated.

### Final checks and cleanup

Snapshot 01 stopped on two `broad-exception-caught` lint warnings. The cleanup
handler deliberately tries each remaining detach/revoke, saves every error, then
raises. Snapshot 02 excludes that warning and convention/refactor rules. Its
remaining lint checks, Python syntax checks, shell syntax check, source hashes and
disabled-slot/configuration-refusal checks pass. Both snapshots are retained.
This is not a full style-compliance result.

The isolated fixture was removed after archiving and checking all eight evidence
files. Cleanup rechecked all three restored hook sites and all 12 loader slots.
The two containers, two networks and four volumes were removed. The build
toolchain container retained its identity and state. Source directories and built
artifacts remain available. See [the cleanup record](CLEANUP-20260928.md#later-parser-lifetime-run).

## Repeat this bounded test

Use the pinned build VM and the existing repaired image. Stage the working source
files, the loader/drain tools and the SSA fixture files under
`/home/starin/eob-config-20260925`. Stage the BPF/native sources under
`/home/starin/eob-tmm-staged/substrate`. Keep all imported fixture modules together.
Choose unused names; each driver refuses to overwrite its receipt.

Run on the build VM:

```sh
python3 /home/starin/eob-config-20260925/lifetime_build.py \
  --output /home/starin/eob-config-20260925/lifetime-build-next
python3 /home/starin/eob-config-20260925/lifetime_fixture.py create \
  --output /home/starin/eob-config-20260925/lifetime-create-next.json
python3 /home/starin/eob-config-20260925/lifetime_live_run.py \
  --run lifetime-live-next --artifact-dir lifetime-build-next \
  --output /home/starin/eob-config-20260925/lifetime-live-next.json
python3 /home/starin/eob-config-20260925/lifetime_snapshot.py \
  --live /home/starin/eob-config-20260925/lifetime-live-next.json \
  --output /home/starin/eob-config-20260925/lifetime-snapshot-next.json
python3 /home/starin/eob-config-20260925/lifetime_fixture.py archive-cleanup \
  --live /home/starin/eob-config-20260925/lifetime-live-next.json \
  --archive /home/starin/eob-config-20260925/lifetime-evidence-next.tar.gz \
  --output /home/starin/eob-config-20260925/lifetime-cleanup-next.json
```

These drivers use only project `eob-template-20260925`. The cleanup command requires
a successful live receipt with the same TMM container identity. If a test fails,
retain the receipt and inspect cleanup state before removal. Copy new receipts and
the archive to `evidence/cache/`; register their hashes in `SOURCES.md` and the
manifest. Do not reuse the earlier one-off multi-project cleanup driver.
