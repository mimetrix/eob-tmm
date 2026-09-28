# Agent attribution: experiment contract

2026-09-25. **Registered as IDEA / unrun; destination-side baseline now MEASURED.** The owner
selected agent attribution as the primary AI-security experiment. The bounded ICAP outcomes
remain a supporting enforcement example; their monitor program is not an attribution implementation.

**View the actual run:** [Agent attribution — recorded experiment](../../explainers/agent-attribution-evidence.html).
The self-contained HTML page shows the real delegation IDs, spoofing records, all 23 outcomes and
links to the implementation and cached receipts. It is a frozen evidence view, not a live dashboard.

**Latest result, 2026-09-28:** the [bounded live join](CORRELATION.md) matches
42 parser observations to accepted authority operations and one to an authenticated
rejection. Eight remain unknown. It builds on the [lifetime gate](LIFETIME.md).
This is a synthetic, closed-window HTTP/1 result with a trusted fixture ledger.
General request identity, native AI-filter visibility and data-path cost remain open.

The later [controlled-gap test](GAPS.md) adds whole-window refusal after reported
observation breaks or exhausted tracking limits. Fresh recovery passes; a retained
connection stays unknown. Silent, unreported breaks remain unvalidated.

**Current direction, corrected 2026-09-28:** first establish the
[probe's application-metadata extraction](METADATA.md). Identity matching and
other analytics follow later. [COVERAGE.md](COVERAGE.md) retains the corrections:
representative workload tests must follow observations, and a real deployment is
not a prerequisite for probe design. The fixed concurrency proposal was withdrawn.

## Question and trust boundary

Can a downstream operation be attributed to the authenticated agent that performed it, with
validated delegation back to an initiating principal, despite connection reuse, concurrency,
retries and hostile identity metadata?

The chain is **configured principal → authenticated agent → accepted parent operation →
scoped delegation → downstream action**. Preserve separately:

- Authenticated actor, authentication authority and evidence type.
- Claimed actor and caller-provided operation/session/task IDs, all untrusted inputs.
- Server-issued operation/attempt identifiers and accepted delegation edges.
- Internal TMM object/process lifetimes, routing bindings and actual observed execution.

No credential evidence means **unknown**, not attribution inferred from an IP, socket, pointer,
MCP session, A2A task ID, or a routing cookie. Delegation does not replace the executing actor.
The cached [source inventory](../../SOURCES.md#ai-protocol-source-inventory-2026-09-24) establishes
MCP session persistence and A2A task/context routing augmentation, not authentication semantics.

## First fixture: explicit limited authentication model

Two agents have independent, per-run random HMAC keys registered to fixture identities. Each
request proof covers method, path, nonce and the exact body. A replay cache rejects reuse of an
authenticated nonce. An agent-name header selects a verification key; it is not trusted until
the proof checks. The configured human/service-principal mapping is a fixture assumption, not
a demonstrated end-user login or production identity-provider integration.

Authentication and delegation validation initially run in the synthetic destination behind
TMM. This creates a trusted comparison ledger; it does **not** demonstrate authentication or
authorization enforcement inside TMM. HTTP is confined to the existing isolated test network.
Keys and signed delegation credentials stay in memory and are omitted from evidence receipts.
This HMAC protocol is a test harness, not a proposed production authentication standard.

Delegation requires an accepted operation belonging to the authenticated issuer. A fixture
authority signs the recipient, parent operation, audience, scope and expiry. The recipient must
authenticate independently. Wrong recipient, tampering and out-of-scope use are rejected.

## Preregistered falsifiers

1. Alternate A and B over one HTTP/1.1 keep-alive connection and run A/B concurrently. Reuse the
   same caller operation and JSON-RPC IDs. Any cross-agent attribution falsifies the fixture.
2. A authenticates while claiming to be B: retain authenticated A and flag the claim mismatch.
   A signature made with A's key while selecting B's credential must fail authentication.
3. Replay a signed request: reject it without a second accepted action.
4. Retry one caller operation with a fresh nonce: record a new attempt under the same actor;
   do not treat caller IDs as globally unique or claim exactly-once execution.
5. A delegates an accepted task to B for `tools/call`: executing actor remains B; originator and
   parent remain A's. Reject wrong recipient, modified grant and an out-of-scope method.
6. A/B use the same caller session/task labels: labels alone must not merge identities or create
   delegation edges. Incomplete evidence must never acquire a guessed principal.

The client states expected results independently; the server ledger records verified actor,
accepted/rejected disposition, request-body hash, connection-local ID, nonce and server operation
ID. Reconcile every attempt and every accepted action. Receipts must show actual connection reuse.

## TMM/eBPF phase and value gate

Use the authenticated ledger as the authority for identity, joined to a validated per-request
TMM observation. Establish cardinality and pointer lifetime under reuse before joining by an
internal handle. A nonce read from a request is only a correlation candidate until its proof is
validated; a missing or ambiguous join is unknown. Do not export credentials in the eBPF payload.

Candidate differentiated facts are actual request-to-upstream association, persistence validation
and fallback/rebinding decisions. Their relevant iRules/WASM equivalents must be audited before
claiming additional visibility. Ordinary authenticated identity or HTTP headers alone do not pass
this gate. Native MCP/A2A filter reachability is not established by the forwarding fixture.

Continuous export, loss accounting and incremental poll-loop cost remain governed by P20/P16.
No armed attribution program or numerical cost result is established by the initial fixture.

**Next application after P21 (owner direction, 2026-09-25):** return here after completing
the [configuration input interface](../../configuration-snapshots.md). A versioned authority
table can use that channel; its presence is not request-authentication evidence. First
retain the credential-validated ledger/TMM-observation join and its missing/ambiguous cases.
P21's isolated live lifecycle now passes on packaged build `b8dc27f3…`: signed load,
versioned updates, withdrawal, reload isolation and revoke, with exact HTTP/event counts
and kernel binary/entry witnesses. The original attribution baseline below used the older
binary and remains a destination-ledger result. Resume the join experiment using the new
isolated configuration-capable TMM; configuration publication does not supply authentication.

The join falsifier must also deliberately reuse a nonce across A/B and replay an identical signed
request. A nonce alone is not a globally unique authenticated attempt key. Require validated
request cardinality and lifetime/attempt scoping; multiple candidates remain unknown.

### Join consumer gate — preregistered before implementation

The next consumer accepts **a trusted authority ledger**, a bounded observation window and
independently established request-scope/accounting evidence. It does not verify credentials
again or treat a caller-selected key name as authentication. A candidate `(path, nonce)` is
usable only when exactly one observed request and one ledger attempt have that candidate.
The event's process-session/request-sequence pair identifies an observation, not an agent.
No join by pointer, IP, caller operation ID, array order or nearest timestamp is permitted.

**Falsifiers:** any identity assigned with unvalidated request scope, missing accounting,
loss/errors, duplicate request identities, an incomplete window, multiple candidate events
or ledger attempts, a replay, an A/B nonce collision or absent authentication evidence.
Spoofed claims must stay separate from the verified actor; rejected operations must never
acquire an accepted operation/parent. Configuration revisions are provenance only. Removing
one ledger row or event must invalidate window completeness rather than silently pairing
the surviving item with a different attempt.

First test the consumer against the retained 23-attempt authority ledger and synthetic
candidate observations, then challenge collisions/missing evidence explicitly. **Those
synthetic observations cannot establish a TMM request lifetime or a live attribution join.**
A subsequent probe must establish that scope and cardinality on the new isolated TMM before
its feed can enable the consumer's `request_scope_validated` gate.

### Consumer result — `attribution-join-01`

**MEASURED, SELF consumer fixture; no live attribution probe.**
[`attribution_join.py`](attribution_join.py) implements the gate above;
[`check_attribution_join.py`](check_attribution_join.py) passes **21 checks** in the pinned
SSA/Tao fixture. On synthetic candidates for the retained 23-attempt ledger:

- **16 attributed:** unique accepted attempts retain the authenticated actor, operation,
  originator and parent. A's spoofed B claim remains separate.
- **Four rejected:** unique authenticated but unauthorized attempts retain their disposition
  and verified actor, with no accepted operation or parent.
- **Three unknown:** both members of the identical-proof replay pair are ambiguous; the
  forged credential has no authentication evidence. The original ledger still has 17
  accepted operations; the consumer deliberately declines one otherwise accepted match.

Fresh in-memory fixture proofs separately authenticate A and B using the same nonce and
reject A's replay. The consumer leaves all three candidates unknown. Missing scope,
incomplete/lossy accounting, missing rows/events, duplicate identities/candidates and
incomplete authority records also fail closed. Changing configuration instance/revision
does not change the authenticated actor. Keys and proof/grant credentials are not exported.
The first receipt has 19 checks; `attribution-join-02` adds explicit ledger/event ordering
permutations, establishing that rearranging either input does not change any association.

The [cached receipt](../../SOURCES.md#agent-attribution-fixture-2026-09-25) includes original
baseline hash, all challenge outputs, collision ledger, exact source text/hashes, container
identity and formatting/lint checks. **Next gate:** a live producer must qualify per-request
scope/cardinality and complete observation windows, including keep-alive reuse, concurrency,
fragmented requests and replay. The boolean gate is supplied by that experiment's trusted
driver, never by request metadata. The consumer does not prove its own input provenance.

Reproduce in the prepared fixture with an unused receipt name:

```sh
docker exec -e PYTHONDONTWRITEBYTECODE=1 eob-config-20260925-fixture-1 \
  python3 /work/check_attribution_join.py \
  --baseline /work/ai-attribution-runtime-02-20260925.json \
  --receipt /evidence/attribution-join-next.json
```

Then collect from the control machine with
`python3 env/ai-traffic/config_snapshot.py --join --output <new-cache-file>`.

## Live parser-scope experiment

### Live parser-scope gate — registered 2026-09-28, before the run

**Registered as IDEA / unrun; result recorded below.** Test the exit of
`http_parse_client_headers` on the repaired
isolated image. Emit one record for every call. Read the result and the copied
argument address only; do not dereference an exit argument. Assign an anonymous
tag to each distinct address seen by one thread. A tag denotes address equality,
not an object lifetime, request, connection, or actor. Keep addresses in the map;
do not export them. Stop assigning tags when the bounded table is full.

Challenge the call-to-request assumption with separately paced header fragments,
an incomplete header followed by close, a complete header with a paced body,
alternating authenticated actors on a keep-alive connection, replay, concurrent
connections, and repeated connection creation. Keep destination authentication as
the authority. A successful parser result means complete headers, not accepted
authentication or a complete body.

**Falsifiers and checks:**

- More than one parser call for a complete request kills call count as request ID.
- One tag across different independently recorded connections kills the tag as a
  connection-lifetime ID. Absence of observed reuse does not prove safe lifetime.
- A completed-header event before the body is sent kills header completion as
  proof that the destination accepted an operation.
- Replays and caller labels must not acquire a guessed identity from these tags.
- Missing events, output failures, VM errors, duplicate call sequences, or changed
  process identity invalidate the window. Match all calls to exported records.
- Require stable executable identity, monitor mode, no SAFE_RETURN selections,
  restored patch bytes and disabled slots after the test.

The driver must keep `request_scope_validated=false`. This probe does not extract
an authenticated correlation candidate or establish object birth/death. HTTP/2,
native filter execution, multiple workers and cost remain separate gates.

### Live result — `scope-live-02`

**MEASURED, 2026-09-28.** The unsampled probe runs on isolated packaged build
`ca69b84f4f5c9e225813b2ed3997c59f18ba2a31`. It records parser exits without
reading an argument's object. The test passes, but the shortcuts to request
identity fail:

| Check | Result |
|---|---|
| Exact HTTP responses and destination ledger | 61 responses: 54 accepted fixture operations, seven intended rejections; includes two unarmed checks |
| Armed window | 66 parser calls and 66 records; 59 successful header parses and seven partial returns |
| Fragmented A, fragmented B with the same nonce, then A replay | Each produces three parser results: `17,17,0`; the destination accepts A/B separately and rejects replay |
| Shared keep-alive connection | 19 requests retain one address tag while actors and disposition change |
| Complete header, then paced body | Successful header parse occurs before the body is sent; the destination has not yet recorded the operation |
| Incomplete header, then close | One partial result; no completed-header event or destination attempt |
| New connections and concurrency | Eight concurrent requests and 32 sequential new-connection requests; eight address tags occur across multiple client connections |
| Attribution gate | All 59 completed-header observations remain unknown: `unvalidated_request_scope` |
| Output and cleanup | Zero reported drops, output refusals, new VM errors or new SAFE_RETURN selections; patch restored, slots disabled, no restart |

Witnesses: **SELF** program/slot counters, client assertions and destination
authentication ledger; **INDEPENDENT** PREVAIL; **KERNEL** executing binary hash,
patch bytes and process state. The client and destination checks are separate
from the probe, but they are authored fixture code. This is not a security audit.
The program's `call_seq` counts calls within one thread and loaded instance.
Its `context_tag` records address equality. Neither field is an authenticated
request ID. The output contains no addresses, request bodies or credentials.

Attempt 01 failed because the test required an absolute slot selection count of
zero. It inherited 16 from the prior tutorial. Attempt 02 requires zero change
within each window and over the full run: `fired` is 121→187, selections remain
16, and errors remain zero. The failed receipt and original source are retained
in [the evidence table](../../SOURCES.md#attribution-parser-scope-2026-09-28).

**Follow-up:** the [registered lifetime gate](LIFETIME.md) now observes initialization,
parser completion and cleanup together. It closes 71 positive parser intervals,
including address reuse and an aborted header. Late/missed initialization remains
unknown. Source inspection also finds temporary contexts, responses and trailers;
the result is limited to this HTTP/1 fixture. The later [correlation gate](CORRELATION.md)
joins bounded header candidates to the credential-validated destination ledger.
Parser success alone does not establish body completion or acceptance. General
request scope, differentiated internal visibility and per-call cost remain open.

### Repeat the bounded scope test

Recreate the repaired fixture on the build box after the
[2026-09-28 cleanup](CLEANUP-20260928.md). Choose unused output names.
The build driver runs pinned verification, interpreter/JIT checks, exit admission,
packaged binding and monitor signing. It does not rebuild TMM.

```sh
python3 /home/starin/eob-config-20260925/request_scope_build.py \
  --output /home/starin/eob-config-20260925/scope-build-next
python3 /home/starin/eob-config-20260925/config_live_run.py \
  --run scope-live-next --suite request-scope \
  --project eob-template-20260925 --artifact-dir scope-build-next \
  --output /home/starin/eob-config-20260925/scope-live-next.json
```

The checked implementation is [`request_scope_suite.py`](request_scope_suite.py)
and [`request_scope.bpf.c`](../../substrate/surfaces/request_scope.bpf.c).
The current snapshot driver collects the original `scope-build-01` receipt;
retain a new build receipt separately when repeating the build.

## First result — `attribution-01`

**MEASURED, SELF witness:** 23 expected outcomes through isolated TMM, with exact client/server
attempt and body-hash reconciliation. Fifteen requests used one backend TCP connection; the
remaining eight interleaved across two additional connections, four from each identity.

| Case | Observed |
|---|---|
| A/B alternate while reusing identical caller operation/session/task/JSON-RPC IDs | Accepted operations retain the expected actor on the shared connection |
| A's valid proof with a claimed B identity | Accepted as A; claim mismatch flagged |
| A's key used with B's credential selector | HTTP 401; actor unknown |
| Exact request-proof replay | HTTP 403; no second accepted operation |
| Fresh-nonce retry using the same caller operation ID | Accepted with a new server operation ID |
| A delegates its accepted task to B, scoped to `tools/call` | B remains executing actor; A remains originator; parent is A's server-issued operation |
| Wrong grant recipient, out-of-scope method, modified grant, foreign parent | HTTP 403 for each; no accepted operation |
| Concurrent A/B requests with colliding caller labels | Eight accepted with the expected actor |

Total: **17 accepted operations, six intended rejections**. Accepted operations include the
grant issuance itself; these are synthetic operations, not execution of real tools or agents.
The two identities are independently keyed accounts in one fixture process, not isolated agent
processes. The `actor` retained on a rejected replay identifies the original proof's verified key;
it does not identify the process/person who replayed it. The ledger's `accepted` and `reason` fields
must accompany that value. Grant expiry is implemented but was not exercised by these 23 attempts.
HTTP/2 multiplexing, missing-evidence joins, native protocol persistence and TMM pointer reuse are
still separate cases. The configured principal map is not end-user authentication evidence.

**Runtime:** VIP `10.203.72.50:18092` forwards to `10.203.72.11:18092`; all origin peers are
TMM self-IP `10.203.72.10`. Executing `/proc/6/exe` hashes to
`a4b9e777a1daccd8c2b8c7f1aa7eba920b6040253f45f017605ea0a5f0a8afd7`, identical to the packaged
ELF with full build ID `c3b81927dfdcc31137cd8212b5e23bb85677a06c`. No eBPF was attached for this run.

[Registered receipts](../../SOURCES.md#agent-attribution-fixture-2026-09-25) include source hashes,
configuration ACKs, complete client/authentication ledgers, Tao XML and checks. Black passes and
pylint rates the four fixture/check modules 10/10 in the pinned image. The result checker rejects
both retained failed ICAP runs and accepts the successful ICAP and attribution runs. Runtime
inventory initially omitted the executable name, then swallowed missing-`readelf` errors; both
receipts are retained alongside the corrected process/hash/reference-ELF snapshot. These recorder
corrections did not rerun or change the attribution test receipts.

## Repeat the destination baseline

The [inspection record](INSPECTION.md) describes the isolated SSA/Tao environment. The current
build-box root is `/home/starin/eob-dlp-20260924`, mounted read-only as `/work` in the test container.
Keep these files together: `attribution.py`, `attribution_suite.py`, `icap_suite.py`, `icap_gate.py`,
`icap_check_result.py`, `icap-run-suite.sh`. Recreate this fixture first: its Compose
containers were removed in the [2026-09-28 cleanup](CLEANUP-20260928.md).

On the build box, choose an unused run name:

```sh
docker exec eob-dlp-20260924-fixture-1 \
  bash /work/icap-run-suite.sh attribution-repeat-01 attribution
```

This reconfigures only the isolated SSA listener and creates `/evidence/attribution-repeat-01/`.
The wrapper retains the runner's exit code separately, then requires successful JSON **and** XML
reports. Missing, malformed, failed or skipped reports produce a nonzero checked result. Do not
infer a pass from the unvalidated `tao_runner` exit code.

From the repository root on the control machine, archive to a new filename:

```sh
python3 env/ai-traffic/icap_snapshot.py \
  --output evidence/cache/ai-attribution-repeat-new.json
```

The collector preserves every earlier attempt and the ICAP build receipt; it refuses to overwrite
an existing output. Register the new hash in `SOURCES.md` and `evidence/cache/MANIFEST.sha256`.
