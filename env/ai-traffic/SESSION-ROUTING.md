# Session and routing metadata extraction

**2026-09-29 — MEASURED in the isolated AIMCP fixture.** Loaded programs now
extract saved request-session-header bytes and selected pool/endpoint state.
Seven requests produced five session records and seven routing records through
the existing separate collector. Existing TMM function bodies were not changed.

**Initial native gate — MEASURED.** Build 01 passes pinned PREVAIL
with the 256-byte stack limit. Interpreter/JIT tests produce 34 session and
38 routing records with exact-value, bounds, invalid-memory and output-refusal
checks. These are authored fixtures, not live field observations.
[Sources and build receipt](../../SOURCES.md#session-and-routing-qualification-2026-09-29).

**Failed first live gate, retained:** both programs declared `metadata_state`.
The map registry shares storage for the same name and shape. Each program then
reset the other's instance-specific sequence. Separate single-program tests did
not cover this interaction. Build 02 uses distinct state-map names and adds eight
interleaved invocations in addition to the 72 individual checks. Both programs
pass pinned verification. Live attempt 04 passes with those programs.

Attempt 02 stopped before loading because the collector retained earlier records.
The test now saves a pre-arm replay cursor and checks new instance identities.
Attempt 03 stopped on a replay JSON error after partial exact-value comparisons.
Its HTTP status was not captured. The new test client records HTTP failures before
JSON decoding and retries only HTTP 503, at the same cursor, at most four times.
Attempt 04 required no retries. The collector image is unchanged.

## Exact live result

These are authored fixture inputs, not production identity observations. Values
come from captured record bytes. Interval labels are test boundaries, not exported
request identities.

| Input | Saved session-header result |
|---|---|
| No session header | No session-hook invocation |
| `fixture-session-01` | Exact 18 bytes, complete |
| `future.session:v7+alpha`, fragmented delivery | Exact 23 bytes, complete |
| 64 `x` bytes | 64/64 bytes, complete |
| 65 `y` bytes | 65/64 bytes, explicitly truncated |
| Mixed-case header name, `case-sensitive-VALUE` | Exact 20 value bytes, complete |
| Only `X-Other-Header: must-not-export` | No session-hook invocation |

Each interval also supplies a routing record with:

- Pool name: `771b9376-bc0e-11f1-8e62-ee28e6388f84`, all 36 bytes.
- Selected endpoint: `10.203.76.11:18095`, route domain 0.
- Complete status for both pool name and endpoint.

The pool value matches the acknowledged configuration input. The endpoint matches
the configured fixture backend. The records describe selected pool-member state
at the AIMCP response hook. They do not describe every possible destination.

Build 02 passes pinned PREVAIL at a 256-byte stack limit. Its 80 native
interpreter/JIT invocations include eight interleaved calls with both programs
loaded. All 12 new live records reach the replay reader with exact counters.
The final journal contains 26 events: 14 retained before this run and 12 new
records. Its integrity and replay checks pass. No reported gaps, health drops,
output failures or new VM errors occurred in the checked run.

Kernel checks show stable process/binary identity, one arm per hook and restored
bytes. Cleanup checked all 12 inactive slots, saved a 30-file archive and removed
the fixture containers, networks and volumes. Other Docker identities and state
stayed unchanged. Values/comparisons are SELF evidence. PREVAIL is INDEPENDENT;
process and hook checks are KERNEL evidence.

The maximum live counts were 43 source reads and 97 source bytes per invocation.
These counts do not measure data-path cost. Empty values, long pool names and
unreadable memory have native tests, not live coverage. Stream-flow storage and
successful encrypted persistence decoding remain outside this measured subset.

## Where the work runs

```text
BUILD BOX — off the data path
  source + debug layout + compiled calls
    -> bounded programs -> PREVAIL + native tests -> signed targets

TMM — data path, existing ca69b84f… binary
  session decode entry -> saved header descriptor -> bounded header bytes
  persistence response entry -> current peer/pool member -> pool + endpoint
    -> one 168-byte record attempt per invocation -> output ring

SEPARATE COLLECTOR — existing image, outside TMM
  acknowledged ring reader -> retained SQLite journal -> Unix-socket replay

CONSUMER — outside TMM
  raw record -> decoder -> exact field bytes, representation and status
  later: qualified identity profiles and blast-radius assessment
```

The collector stores the new schema as raw bytes. The
[decoder](session_routing_decode.py) supplies its field meanings. The record uses
magic `0x53524d45`, ABI 1, per-program instance/sequence and separate string/endpoint
status. The session field contains saved header bytes before decryption. The pool
name is a bounded zero-terminated string; the endpoint excludes native padding.
Shared PID namespace, `SYS_PTRACE` and unconfined AppArmor retain the
[collector's security limits](COLLECTOR-CONTAINER.md).

## Verify or reproduce

From the repository root, check the saved receipts and export captured values:

```sh
python3 env/ai-traffic/session_routing_verify.py
python3 env/ai-traffic/session_routing_verify.py --export
```

The separate offline [replay-client check](check_session_routing_client.py) tests
HTTP status handling, cursor preservation and bounded error messages:

```sh
python3 env/ai-traffic/check_session_routing_client.py
```

Reproduction needs the prepared build box and pinned tools in
[METADATA.md](METADATA.md). Stage the new scripts, ABI, program and two native
checks at the paths in the receipts. Use unused names in place of `NEXT`:

```sh
ROOT=/home/starin/eob-config-20260925
python3 "$ROOT/session_routing_discover.py" --output "$ROOT/session-routing-discovery-NEXT.json"
python3 "$ROOT/session_routing_build.py" \
  --discovery "$ROOT/session-routing-discovery-NEXT.json" --output "$ROOT/session-routing-build-NEXT"
IMAGE=sha256:26f3184a4e3fe96b61f780761497933facc385f3d62d6f1cf66f04e56abd5054
mkdir "$ROOT/session-routing-source-NEXT"
python3 "$ROOT/lifetime_fixture.py" create --collector-image "$IMAGE" \
  --collector-source "$ROOT/session-routing-source-NEXT" --output "$ROOT/session-routing-create-NEXT.json"
python3 "$ROOT/session_routing_live.py" --run session-routing-live-NEXT \
  --artifact-dir session-routing-build-NEXT --image-build "$ROOT/collector-image-02/image-build.json" \
  --source-dir "$ROOT/session-routing-source-NEXT" --output "$ROOT/session-routing-live-NEXT.json"
python3 "$ROOT/lifetime_fixture.py" archive-cleanup --collector-image "$IMAGE" \
  --collector-source "$ROOT/session-routing-source-NEXT" --live "$ROOT/session-routing-live-NEXT.json" \
  --output "$ROOT/session-routing-cleanup-NEXT.json" --archive "$ROOT/session-routing-evidence-NEXT.tar.gz"
```

The session entry is `0xbbcf40`; the route entry is `0xbbca80`. Both use pad
offset zero on build `ca69b84f4f5c9e225813b2ed3997c59f18ba2a31`. Requalify types,
storage variants and compiled calls for a different binary.

## Consumer goals: identity profiles and blast radius

**IDEA, owner direction 2026-09-29.** Use extracted metadata to build identity
profiles and assess blast radius. Blast radius means the resources and operations
that a compromised identity could affect. A measured traffic path is one input
to that assessment, not its complete boundary.

The field register must distinguish these inputs:

| Input | Proposed use | Required evidence |
|---|---|---|
| Identity claim, issuer and tenant | Group activity under a qualified identity | Claim source and authentication result. A header alone is an unverified claim. |
| Granted authority and delegation | Describe permitted resources and operations | Policy version, decision, scope and expiry from the authority that made the decision |
| Session metadata | Describe observed session activity | Field representation, observation phase and qualified lifetime. Do not infer an identity from a session value. |
| Message ID | Input to request/reply association | [Bounded type and raw bytes are measured](MESSAGE-ID.md). The [combined gate](ID-FLOW.md) also measures flow side in the same record. [Local lifecycle](JSON-LIFECYCLE.md), ID equality and a common connection/session lifetime remain to be qualified. An ID is not authenticated caller identity. |
| Selected pool and endpoint | Record destinations used by the data plane | Selection-state observation and process/worker scope |
| Resource and operation metadata | Describe observed resource use | Bounded extraction and protocol-specific meaning. A method name alone does not identify a resource. |
| Shared destinations and dependencies | Find possible common impact | Qualified relationships with time bounds and explicit gaps |

A consumer must keep observed activity, policy-permitted reach and inferred
relationships separate. Each result needs source provenance, observation time,
evidence tier and unresolved gaps. Missing traffic does not establish that an
identity cannot reach a resource. Authentication, policy and delegation sources
remain to be qualified; the current session/routing gate supplies only its named
fields. Never export credential contents as an identity-profile field.

## Registered contract

Qualify the observed `Mcp-Session-Id` header and the parsed session, pool and
endpoint fields. Check source, debug layouts and compiled calls on the pinned
build before selecting a hook. Compiler clones require their actual argument
layout. A hook-index entry alone does not establish call-path coverage.

Keep these meanings separate:

- Header bytes are an observed value, not authenticated identity.
- Successfully decoded persistence fields describe the supplied routing value.
  They do not prove that TMM selected that destination.
- A selected pool member needs a separate observation of the selection state.
  A response does not by itself prove completion of an MCP operation.

Export only qualified metadata fields. Do not export keys, passphrases, temporary
decryption buffers, unrelated headers or object addresses. Each invocation must
attempt at most one bounded record through the existing collector. Set fixed
field, read and output limits before building the probe. Keep field status and
representation with the value. A failed decode must not expose stale parsed data.

## Falsifiers and checks

Reject the candidate if any of these occur:

- A failed decode supplies parsed values, or an old value is marked current.
- A non-session header or unrelated memory is exported.
- A field exceeds its limit without an explicit status.
- The probe changes application memory or calls an application accessor.
- Pinned PREVAIL verification fails, or native/live bytes differ from the input.
- A parsed destination is presented as a selected destination.

Native checks must cover valid, missing, failed, truncated and unreadable values,
unchanged input and output refusal. Live checks must compare exact field bytes
through the collector and check process identity, hook restoration and reported
loss. Save receipts before removing the isolated fixture.

General protocol coverage, authenticated identity, request association and
data-path cost remain open. Sources require the external TMM build tree and the
prepared fixture described in [METADATA.md](METADATA.md).

## First bounded candidates

**IDEA, registered before building.** Observe the saved request-header bytes at
entry to `aimcp_decrypt_and_parse_sessionid.constprop.0`. The candidate reads
`saved_sid` after the caller copies the header. It does not interpret these bytes
as successfully decoded persistence fields. Qualify the inline HUD node context
before reading its saved descriptor. Missing headers may cause no invocation.

At entry to `hud_aimcp_add_persist.isra.0`, qualify the current client flow and
its peer, then read the selected pool member's pool name and endpoint. Support
the connection-flow storage form first. Report stream-flow pointers as outside
this candidate's scope. Do not infer a relationship with another record.

Limits: 64 session or pool-name bytes, 20 endpoint bytes, 80 source reads,
256 source bytes and one 168-byte record per invocation. Session length comes
from the saved descriptor. Scan a pool name for at most 65 bytes. If its length
exceeds 64, report an unknown total length and an explicitly truncated prefix.
Do not copy native structure padding into the endpoint field.

The first live gate uses the existing non-encrypting fixture. It checks observed
request-header bytes and selected response-side routing state. Successfully
decoded persistence fields need their own later gate with configured encryption.
