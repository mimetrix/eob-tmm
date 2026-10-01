# Requested tool and resource metadata

**2026-09-29 — MEASURED in the bounded one-worker fixture.** The probe now records
which tool or resource a request names. It extracts literal `params.name` for
`tools/call`, and `params.uri` for `resources/read`, from the existing JSON cache.
The contract was registered as IDEA before implementation.

This adds the requested activity to a future identity profile. It does not
identify the caller. A trusted identity source and a reliable link to each
observation are separate requirements.

## Measured result

The pinned build passes PREVAIL with a 256-byte stack limit and 74 native
interpreter/JIT invocations. Live attempt 01 passes 28 cases and produces 56
records: one request-cache and one response-cache observation per fixture case.
The response records have `no_literal_method`; they are retained.

| Request observation | Count | What was checked |
|---|---|---|
| Complete target bytes | 14 | Both target kinds; known, unfamiliar, escaped and empty values; exact 64-byte values; reordered members, nested decoys and first literal duplicates |
| Truncated target bytes | 2 | 65-byte tool/resource values retain 64 bytes and the original length |
| No literal target | 4 | Nested-only name, missing params, missing target and escaped key |
| Unsupported method | 3 | First duplicate method, escaped method and unfamiliar method |
| Nonstring target | 1 | Numeric tool name |
| Out of scope | 2 | Array params and root array |
| Budget exhausted | 2 | Relevant root or params member after the fourth direct member |

Exact values include tool name `inventory.lookup` and resource address
`file:///inventory/items`. `future\\u002etarget` remains raw escaped text; the probe
does not turn it into `future.target`. Nested `arguments.name` does not replace
the direct `params.name`. Duplicate selection follows this probe's explicit rule,
not a claim about a remote server's interpretation.

The final journal contains 58 events, including all 56 records. Replay agrees with
the captured records; no retries, drops, output failures or observation gaps are
reported. Native tests also check corrupt tokens, invalid source flags, fragment
limits, unreadable memory, a guarded partial read and unchanged input.

The live maximum is 37 application-memory reads and 695 source bytes per
invocation. Registered limits remain 96 reads, 4,096 source bytes, four direct
members per lookup, four fragments per selected byte read and 64 target bytes.
Each invocation attempts one 144-byte record. These are bounds and observed read
counts, not measurements of execution time or per-packet cost.

The hook is `fentry/json_filter_handle_json_complete`, patch address `0xd93540`,
on build `ca69b84f4f5c9e225813b2ed3997c59f18ba2a31`. Process identity stays stable,
and kernel reads show the armed call and restored five NOP bytes. Cleanup checks
all 12 slots inactive, verifies the seven-file archive, and removes the isolated
containers, networks and volumes. Other Docker identities and state are unchanged.

**Witnesses:** SELF for authored traffic, values, counters and journal comparisons;
INDEPENDENT for PREVAIL; KERNEL for hook bytes and process identity; TOOL for
source and container inspection. [Receipts and checksums](../../SOURCES.md#requested-operation-targets-2026-09-29).

## Field contract

- Match literal root `method` values and literal root `params` keys. Require an
  object for `params`. Select only its direct `name` or `uri` member.
- Preserve raw JSON string bytes. Do not decode escapes or normalize URIs.
  Use the first literal duplicate key. This selection rule does not establish
  how a remote server resolves duplicate keys.
- Export a target kind, field status, original length and at most 64 target
  bytes. Do not export other parameter values. A named target is a requested
  target, not proof of authorization, access or operation success.
- Bound each lookup to four direct members and each byte read to four fragments.
  Register a total limit of 96 reads and 4,096 source bytes per invocation.
  Emit at most one 144-byte record. TMM must not wait for the collector.
- Preserve missing, unsupported, nonstring, unreadable, invalid-cache and budget
  outcomes. Clear partial bytes on failure. No application accessor calls or
  application-memory writes. Give the state map a private name.
- This is a JSON-cache observation, not authenticated MCP protocol identity or
  request association. Retain response/no-method observations with explicit status.

## Qualification and falsifiers

Use the pinned build-box source, debug layout and compiled completion path from
the [token-cache method gate](TOKEN-METHOD.md). Recheck them before a live claim.
Confirm how object size, value siblings and nested tokens delimit direct members.

Native and live cases must include both target kinds, unfamiliar/escaped/empty
values, 64/65-byte lengths, method/params ordering, nested decoys, duplicate keys,
missing keys, wrong types, unsupported methods and exhausted member budgets.
Native checks also cover bad bounds, unreadable/guarded memory, fragment limits,
output refusal and unchanged input. Live checks compare exact bytes, configuration
ACKs, counters, journal/replay, stable process and restored hook bytes. Save all
attempts and remove the isolated fixture after checked evidence is archived.

**Falsifiers:** a nested decoy becomes the target; unrelated argument bytes escape;
stale or partial bytes are marked complete; unsupported syntax gets a guessed
target; a bound is exceeded without explicit status; or a requested target is
reported as authorized or successfully accessed.

## Where the work runs

```text
BUILD BOX: source + debug + compiled path -> bounded program -> verify/sign
TMM: qualified JSON-cache invocation -> selected target/status -> one ring record
COLLECTOR: ring -> acknowledged journal -> cursor replay
CONSUMER: raw record -> exact target bytes and explicit limits
```

Identity profiles and blast-radius assessment remain proposed consumers. They
also need qualified identity, authority and resource relationships. The subsequent
[reply-field gate](REPLY-METADATA.md) now extracts result/error presence, integer
error codes and Boolean tool-error reports. These are reported fields, not proof
of successful access or a reliable request/identity association.

## Verify or reproduce

The [ABI](../../substrate/surfaces/operation_target_abi.h) uses magic `0x4f544754`,
version 1 and the 144-byte layout `<II6Q4IHHI64s>`. The shared C event word named
`getter_result` carries `target_kind` in this schema: zero unknown, one tool name,
two resource URI. The [decoder](operation_target_decode.py) checks field status,
lengths, zero padding and read bounds. Values are raw JSON string bytes.
Instance/revision/run identify the observation source. They do not identify a
request, session or authenticated actor. The collector stores raw records; the
consumer decodes them.

Verify the saved result without sending more traffic. Add `--export` to include
all 56 decoded observations:

```sh
python3 env/ai-traffic/operation_target_verify.py
python3 env/ai-traffic/operation_target_verify.py --export
```

For a new live run, use the prepared build box, pinned toolchain and existing
collector image from the [response procedure](RESPONSE-METADATA.md#decode-and-reproduce).
Stage the new scripts beside the existing fixture scripts and the C files under
the staged substrate. Use fresh names for each run and receipt. The discovery
wrapper retains the reused token-path discovery in a separate `-base.json` file.
No TMM rebuild is needed.

```sh
ROOT=/home/starin/eob-config-20260925
IMAGE=sha256:26f3184a4e3fe96b61f780761497933facc385f3d62d6f1cf66f04e56abd5054
python3 "$ROOT/operation_target_discover.py" --output "$ROOT/operation-target-discovery-NEXT.json"
python3 "$ROOT/operation_target_build.py" \
  --discovery "$ROOT/operation-target-discovery-NEXT.json" --output "$ROOT/operation-target-build-NEXT"
mkdir "$ROOT/operation-target-source-NEXT"
python3 "$ROOT/lifetime_fixture.py" create --collector-image "$IMAGE" \
  --collector-source "$ROOT/operation-target-source-NEXT" --output "$ROOT/operation-target-create-NEXT.json"
python3 "$ROOT/operation_target_live.py" --run operation-target-live-NEXT \
  --artifact-dir operation-target-build-NEXT --image-build "$ROOT/collector-image-02/image-build.json" \
  --source-dir "$ROOT/operation-target-source-NEXT" --output "$ROOT/operation-target-live-NEXT.json"
python3 "$ROOT/lifetime_fixture.py" archive-cleanup --collector-image "$IMAGE" \
  --collector-source "$ROOT/operation-target-source-NEXT" --live "$ROOT/operation-target-live-NEXT.json" \
  --output "$ROOT/operation-target-cleanup-NEXT.json" --archive "$ROOT/operation-target-evidence-NEXT.tar.gz"
```

**Remaining limits:** literal keys and method values only; bounded JSON-cache
coverage; no decoded-URI normalization, general MCP validation, request identity,
authorization decision, remote-operation result or measured data-path cost.
