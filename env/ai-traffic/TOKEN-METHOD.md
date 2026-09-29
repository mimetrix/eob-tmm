# Method extraction from the JSON token cache

**2026-09-28 — MEASURED in the isolated AIMCP/JSON fixture.** The probe now
extracts `tools/list` as the exact 10 bytes from TMM's existing JSON tokens.
Thirteen requests produced 26 cache records through the separate collector.
The original getter remains limited to values the application requests.
[Receipts and checksums](../../SOURCES.md#token-cache-method-extraction-2026-09-28).

MCP means Model Context Protocol. AIMCP is the TMM filter name used in this
fixture. A JSON token identifies a parsed value and its position in the input.
The token cache keeps those tokens and the input buffers.

The getter probe did not extract `tools/list` on the AIMCP path. The existing
[source inventory](../../SOURCES.md#ai-protocol-source-inventory-2026-09-24)
describes session-header persistence. A getter observes only values that the
application requests. The initial candidate was `json_http_set_cache`: its JSON
argument supplies the existing token cache before attachment to an HTTP message.
The build-box qualification includes source, binary layout, call sites and admission.

## Registered test and limits

**First candidate withdrawn after live attempt 01:** `json_http_set_cache`
was armed and restored, but produced no records for the forwarded request.
The compiled completion path contains the opaque-table operations inline.
The function's padded entry does not cover that call path. The failed receipt
and first three builds remain part of the record.

The revised candidate is entry to `json_filter_handle_json_complete`. Read
`json_scb.json` only when the flags establish valid JSON and HTTP-message mode.
SSE-message mode and invalid parsing produce status-only records.
Read only a non-null, raw-valid cache
with a complete root object. Follow the tokenizer's same-level sibling links.
Check at most four root members. Match the literal six-byte key `method` and
copy at most 64 escaped value bytes. Do not call getters, parse the body again,
export other values, or change the cache. Each invocation attempts one record.

Use at most four buffer fragments for each selected key or value read, at most
40 application-memory reads and 1,024 source bytes per invocation. Report a
budget limit or read failure explicitly. A field beyond the member limit is
unknown. A key with escape sequences is outside the literal-key contract.
The probe selects the first matching member. Duplicate keys do not imply a unique
logical method. The probe observes caches, not request identity or protocol
identity. Cache attachment can fail after the entry observation.

**Falsifiers:** a nested or unrelated value is exported; a failed or partial read
leaves value bytes in an error record; traversal exceeds a bound; source memory
changes; the pinned verifier rejects the program; or live extracted bytes differ
from the authored method. No positive result follows from hook counts alone.

Native checks must cover exact, unfamiliar, empty, escaped, 64-byte and longer
values; multiple fragments; member and fragment limits; invalid token indices,
types and offsets; unreadable memory; root arrays; duplicate keys; and output
refusal. Live checks must cover the AIMCP method gap through the existing
collector, with exact values, reported loss, stable process identity and restored
hook bytes. The fixture must then be archived and removed.

This does not establish general MCP coverage, semantic decoding of escaped keys,
all-message coverage, multiworker behavior, or data-path cost. TMM's existing
function bodies remain unchanged.

## Exact live values

These values come from captured record bytes. The test labels identify isolated
input intervals. The probe does not emit request or protocol identity.

| Fixture case | Extracted value or status | Original / copied bytes |
|---|---|---|
| Known method | `tools/list` | 10 / 10 |
| Unfamiliar method, fragmented delivery | `future.variant` | 14 / 14 |
| Empty method | Empty string, complete | 0 / 0 |
| Escaped value | Literal `future\u002evariant`, escapes preserved | 19 / 19 |
| Length limit | 64 `x` bytes, complete | 64 / 64 |
| Longer value | 64 `y` bytes, explicitly truncated | 65 / 64 |
| Numeric method | `nonstring`, no value | — / 0 |
| Method in fifth root member | `budget_exhausted`, no value | — / 0 |
| Nested method only | `no_literal_method`, no value | — / 0 |
| Nested method plus root method | `tools/list`. The probe does not export nested `private`. | 10 / 10 |
| Escaped key `m\u0065thod` | `no_literal_method`, no value | — / 0 |
| Duplicate literal keys | `first`. First-match contract, no uniqueness result. | 5 / 5 |
| Root array | `out_of_scope`, no value | — / 0 |

Each interval also contains a response cache with `no_literal_method` status.
Thus, 26 records are cache observations, not 26 requests. The application filter
configuration includes JSON and AIMCP. This result does not establish extraction
when the JSON filter is absent. Successful cache completion does not prove that
all trailing body bytes were parsed or that the peer completed an MCP operation.

Build 04 passed clang-18/PREVAIL with the unchanged 256-byte stack limit. Its
68 interpreter/JIT test invocations include guarded memory, corrupted token
indices, backward/nested sibling links, multiple fragments, output refusal, and
checks that input memory did not change. These are authored SELF tests.

Live attempt 02 passed the fixture JSON and Tao XML checks. All 26 records reached
both logical replay readers through the same socket API. The saved SQLite journal
contains 28 events: source boundary, zero-drop health record and 26 probe records.
Its integrity check passes. The maximum recorded counts were 17 reads and
330 source bytes. The enforced limits are 40 reads and 1,024 bytes. These
counts are not a measurement of data-path cost.

Kernel checks show one arm, restored hook bytes and a stable TMM process/binary.
The 14-file archive retains both live attempts and their journals. Cleanup removed
the fixture, TMM and collector containers, plus their networks and volumes. Other
Docker container identities and state stayed unchanged.

## Where the work runs

```text
BUILD BOX — off the data path
  pinned source + debug types + compiled call path
    -> bounded probe -> PREVAIL + native checks -> signed program

TMM — data path, existing binary ca69b84f…
  JSON completion hook -> valid HTTP-mode check -> existing token/fragment reads
    -> literal root method or explicit status -> one bounded ring record

SEPARATE COLLECTOR — existing image, outside TMM
  acknowledged ring reader -> SQLite journal -> Unix-socket replay

CONSUMER — outside TMM
  raw record -> token_method_decode.py -> exact value and read status
```

The collector keeps the new record as raw bytes. Its built-in decoder recognizes
the previous getter schema. The consumer decodes the new schema.
The record is 144 bytes, magic `0x544d4554`, version 1. It carries program instance,
configuration revision, run token, time, sequence, output refusals, field status,
root-member count, lengths, flags, read counts and up to 64 value bytes. No object
addresses or other field values are exported. Shared PID namespace, `SYS_PTRACE`
and unconfined AppArmor retain the [collector's security limits](COLLECTOR-CONTAINER.md).

`root_members` is the member count in the root token, not the number of visited
members. A value of five can accompany `budget_exhausted`. The probe visits a
maximum of four members. Nonzero flags identify configuration, state-map,
sequence-saturation or clock errors. Consumers must keep these flags with the
field status. The [ABI header](../../substrate/surfaces/token_method_abi.h) and
[decoder](token_method_decode.py) specify the record layout and status codes.

## Verify or export the saved result

From the repository root:

```sh
python3 env/ai-traffic/token_method_verify.py
python3 env/ai-traffic/token_method_verify.py --export
```

The first command checks receipt/source hashes, native records, live comparisons,
replay equality, hook restoration and the archived SQLite journal. The second
also emits every decoded observation from captured bytes. Neither sends traffic.

## Reproduce on the prepared build box

The repo is not self-contained. Use the pinned package, verifier, compiler,
signing key and prepared SSA fixture described in [METADATA.md](METADATA.md).
Stage the new probe, ABI header, native check and Python files at the paths used
in the build receipts. Use an unused name in place of `NEXT` for each attempt.

```sh
ROOT=/home/starin/eob-config-20260925
python3 "$ROOT/token_method_discover.py" --output "$ROOT/token-method-discovery-NEXT.json"
python3 "$ROOT/token_method_build.py" \
  --discovery "$ROOT/token-method-discovery-NEXT.json" --output "$ROOT/token-method-build-NEXT"
IMAGE=sha256:26f3184a4e3fe96b61f780761497933facc385f3d62d6f1cf66f04e56abd5054
mkdir "$ROOT/token-method-source-NEXT"
python3 "$ROOT/lifetime_fixture.py" create --collector-image "$IMAGE" \
  --collector-source "$ROOT/token-method-source-NEXT" --output "$ROOT/token-method-create-NEXT.json"
python3 "$ROOT/token_method_live.py" --run token-method-live-NEXT \
  --artifact-dir token-method-build-NEXT --image-build "$ROOT/collector-image-02/image-build.json" \
  --source-dir "$ROOT/token-method-source-NEXT" --output "$ROOT/token-method-live-NEXT.json"
python3 "$ROOT/lifetime_fixture.py" archive-cleanup --collector-image "$IMAGE" \
  --collector-source "$ROOT/token-method-source-NEXT" --live "$ROOT/token-method-live-NEXT.json" \
  --output "$ROOT/token-method-cleanup-NEXT.json" --archive "$ROOT/token-method-evidence-NEXT.tar.gz"
```

The measured target is `fentry/json_filter_handle_json_complete`, entry/patch
`0xd93540`, with pad offset zero, on build
`ca69b84f4f5c9e225813b2ed3997c59f18ba2a31`. Requalify layouts and call paths for a
different binary. Session/routing fields, general protocol identity and production
coverage remain separate work.
