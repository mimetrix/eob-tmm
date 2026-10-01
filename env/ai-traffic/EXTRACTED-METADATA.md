# Extracted application metadata

**MEASURED — saved live TMM runs.** These are actual probe
values from authored fixture requests. They are not production agent data.
Values below are decoded from the captured ring payloads. The exporter
checks them against the saved records before displaying them.

The latest [boundary result](JSON-LIFECYCLE.md) adds 306 entry records from
13 exchanges. Use `python3 env/ai-traffic/json_lifecycle_verify.py --export` to
check and display them. Eleven unavailable-context records invalidate the full
consumer window. Storage tags have no qualified lifecycle or request meaning.

The [combined ID/side result](ID-FLOW.md) adds 88 records from 44 exchanges.
It includes exact ID bytes and an independent flow-side status in each record.
Use `python3 env/ai-traffic/id_flow_verify.py --export` to check and display them.
Flow side does not establish message role, common lifetime or request association.

## Earlier getter values

Field: `root_object.method`. Values use JSON notation. Escapes in the
application's string are preserved; the exporter does not expand them.

| Sequence | Extracted value (JSON notation) | Status | Original bytes | Copied bytes | Getter result |
|---|---|---|---|---|---|
| 1 | `"SendMessage"` | complete | 11 | 11 | 0 |
| 2 | `"future.variant"` | complete | 14 | 14 | 0 |
| 3 | `""` | complete | 0 | 0 | 0 |
| 4 | `"future\\u002evariant"` | complete | 19 | 19 | 0 |
| 5 | `"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"` | complete | 64 | 64 | 0 |
| 6 | `"yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"` | truncated | 65 | 64 | 0 |
| 7 | — | getter_error | unknown | 0 | 29 |
| 8 | — | budget_exhausted | unknown | 0 | 0 |

An empty string with complete status is a captured value. An error or
budget-exhausted record has no extracted value; it does not establish absence.
The truncated record contains only the displayed prefix.

## Inputs without a field observation

These labels come from the isolated fixture, not from probe field extraction.

- `nested` (configured filter: `a2a`): no getter record.
- `mcp-not-consumed` (configured filter: `aimcp`): no getter record.

These cases have no extracted field value in the getter run. The later token-cache
run below observes the AIMCP method through a different hook.

## Source and record context

- Receipt: `evidence/cache/method-live-01-20260928.json`.
- Receipt SHA-256: `99a55f596c65f6450ba58881db0fea67accc9de5ddf35605746445b9253d8c9f`.
- TMM build ID: `ca69b84f4f5c9e225813b2ed3997c59f18ba2a31`.
- Hook: `fexit/tmm_json_value_get_string`.
- Program SHA-256: `fbea388dd50f97205610451fb63bf230775d047febf6d244c6a41296a3b5aa33`.
- Value witness: SELF. See the evidence index for the separate kernel witnesses.

The JSON export also retains each complete probe record: instance, config
revision, run token, monotonic timestamp, sequence, return code, read counts
and output-health fields. No object addresses are exported.

## Reproduce the export

From the repository root:

```sh
python3 env/ai-traffic/metadata_export.py
python3 env/ai-traffic/metadata_export.py --format markdown
```

Both commands read the saved receipt. They do not load a probe or send traffic.
The first command emits JSON, including exact hexadecimal value bytes.

[Field scope and limits](METADATA.md#7-field-result--measured-on-the-pinned-build)
· [Evidence index](../../SOURCES.md#root-object-method-extraction-2026-09-28)

## Later token-cache values on the AIMCP/JSON path

The completion-hook probe observes the existing JSON tokens. It does not depend on
an application getter call. The following rows come from the captured payloads in
`token-method-live-02.json`. Values use JSON notation, as in the earlier table.

| Sequence | Extracted value (JSON notation) | Status | Original / copied bytes |
|---|---|---|---|
| 1 | `"tools/list"` | complete | 10 / 10 |
| 3 | `"future.variant"` | complete | 14 / 14 |
| 5 | `""` | complete | 0 / 0 |
| 7 | `"future\\u002evariant"` | complete | 19 / 19 |
| 9 | 64 `x` bytes | complete | 64 / 64 |
| 11 | 64 `y` bytes | truncated | 65 / 64 |
| 13 | — | nonstring | unknown / 0 |
| 15 | — | budget_exhausted | unknown / 0 |
| 17 | — | no_literal_method | unknown / 0 |
| 19 | `"tools/list"` | complete | 10 / 10 |
| 21 | — | no_literal_method | unknown / 0 |
| 23 | `"first"` | complete | 5 / 5 |
| 25 | — | out_of_scope | unknown / 0 |

Even sequences 2–26 are the 13 response-cache records, all `no_literal_method`.
The input cases include a nested-only method, an escaped key and duplicate keys.
See the [case table](TOKEN-METHOD.md#exact-live-values) for their exact scope.
These are cache observations, not proven request identities or protocol outcomes.

- Receipt SHA-256: `dcd59034a8278644bd4259e02018e5a82765131b71b55b66f7bc5580a19ef963`.
- TMM build ID: `ca69b84f4f5c9e225813b2ed3997c59f18ba2a31`.
- Hook: `fentry/json_filter_handle_json_complete`.
- Value witness: SELF; verifier witness: INDEPENDENT (PREVAIL);
  hook/process witness: KERNEL.

To check and export all 26 captured records, including exact hexadecimal bytes:

```sh
python3 env/ai-traffic/token_method_verify.py --export
```

The saved journal contains 28 events. It retains the new schema as raw records;
the consumer decoder supplies the fields above. The test fixture has been removed.
[Contract and limits](TOKEN-METHOD.md)
· [Evidence index](../../SOURCES.md#token-cache-method-extraction-2026-09-28).

## Saved session headers and selected routes

**MEASURED, 2026-09-29.** The session/routing run supplies five saved request-header
observations and seven selected-route observations. The header is the saved wire
value before decryption. It is not an authenticated identity.

| Session sequence | Exact value | Status | Original / copied bytes |
|---|---|---|---|
| 1 | `fixture-session-01` | complete | 18 / 18 |
| 2 | `future.session:v7+alpha` | complete | 23 / 23 |
| 3 | 64 `x` bytes | complete | 64 / 64 |
| 4 | 64 `y` bytes | truncated | 65 / 64 |
| 5 | `case-sensitive-VALUE` | complete | 20 / 20 |

All seven routing records contain complete pool name
`771b9376-bc0e-11f1-8e62-ee28e6388f84` and selected endpoint
`10.203.76.11:18095`, route domain 0. These fields match the acknowledged fixture
configuration. Each program has its own instance and sequence. Sequence numbers
do not associate session observations with routing observations.

The missing-header and unrelated-header cases have no session-hook invocation.
This is a fixture result, not a general rule for absent records.

- Receipt: `evidence/cache/session-routing-live-04.json`.
- Receipt SHA-256: `440d7232b497fef22d99937be1d87ee5b1b30579b32ff07caef60f1df87cf6b6`.
- TMM build ID: `ca69b84f4f5c9e225813b2ed3997c59f18ba2a31`.
- Session hook: `fentry/aimcp_decrypt_and_parse_sessionid.constprop.0`.
- Routing hook: `fentry/hud_aimcp_add_persist.isra.0`.
- Value witness: SELF. PREVAIL is INDEPENDENT; hook/process checks are KERNEL.

Export all 12 captured records with exact hexadecimal bytes:

```sh
python3 env/ai-traffic/session_routing_verify.py --export
```

The final journal retains 14 earlier events plus these 12 new records. The fixture
has been removed. [Contract, failed attempts and proposed consumer uses](SESSION-ROUTING.md)
· [Evidence index](../../SOURCES.md#session-and-routing-qualification-2026-09-29).

## HTTP status and local transfer completion

**MEASURED, 2026-09-29.** Nine response cases produce 201 handler records,
including 18 status observations and 18 done observations. Status values are
200, 204, 404, 503 and 777. Each case has two observations of each field at the
selected handler. The interrupted body has HTTP 200 and `transfer_complete=0`.
All other cases have done one, including HTTP 404 and 503. Transfer completion
does not imply remote-operation success.

The paced case supplies status before body release, with no done observation at
that point. The 165 other handler records mark both fields not applicable.
Fixture case labels are not exported request identifiers.

- Receipt: `evidence/cache/response-metadata-live-02.json`.
- SHA-256: `7d891d65dc52e690d34ff31d7ddc638f8c6ed1b1472509dfca08d8f432aa110a`.
- Hook: `fentry/hud_aimcp_handler`, build `ca69b84f4f5c9e225813b2ed3997c59f18ba2a31`.
- Value witness: SELF; PREVAIL is INDEPENDENT; hook/process checks are KERNEL.

```sh
python3 env/ai-traffic/response_metadata_verify.py --export
```

The journal retains 23 earlier events and all 201 new records. Both live attempts
are archived, and the fixture is removed. [Exact cases, schema and limits](RESPONSE-METADATA.md)
· [Evidence index](../../SOURCES.md#response-metadata-qualification-2026-09-29).

## Requested tools and resources

**MEASURED, 2026-09-29.** The next probe reads the tool or resource named by the
request. Examples are tool `inventory.lookup` and resource
`file:///inventory/items`. The 28-case run produces 56 records: 14 complete
targets, two truncated targets, 12 explicit request exclusions and 28 response
records without a literal method.

Both target kinds preserve unfamiliar and empty values, raw escaped text and
exact 64-byte strings. A 65-byte value keeps 64 bytes with a truncation status.
Nested `arguments.name` does not become the tool name. Literal duplicate keys
select the first value. These are requested targets, not caller identities or
proof of authorized access.

```sh
python3 env/ai-traffic/operation_target_verify.py --export
```

Receipt `evidence/cache/operation-target-live-01.json`, SHA-256
`97d61b045175d1ab71dff708e8e5efc21ba1d74ac9232312c6d64e6daa661a81`.
The 58-event journal and seven-file archive are checked; the fixture is removed.
[Contract and exact cases](OPERATION-TARGET.md)
· [Evidence index](../../SOURCES.md#requested-operation-targets-2026-09-29).

## Reported reply fields — 2026-09-29

**MEASURED, bounded fixture; value witness SELF.** Thirty-eight exchanges yield
76 observations. Exact error codes include `-32601`, `0`, `7654321`,
`-2147483648` and `2147483647`. Tool-error reports preserve Boolean `true` and
`false`. A missing `isError` field stays unavailable. Nested decoys, duplicate
fields, conflicting root fields, type errors and limits produce explicit states.

These are message reports, not proof of successful tool execution or caller
identity. All HTTP responses in this fixture are 200, including reported errors.

```sh
python3 env/ai-traffic/reply_metadata_verify.py --export
```

Receipt `evidence/cache/reply-metadata-live-03.json`, SHA-256
`955af1f0a649a9e0311c38e133b7508f9d290ec4dfe91c0391d67e3505bb1e18`.
[Contract and limits](REPLY-METADATA.md)
· [Evidence index](../../SOURCES.md#reported-reply-fields-2026-09-29).

## Observed message IDs — 2026-09-29

**MEASURED, bounded fixture; value witness SELF.** Thirty-five exchanges yield
70 observations. Numeric `1` and string `"1"` share the value byte `31`, but retain
different types. `9007199254740993`, `-0`, `0.125`, `1e+3` and `-2.5E-30` retain
their exact numeric spelling. Explicit `null` and an empty string remain distinct
from missing IDs. Duplicate, wrong-type, truncated and limited IDs have explicit
states. Reused and mismatched IDs remain observations, not request/caller matches.

```sh
python3 env/ai-traffic/message_id_verify.py --export
```

Receipt `evidence/cache/message-id-live-01.json`, SHA-256
`94439d801e899c64ca21a173920e4b35b50ec7ea73dcef164647d503968024e3`.
[Contract and limits](MESSAGE-ID.md)
· [Evidence index](../../SOURCES.md#observed-message-ids-2026-09-29).
