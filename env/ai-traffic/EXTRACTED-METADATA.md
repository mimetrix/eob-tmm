# Extracted application metadata

**MEASURED — saved live TMM runs.** These are actual probe
values from authored fixture requests. They are not production agent data.
Values below are decoded from the captured ring payloads. The exporter
checks them against the saved records before displaying them.

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
