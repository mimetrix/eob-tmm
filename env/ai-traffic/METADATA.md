# Application-metadata probe

**2026-09-28 — MEASURED root-object method-value extraction in the native A2A
fixture, plus handler event-code extraction. The later [token-cache probe](TOKEN-METHOD.md)
also extracts `tools/list` on the AIMCP/JSON path. The subsequent
[session/routing probe](SESSION-ROUTING.md) extracts saved session-header bytes
and selected pool/endpoint state in a bounded fixture. The
[response probe](RESPONSE-METADATA.md) adds HTTP status and local transfer
completion, including paced and interrupted bodies. The
[requested-target probe](OPERATION-TARGET.md) adds literal tool names and resource
addresses. The [reply probe](REPLY-METADATA.md) adds result/error presence, error
codes and Boolean tool-error reports. These describe requested activity and
reported outcomes, not authenticated caller identity or proven remote success.
The [message-ID probe](MESSAGE-ID.md) preserves ID type and raw bytes as an input
to later request/reply association. The [combined ID/side probe](ID-FLOW.md) now
adds flow side in the same record. That association remains unqualified.**

[View the extracted values](EXTRACTED-METADATA.md) or run
`python3 env/ai-traffic/metadata_export.py` from the repo root for the JSON export.
The [production streaming contract](PRODUCTION-STREAM.md) defines the proposed
continuous collector, consumer interface and delivery limits.

The first live run emitted 192 records from 192 handler calls, across eight
requests. Each handler emitted 96 records containing 22 different event codes.
The records contain event codes, argument-presence bits and probe identity.
They do not contain method names or session values. These counts establish hook
reachability and output accounting, not the requested application-field extraction.
That limit led to the exact method-value test in §7, including an unfamiliar
value. [Event-probe receipts](../../SOURCES.md#native-handler-event-probes-2026-09-28).

The immediate goal is to extract metadata from the application as it runs.
Here the application is TMM and its protocol filters. These hooks do not observe
code running inside a remote agent. Preserve observations and unfamiliar values
so that later consumers can interpret them without changing the original record.

The first deliverable is a probe, its field manifest and a checked extraction
record. Agent identity, workflow reconstruction and representative usage tests
are later work. [COVERAGE.md](COVERAGE.md) retains the two planning corrections.

## 1. Which hooks?

### Existing live foundation

The [bounded HTTP/1 experiment](CORRELATION.md) used these four sites:

| Function | Phase | Existing extraction |
|---|---|---|
| `http_parse_ctx_init` | Entry | Observed parser-context initialization |
| `http_parse_headers` | Entry | Bounded fixture path and nonce from parser input |
| `http_parse_client_headers` | Exit | Return status, including partial and complete headers |
| `http_parse_ctx_fini` | Entry | Observed parser-context cleanup |

These are MEASURED in the stated fixture. They do not establish native AI-filter
metadata extraction. Keep parser intervals separate from requests and agents.

### Application-layer candidates checked against the package

[Discovery receipts](../../SOURCES.md#application-metadata-hook-discovery-2026-09-28)
contain the source, hook index, ELF build ID, binary hash and selected disassembly.
Build: `ca69b84f4f5c9e225813b2ed3997c59f18ba2a31`.
Addresses below are **patch addresses**, not necessarily function-entry addresses.

| Priority | Function in this package | Patch address | Observation and qualification |
|---|---|---|---|
| First | `hud_a2a_handler` | `0xa8fdc4` | Native filter event code and event-specific input metadata, before the handler selects a branch |
| First | `hud_aimcp_handler` | `0xbbd304` | Native filter event code; request, response and teardown input where type and lifetime are established |
| Next | `a2a_response` | `0xa8fb80` | Response/message input; stored method name and length; available result metadata |
| Next | `aimcp_decrypt_and_parse_sessionid.constprop.0` | `0xbbcf40` | Decode return status; session/pool/endpoint fields only after a proven successful decode and lifetime check |
| Next | `hud_aimcp_add_persist.isra.0` | `0xbbca80` | Session-persistence input and return status; distinguish input from rewritten state |
| Investigate | `tmm_json_object_get` | `0xd9bac4` | Application lookup key and returned value; extraction pending |
| Implemented | `tmm_json_value_get_string` | `0xd99c04` | **MEASURED** exit observation: bounded root-object method value; scope and limits in §7 |
| Investigate | `hud_inference_egress` | `0xd2cbc4` | Response-buffer length and local filter state; not tokens, client delivery or model completion |
| Investigate | `http_process_server_headers` | `0xca8100` | Server-header processing; call-path coverage and post-parse field validity remain open |

The two handler entries and JSON string getter have live attachment results.
The later [session/routing gate](SESSION-ROUTING.md) also validates entry probes
at the two AIMCP persistence clones. It observes saved header bytes before decode
and selected routing state before response rewriting. Successful decode-return
fields and the other candidates remain unvalidated. The
[response gate](RESPONSE-METADATA.md) qualifies response-status and done fields at
`hud_aimcp_handler`; these fields do not establish remote-operation success.
The `.cold` entries listed as `displace` are not selected padded hooks. Compiler
clones (`.constprop` and `.isra`) need their actual machine-code argument layout
checked; the source signature alone is insufficient. Exit admission passed for
the JSON string getter; other exits remain unchecked. Do not arm the entire table
as one probe set.

**Shortlist correction:** `a2a_request`, `a2a_lookup_method` and `aimcp_request`
were useful source leads, but discovery found no exact or clone-prefixed rows for
them in this package's hook index. Do not present them as available hook entries.
The surrounding handlers provide the next candidates. Index absence alone does
not establish why a source function lacks an entry.

`a2a_walk_and_replace` also has a padded entry (`0xa8edc0`). It follows configured
ID paths for persistence. It cannot stand for all fields or unfamiliar methods.

## 2. What the source says about extraction

These are **MEASURED source facts**, not live probe results. The exact source
files and their hashes are in the discovery receipts above.

- A2A request processing obtains a JSON method string, then looks it up in a
  method table. Unknown methods take a separate path. Reading only
  `a2a_scb.method_entry` would lose the unknown method's value. The handler event
  must survive even when the value cannot be extracted.
- `a2a_response` receives a normal response or an individual Server-Sent Events
  (SSE) message. Its caller selects these cases. One call is not an entire stream.
- AIMCP retains `parsed.mcp_session_id`, `parsed.pool_name` and `parsed.ip_tup`.
  Successful decode is a prerequisite for treating these as this input's parsed
  values. Raw key fields and temporary decrypted buffers are not metadata inputs.
- The JSON cache parses values on demand. A tokenized message does not imply a
  fully materialized object tree. Probe code must not call application getters
  that can parse, allocate or change state. An accessor hook observes calls the
  application itself makes; it does not enumerate untouched fields.
- `tmm_json_string` has a pointer and length. It need not end with a zero byte.
  The header describes escaped string storage. Record encoding and length;
  do not silently export it as an already decoded string.

The first handler probe should establish event-code extraction on every call.
Then add fields whose types and lifetimes are proved at that phase. Resolve the
`HUDNODE_CTX` storage variant before reading filter state. Do not assume an
ordinary pointer edge or a supported bitfield access.

## 3. Extraction and output contract

This is a proposed logical contract, not a frozen binary record layout.

**Each probe invocation attempts one output record**, including unsupported input
and failed reads. Do not require a fixture nonce, known method, actor or recognized
workflow to retain an event. Output loss must be counted separately; an output
attempt is not proof that the collector received it.

The record and its build-side manifest must provide:

- **Provenance:** schema, program/loaded-instance identity, binary identity, hook,
  entry or exit phase, and configuration revision. Constant data can live in the
  manifest; the record must carry enough identity to resolve it unambiguously.
- **Observation context:** process/worker scope, sequence and clock source where
  supported. An object reference is optional and lifetime-scoped, never an agent
  identity. A failed association must not suppress otherwise valid field values.
- **Field facts:** field identifier, source type/path, representation, original
  length where known, copied length, value and read status. Preserve raw event
  codes and bounded unfamiliar metadata values, rather than mapping them to a
  fixed list of agent operations.
- **Availability:** distinguish complete, truncated, read-failed, unsupported,
  budget-exhausted and unavailable. Say absent or not-materialized only if the
  observed application state proves that distinction. A failed read proves neither.
- **Observation health:** attempted output, reported drops/refusals, attachment
  history and missing history. Continuous sequence numbers alone do not establish
  continuous hook coverage; see [GAPS.md](GAPS.md).

**Initial extraction budgets — IDEA, to verify before arming:** at most eight
application-memory reads and 256 source bytes per invocation; at most 64 bytes of
one selected metadata string; one output payload no larger than 256 bytes. Report
truncation and budget exhaustion. No recursive walk or unbounded scan. Use only
the registered read/output helpers and bounded local work. These limits constrain
the experiment; they are not measured data-path cost or sufficient coverage claims.

Metadata selection is explicit: event codes, field names/types, lengths, method
labels and qualified session/routing fields. Do not export entire structures,
credentials, prompts, tool arguments or raw bodies. General JSON getter hooks need
a demonstrated scope before string capture; they can see non-metadata content.

```text
BUILD BOX — off the data path
  Source + packaged binary + types + call sites
    -> hook/field/lifetime manifest -> bounded probe -> verify and sign

TMM — data path
  Selected function invocation -> bounded metadata reads + read status
    -> one record attempt -> existing output ring

COLLECTOR — separate process
  Drain + preserve records + report extraction/loss status
    -> versioned metadata record for later consumers

LATER ANALYTICS
  Interpret activity and relationships using the preserved observations
```

## 4. Next verification gates

1. Establish handler argument layouts and event-code constants on this package.
   Record each field's valid phase, storage variant and source representation.
2. Implement the bounded handler probe and decoder. Check exact extraction with
   pinned PREVAIL and interpreter/JIT execution. Exercise unknown event codes,
   null/unreadable fields, exact length limits and output refusal. These are
   extraction tests, not assumptions about representative agent workflows.
3. Use an isolated native-filter fixture to establish actual hook reachability.
   Compare values with a separate application record. Include unknown inputs and
   fragmented/streamed delivery where supported. Reconcile calls, records and loss.
4. Expand fields and hooks from observed gaps. Before cost or coverage claims,
   measure worker/output pressure and enabled, disabled and bypassed filter paths.

**Falsifiers:** a wrong value or representation; stale data marked current;
unknown events silently excluded; missing data labeled absent; truncation hidden;
probe-induced application changes; lost records presented as complete extraction;
or a source name presented as a validated live hook.

**Current limit:** handler events and the bounded method-field read in §7 are
live-validated in the isolated native-filter fixture. These synthetic requests
do not establish representative workloads or complete protocol coverage.

**Correction after review:** event extraction was treated as the first implementation
step. It must not substitute for the owner's goal of extracting application fields.
The unfamiliar request method was forwarded in the live test, but its value was
not in the probe record. The later value-comparison test in §7 closes that gap for
the tested A2A path, with explicit limits.

## 5. First implementation gate — registered before the build

The first two programs observe handler entry. Both source signatures take
`(node, msg, flow, data)`. The saved disassembly moves `%esi` into `%ebp` for
dispatch. Thus the first field is the low 32 bits of `arg[1]`, not a pointer read.
Retain every numeric value. Resolve event names off the data path from the pinned
`hud_msg_t` enum, and leave unknown codes unnamed.

Export the probe kind, event code, argument-presence bits, monotonic clock,
configuration instance/revision/run, call sequence and previous output refusals.
Presence means only zero versus nonzero; it does not prove a valid object. This
first program makes no application-memory reads and exports no addresses or
message content. Field dereferences follow only after their lifetime gate.

Native tests must run both real programs with shared host map helpers, in both
interpreter and JIT modes. Check known and unknown codes, nonzero upper register
bits, null and unreadable pointer arguments, missing configuration, sequence
saturation, output refusal and replacement-instance reset. Neither program may
select an action. The live check must show native-filter calls, preserved numeric
codes, complete output accounting and restored hook bytes. Profile configuration
or successful HTTP forwarding alone does not prove native-filter reachability.

## 6. Method-value gate — registered before the field build

Observe the return from `tmm_json_value_get_string`. A successful return supplies
a length-delimited string in the caller's output descriptor. The source keeps the
value and its owner alive across this call. Read the descriptor before the caller
resumes. Do not call the getter from the probe.

Before copying content, require that the value belongs to an ownerless JSON object
and that the matching member has the parsed key `method`. Match the member by its
value pointer, not by method spelling. This selects a root-object method field;
it does not prove A2A/MCP origin or a network-request identity. Nested method fields
and other keys must produce status-only records. No retained pointer association
is required between hook invocations.

The private JSON layout is pinned to this binary and checked against its debug
types. Its circular member list needs a bounded walk. This field experiment raises
the proposed source-read budget to **12 reads / 320 bytes**, with at most four
members checked and at most 64 string bytes copied. Every invocation still attempts
one record of at most 256 bytes. Report an exhausted walk as budget exhaustion,
not absence. Do not copy a fifth member or silently widen the limit.

Preserve escaped bytes, original length and copied length. Check exact extraction
for known, unfamiliar, empty, escaped, 64-byte and longer values. Native checks
must also cover unreadable descriptors/data, nested fields, unrelated keys, an
exhausted walk, getter failure and output refusal. The live test must compare
extracted bytes with the authored inputs. A missing getter call is an extraction
coverage gap, not evidence that the request lacked a method.

## 7. Field result — measured on the pinned build

[Field receipts](../../SOURCES.md#root-object-method-extraction-2026-09-28) retain
source, debug layouts, failed and successful builds, native checks and the live run.
The first build exceeded the 256-byte PREVAIL stack limit. Packing the small record
counters reduced the record from 152 to 144 bytes. Build 02 passed the **same**
stack limit, exit admission and interpreter/JIT checks. No failed build was loaded.

The live test sent ten requests through the native filters. It compared extracted
bytes with authored request values, rather than using hook counts as a substitute.

| Input or case | Extracted result |
|---|---|
| `SendMessage` | Exact 11 bytes; complete |
| `future.variant`, fragmented delivery | Exact 14 bytes; complete |
| Empty method | Zero bytes; complete |
| Escaped `future\u002evariant` | Exact 19 escaped bytes; complete, not silently decoded |
| 64-byte method | All 64 bytes; complete |
| 65-byte method | First 64 bytes; original length 65, explicitly truncated |
| Numeric method | Getter-error status; no value bytes |
| Method beyond the four-member walk | Budget-exhausted status; no value bytes |
| Nested-only method | No getter invocation; no field observation |
| AIMCP `tools/list` request | No getter invocation in this experiment; the later [token-cache probe](TOKEN-METHOD.md) extracts it |

Eight getter calls produced eight records. No output loss or new VM error was
reported. The process did not restart. Kernel byte checks confirmed the hook was
restored. The fixture was archived and removed. The value comparisons and native
tests are SELF evidence; PREVAIL and kernel witnesses are identified separately
in `GROUND_TRUTH.md`. Data-path cost remains unmeasured.

### Record and scope

`method_decode.py` decodes a 144-byte record. It retains program instance, config
revision, run token, monotonic clock, sequence, output refusals, getter return code,
field status, original/copied lengths, read count, source-byte count and up to
64 escaped value bytes. It exports no object addresses. Length zero means an empty
field **only with complete status**. Zero length on an unavailable/error record
does not establish an empty or absent method.

This is a **root-object `method` field consumed by the application getter**. It is
not proof of protocol origin, request identity or complete JSON coverage. The scope
check uses only the current invocation's owner/member links. There is no retained
address join. Unreadable memory, nested fields and other keys are checked in native
tests. The live nested-only request did not exercise the getter's exclusion branch.

The 12-read / 320-byte cap and four-member walk are deliberate limits. A later
member is unavailable to this probe even when TMM parsed it. The later
[token-cache probe](TOKEN-METHOD.md) closes the measured AIMCP method gap with a
different hook. It requires the JSON filter, literal keys and bounded traversal;
it does not establish general MCP coverage. Saved session-header bytes and selected
routes now have a [separate measured gate](SESSION-ROUTING.md). Task IDs and tool
fields remain separate work. The original getter gap remains part of the record.

### Implementation

- `substrate/surfaces/json_method.bpf.c`: observe-only exit probe.
- `substrate/surfaces/json_method_abi.h`: record and pinned local read layouts.
- `substrate/check_json_method.c`: real VM/map/read helpers, guarded buffers and
  exact-value checks; output sink and input objects are authored test fixtures.
- `env/ai-traffic/method_build.py`: pinned build, admission, signing and native checks.
- `env/ai-traffic/method_decode.py`: bounded record decoder.
- `env/ai-traffic/method_suite.py`: live value comparisons and output accounting.

The successful build is `/home/starin/eob-config-20260925/method-build-02` on the
build box. Sources here require the pinned external TMM package and toolchain.
The fixed layouts are qualified for build `ca69b84f…`, not a portable field ABI.

### Output transport decision

The tested path is TMM → bounded ring → separate collector. A ZeroMQ publisher
inside TMM is not required for this extraction. If later consumers need ZeroMQ,
the recommended extension is a publisher in the collector. Connection management
and delivery policy belong there. That extension is IDEA and was not implemented
or measured in these tests.
