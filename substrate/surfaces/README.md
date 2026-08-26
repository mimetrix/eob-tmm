# Surfaces — portable CO-RE bytecode, one per surface

Each program is portable bytecode: it names TMM fields by struct+field, carries
`.BTF.ext` relocation records, and is relocated to the running build's byte
offsets at load (`ls_core_relo.c`) before verify+JIT. No baked offsets, no
rebuild. All use the generic register context `struct ls_ctx_generic { arg[5] }`
— the same context the trampoline hands every program.

Validated on the pinned toolchain (build box, clang-18, PREVAIL 06769f7b, gates
`--termination --no-division-by-zero --strict`) against the current build's BTF:
each **compiles → relocates (rc=0) → PREVAIL PASS**. Live arming additionally
needs the build's BTF baked to `/usr/share/ls/tmm.btf` (the one remaining piece
of 3b).

| file | surface | attach (section) | reads (CO-RE) | does |
|---|---|---|---|---|
| `probe_parser.bpf.c` | **probe** | `http_parse_client_headers` | `http_parse_ctx.version_num` | returns HTTP minor version; host buckets/counts |
| `debug_field.bpf.c` | **debug** | `ssl_alpn_match` | `ssl_ctx.cf` | returns one named field's live value; re-point by loading a sibling that names a different field |
| `shield_nullguard.bpf.c` | **shield** | `http_parse_client_headers` | `http_parse_ctx.parser` | `SAFE_RETURN` when the internal pointer is NULL (skip the body), else fall through |
| `trace_stream.bpf.c` | **trace** | `http_parse_client_headers` | `version_num` + `state` | emits one record per invocation to the egress ring (`bpf_perf_event_output` id 25 → `ls_drain`) |
| `http_observe.bpf.c` | (probe prototype) | `http_parse_client_headers` | `state` + `version_num` | the Phase-4 proof `probe_parser` generalizes |

Why iRules can't do these: the attach points are internal functions with no iRule
event, and the fields are internal state with no iRule variable. `debug` reads a
*different* struct than `probe`, showing "any struct, any field, by name."

Not claimed here: per-call cost (unmeasured — see probe #5 in `../../co-re-plan.md`).
