# Broader coverage: from attachable functions to supported operations

**Status:** Working roadmap · proposed extensions are **IDEA** until validated below.
**Started:** 2026-09-24 · **First implementation:** named embedded-structure traversal in the DSL.

Companions: [capability summary](tmm-ebpf-capabilities-summary.md),
[AI gateway working paper](ai-gateway-tracepoints.md), [evidence matrix](GROUND_TRUTH.md).

## 1. What coverage means

Broader coverage means answering more useful questions and applying a defined policy across every
relevant path. An attachment count alone does not establish it. For each supported operation, record:

> Event available → required fields valid → relevant paths covered → allowed actions defined
> → independently tested → cost characterized.

Observation coverage will generally be wider than enforcement coverage: a state may be visible
where intervention would already be too late or leave inconsistent state.

## 2. Six dimensions

| Dimension | Current foundation | Work to expand coverage | Evidence required |
|---|---|---|---|
| **Code: where we attach** | Function entry/exit hooks on suitable padded functions; build-generated discovery. | Account for inlined copies, preserve per-build coverage annotations, add deliberate semantic boundaries, and consider displacement only for valuable unpadded targets. | Identify the packaged binary; show the intended paths actually execute through the attachment, not just that a symbol exists. |
| **State: what we inspect** | Scalar arguments/fields, pointer chains and named embedded structures (P17's scoped validation below); 96-byte runtime context allocation. | Wider live field coverage, correct bitfields, validity/provenance, host-computed semantic fields, and versioned schemas. | Independently known field values and offsets; positive, negative, null, and unreadable cases. |
| **Lifecycle: when we observe** | Entry and exit events, counters, structured records. | Correlate admission, queueing, dispatch, attempts, first output, progress, completion, cancellation, and failure. | An independent client/upstream ledger across concurrent operations; intervals with defined endpoints and overlap semantics. |
| **Protocol/path: which variants** | Recorded demonstrations on specific functions and configurations. | Normal/error, streaming/non-streaming, retries/fallback, multiplexing, disconnect/cancel, adapter versions, and optimized paths. | A matrix per adapter and operation; a restriction covers every protected forwarding path in its declared scope. |
| **Action: what the host can do** | Selective function early return with a configured safe value. | Protocol-correct rejection, cancellation, stream termination, content withholding, and eventually approved routing choices. | Correct boundary placement, caller-visible outcome, cleanup, and isolation of unrelated traffic. |
| **Validation: where we have evidence** | Live mechanism tests and focused regressions, including the deployed context fix. | More simultaneous probes, repeated replacement/disarm, long-running concurrent traffic, slow drainers, deployment variants, and cost measurement. | Stable identified deployments, independent traffic witnesses, bounded resources, and workload-specific performance results. |

The latest context regression exercised entry and exit on one HTTP function; earlier records cover
additional mechanisms and paths. Neither constitutes qualification of an AI gateway. The 96-byte
fix makes the existing allocation contract correct; it does not automatically expose new fields.

## 3. First implementation order

**Deployment prerequisite completed, 2026-09-24:** bulk catalogs now stay on the build box,
with authenticated per-program targets and live entry/exit validation. P18 and
[`catalog-free-deployment.md`](catalog-free-deployment.md) record that boundary. The first
state-coverage slice below is also validated, with catalogs retained on the build box.

1. **State coverage:** named embedded structures first, then bitfields and explicit validity.
2. **One semantic lifecycle:** MCP dispatch/completion and inference routing, first output,
   completion, and cancellation, with correlation designed in.
3. **One host-owned action:** dispatch rejection, including retry paths.
4. **Concurrency and performance:** representative streams, repeated probe lifecycle operations,
   and a stopped/slow telemetry consumer.
5. **Additional attachment mechanisms:** only where a useful event remains unreachable.

For lifecycle, dispatch, cancellation, and cost, the falsifiers are already registered as P13–P16
in [02-RESEARCH-PARAMETERS.md](02-RESEARCH-PARAMETERS.md). The first state extension is P17 there.

## 4. Does `tmmtrace list` still work without names/type information in the ELF?

**Yes: discovery reads a separate catalog.** Removing embedded BTF (BPF Type Format) from the
runtime executable did not remove the compiled functions, nor the build-generated metadata used
by the tools. It is important to distinguish these artifacts:

| Artifact | Consumer / purpose | Location in the current workflow |
|---|---|---|
| `hook-map.json` | `tmmtrace list`: names and discovery metadata | Build box under `~/lstools`; toolbox uses its configured copy via `LS_HOOKMAP`. |
| `hook-index.tsv` | Build-side binder: function name → entry/pad address, tied to a build ID | Build box only; removed from the new TMM image. |
| `signatures.tsv` | Named arguments and parameter types for authoring | Build box only; removed from the new TMM image. |
| `types.json` | Scalar widths, pointer edges, and additional field metadata for the DSL | Authoring environment, generated from the target build's BTF. |
| `tmm.btf` | Resolve field offsets before verification/signing | Build box; the deployed runtime does not require an embedded copy. |

```text
BUILD / AUTHORING
  Packaged executable + matching debug information
    → hook map + address index + signatures + type catalog / BTF
    → tmmtrace discovery and source generation
    → compile → relocate → strip → bind target → verify → sign

DEPLOYED TMM
  BTF-less executable + small runtime identity receipt
    → signed program/target admission → attach admitted entry → execute
```

**Rechecked after catalog-free deployment, 2026-09-24:** discovery still returns one matching
name for build `c3b81927dfdcc31137cd8212b5e23bb85677a06c` (cached `catalog-discovery-20260924.log`).
The earlier check used `5c76bc3a…`, the preceding [context-fix image](ctx-contract-validation.md).

```sh
LS_HOOKMAP="$HOME/lstools/hook-map.json" \
  python3 "$HOME/eob-tmm-staged/substrate/tmmtrace.py" list 'http_parse_client_headers'
```

**Limits:** the map has 71,310 indexed entries, not 71,310 proven attachment targets. The command
reported missing `inline_status`; it cannot establish complete coverage of inlined call sites.
The current `--armable` filter tests `relocatable`, so it is not a sufficient proof of support by
the deployed pad-only attachment mechanism. Restoring annotations and making that distinction
explicit are discovery backlog items. The JSON listing catalog is not the TSV arming index, and
the current TMM image recipe does not install the JSON catalog in the data-plane container.

### Metadata removal is not attack-surface reduction

**Clarification raised during review:** shipping `hook-index.tsv` and `signatures.tsv` alongside
the executable preserves disclosure outside the ELF. The index contains function names and
addresses; signatures expose parameter names and type descriptions. Removing embedded BTF removes
that particular source of full type layouts, but does not conceal the function map and does not
remove executable code, listeners, or vulnerable paths. No reduction in exploitability is established.

The demonstrated architectural change is **moving field resolution to the build/signing side**,
so the runtime can accept already-relocated programs without carrying embedded BTF. Calling that
change attack-surface elimination or symbol obfuscation would overstate it. Engineering metadata
remains recoverable on the build box.

**Deployment boundary clarified by the owner:** metadata retained on the build box is acceptable;
the concern is what ships to or is deployed at the gateway. **MEASURED, 2026-09-24, in the running
`f5-tmm` container** of pod `f5-tmm-59696979b6-6xv8n`: `/usr/share/ls/hook-index.tsv` is
3,409,257 bytes and `/usr/share/ls/signatures.tsv` is 6,467,602 bytes. Both headers match executing
build `5c76bc3a6069d7aa2aea51d32b69a2742563ddc4`; `/proc/24/exe` has no `.BTF` sections. Pod UID
`041de6aa-9680-4a01-a674-0364ef270a43` and zero restarts match the recorded deployment.
This confirmed that the two bulk catalogs **shipped in that preceding image**, despite BTF removal.
It is a targeted check of these files and the executing ELF, not a whole-image metadata audit.

**Implemented after that finding:** the new image omits the catalogs; the existing build box
resolves names and signs attachment metadata. The runtime validates the full build ID, target
eligibility, kind, attachment ownership and mode ceiling. An authoring service is not required
for this workflow. The all-layer audit and live results are in `catalog-free-deployment.md`;
hiding metadata still does not replace patching or runtime security.

## 5. First slice: named embedded-structure traversal

### Contract

Keep existing expressions such as `args.a.b.value` and `arg1.a.b.value`. Each intermediate edge
may be a pointer or a **named embedded struct**:

- A pointer edge loads an address through `bpf_probe_read`, checks the helper result and NULL,
  and starts the next object access.
- An embedded edge computes the address of a member within the same object. It must not read
  those bytes as though they held a pointer.
- The final scalar is copied through the bounded read helper; read failure declines the probe.
- Generate nested CO-RE declarations in dependency order, resolve offsets against the target BTF,
  and verify the resulting bytecode with the pinned toolchain.

Add `__embedded__` metadata without changing the existing flat scalar catalog. This slice covers
named struct members with named struct types, including typedef/qualifier wrappers. Anonymous
aggregates, unions, arrays, bitfield reads, expanded argument/return conventions, and new verdicts
remain separate work. Existing catalogs without the new metadata must retain pointer-only behavior.

### Acceptance and status

P17 requires nested-only, pointer→embedded, and embedded→pointer paths; multiple fields of the
same nested type; unchanged scalar/pointer behavior; and continued bitfield/unsupported-path refusal.
Offsets must agree with an independent oracle, and final relocated bytecode must pass pinned
clang-18/PREVAIL. Fixture evidence does not establish that a live hook observes a useful value at
the right time; real-TMM checks are recorded separately.

**Implementation status, 2026-09-24:** implemented and installed in build-box authoring tools/catalog.
Native execution fixtures and 12/12 real-TMM relocation checks pass; three signed HTTP/1 monitor
probes ran live with 16/16, 0/16 and 16/16 matches, clean disarm and zero restarts. See
[`embedded-traversal-validation.md`](embedded-traversal-validation.md) for evidence tiers and limits.
The HTTP/2 pointer→embedded example is verified/signed, not live-tested.

## 6. Backlog and collaborator decisions

| Work item | Next concrete decision or deliverable |
|---|---|
| Discovery accuracy | Distinguish indexed, padded, partially inlined, and tested targets; carry annotations across baking. |
| Embedded structures | P17's first slice is measured; expand useful live fields and independently check their values/lifetime. |
| Bitfields | Agree on supported widths, shifts, signedness, and relocation kinds before enabling reads. |
| Validity/provenance | Define unknown/read-failed semantics independently of a numeric zero. |
| Semantic lifecycle | Pick one MCP operation and one inference adapter; assign ownership of correlation and terminal states. |
| Dispatch action | Identify the last reversible boundary and the host's rejection/cleanup API. |
| Operational qualification | Specify concurrency, traffic matrix, resource bounds, and numeric budgets before measurement. |

Collaborators should nominate useful operations and fields, not just additional function names.
Each nominated capability needs a scope, a witness, and a falsifier before it becomes a coverage claim.
