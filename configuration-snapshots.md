# Configuration snapshots: controller → eBPF input, v1

**2026-09-25 · Implemented; MEASURED in the pinned build-box bench, Unix-socket
harness and live isolated SSA/Tao TMM. Per-call cost remains unmeasured.**

An extension can consume policy or enrichment data without recompiling its bytecode.
The controller publishes a complete, versioned snapshot; the program uses ordinary
`bpf_map_lookup_elem` against a dedicated ARRAY view. Program output continues through
the existing event-output helper/ring. Configuration is separate from mutable counters.

Evidence: [P21](02-RESEARCH-PARAMETERS.md#p21--controller-published-configuration-snapshots--implementation-in-progress),
[registered receipts](SOURCES.md#configuration-snapshots-2026-09-25),
[ground truth](GROUND_TRUTH.md). Per-call cost is unmeasured.

## The implemented boundary

```text
AUTHORING / ADMISSION                 CONTROL PLANE — local controller
SDK + program                        config-status: instance + hash + revision
  → clang-18 → PREVAIL → sign         config-publish: complete replacement image
  → existing signed LOAD                         │ owner-UID Unix socket
            │                                    ▼
            │                        exact framing / identity / revision checks
            │                                    │ atomic publication
────────────┼────────────────────────────────────┼────────────────────────────
TMM INLINE  ▼                                    ▼
   loaded-program instance             host-owned configuration image
            │                                    │ one bounded copy attempt
   invocation → map lookup ──────────────────────┘
            │ invocation-private snapshot; subsequent lookups reuse it
            ├── ordinary map state for counters (separate existing mechanism)
            └── event-output helper → per-thread STREAM ring
──────────────────────────────────────────────────────┼───────────────────────
EXTERNAL COLLECTOR                                    ▼
   existing drain → decode schema → reconcile configuration revision → consumers
```

Only bounded snapshot copying and lookups run inside the program invocation. No
configuration socket, JSON parser, allocation, reader lock, retry loop or network
request is introduced on that path. The existing output path has its own initialization
and loss behavior; this change does not establish its delivery guarantees or cost.

## Program contract

Include [`substrate/config_snapshot.bpf.h`](substrate/config_snapshot.bpf.h).
It declares the global ELF map symbol `ls_config_v1`:

| Field | Required value |
|---|---|
| type | `BPF_MAP_TYPE_ARRAY` = 2 |
| key size | 4 bytes, unsigned index |
| value size | 32 bytes |
| max entries | 17: one metadata record plus at most 16 data records |
| map flags | `BPF_F_RDONLY_PROG` = 128 |

This is a **dedicated configuration ARRAY**, not general ARRAY-map support. It does
not consume a slot in the existing four-name hash/output-map registry. Map relocation
embeds a host-issued instance handle; the same symbol in two loaded programs does not
share configuration. The runtime currently has 12 VM slots; the configuration protocol
reserves a 64-slot namespace, and operations require an actually loaded instance.

### Lookup and lifetime

- `ls_cfg_get(0)` returns metadata, or NULL when no snapshot is available.
- `ls_cfg_get(1)` through `ls_cfg_get(meta->entries)` return 32-byte opaque records.
- An absent record, invalid index, wrong instance/slot or inactive invocation returns NULL.
- The **first valid lookup** selects the invocation's snapshot. Every subsequent lookup
  uses the same copy, even if the controller publishes another revision meanwhile.
- If publication overlaps the copy, that invocation remains unavailable. It does not retry
  or silently fall back to older policy. The program defines its missing-input behavior.
- References expire when the invocation returns. Retaining a pointer in a hash map does
  not extend its validity.
- Update/delete helpers refuse this map. Direct stores can alter the program's own scratch
  copy; they cannot alter the host image or a later invocation. Host-image protection does
  not depend on PREVAIL treating map values as read-only.

Metadata is 32 bytes, little-endian:

| Offset | Type | Meaning |
|---|---|---|
| 0 | u64 | Published revision, nonzero |
| 8 | u64 | Loaded-program instance handle |
| 16 | u32 | Application schema ID, nonzero |
| 20 | u32 | Data-record count, 0–16 |
| 24 | u64 | Reserved, host writes zero |

The host transports opaque rows; the program must check the schema before interpreting
them. Different programs may use different schema vocabularies because their snapshots
are instance-scoped. There is no global schema registry in v1.

**Working example:** [`substrate/surfaces/config_threshold.bpf.c`](substrate/surfaces/config_threshold.bpf.c)
reads a controller-provided threshold, compares a fixture scalar, and emits revision,
instance, observation and match result. Its hook is the synthetic `config_fixture`, not a
deployable TMM hook. Its return-value check is an invocation-consistency test, not a
mitigation. Ordinary event emission still uses helper 25 and a PERF_EVENT_ARRAY handle.

## Controller contract

The existing 192-byte `shield_msg` header is unchanged. Two operations are added:

| Operation | Number | Payload / result |
|---|---|---|
| `CONFIG_STATUS` | 5 | No payload; session, instance, program SHA-256 and current revision/schema/count |
| `CONFIG_PUBLISH` | 6 | Versioned body in `prog[]`; complete replacement or error |

`epoch` retains the loader's existing slot-number convention. This interface is local:
socket mode 0600 plus an explicit `SO_PEERCRED` owner-UID check. **The policy body is not
signed.** Its authority is the local loader-owner account, not the program signing key,
and not a remote end-user/tenant identity. Production tenant delegation needs a separate
authorization contract and TMA.

Publication requires all of:

1. The current random process/fork session from `config-status`.
2. The loaded-program instance handle and program SHA-256 recorded after signed LOAD.
3. `expected_revision` equal to the current revision.
4. A strictly greater `revision`; revisions never wrap or reset within an instance.
5. ABI 1, nonzero schema, zero reserved field, exact length and at most 16 rows.

A successful LOAD creates a new instance with no published snapshot, including a reload
of identical bytecode. Old in-flight bytecode cannot read its replacement's configuration.
Normal REVOKE invalidates the instance; a still-outstanding prepare after timeout keeps
CONFIG operations busy. Existing late-prepare/reclamation issues are not solved here.

Publication acknowledgement means the host image was installed, **not** that every TMM
thread has used it. Already-running invocations may finish using their earlier copy.
There is no cross-process/fleet transaction. A timed-out publisher must query status to
resolve the outcome, not blindly allocate another revision and retry.

Zero rows publishes an explicit empty snapshot and advances revision. To roll back data,
publish the earlier contents under a **new, higher** revision with the current expected
revision. Preserve the input JSON in the controller's own evidence store if emitted
revision numbers must later resolve to exact policy bytes.

### Wire body

All fields are little-endian. Fixed header: **80 bytes**, followed by `entries × 32` bytes.
Maximum body: **592 bytes**. Extra/truncated bytes and missing write EOF are refused.

| Offset | Field |
|---|---|
| 0, 4 | u32 ABI, u32 schema |
| 8, 16 | u64 session, u64 instance |
| 24, 32 | u64 expected revision, u64 new revision |
| 40, 44 | u32 entries, u32 reserved = 0 |
| 48 | 32-byte program SHA-256 |
| 80 | Data rows, no implicit padding/truncation |

The stream reader now reads the fixed header and declared bounded body separately,
with a receive timeout. This also fixes fragmented legacy loader messages being mistaken
for complete short messages. Configuration errors/empty or ambiguous replies cause a
nonzero exit from the new CLI commands.

### CLI usage

```sh
python3 env/scripts/ls-load.py config-status 5 > identity.json
```

Construct a snapshot from that identity, retaining an explicit expected revision:

```python
import json, struct
snapshot = json.load(open("identity.json"))
snapshot["expected_revision"] = snapshot.pop("revision")
snapshot["revision"] = snapshot["expected_revision"] + 1
snapshot["schema"] = 1
snapshot.pop("entries")
snapshot["rows"] = [struct.pack("<QQQQ", 100, 1, 0, 0).hex()]
with open("snapshot.json", "w") as out:
    json.dump(snapshot, out, indent=2)
```

```sh
python3 env/scripts/ls-load.py config-publish 5 snapshot.json
python3 env/scripts/ls-load.py config-status 5
```

The schema-1 example row means threshold 100, enabled 1, two zero reserved words.
The isolated September 25 image implements these operations; the shared September 24
deployment does not. Select the loader socket for the intended TMM instance explicitly.

## Validation and integration

[`check_config.py`](substrate/check_config.py) runs the pinned clang-18/PREVAIL gates,
actual uBPF interpreter/JIT, host concurrency tests and actual loader configuration
handler over Unix sockets. It writes an exclusive receipt even when a check fails.

```sh
UBPF=/home/starin/code/tmm/.ubpf \
PREVAIL=/home/starin/eob-tmm-staged/ebpf-verifier/bin/prevail \
python3 substrate/check_config.py --receipt /path/to/new-receipt.json
```

The first verifier run failed because the map symbols were `static`; global symbols fixed
the ELF map references. Both the failure and successful runs are retained. Tests cover
publication during program execution, next-invocation visibility, scratch-write isolation,
10,000 updates against four readers, stale identity/revision refusal, truncated/trailing
messages, and client error exits. Socket tests use fixture binding/session data and stub
the audit sink; they do not prove signed LOAD integration, owner-UID mismatch rejection,
or live TMM behavior.

TMM integration requires the new header, changed substrate sources, one globals-whitelist
entry and a rebuild: [exact source delta](substrate/TMM-TREE-DELTA.md). No new F5 function
body or C translation unit is required. Sequentially consistent atomic words make the
snapshot copy data-race-free; their cost, publication-pressure availability, initialization
and added dispatch work must be measured on the target before a performance claim.

### Live lifecycle — measured, isolated SSA/Tao TMM

[`config_observe.bpf.c`](substrate/surfaces/config_observe.bpf.c) reports configuration
instance/revision/tag at `http_parse_client_headers`, reading no request data. It was compiled,
bound to the **packaged** ELF, PREVAIL-verified and signed monitor-only. `lifecycle-02` passed:

| Phase | Requests / events | Observed configuration |
|---|---|---|
| Signed LOAD, no publication | 8 / 8 | Explicit unavailable, all-zero payload |
| First publication | 8 / 8 | Revision 1, tag 101 |
| Second publication | 8 / 8 | Revision 2, tag 202 |
| Empty withdrawal | 8 / 8 | Revision 3 retained, no data row |
| Reload identical bytecode | 8 / 8 | New instance, no inherited snapshot |
| Publish to replacement | 8 / 8 | New instance, revision 1, tag 303 |

Five stale publications were refused: expected revision, session, instance, program hash,
and the previous instance after reload. Two baseline and two disarmed requests bring the
total to **52 exact HTTP 200 responses**; the six armed phases reconcile **48 requests =
48 counter increments = 48 events**, with zero reported drops, VM errors or safe returns.
REVOKE succeeds and subsequent configuration status is refused. Two SSA configuration ACKs
and the fixture JSON/XML are independently checked by the runner wrapper.

Witnesses: **SELF** program events/counters and fixture assertions; **INDEPENDENT** PREVAIL;
**KERNEL** `/proc/7/exe` hash and `/proc/7/mem` entry-byte reads. Entry `0xccc600` retains
`endbr64`; its five-byte pad changes NOPs → `e8` call → identical NOPs on both load/arm cycles.
Process starttime, container identity/state and restart count (0) stay unchanged. Runtime:

- Build ID: `b8dc27f34a93db91f91b60f0844105bfb30c6f90`.
- Executable SHA-256: `26e8f07b12a279e7d84f2328363db998a7dfa109a9b3c71847be408a6710a12c`.
- Image: `tmm:CONFIG-20260925`; Compose project: `eob-config-20260925`.
- VIP/backend: `10.203.74.50:18093` → `10.203.74.11:18093`; observed peer `10.203.74.10`.

The first attempt's fixture passed but its outer recorder incorrectly required `e9` rather
than the implemented `e8`. Both attempts and that correction are retained in
[SOURCES.md](SOURCES.md#configuration-snapshots-2026-09-25) and
[contested premises §21](CONTESTED-PREMISES.md#21--the-armed-pad-must-contain-a-jump--wrong-recorder-expectation).

**New limits:** these live publications occur between request batches. Concurrent copy behavior
is covered by the bench, not a live publication-pressure result. Cross-UID refusal, randomized
startup failure, timeout/reclamation cases, multi-process coordination and incremental cost
remain unvalidated here. The observer reads no identity or request fields, so this result
establishes configuration I/O rather than attribution.

### Repeat the isolated test

The source/image setup is in `env/ai-traffic/config-compose.yaml` and `config-fixture.env`,
layered over `icap-compose.yaml` using an explicit project name. Build/sign via
`config_build_probe.py` with a fresh output and this build's packaged context. On the build
box, with the prepared containers and an unused run/receipt name:

```sh
python3 /home/starin/eob-config-20260925/config_live_run.py \
  --run lifecycle-next \
  --output /home/starin/config-io-20260925.039uaw/config-live-next.json
```

The driver captures the kernel witnesses, runs the SSA wrapper, retains failures and leaves
the target disarmed/revoked. `env/ai-traffic/config_snapshot.py --output <new-cache-file>`
collects the fixture attempts and source/check receipts from the control machine. Register
each new receipt in `SOURCES.md` and the cache manifest.

## Return to attribution

Attribution remains the next application. This channel can carry an authority's small
identity/policy table, identified by instance and revision. It **does not authenticate a
request**. The next experiment must still join credential-validated evidence to a correctly
scoped TMM request observation, and retain unknown when that evidence is absent or
ambiguous. Caller headers, session IDs and pointers do not become trusted because an
input map exists. See [the attribution contract](env/ai-traffic/ATTRIBUTION.md).
