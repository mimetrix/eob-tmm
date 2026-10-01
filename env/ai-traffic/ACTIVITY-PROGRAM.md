# One activity artifact

**2026-09-30 — MEASURED: both entry hooks run together in isolated live TMM.**
The current artifact supplies explicit exchange keys. The exporter combines ten
live exchanges, including keep-alive and concurrent equal message IDs.
[Combined result](ACTIVITY-COMBINED.md),
[evidence](../../SOURCES.md#combined-activity-records-2026-09-30).

Build one bytecode file in Executable and Linkable Format (ELF), with two entry
points. Load the same file into two slots. Each slot has its own program instance
and configuration. This is one deployable artifact, with two loaded instances.

| Function entry | Observations |
| --- | --- |
| `json_filter_handle_json_complete` | Method, tool/resource target, message ID and flow side, reported reply fields |
| `hud_aimcp_handler` | HTTP status and local transfer completion |

Reuse the bounded readers. The JSON entry makes four output attempts per call.
They share one sequence and failure counter within that loaded instance. The
HTTP entry has a separate counter. The two state maps, output map and shared
exchange map use the four-map limit. The exchange map reserves one of its 128
rows as an admission counter. It retains at most 127 addresses and prevents host
map eviction. A full output ring drops the new record; it does not wait.

Each field record has a 48-byte ABI 2 group prefix. The largest framed record is
192 bytes. The [exchange contract](ACTIVITY-COMBINED.md) defines its start,
header confirmation, symmetric peer check and end boundary.

The readers are separate bytecode functions inside the ELF. Both entry sections
pass the pinned 256-byte per-function verifier stack check. Use clang 18 with
`-ffunction-sections -mllvm -disable-block-placement`. Function sections keep
nested calls relocatable when uBPF selects an entry. Default placement was refused
by the pinned uBPF subprogram check. The JIT compiler needs a 512 KiB temporary output
buffer. The retained executable mapping uses the actual generated code size.
Strip debug sections before binding and signing. The build checks that executable
sections stay identical and the final ELF fits the existing 256 KiB file limit.

The signed ELF must bind each entry section to its own build-resolved target.
Reject missing, duplicate, extra or mismatched bindings. Keep the existing
single-target format. Old loaders must refuse the new multi-target format.
Version 1 of the target set supports entry hooks only.

Reject the implementation if either entry cannot pass the pinned verifier, if
one hook resets the other's counters, if extraction results differ from the
existing readers, or if both hooks cannot run together in the isolated fixture.
Check malformed target sets and wrong-target attachment as well as valid loads.

Arming two entries is not atomic. The fixture reports partial failures and attempts
each owned disarm and revoke. A manual caller must do the same cleanup. A common
artifact alone does not establish identity, association, storage lifetime or
completed agent execution. The separate exchange contract qualifies bounded
request/reply association. This test uses one loaded pair on one TMM worker;
multiple pairs, multiple workers and sustained data-path cost remain unqualified.

## Built artifact

On the pinned build box, `10.145.37.36`:

```text
/home/starin/eob-config-20260925/activity-group-check-06/agent_activity.bpf.o
```

- Size: **182,056 bytes**.
- SHA-256: `aeda57b92798f3ceac6aec6d7fba7b0aa42191d9037b252ebed5cdb8f118e1d7`.
- Bound TMM build: `f9a1ed8c8c54192e76e54bf7f1c59921b8a774c9`.
- Runtime SHA-256: `9d3670067daa0f960f90257870cea79b9e70ca2a8cf3c3ac8a2ced87ad514a7f`.
- Image: `tmm:ACTIVITY-20260930`, immutable ID
  `sha256:d19a837512c3acb41129d3da678de7b1763bb0d3fddf74124fb4e7ba5ef09485`.

`activity-json.sig` and `activity-http.sig` authenticate the same ELF for their
respective hooks. They stay beside the artifact on the build box. Use this repo's
updated `env/scripts/ls-load.py`; `load-signed` selects an explicit signature:

```text
load-signed 11 agent_activity.bpf.o activity-json.sig 1
load-signed 9  agent_activity.bpf.o activity-http.sig 1
```

These are client subcommands. Run them where the loader socket and artifact are
mounted. Before arming either slot, publish each instance's configuration with
`config-status` and `config-publish`. `Metadata.start()` in `metadata_suite.py`
performs this sequence, then calls `arm 11` and `arm 9`. The activity fixture uses
that path. The target set and both signatures must be rebuilt for a different TMM.

To repeat the build on the pinned box, use a new output directory:

```sh
R=/home/starin/eob-config-20260925
python3 "$R/activity-group-source-06/env/ai-traffic/activity_program_build.py" \
  --source "$R/activity-group-source-06" \
  --output "$R/activity-group-check-NEW" \
  --package "$R/activity-integration-01/image-context" --sign \
  --debug "$R/activity-integration-01/debug/usr/lib/debug/usr/bin/tmm64.no_pgo.debug"
```

The saved source tree includes the bytecode readers, test harnesses, binder,
signer, loader client and their headers. In the original `activity-program`
series, check 06 omitted `shield_abi.h`; check 07 passed native tests but exceeded
the live file limit. Both failures are retained. In the later `activity-group`
series, check 06 passes with the corrected exchange admission counter.

## Current combined-record result

Ten exchanges produce 264 probe records: 80 JSON field records and 184 HTTP
records. The exporter produces ten checked exchange records, preserving equal
IDs on separate concurrent connections and assigning fresh keys on keep-alive.
Both hooks were restored. All three attempts were archived before fixture removal.
See [ACTIVITY-COMBINED.md](ACTIVITY-COMBINED.md) for tests, commands and limits.

## Earlier observation-only live result

The original 176,176-byte ELF was built in `activity-program-check-08` with SHA-256
`5a8acd172495a655fcc7eb93a1ccdf73d7e5bea31e26a29a2cdebc2a707605a2`.
[Original evidence](../../SOURCES.md#activity-program--2026-09-30).

The fixture keeps both hooks armed for three request/reply exchanges. It checks
`tools/call`, `resources/read`, tool names, a resource URI, both flow sides,
ID `9007199254740993`, error code `-32601`, and both values of `result.isError`.
Response bytes are sent in two pieces and compared at the client.

| Observation | Result |
| --- | --- |
| JSON completion | 6 calls; 24 records, four per call |
| HTTP handler | 63 calls; 63 records, including status and transfer completion |
| Collector | All 87 records exported and replayed with a second cursor |
| Loader | Wrong-target arm refused; no VM errors or safe returns |
| Kernel witness | Both entry patches observed and restored; process unchanged, zero restarts |
| Cleanup | Both attempts archived; all slots inactive; isolated fixture removed |

SELF witnesses cover extraction, traffic comparisons, counters and replay. Kernel
reads cover the binary, process and hook bytes. PREVAIL independently checks both
entry sections. These witnesses do not authenticate the observed agent.

Use `json_initialization_fixture.py --package … create` with both collector
arguments to recreate this isolated fixture. `json_initialization_live.py
--activity` runs `activity-program-run.sh` with both kernel witnesses. Finish with
the fixture driver's `archive-cleanup` action. The cached receipts contain the
exact sources and executed commands. Use fresh run, output and collector-source
paths. The archived fixture is not left running.

The one-row [observation format](AGENT-ACTIVITY.md) keeps correlation and identity
`unknown`. The current [combined format](ACTIVITY-COMBINED.md) adds checked
exchange correlation while identity remains unknown.
