# Write your first TMM eBPF program

Use [`substrate/template.c`](../substrate/template.c) as a starting point.
It reads live configuration and internal fields, keeps a counter, selects a
verdict, and attempts one metadata record on every hook call. You can change its
threshold without replacing the bytecode. There is no sampling option.

**Status — MEASURED, 2026-09-25; repaired live test passes:** both variants pass
pinned PREVAIL, interpreter/JIT checks, target binding and the isolated live test.
The repaired packaged build is `ca69b84f4f5c9e225813b2ed3997c59f18ba2a31`.
Its host fixes small HASH-table lookup, map storage after revoke, and reversed
output results. The live test gives 126 exact HTTP responses and one record for
each of 112 tutorial calls. It also checks map replacement and preserves an
active slot's count when another loaded slot is revoked. Cost and sustained
output pressure remain unmeasured. This is not a demonstrated security rule or
request identity system.
[Repair results](../SOURCES.md#unsampled-observability-repairs-2026-09-25) ·
[earlier failures](../SOURCES.md#ebpf-tutorial-2026-09-25).

## 1. Follow the data

```text
BUILD BOX
  template.c → clang-18 → resolve fields → bind target → PREVAIL → sign
                                                            │
CONTROL PROCESS                                             │ signed object
  policy JSON → local loader socket → configuration store    │
                                     │                      ▼
TMM PROCESS                          │             loaded program
  function hook → copied context ────┼───────────────────────┤
                                     ▼                      │
                          private configuration snapshot    │
                                     │                      ▼
                   memory-read helper → fields → counter → decision
                                                            │
                           host applies entry verdict ◄─────┤
                                                            ▼
                           event-output helper → shared-memory ring
                                                            │
COLLECTOR PROCESS                                            ▼
  ls_drain → JSON with binary payload → template_io.py decode → consumer
```

Only the program call and its helpers run in the traffic-processing path.
Compilation, field resolution, signature checks and configuration parsing run
outside that path. Some helpers initialize storage or refresh memory mappings;
do not assume every helper call is free of allocation or system calls.

## 2. Read the numbered sections in template.c

| Section | Capability | What to change for your program |
|---|---|---|
| 1 | Entry context; exit result at byte 40 | Match arguments to the target function's signature. |
| 2 | Six general helpers | Keep the helper signatures and IDs correct. |
| 3 | Versioned configuration through map lookup | Define and validate your own 32-byte input records. |
| 4 | Hash-map lookup, update and delete | Choose map names and keys with explicit lifetimes. |
| 5 | Fixed event format | Add an application format version; initialize every byte. |
| 6 | Named-field relocation and a two-hop memory read | Declare only the fields you need. Check every read. |
| 7 | Conditional logic and entry verdict | State what missing input and failed reads must do. |
| 8 | Monotonic timestamp | Timestamp each call; time never determines whether to emit. |
| 9 | Metadata publication and output refusal | Preserve the decision even if an event cannot be sent. |

The entry variant reads `xbuf.len`, `http_parse_ctx.version_num`, and
`http_parse_ctx.parser->header_count`. These are internal function inputs.
The buffer length is not necessarily a complete request length. The parser's
`header_count` is a parser-table field, not a count of headers in this request.
The program exports no raw pointer, request body, or credential.

The exit variant reads the function's return value as an unsigned number.
It does not dereference argument pointers: the function might have freed their
objects. Interpret a return value using the target's actual return type.

### What “all capabilities” means here

The entry build calls all six general helpers registered by `ls_map_glue.h`:
lookup (1), update (2), delete (3), read (4), clock (5), output (25).
The exit build uses five; it deliberately omits memory reads.

Some capabilities belong to the host or build tools, rather than bytecode:

- Entry and exit attachment use separate objects built from this one source.
- Type relocation, verification, signing and target binding precede LOAD.
- LOAD, ARM, status, DISARM, replacement and REVOKE use the control tool.
- The host applies a permitted entry verdict and emits its own audit record.
- Named embedded fields use the same relocation mechanism. See
  [the embedded-field tests](../embedded-traversal-validation.md).
- Use only helper IDs registered by this host. Earlier versions of this tutorial
  incorrectly pointed to the absent `shields/alpn_reach.bpf.c` example for helper
  112. That helper is not in the current general registration set.
- General ARRAY maps, helper 130, tail calls, map iteration, arbitrary network
  output and packet rewriting are not supplied by this template/runtime interface.

## 3. Build and check

Use the x86-64 build box and the versions in `substrate/vendor.pins`.
The repository alone does not contain a runnable TMM. See
[TMM build prerequisites](TMM-BUILD.md) and [the bytecode pipeline](BYTECODE-BUILD.md).

From the repository root on the build box:

```sh
export UBPF=/home/starin/code/tmm/.ubpf
export PREVAIL=/home/starin/eob-tmm-staged/ebpf-verifier/bin/prevail
python3 substrate/check_template.py --output /tmp/tutorial-check-01
```

Use a new output directory for each run. The command preserves `receipt.json`,
including failures. It compiles both variants, relocates entry fields against
deliberately different native layouts, and checks them with PREVAIL.
It then runs the actual interpreter and just-in-time compiler (JIT) paths.
The output sink is a test double. It did not expose the live bridge's reversed
success/drop result. This is not a live traffic test.

To also produce objects for a specific TMM, supply its packaged build context
and matching debug binary:

```sh
python3 substrate/check_template.py --output /tmp/tutorial-target-01 \
  --context "$CONTEXT" --debug "$DEBUG_ELF"
```

`CONTEXT` must contain `tmm64.no_pgo`, `tmm.btf`, and `hook-index.tsv` from the
same packaged build. `DEBUG_ELF` is that build's `tmm64.no_pgo.debug`.
The exit binder checks the return convention and unwind information.
Do not substitute type data from another build.

The deployable outputs are `template-entry.bpf.o` and `template-exit.bpf.o`.
They are bound and verified, but **unsigned**. The `*.bench.o`, `*.local.o`, and
`*.unrelocated.o` files are test artifacts; do not load them into TMM.

Sign each final object on the build box. For the entry object:

```sh
python3 substrate/sign_shield.py --key "$SIGN_KEY" \
  --prog /tmp/tutorial-target-01/template-entry.bpf.o \
  --hook http_parse_client_headers --mode-ceiling monitor \
  --build-min "$BUILD_PREFIX" --build-max "$BUILD_PREFIX" \
  -o /tmp/tutorial-target-01/template-entry.bpf.sig
```

Use the same signing command with the exit object and an exit signature filename
to prepare the exit variant.

`BUILD_PREFIX` is `0x` plus the first eight hexadecimal digits of the packaged
GNU build ID. The signed object also binds the full build ID. Keep the key on
the build box. Deliver the `.o` and `.sig` together. Copy `template_io.py` to
the controller/collector environment for the next steps.

## 4. Load, publish input, and attach

Use a configuration-capable TMM and an unused program slot. The commands below
run where the loader socket and delivered files are accessible. Set
`LS_LOAD_SOCKET` to that TMM's socket. Slot 5 is an example, not a reservation.
Check that the target function is available before attaching.
Use the repaired host described above. Earlier packages fail small-map lookup
and changed-layout reuse. An unused slot does not establish unused map storage:
map names and descriptor capacity are shared across the process.

```sh
python3 ls-load.py load 5 ./template-entry.bpf.o 1
python3 ls-load.py config-status 5 > identity.json
python3 template_io.py policy --identity identity.json \
  --threshold 1024 > policy.json
python3 ls-load.py config-publish 5 policy.json
python3 ls-load.py arm 5
python3 ls-load.py status 5
```

Check for a positive reply after each control operation. Mode `1` is monitor:
the host runs the program without applying its selected SAFE_RETURN.
The initial policy also leaves SAFE_RETURN selection disabled.

Send test HTTP traffic through the configured listener. Collect from the ring
owned by this test:

```sh
ls_drain --segment "$RING" --once > events.jsonl
python3 template_io.py decode < events.jsonl
```

Keep the collector's stderr: it reports drops. A separate host audit record may
accompany a selected SAFE_RETURN; the tutorial decoder skips that record.
Each ring needs one coordinated consumer. The repaired helper returns zero for
submission and a negative value for refusal. Submission does not prove that the
collector consumed the record. Check actual records and collector drop counts.
The program attempts one record per call; transport loss can still occur.

## 5. Change behavior without changing the program

Read a fresh identity before each publication. Publish a higher revision:

```sh
python3 ls-load.py config-status 5 > identity.json
python3 template_io.py policy --identity identity.json \
  --threshold 4096 > policy.json
python3 ls-load.py config-publish 5 policy.json
```

The program now tests against 4096. Every call still attempts output.
Configuration changes take effect on a later call, not in the middle of a
private snapshot. Schema 2 removes `--interval-ns`; that option is refused.
The schema-1 default was already zero, so sampling was not the default behavior.

Other options:

- `--reset-token 2`: restart the counter in each thread on
  its next call. Choose a token different from the previous one.
- `--enabled 0`: delete that thread's counter on its next call and emit a
  disabled diagnostic. This does not detach the hook.
- `--request-safe-return`: request verdict 1 for a matching entry observation.
  Use this in monitor mode to see the selection without applying it.

The policy row is `<QQQII`: threshold, reserved zero, reset token,
flags, reserved zero. Configuration schema is 2. It occupies one 32-byte row.
The program reports invalid input for schema 1 or a nonzero reserved field.
The helper can also publish data for the exit variant, using that instance's
fresh identity. Entry and exit configuration are separate.

### Verdicts are not return values

`0` means continue normal processing. `1` selects SAFE_RETURN at an entry hook.
The host supplies the configured return value to the original caller.
A policy flag cannot exceed the signed mode ceiling. Applying SAFE_RETURN
requires an enforce-capable signature, enforce mode, and a hook-specific safe
return value. The length predicate in this tutorial is not a validated reason
to reject a real request. The exit variant always returns verdict 0.

## 6. Interpret the records

The payload is 88 bytes, little-endian: Python format `<II7Q6I`.
`template_io.py decode` retains the transport fields and names each payload field.

| Fields | Meaning |
|---|---|
| `magic`, `abi` | `0x544d4d31`, format version 1 |
| `instance`, `revision` | Loaded program instance and configuration used |
| `monotonic_ns` | Program clock; do not subtract the transport's wall-clock timestamp |
| `seen` | Enabled calls counted by this TMM thread; not proof of record delivery |
| `observed`, `threshold` | Buffer length at entry, or unsigned result at exit; policy threshold |
| `result` | Function result at exit; zero at entry |
| `kind` | 1 for entry; 2 for exit |
| `version`, `header_count` | Copied parser fields at entry; zero at exit |
| `matched`, `verdict` | Comparison result and selected host action |
| `flags` | Diagnostic bit mask below |

Flags: 1 missing input, 2 invalid input, 4 failed memory read, 8 failed map
operation, 16 failed clock, 32 disabled, 64 saturated counter.
Read `flags` before interpreting zero-valued fields.
Missing input, invalid input, failed-read and disabled diagnostics also attempt
one event on every call.

## 7. Remove or replace the program

```sh
python3 ls-load.py disarm http_parse_client_headers
python3 ls-load.py revoke 5
```

The same disarm command removes either variant. Disarm before changing
entry/exit kind. Then load the
replacement, obtain its new identity, publish its configuration, and arm it.
A reload starts with no configuration. This tutorial detects the new instance
and resets its own counter state when valid input is next available.

## Limits to keep in your own program

- Input capacity is 16 records of 32 bytes, plus metadata. Validate the schema.
- Input pointers expire when the call returns. Never retain them in a map.
- The tutorial uses a one-entry HASH. Earlier hosts require the small-table fix;
  successful descriptor admission alone did not establish usable lookup.
- The template uses two of four process-global named map descriptors. Values
  are per thread. Same-name maps share storage; rename both tutorial maps for
  independent programs. Simultaneous entry and exit variants would otherwise
  reset each other's state through their different instance tokens.
- A memory mapping check does not establish object type or lifetime. It also
  does not provide the kernel's fault-recovery guarantee.
- Count hook calls, not requests, until request scope has been demonstrated.
- Output is best effort. Missing records must not acquire guessed identities.
- Registry reset requires all slots disabled, idle preparation and no active
  readers. A busy reset retains storage; revoke can be retried after calls finish.
  Generation tags reject old map references. VM-memory reclamation is separate.
  See [contested premise 23](../CONTESTED-PREMISES.md).
- Map reset adds shared atomic operations and a first-use storage clear.
  Their traffic-path cost remains unmeasured.
- Verification does not prove a time budget. No per-call cost is established
  for this tutorial.

## Recorded checks

### Repaired host and unsampled tutorial

`check-07` uses the pinned compiler, verifier and uBPF revisions below. It passes
with a one-entry HASH and schema 2. It checks 128 successive output attempts,
consecutive output refusals, old-schema refusal and the removed CLI option.
Both variants bind to the repaired packaged binary and pass final PREVAIL.

Host attempt 03 checks all 256 map capacities, collision chains after deletion,
two retained thread-local map sets across 100 replacements, stale references,
busy reset, and real output delivery/drop/off results. Its selected VM, loader,
context and ring regressions pass. It uses the existing generated shield blob;
the legacy generator's missing default source remains a separate prerequisite.
Host attempts 01–02 retain the compiler-bound and generator failures.
Configuration snapshot and socket regressions also pass.

The repaired live run first produces 16 records from eight calls through two
output maps. It then revokes that program and loads the tutorial into the same
process. This forces the HASH to reuse storage previously used by an output map.
Both entry and exit variants pass all 14 phases: 112 calls, 112 records,
16 monitor SAFE_RETURN selections and zero reported errors/drops. For these
bodyless requests, entry observations equal the independent origin's request
byte counts. Revoking a second loaded, unattached slot preserves the active
slot's count. All 126 HTTP responses match. Kernel reads show three call/NOP
cycles, restored original bytes and stable process state; restart count is zero.

Witnesses are SELF for program counters and native assertions, INDEPENDENT for
PREVAIL and the HTTP checks, and KERNEL for executable and patch bytes. Live
multi-worker behavior, output pressure, enforcement and cost remain unmeasured.
[Receipts and source snapshot](../SOURCES.md#unsampled-observability-repairs-2026-09-25).

### Earlier bench results, before the repair

`check-05` used clang 18.1.3, PREVAIL `06769f7b`, and uBPF `c900ed9f` on the
pinned build box. Four native field offsets matched the relocated instructions.
The unrelocated entry object produced the expected mismatch.
Both interpreter and JIT checks covered missing/invalid input, changed threshold,
counting, reset, deletion, sampling without a changed verdict, output refusal,
and stale-instance state. Entry checks included null and invalid nested pointers.
Exit checks used invalid argument pointers to confirm that they were not read.
The decoder consumed actual bench records and refused malformed lengths.

Witnesses: **SELF** for the bench assertions and output sink; **INDEPENDENT**
for PREVAIL. Native `offsetof` checks are independent of the relocation parser.
Target binding checked the packaged executable and matching debug file;
it did not attach either program to a running TMM.

Attempts 01–03 are retained: one missing staging header, then two small-map
failures. Attempt 04 passed the bench after the map shape changed to 256.
Attempt 05 added target binding and the input/output tool checks.

### Earlier live results, before the repair

The unchanged, target-bound attempt-05 objects were signed with a monitor ceiling.
Live attempt 01 used the existing configuration fixture and exposed map reuse.
The remaining attempts used separate SSA containers named
`eob-template-20260925-{fixture,tmm}-1`, with the same `tmm:CONFIG-20260925` image.
The new fixture used networks `10.203.75.0/24` and `10.203.76.0/24`.

Live attempt 03 completed all 14 phases. Its result is **FAIL**, with two failed
sampling checks. Completing the matrix does not turn those failures into passes.

| Check | Measured result |
|---|---|
| HTTP traffic | 118 exact HTTP 200 responses, including baseline and disarmed requests |
| Hook accounting | 112 armed calls and 112 decoded program records; zero reported VM errors or ring drops |
| Configuration | Revisions 1–6 observed in each variant; missing-input diagnostics also checked |
| Entry observations | Buffer length changes with the test requests; parser version field 0 and parser-table count 38 |
| Threshold and verdict | High threshold does not match; zero threshold matches; 16 entry selections in monitor mode, all requests still succeed |
| State | Counter advances; reset restarts at 1; disable deletes state; re-enable restarts at 1 |
| Exit | Reports result 0 on these requests; no argument-field reads and no action selection |
| Sampling | **FAIL in both variants:** eight program records instead of zero in each sampled phase |
| Cleanup | Two call/NOP cycles, restored original bytes, disarm/revoke replies, refused configuration status |
| Process | Same executable hash, process start time and container during the run; restart count 0 |

Program events and counters are **SELF** witnesses. HTTP checks use a separate
client and origin, but remain our test code. `/proc` memory/executable reads and
container state supply **KERNEL** witnesses. Exit result diversity, request
lifetime across fragments or multiplexed traffic, enforcement and cost remain
unmeasured by this tutorial.

The pinned native reproducers are `substrate/check_map_reuse.c` and
`substrate/check_output_result.c`. Both returned 1 on that host. The latter called the
real output bridge: a consumed eight-byte record accompanies result -1; a counted
full-ring drop accompanies result 0. The earlier substitute sink hid this defect.

### Repeat the live verification

The fixture scripts are under `env/ai-traffic/`. `template_prepare.py` checks the
bench receipt and signs the exact final objects. `config_build_probe.py
--map-reuse` builds the two-output-map precursor. `observability_deploy.py`
installs the checked image in the isolated tutorial fixture. `template_suite.py`
checks replacement, both variants and cleanup. `observability_snapshot.py`
retains source texts, earlier failures, final state, and build/package records.
The older `template_fixture.py` and `template_snapshot.py` describe the pre-fix
falsifier runs. Use the new scripts for the repaired host.

With that fixture prepared, run from the build box with new result names:

```sh
python3 /home/starin/eob-config-20260925/config_live_run.py \
  --suite tutorial --project eob-template-20260925 \
  --artifact-dir observability-01 --run observability-next \
  --output /home/starin/eob-config-20260925/observability-live-next.json
```

`observability-01` contains the signed objects from the recorded repaired build.
For another build, use a new artifact directory. Rebind, verify and sign against
its packaged binary before loading. Preserve nonzero exits and complete receipts.
