# Programs and hook attachments

Status: **MEASURED in native/socket tests and isolated live TMM**, 2026-09-30.
This contract was written before implementation. The earlier ROADMAP status is
superseded by [the recorded checks](../SOURCES.md#program-ownership-and-tmm-build-2026-09-30).
The [packaged live result](../SOURCES.md#program-ownership-live-validation-2026-09-30)
covers two owners and two entry hooks on one worker. Multiple workers and
sustained data-path cost remain unqualified.

A **program** is one signed ELF object. It owns its configuration, maps and entry
programs. An **attachment** connects one entry program to its signed function
entry. A **site** is the patched function entry. Several programs can use a site.
The uBPF library still compiles each entry program into a separate VM instance.
Those instances belong to one program; they are not separate loaded programs.

## Contract

- Load all entry programs before publishing the program. A failed load publishes
  none and releases the VMs it created. Loading does not attach hooks.
- Give each successful load a new instance identity. Control requests must name
  that identity. A stale request cannot change a replacement program.
- Share maps by name only within one program. The same name in another program
  has separate storage. Configuration belongs to the program, not an attachment.
- Allow independent attach and detach operations. Attach only to the function
  authenticated for that entry program. Repeated attachment is an error.
- At a shared site, call each attached program once, in program-index order.
  Give each call a fresh context copy. A context write by one program cannot
  change the input of another program or the application's registers.
- Monitor programs cannot suppress the function body. Enforce programs can select
  SAFE_RETURN. All attachments at a shared site must agree on the safe return
  value. Continue to run observers after a SAFE_RETURN selection.
- Detaching one program must leave other programs at that site attached. Restore
  the original pad only when the last attachment leaves.
- Revoke disables the whole program, detaches its hooks and releases its VMs only
  after its calls finish. A failed text restore retains site ownership for retry.
  Per-thread map allocations are bounded and reused with a new generation.
- A data-path call never waits for control work. A busy control operation returns
  an error. Preparation occurs on the existing TMM prepare thread.
- Legacy slot operations remain separate. They cannot replace a program-owned
  entry or disarm a program-owned site.

Initial bounds: eight programs, twelve entry programs per program, and twelve
simultaneously patched sites shared with legacy hooks. These are distinct limits.
Only function-entry attachments are in this contract. Return-hook admission keeps
its current limits. No per-call cost or multi-worker TMM result is claimed.

A site used by this model remains reserved against legacy attachment for the
process lifetime. Program-owned attachments can reuse it after detachment.
This reservation protects delayed trampoline calls. Initialization is exercised
on one live worker. Multiple workers, sustained concurrency and loader-timeout
stress still need live qualification.

## Falsifiers and checks

The implementation fails this contract if any of these checks fail:

1. Two programs each attach two functions and receive the expected calls.
2. The two entries of a program share a map; another program with the same map
   name cannot read or change that map.
3. Two programs share a function. Detaching or revoking either leaves the other
   running. The last detach restores the original instruction bytes.
4. A context-writing program cannot change the next program's input.
5. A wrong instance, unsigned target, duplicate attachment, full table or failed
   entry load is refused without changing another program.
6. Repeated load/revoke cycles reuse bounded storage. Old map handles and control
   identities cannot access the replacement.
7. An in-flight call prevents reclamation. A late trampoline call from a former
   site cannot run programs attached to a different function.

Run native checks with pinned GCC, clang, uBPF and PREVAIL on the build box.
Native checks are not a TMM traffic result. Record a separate receipt for each
build and live fixture run.

## Measured build and reproduction

Native checks 09 and 10 pass on the pinned x86-64 build box. They exercise the
contract above through both interpreter and JIT paths. Check 10 includes signed
socket loading and compiles the loader without a command-line `_GNU_SOURCE`.
It also repeats the existing activity, context, trampoline and return-hook tests.
The fixture script uses recorded build-box dependency paths; it is not a portable
fresh-host installer.

Run it from an isolated source snapshot. Select a new output directory:

```bash
python3 "$SOURCE/substrate/check_programs.py" --output "$NATIVE_OUTPUT"
```

`SOURCE` is the source snapshot root. `NATIVE_OUTPUT` must not exist. Keep the
result receipt and all source hashes. The snapshot must include the CLI under
`env/scripts/ls-load.py`, as well as the substrate sources and test dependencies.

The incremental TMM driver is
[`build-programs-integration.py`](../env/scripts/build-programs-integration.py).
It requires explicit source, TMM tree, staged source, native receipt, receipt
hash, TMM revision, toolchain container and new output paths. Use `--help` for
the complete argument list. Its first-run preconditions expect the previous
activity host. An already-integrated tree requires `--previous` and
`--previous-sha256`; its source and whitelist hashes must match that receipt.
`--verify-built` checks a prior successful compile without running it again.

The driver copies ten selected source files, including two new headers. It
registers `g_programs` in both globals whitelists and removes `g_prog_stack`,
which is now thread-local storage (TLS). It invalidates substrate objects and
`harness.o`, then runs top-level `make tmm` through the Docker toolchain.

**Result:** build `5784e768cc4f5c25993aef7dfb050c54a14042ea` passes linked
function, TLS, globals and twelve trampoline checks. The saved binary is
`/home/starin/eob-config-20260925/programs-integration-03/tmm.no_pgo`.
Its SHA-256 is
`1dcd0231627fc55a25beeba621c225365e929c5100ff156a4c69864d20772966`.
The build preserves the existing HTTP/2 CVE-fix revert. No new live ownership
result follows from this compile. The earlier activity traffic used separate
legacy instances and does not qualify this model.

## Live ownership gate

Registered before the live run: package the checked sources, then load the same
two-entry test ELF as two independent owners in the isolated single-worker
HTTP/1 fixture. Bind its entries to JSON completion and the AIMCP handler.
Use distinct configuration values and a shared counter map within each owner.

Reject the result if response bytes change, either entry is absent, sequences
skip, one owner's configuration or context writes reach another, or removing an
attachment stops the other owner. Test detach, reattach, mode changes, revoke,
reload with a fresh instance and stale-control refusal. The remaining owner
must continue its sequence. Both final entry pads must match their original
bytes, with the same process start time and no restart. Archive the result
before removing the isolated fixture. This gate does not qualify multiple
workers, sustained load, collector durability or application-field extraction.

## Measured live result

The package and live gate pass. Packaging rebuilds the runtime, so the packaged
build ID is `2ab960fa38e447bab97738e47e1d5b2ce25c401a`, not the earlier linked
build ID. The saved package directory on the build box is
`/home/starin/eob-config-20260925/programs-package-01`.

| Artifact | Location or identity |
|---|---|
| Image tag | `tmm:PROGRAMS-20260930` |
| Image ID | `sha256:0b96d57129bc62948f7bb38d7e8dbe4baa9dae5e1aeaed81b0c64b90018c1217` |
| Runtime ELF | `image-context/tmm64.no_pgo` under the package directory |
| Runtime SHA-256 | `50d5d1e711dc4a79adf1bd1bb30f6c306d36ad75bbda8e7d03998e88a5124fc8` |
| Saved DEBs | `debs/` under the package directory |
| Matching debug ELF | `debug/usr/lib/debug/usr/bin/tmm64.no_pgo.debug` under the package directory |

One signed ELF supplies two entries: `json_filter_handle_json_complete` and
`hud_aimcp_handler`. Its executable sections are the native-tested program's
unchanged bytes. The final bound entries pass pinned PREVAIL. Owner 0 uses
configuration marker 101; owner 1 uses 202. Replacement owner 0 uses 303.
All 18 requests reach the backend with the expected body. Each reply has HTTP
status 200 and the expected response body.

| Phase | Requests | Hook records | Required result |
|---|---:|---:|---|
| Both owners, both hooks | 4 | 184 | Separate markers and counters; shared per-owner state across entries |
| Detach owner 0's JSON entry | 2 | 88 | Its HTTP entry and both owner 1 entries continue |
| Reattach the JSON entry | 2 | 92 | Both owners continue their sequences |
| Revoke owner 0 | 2 | 46 | Owner 1 continues |
| Reload owner 0 | 2 | 92 | New instance, marker and sequence; owner 1 continues |
| Disable owner 0 | 2 | 46 | Only owner 1 emits |
| Re-enable owner 0; revoke owner 1 | 2 | 46 | Owner 0 continues |
| Revoke the last owner | 2 | 0 | Traffic continues; no program emits |

Total: **594 records**. The two recorded context fields match at shared calls
despite the first program writing those fields in its input copy.
Duplicate attachment, an enforce request above
the signed monitor ceiling, wrong/stale instances and stale configuration are
refused. Final owner status is empty in all eight slots. Independent process
memory reads show both original entry pads restored. Process start time is
unchanged and restart count is zero. The twelve-file archive is checked before
the two-container fixture, networks and volumes are removed.

The first two attempts stopped before program loading. One lint command lacked
the test module directory. The runner then replaced Tao's inherited module
path and hid `declTmm_base_pb2`. The corrected runner extends that path.
Both failures remain in the [receipt index](../SOURCES.md#program-ownership-live-validation-2026-09-30).

This test uses a dedicated ring drain. It does not revalidate activity-field
extraction or collector durability. Live enforce composition, multiple workers,
sustained load/cost and loader-timeout stress remain open.

### Reproduce in the prepared build environment

Use isolated source snapshots and new output names. The complete executed
arguments and source hashes are in the receipts. These are the stage interfaces:

```bash
python3 "$SOURCE/env/scripts/package-programs.py" \
  --source "$SOURCE" --tree "$TMM" --build "$BUILD_RECEIPT" \
  --output "$PACKAGE" --image "$IMAGE_TAG"
python3 "$TEST_SOURCE/env/ai-traffic/programs_live_build.py" \
  --source "$SOURCE" --package "$PACKAGE" --native "$NATIVE_OUTPUT" \
  --output "$ARTIFACTS"
python3 "$TEST_SOURCE/env/ai-traffic/programs_fixture.py" \
  --package "$PACKAGE" --output "$CREATE_RECEIPT"
python3 "$TEST_SOURCE/env/ai-traffic/programs_live_run.py" \
  --run "$RUN" --source "$TEST_SOURCE" --artifacts "$ARTIFACTS" \
  --package "$PACKAGE" --output "$LIVE_RECEIPT"
python3 "$FIXTURE_ROOT/json_initialization_fixture.py" \
  --package "$PACKAGE" archive-cleanup --output "$CLEANUP_RECEIPT" \
  --archive "$ARCHIVE" --live "$LIVE_RECEIPT"
```

`SOURCE` contains the packaging scripts, Docker files and substrate dependencies.
`TEST_SOURCE` contains the ownership test scripts. `TMM` is the selected build
tree. `BUILD_RECEIPT` is integration verification 03; `NATIVE_OUTPUT` is native
check 10. The drivers pin these receipts. `FIXTURE_ROOT` is the existing
`/home/starin/eob-config-20260925` SSA workspace, with its recorded Compose files,
Tao image, configuration modules and environment file. `PACKAGE`, `ARTIFACTS`
and `TEST_SOURCE` must be under this root for its read-only `/work` mount.
`IMAGE_TAG`, `RUN`, all receipt paths and `ARCHIVE` must be new names selected
for the run. This procedure assumes the prepared lab; it is not a fresh-host
installer. Keep signed bytecode and the private signing key on the build box.
