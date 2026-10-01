# Production entry snapshots

**2026-09-29 — MEASURED native VM tests, TMM build and package. Live admission refused.**
The contract below was registered as IDEA before implementation.
[Evidence](../../SOURCES.md#production-entry-snapshots-2026-09-29).

The objective is to save bounded entry state with the return frame. The same
loaded program can then report an action after a matched normal return.
The [native test](VOID-COMPLETION.md) establishes the mechanism with a test
adapter. This gate must use the production virtual machine and return frame.

## Contract

1. Use a separate signed target version and `fexit/snapshot/<function>` section.
   Older hosts must refuse it. Ordinary entry and value-return hooks retain
   their context layout and invocation count.
2. Keep the tracing context at 96 bytes. Arguments occupy bytes 0–39. Bytes
   40–47 are zero: this mode has no return value. Bytes 48–51 identify entry
   or return. Bytes 52–55 identify a completed entry capture. Bytes 56–63
   hold the invocation sequence. Bytes 64–95 hold 32 bytes of program state.
3. At entry, run the program on a zeroed private context. Copy only those
   32 state bytes into the matched shadow frame after successful execution.
   Program writes to arguments, phase, sequence or return value cannot change
   the saved arguments, host state, real return address or target body.
4. At return, reconstruct the context from host-owned fields. A failed entry
   execution supplies zero state and an invalid-capture flag. A successful
   execution does not itself prove that the program captured its predicate.
   The program must keep an explicit known/unknown state.
5. Bind the frame to the loaded instance and a mode-change epoch. Replacement,
   disable/re-enable, invalid identity or exhausted sequence must not transfer
   entry state to another invocation or program. Count rejected return calls.
6. Keep the 512-frame bound, skipped-return reclamation and caller transparency.
   Overflow leaves the target's normal return path intact. No allocation,
   waiting, application writes or application calls enter the hook path.
7. Admission for the new mode requires an exact `void` return, matching debug
   and runtime build IDs, a supported padded entry and complete unwind checks.
   Missing or failed tools are refusals. The ordinary admission policy remains
   a separate gate.
8. Test with pinned GCC, clang, uBPF and PREVAIL on the x86-64 build box.
   Exercise both interpreter and JIT execution. Test nesting, recursion, skipped
   returns, capacity, entry errors, replacement, mode changes, context writes,
   invalid capture, arbitrary return-register contents and unreadable context
   after the target body. Test ordinary hooks and malformed target records.

## JSON initialization probe

The output is one 96-byte record per matched return. It uses magic `0x4a494e49`,
ABI 1 and private maps `json_initialization_state` and
`json_initialization_events`. An initialization candidate makes at most three
guarded reads and reads at most nine bytes: node header at `node+44` (four),
context flags at `node+152` (four), and connection-flow side at `flow+37` (one).
Non-initialization events make no application reads. The 32-byte frame state
holds instance, configuration revision, run token, guard result and read counts.
Changed configuration invalidates the completion record. A per-program output
sequence and output-failure count allow the consumer to reject known loss.

On the qualified JSON handler build, capture event 57, context presence and the
disabled flag at entry. A matched return with a known eligible snapshot reports
completed initialization. Read application memory only at entry. Keep unknown,
disabled and other-event cases distinct. Use one bounded output attempt at return.

The [source qualification](JSON-INITIALIZATION.md#what-the-source-already-establishes)
gives the conditional proof. Recheck the source, instructions and layout against
the rebuilt binary before a live claim. A completion record reports a past action;
it does not establish that storage remains alive after forwarding.

## Falsifiers and evidence

Reject this gate if old hosts accept the new contract, ordinary hooks change
behavior, an old snapshot reaches a replacement program, capture failure becomes
known state, a context write changes caller state, or a skipped return produces
completion. Reject live initialization if entry guards do not establish the
source predicate, return code reads application storage, evidence is lost, or
the hooked process changes during the test.

```text
BUILD BOX: contract -> code -> PREVAIL + native VM tests -> TMM build + package
TMM ENTRY: private context -> program -> frame-owned state + instance identity
TMM RETURN: matched frame + same instance -> program -> bounded output attempt
COLLECTOR: journal -> replay -> exact evidence checks
```

Retain failed runs, source snapshots, commands and tool versions in unique
receipts. Archive fixture files before scoped removal. SELF witnesses cover
fixtures, programs and assertions; TOOL covers compilation and source inspection;
INDEPENDENT covers PREVAIL; KERNEL covers process and hook-memory checks.

Multiworker execution, lifetime boundaries, request association and per-call
data-path cost require separate qualification. The following results implement
part of this contract. They do not establish live initialization.

## Native result

Build 02 passes 78 cases per compiler with GCC 13.3.0 and clang 18.1.3.
The interpreter and JIT execute verified bytecode through `ls_vm.c`; the target
and output receiver are authored fixtures. The production shadow frame keeps
the 32-byte state copy and instance/epoch identity. Replacement and mode changes
reject old return calls. Failed or omitted entry capture remains unknown.

The tests include a protected post-body page, context overwrites, 514 nested
calls with two overflow cases, one skipped return, sequence/epoch exhaustion,
and an interpreter instruction-limit fault. Ordinary return/context regressions
pass. The old target parser refuses version 2. Malformed version, kind, pad,
reserved bytes and target address are refused by the new parser.

The first build omitted `ls_core_relo.c` from its link command. Its failed receipt
is retained. The corrected command links the existing module.

The JIT has no separate execution-error return channel. Its capture flag means
that the JIT call returned; the program's explicit known state remains required.
The interpreter test separately verifies its execution-error path. This gate
does not claim recovery from arbitrary native JIT faults.

Historical verifiers that compare current substrate files with their saved
source hashes will now report a source change. Their saved source snapshots and
receipts remain unchanged. Use those snapshots to replay the earlier tree.

## JSON program and packaged TMM

The JSON program passes strict PREVAIL with a 256-byte stack limit. It passes
22 native cases in each of the interpreter and JIT modes. Tests cover both sides,
entry guards, disabled-state changes, failed reads, inaccessible storage after
entry, missing capture, configuration changes and output rejection. The test
checks that return execution makes no application reads.

The six engine files were synchronized into the TMM tree. `ls_snapshot.h` is the
only new file in this integration. Toolchain `make tmm` and package/image checks
pass. Packaged build: `7bbb06a03cf8bafd7b81e09421530d7d4d891a9a`.
Runtime SHA-256: `a68bbcb1c7bd3decbbcce59cb21f26af3e153c0de537df58f0729bfab7108e18`.
Protected source/build files, including the existing HTTP2 revert, are unchanged.

Program attempt 02 checks unchanged JSON sources, the new debug layout and the
compiled guard, initialization, final-write and forwarding instructions. Binding
then refuses `_Unwind_Resume`, `__cxa_begin_catch` and `__cxa_rethrow` imports.
Full-width inspection finds the same imports in the previous packaged binary.
The old return gate hid them through shortened symbol output. It is corrected
and now refuses both binaries. Native admission controls and failed-tool tests pass.
See [`CONTESTED-PREMISES.md` §39](../../CONTESTED-PREMISES.md#39--no-unwind-imports-means-return-hook-admission-is-clear--falsified-check).

The isolated fixture was created before this refusal was inspected. The live
driver stopped at its failed-build check. No initialization program was loaded.
The fixture was archived and removed: unchanged hook, zero fires in all slots,
no collector start, and unchanged unrelated containers. The live suite is authored
but unvalidated. Source imports do not prove that an exception crosses this target;
target-specific exception reachability remains the admission prerequisite.

## Reproduce the checks

From this repository, check the saved receipts, source hashes, decoded native
records, malformed records and cleanup archive:

```sh
python3 env/ai-traffic/entry_snapshot_verify.py
```

This passes locally and on the build box: 11 receipts, 69 distinct source
snapshots, 44 JSON records and 13 malformed-record refusals. It also checks
explicit unknown results for missing identity and reported output loss.
The saved refusal is an expected result, not a successful live run.

For a fresh native run on the pinned build box, stage a new source directory
with the substrate headers/C files, snapshot tests and driver. Use a new output
directory for each attempt:

```sh
python3 entry_snapshot_build.py --source SOURCE --output NEW_NATIVE_OUTPUT
python3 json_initialization_program.py --source SOURCE --output NEW_JSON_OUTPUT
```

Add `--package PACKAGE_DIRECTORY --debug MATCHING_DEBUG_BINARY` to the JSON
driver to repeat packaged-source qualification and binding. On the recorded
binary, binding must refuse unwind imports. Do not use a failed build receipt
with the live suite. `snapshot_unwind_audit.py` captures the two recorded binaries;
`snapshot_unwind_check.py` checks corrected admission and failed-tool handling.
These drivers use the paths and toolchain pinned in their saved source snapshots.

The first local evidence check incorrectly compared a raw PTY log digest with
normalized text. Source hashes are now checked separately; the complete receipt
pins the saved log fields. The initial live-driver prerequisite assertion did not
write a receipt. The driver now records that refusal before running commands.
Both stops remain in the indexed session summary.
