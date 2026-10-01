# Void-return completion test

**2026-09-29 — MEASURED native result.** The test passes with GCC 13.3.0 and
clang 18.1.3 on the pinned x86-64 build box. Each compiler variant runs 24 cases
and observes 1,100 returns. The ordinary return-hook and context-contract
regressions pass. [Receipts](../../SOURCES.md#void-return-completion-test-2026-09-29).

The contract below was registered as **IDEA** before the test. It tests the
source-derived claim from [JSON-INITIALIZATION.md](JSON-INITIALIZATION.md): a
matched normal return can report a past initialization without a return value
or a post-return context read.

## Contract

Run on the pinned x86-64 build box. Link the unchanged `ls_fexit.c` and trampoline
with a void-return native fixture. The fixture supplies an entry adapter which
saves the initialization predicate beside the exact shadow-stack frame. This
adapter is a test implementation, not an installed TMM capability. The exit-program
stand-in uses only the saved predicate and original scalar arguments. It must not
read application memory or use the return register.

The fixture uses the source-derived predicate: event 57, present context and
disabled flag clear. Initialization sets the final state field before forwarding.
Keep this fixture explicitly separate from execution of the real JSON handler.

Require these cases:

- Enabled initialization: one completion, with the final write before the callback.
- Disabled initialization, absent context and another event: no initialization claim.
- Downstream changes the flag in either direction: use the saved entry value.
- Nested calls, recursion and repeated use of the same address: preserve each call.
- Downstream makes the context unreadable: the exit observer must still finish.
- A non-local exit skips a frame: no completion for the skipped call.
- Shadow-stack overflow: count it, do not invent a completion or corrupt the caller.
- Two different arbitrary return-register values: identical completion decisions.
- Entry capture omitted: unknown, never initialization-completed.

Also run the existing return-trampoline and context-contract regressions against
the same source. Save source hashes, compiler identity, commands and outputs in an
exclusive build directory. Any failed assertion fails the test. No live TMM,
admission-policy or production-coverage result follows from this native fixture.

## Falsifiers and next implementation

A wrong invocation, a skipped return reported as complete, a decision derived from
post-return fields, or a dependence on the void return register kills the candidate.
If the native test passes, use its frame-bound snapshot requirement to implement
the host entry/exit interface. That interface must expose explicit phase and valid
fields, keep entry state with the returning invocation, and reject stale state on
program replacement. Preserve ordinary return-value hooks. Qualify that integration
before using the real JSON handler to claim completed initialization.

## Results

| Case | Native result, repeated with two arbitrary return-register values |
|---|---|
| Enabled initialization | One return observation reports completion; final initialization field is set. |
| Disabled entry, then enabled downstream | No initialization claim. The later flag does not change the saved condition. |
| Enabled entry, then disabled downstream | Reports the completed initialization despite the later flag change. |
| Absent context or another event | No initialization claim. |
| Nested calls on the same address | Inner and outer conditions remain separate; returns arrive inner first. |
| Eight recursive calls | Eight correctly ordered return observations. |
| Twenty calls reusing one address | Alternating enabled/disabled entry conditions retain their own results. |
| Context changed to `PROT_NONE` downstream | The exit observer finishes without reading the protected context. |
| Non-local exit from an inner call | Only the outer return is observed; the skipped frame is reclaimed. |
| 514 recursive calls | 512 returns observed; two overflows counted; caller returns without stack desynchronization. |
| Entry capture omitted | Unknown, even though the fixture body initialized its object. |

The fixture calls the real `ls_fexit_slot1` entry trampoline. Linker wrapping adds
the test entry adapter around `ls_fexit_enter`. The unchanged core matches the
returning frame; the test observer retrieves that frame's snapshot. The void body
sets the return register to zero or `0xfedcba9876543210`. Neither value controls
the result. The observer is a native stand-in for a program, not an eBPF program.

**Limit:** these are native fixture results, not execution of the real TMM JSON
handler. The production entry-snapshot interface, bytecode verification and live
initialization test remain to be implemented and tested. Context lifetime after
forwarding and request/reply association do not follow from this result.

Build 01 stopped before compilation because the source list included nonexistent
`ls_tramp.h`. Build 02 removes it and passes. The first evidence-check invocation
also expected the filename in `repr(FileNotFoundError)`, which omits it. The
corrected checker passes on the build box and locally. Both `ask` lookups returned
**NO RECORD**. The authored preflight record retains the tracebacks' meaning.
Linker warnings from the native position-independent executables remain in the
receipt; this test does not validate TMM packaging.

## Reproduce

Check the saved results from this repository:

```bash
python3 env/ai-traffic/void_completion_verify.py
```

For a fresh native run, stage `void_completion_build.py`, this document,
`substrate/check_void_fexit.c` and `substrate/void_fexit_victim.S` together in the
prepared build-box experiment directory. Select an unused output directory:

```bash
python3 /home/starin/eob-config-20260925/void_completion_build.py \
  --discovery /home/starin/eob-config-20260925/json-initialization-discovery-02.json \
  --output /home/starin/eob-config-20260925/void-completion-build-03
```

## Implementation handoff

The mechanism question is resolved for this native fixture. Move to the host
entry-snapshot interface rather than repeat this qualification. Carry the bounded
snapshot in the same return frame, with explicit entry/return phases. Bind it to
the loaded program instance so replacement cannot consume old entry state. Keep
the completion-only return-value field invalid, and preserve ordinary value-return
hooks. Entry read failure, execution failure and missing capture must yield unknown.
