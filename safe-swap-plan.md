# The safe swap — plan before building

### The last piece of Path B: rewrite a function's entry into a hook (and back) while other CPU cores are executing that exact code, without ever letting one of them run a half-written or stale instruction. This maps the hazards, the candidate mechanisms, the test that can actually catch a mistake, and the iterate-till-right loop.

Everything else in Path B is built and validated (`ls_arm.c`, `trampoline_x86_64.S`, both proven
on hardware). What those did **single-threaded**, this does **under live multi-core traffic**.

---

## 1 · What "safe" has to mean — three distinct hazards

Arming writes 5 bytes over the entry pad. On a running multi-core TMM, three things can go wrong,
and they need different fixes:

1. **Torn read.** A core fetches the 5 bytes mid-write and sees part-old, part-new — e.g. the new
   `call` opcode with the old (nop) bytes as its displacement, i.e. a call to a garbage address.
   *Mostly handled already:* writing the opcode byte **last** means a core either sees the old nop
   (and never interprets the following bytes as a displacement) or sees the new opcode (whose
   displacement was already written). Correct on x86 **for byte-coherent, ordered stores.**

2. **Stale prefetch / cross-modifying code.** A core may have **already decoded the old bytes into
   its pipeline** before the write. Per Intel's SDM (cross-modifying-code rules), without a
   serializing event on that core, it may execute the **stale** instruction even after the new
   bytes are globally visible. This is the hazard opcode-last does **not** fix. It needs every
   other core to serialize — a `membarrier(SYNC_CORE)`, an IPI, or a natural serialization point.

3. **A core standing inside the pad.** If a core is executing the pad bytes at the instant they
   change, behaviour is undefined. Needs a guarantee no core is *in* the window during the write.

---

## 2 · The honest constraint: testing alone is weak evidence here

This is a **concurrency + cross-modifying-code** problem, and hazard 2 in particular is **rare and
timing-dependent** — a stress test can pass a million times and still be wrong, because the stale-
prefetch window is narrow and machine-specific. So the discipline for this piece is different from
the rest of the session:

- **Correctness comes from following a documented-correct protocol**, not from "it didn't crash."
  The Linux kernel's `text_poke_bp()` is the proven answer to exactly this problem; we implement
  *that*, not something we invented.
- **The stress test's job is to catch implementation bugs and gross mistakes** (a wrong offset, a
  missing barrier, a torn read), not to *prove* cross-modifying-code correctness. Passing it is
  necessary, not sufficient.
- **The test must be shown to have teeth first** (§4): a deliberately-unsafe baseline must *fail*
  the test before we trust the test's *pass* on the safe version. A green concurrency test that
  was never shown to go red proves nothing.

This is the `execute-to-verify` rule sharpened for a race: build the thing that would fail if
we're wrong, prove it fails on the unsafe version, then make the safe version pass it.

---

## 3 · The candidate mechanisms

| | A · Poll-loop rendezvous | B · `text_poke_bp` in userspace | C · Aligned atomic + barrier |
|---|---|---|---|
| **How** | Every data-plane thread reaches a known point where it is provably not in any hooked prologue, acks, patch happens, resume | Write `INT3` over byte 0, `membarrier(SYNC_CORE)`, write bytes 1-4, barrier, write real opcode over `INT3`; a `SIGTRAP` handler covers any core that hit the breakpoint mid-patch | Single 8-byte aligned atomic store swaps all 5 bytes at once, then `membarrier(SYNC_CORE)` |
| **Handles hazard 1 (torn)** | yes — no core near the bytes | yes — INT3 is a 1-byte atomic swap | yes — atomic store |
| **Handles hazard 2 (stale)** | yes — threads serialize at the rendezvous | yes — the membarrier | yes — the membarrier |
| **Handles hazard 3 (in-pad)** | yes — quiescence guarantees it | yes — the SIGTRAP handler emulates the intended effect for a core caught mid-patch | **no** on its own — needs a story for a core in the pad |
| **Touches the poll loop** | **yes** — modifies the one loop everything runs through | no | no |
| **Standalone-testable** (no full TMM) | no — needs TMM's loop | **yes** | yes, but layout-constrained (our pad straddles the 8-byte boundary) |
| **Proven-correct precedent** | ftrace's other mode | **the kernel's live-patch path** | used in JIT patching |

**Recommendation for the iterate-till-right phase: prototype B (`text_poke_bp`) in a standalone
harness.** Reasons: it is the kernel's proven protocol, it is self-contained (does not need TMM's
poll loop, so we can hammer it in a tight test loop today), and it handles all three hazards
including a core caught mid-patch. Keep A in reserve for **integration** — inside TMM, the
run-to-completion loop offers natural quiescence points that may make the rendezvous *simpler*
in situ than it looks in the abstract. Decide A-vs-B for the final TMM form once the harness
numbers are in; do not decide it now.

---

## 4 · The test that can actually catch a mistake

A standalone harness, extending the validated `check_arm` setup:

- **An executable page** (`MAP_SHARED`, in `rel32` range of the trampoline — the setup already
  proven to work), holding the target (endbr64 + 5-nop pad + a body that returns a known value)
  and the trampoline stub.
- **K worker threads, pinned one per core**, each in a tight loop calling the target billions of
  times and checking the return is **always one of two legal values** — the body's result, or the
  safe-return value. **Anything else is corruption** and is recorded.
- **One arming thread** looping arm → disarm as fast as it can.
- **Signal handlers** for `SIGSEGV`, `SIGILL`, `SIGBUS`, `SIGTRAP`, each recording the fault and
  which mechanism was live. A worker that faults is a failed swap.
- **Run to a fixed iteration count** and to a wall-clock floor, on the real multi-core box.

**Prove the teeth first.** Before trusting a pass: run the **naive** swap (plain 5-byte store, no
barrier, no INT3, no rendezvous) under the same stress. It must eventually produce a corruption or
a fault. If it never does, the harness is not provoking hard enough — add cores, tighten the loop,
put the pad on a contended cache line — until the *unsafe* version reliably fails. Only then does
the safe version's *pass* mean something.

Caveat carried honestly (per §2): even a teeth-proven harness may not reliably provoke hazard 2 on
a given machine. So the pass criterion is **both** "clean under stress" **and** "implements
`text_poke_bp` as specified," not either alone.

---

## 5 · The iterate-till-right ladder

Each rung is a run in the break-safe dev environment; observe, then add the next layer.

1. **Baseline, unsafe.** Naive 5-byte store under full stress. *Expected: fails* (proves the
   harness has teeth). If it doesn't fail, harden the harness until it does.
2. **Opcode-last only.** Should remove the torn-read failures (hazard 1); stale-prefetch and
   in-pad may remain. Observe what's left.
3. **Add `membarrier(SYNC_CORE)`** after the write. Should close hazard 2. Observe.
4. **Full `text_poke_bp`** — INT3 dance + barriers + SIGTRAP handler. Should close hazard 3 (core
   caught mid-patch). *Expected: clean.*
5. **Soak.** Run the clean version for a long fixed count / duration across all cores. No fault, no
   corruption, arm and disarm each verified to take effect.
6. **Only then, integration.** Move into TMM behind the real hook, and re-evaluate A-vs-B given
   TMM's actual poll-loop structure.

The value of running the ladder rather than jumping to rung 4: each rung shows *which hazard each
layer actually fixed*, so the final thing is understood, not just observed-to-work. If rung 3
already goes clean and stays clean under a teeth-proven harness, that is itself a finding about
how much the INT3 dance buys us in practice.

---

## 6 · Definition of done

- The safe version is **clean under a teeth-proven stress harness** on the real multi-core box —
  billions of calls, continuous arm/disarm, zero faults, zero corrupt returns.
- The unsafe baseline **failed** the same harness (teeth proven).
- The mechanism **matches `text_poke_bp` as documented**, so correctness rests on a proven
  protocol, not only on the stress result.
- Arm and disarm are each **verified to take effect** (the earlier `check_arm` assertions) under
  concurrency, not just single-threaded.
- What is **not** claimed until TMM integration: behaviour inside TMM's real poll loop, and the
  final A-vs-B choice, both explicitly deferred to rung 6.

---

## What this does not touch

Reclamation (item 0c — freeing a swapped-out program once no core is inside it) is a separate
problem from installing the swap; it is not in this plan. And this is x86-64 only — aarch64's
aligned `NOP`↔`B` swap is inside the architecture's concurrent-modification set and needs none of
this.
