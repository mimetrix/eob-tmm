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

---

## Results — rungs 1–4 run, and cross-checked against the sources

Run on the 16-core x86-64 build box (`substrate/check_swap.c`), 2026-08-13.

| rung | mechanism | window | outcome |
|---|---|---|---|
| 1 | unsafe (opcode-first) | **natural (widen=0)** | **0 faults in 43M calls** — the race is real but its window is nanoseconds, so the test cannot see it. This is the evidence that a passing stress run is weak proof here |
| 1 | unsafe (opcode-first) | widened | **2.4M faults** — teeth proven; the harness *can* catch a torn read |
| 2 | opcode-last | widened | **2.1M faults — the hypothesis was wrong.** Any 5-byte ordering passes through a dangerous state: opcode-first is a call to garbage; displacement-first is a nop that falls through into the displacement executed as instructions. There is no safe 5-byte ordering |
| 4 | `text_poke_bp` | widened | **0 faults, 0 corrupt returns, 1.19M INT3 traps handled** — clean under the same window that broke both naive versions. The traps prove cores *were* caught mid-patch and safely redirected |

Rung 3 (opcode-last + membarrier) was skipped once rung 2 showed ordering alone cannot fix the
torn read for a 5-byte call — the `INT3` step is not gold-plating, it is required.

### Cross-checked, not just self-tested

The result above is a test I wrote passing; that is weak evidence on its own for a race. Checked
against the authoritative sources:

- **Sequence** — matches the kernel's `text_poke_bp_batch` exactly: *INT3, sync, write tail,
  sync, write first byte, sync.*
- **`membarrier(SYNC_CORE)`** — the man page guarantees "all running thread siblings have executed
  a core serializing instruction… exactly the JIT/self-modifying code use case." Registered with
  `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE` as required. It is the userspace equivalent
  of the kernel's per-CPU IPI, and its per-process scope is *better* here — it serialises only this
  process's threads, which are the only ones executing the patched text.
- **Barrier placement** — after every write, matching the kernel.

**One deliberate difference, surfaced by the cross-check.** The kernel's `poke_int3_handler`
*emulates the intended instruction* (RET/CALL/JMP) for a core caught on the breakpoint. This
harness instead redirects that core to the function body — it behaves as *unarmed* for that one
in-flight call. Safe (never executes garbage), but it means the few calls that trap during the
~microsecond arming window are not shielded. Production choice: emulate the call to shield even
those, or accept the transient. Recorded rather than shipped silently.

### What this establishes and what it does not

Establishes: the swap can be made safe under heavy multi-core contention by the proven protocol,
and a naive swap cannot — both demonstrated on real hardware and matched to the kernel's design.
Does **not** establish: behaviour inside TMM's real poll loop (rung 6, integration), the A-vs-B
choice for the final form, or that a stress pass alone proves cross-modifying-code correctness —
it does not, which is why this leans on the protocol match.

### Now confirmed on the real surface — private `.text`, patched via `/proc/self/mem`

The table above used a scratch `MAP_SHARED` page and plain stores. TMM's functions are not that:
they live in the binary's own `.text`, mapped `r-xp` (private), writable only the way a debugger
writes a breakpoint — through `/proc/self/mem`. `check_swap_realtext.c` reruns the ladder on that
real surface: a real compiled function's `-fpatchable-function-entry` pad, every patch byte written
by `pwrite` to `/proc/self/mem`, 15 workers pinned per core, same widened window.

| rung | mechanism | outcome on real private `.text` |
|---|---|---|
| 1 | unsafe (opcode-first), widened | **7.49M faults** — the harness has teeth on the real write path too |
| 4 | `text_poke_bp`, widened | **0 faults, 0 corrupt, 8.9M INT3 traps handled in 163M calls** — clean |

This closes the gap that the whole swap proof had rested on a page *we* made writable. It holds on
the surface TMM actually presents. One cost note surfaced here: `membarrier(SYNC_CORE)` per write
makes each arm/disarm far heavier than a store (72K arm/disarm cycles vs 4M in the same wall-clock),
which is irrelevant on the packet path — it is paid only at arm time — but means arming is a
syscall-bound operation, not a memory write. What is still **not** established: behaviour inside
TMM's real poll loop, whether `tmm64`'s text is hugepage-backed (proven on 4 KB pages), and the
production node's code-integrity policy.

**Sources:** kernel `text_poke_bp` (`arch/x86/kernel/alternative.c`); `membarrier(2)` man page,
`MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE`; Intel SDM Vol 3A §8.1.3, cross-modifying code.
