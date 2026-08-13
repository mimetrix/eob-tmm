# Joining the pieces into BNK — the integration map

### The pieces are proven on the bench; none is joined into a running TMM that shields a live CVE end to end. BNK is the first target application. This maps the unbuilt work to get there, grounded in what we already have running.

**State, stated plainly.** What exists is validated *components*, not an integrated whole:

| piece | proven | where |
|---|---|---|
| the VM, in a real TMM | yes | BNK pod — armed a shield, ran verified bytecode |
| the shield's *decision* on the CVE condition | yes, but on a **synthetic** input | BNK pod, `LS_VM_SELFTEST` |
| trampoline (the jump target) | yes | standalone, build box |
| arming (install the jump) | yes — incl. on real private `.text` via `/proc/self/mem` | build box |
| patching TMM's own `r-xp` `.text` so execution sees it | **yes** | build box (`patchtext2`) |
| the safe swap (`text_poke_bp`) under contention | yes, cross-checked to the kernel — **incl. on real private `.text`** | build box (`check_swap_realtext`) |
| **the whole Path B slice joined** — VM verdict drives an armed real function | **yes**, single-thread | build box (`check_integrated`) |
| the same **under multi-core load** — safe swap + VM in the loop, armed/disarmed live | **yes, clean** (118M calls, 5.6M mid-patch traps, 0 faults/corrupt in 20s; 20-min soak) | build box (`check_swap_integrated`) |

**Joined on the bench (2026-08-13):** the real trampoline, the real VM running a PREVAIL-verified
program, and arming on a real private-`.text` function via `/proc/self/mem` now run as one flow
(`substrate/check_integrated.c`) — the VM's verdict decides whether the hooked body runs
(FALLTHROUGH → body runs; SAFE_RETURN → body skipped, caller gets the safe value; reversible). This
is the mechanism, proven end to end, single-threaded, on the bumped ubpf (`508d5e4b`) + PREVAIL
(`v0.2.6`).

**Still not joined:** that same flow *inside a running BNK TMM*, arming an unmodified function while
traffic flows (the safe swap from `check_swap_realtext` folded into the armed path under live
multi-core load), blocking a **real CVE hit arriving over the wire**. That is the deliverable.
Everything below is how to get from the bench slice to that.

---

## 0 · The floor already in BNK

Path A runs in the pod today: VM compiled in, shield armed at a designed-in call site, and the
self-test shows the shield returning "safe" on the null-pointer condition while the same binary
crashes with the shield off. That is real and integrated — but it uses a **planted** hook and a
**synthesized** condition, not the patched-entry mechanism and not live traffic. It is the
fallback, not the target.

---

## 1 · Build side — link the Path B pieces into the BNK TMM

- **Turn on `-fpatchable-function-entry=5,0`** for the BNK TMM build. Proven to compile clean
  across 2,039 files. This is the per-build "leave a gap" step; it pads the TMM core (82–97%),
  not the separately-built components.
- **Add `trampoline_x86_64.S`, `ls_arm.c`, and a new `ls_swap.c`** (the `text_poke_bp` protocol
  extracted from `check_swap.c`) to `src/base`, register in `src/compile/filelist` with the uBPF
  include option, and add the new global-state symbols (arming slots, the patch state) to the
  whitelists. The whitelist is a manifest checked both ways — expect to add a handful.
- **Generate the trampoline's per-hook C** (`ls_tramp_dispatch`) against the real `ctx` for each
  target, from the build's DWARF — the same pipeline already used for the shield `ctx`.

## 2 · The integration blocker — SETTLED: TMM can patch its own text

**This gate is closed, on the simplest branch.** `check_swap` patched a scratch `MAP_SHARED` page
we allocated; a real TMM function lives in the binary's `.text`, mapped `r-xp` (**private**), and an
earlier probe had claimed neither `mprotect`-then-store nor `/proc/self/mem` reached the *executed*
bytes on a private page. That claim was wrong — it read the byte back with a normal load, and a
load and an instruction *fetch* can see different pages during copy-on-write, so the readback lied.

Testing *execution* instead settles it. Write `0xcc` (a breakpoint) to a real function's pad via
`/proc/self/mem`, then **call** the function — it **traps**, so the write was fetched. Measured
(`patchtext2`, build box):
- **control** — no write → the function runs, no trap;
- **patched at the pad** (offset 4, right after `endbr64` — the real `-fpatchable-function-entry`
  slot) → **SIGTRAP**, so the write is executed;
- **restored** → the function runs again, unchanged.

`mprotect`-then-store also reached the executed bytes here, but `/proc/self/mem` is the path to use:
it is what gdb uses for breakpoints, and needs no `PROT_EXEC|PROT_WRITE` relaxation that a
production node's W^X policy might deny.

And the whole safe swap now runs on this real surface. `check_swap_realtext.c` arms and disarms a
real private-`.text` function's pad through `/proc/self/mem`, 15 workers hammering it, using the
`text_poke_bp` protocol: **clean** — 163M calls, 8.9M mid-patch breakpoint traps handled, zero
faults, zero corrupt returns — while the unsafe baseline on the same surface faults in the millions
(teeth proven).

**So arming real TMM text is a syscall, not a memory-manager project.** Two narrow checks remain,
and neither is the old blocker: whether `tmm64`'s text is hugepage-backed (this is proven on 4 KB
pages), and whatever code-integrity policy the production node enforces.

## 3 · The safe swap in TMM's real threads

TMM runs N pthreads (`kern/sys.c` `pthread_create(&tmm_threads[td], …)`), one per core — exactly
the scope `membarrier(SYNC_CORE)` serialises (per-process, running siblings). Confirmed available
on the BNK node's kernel. Two forms, decide with the loop in hand:

- **`text_poke_bp` + `membarrier`** — soaked clean on the bench (§results in `safe-swap-plan.md`);
  self-contained, no poll-loop change.
- **Poll-loop rendezvous** — TMM's run-to-completion loop may offer a natural point where no thread
  is in a hooked prologue, making the swap trivially safe without the INT3 dance. Cheaper per-arm,
  but touches the loop.

The bench proved `text_poke_bp` works; the rendezvous is the "maybe simpler in situ" option to
evaluate once integrated, not to assume now.

## 4 · The SIGTRAP handler must coexist with TMM

TMM has its own signal handling, a crash agent (`crashagent`) and `apport` in the pod. The
`text_poke_bp` handler catches `SIGTRAP` on the patch bytes; it must be scoped to *only* our pad
addresses and chain to TMM's existing handler for everything else, and it must not race the crash
agent. This is real integration care, not a component we can bench in isolation.

## 5 · Arming wired to the load path

Today `ls_vm_arm` loads bytecode into a slot. Path B adds: given a target function name in a
`shield_msg`, resolve its address (from the signed hook map — item 5), and `ls_arm` the trampoline
onto its padded entry, then `ls_swap` it in safely. Extend the loader (`ls_vm_load.c`) so a `LOAD`
can carry "hook this function" and drive that path.

## 6 · Trigger the real CVE with live traffic

The shield's decision is proven on a synthetic input; the end-to-end demo needs the real path hit.
`http_psm_profile_name_lookup` runs when a security log record with `${profile_name}` in its format
is built for a flow whose listener has **no** protocol-transfer log profile. So: configure a
security log profile with that format, attach it, leave the protocol-transfer profile unset, and
drive HTTP through the Gateway path (already working). That reaches the null deref.

---

## The end-to-end demo, on BNK

One BNK TMM pod, functions padded, shield **not** compiled in (loaded at runtime):

1. Drive the CVE traffic → **TMM crashes** (baseline, unshielded).
2. Over the load path, arm the verified shield onto the function's padded entry — **no rebuild,
   no restart**, using the safe swap.
3. Drive the CVE traffic again → **no crash**, shield fire-count > 0.
4. Disarm → the crash returns.

That is the whole proposal, on the first target application, end to end. Nothing above is built;
this is the plan for building it.

---

## Order of work, and the first gate

1. **§2, the patchable-text experiment — DONE (green).** Arming real TMM text is a syscall
   (`/proc/self/mem`), not a memory-manager project, and the full safe swap runs clean on real
   private `.text` (`check_swap_realtext.c`). This also de-risks §3 down to wiring the swap into
   TMM's own threads, plus the hugepage / code-integrity checks.
2. Build side (§1) + arming wired to the loader (§5).
3. The safe swap in TMM's threads (§3) + SIGTRAP coexistence (§4).
4. The CVE trigger config (§6), then the four-step demo.

Deferred and out of this map: reclamation (freeing a swapped-out program — item 0c), aarch64 (the
DPU case — needs none of the x86 swap machinery), and every component beyond the TMM core (SSL et
al. — separate builds, separate follow-ons).
