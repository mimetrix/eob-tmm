# Joining the pieces into BNK — the integration map

### The pieces are proven on the bench; none is joined into a running TMM that shields a live CVE end to end. BNK is the first target application. This maps the unbuilt work to get there, grounded in what we already have running.

**State, stated plainly.** What exists is validated *components*, not an integrated whole:

| piece | proven | where |
|---|---|---|
| the VM, in a real TMM | yes | BNK pod — armed a shield, ran verified bytecode |
| the shield's *decision* on the CVE condition | yes, but on a **synthetic** input | BNK pod, `LS_VM_SELFTEST` |
| trampoline (the jump target) | yes | standalone, build box |
| arming (install the jump) | yes | standalone, build box |
| the safe swap (`text_poke_bp`) under contention | yes, cross-checked to the kernel | standalone, build box |

**Not yet joined:** a single BNK TMM that patches an *unmodified* function's entry, safely arms a
verified shield onto it while traffic flows, and blocks a **real CVE hit arriving over the wire**.
That is the deliverable. Everything below is how to build it.

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

## 2 · The integration blocker — making TMM's own text patchable

**This is the piece the bench sidestepped, and it must be solved first.** `check_swap` patched a
scratch `MAP_SHARED` page we allocated. A real TMM function lives in the binary's `.text`, mapped
`r-xp` (**private**). Our earlier probes showed both `mprotect`-then-store and `/proc/self/mem`
failing to reach the *executed* bytes on a private page — the store hit a copy the CPU never
fetches.

**But that result is suspect and must be re-verified, because gdb patches private `r-xp` text via
`/proc/self/mem` every time it sets a breakpoint, and it works.** The likely flaw in our earlier
test: we read the byte back with a normal load, and a normal *load* and an instruction *fetch* can
see different pages during COW. So the real experiment is: write `0xcc` to a real function's entry
via `/proc/self/mem`, then **call the function** and see whether it traps — test *execution*, not
readback.

Three outcomes, each with a known path:
- **`/proc/self/mem` write is executed** → TMM patches its own text with no memory-manager change.
  Simplest, and most likely given gdb.
- **It is not** → TMM maps a second `MAP_SHARED` alias of its text pages and writes through that,
  or routes through the memory manager's W^X relaxation (hugepage-COW-aware). Heavier.

**Settle this experiment before anything else in Path B integration** — it decides how much of
item 2 (arm/disarm) is real work versus a syscall.

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

1. **§2, the patchable-text experiment** — a half-day test that decides whether arming real TMM
   text is a syscall or a memory-manager project. Everything else in Path B waits on it.
2. Build side (§1) + arming wired to the loader (§5).
3. The safe swap in TMM's threads (§3) + SIGTRAP coexistence (§4).
4. The CVE trigger config (§6), then the four-step demo.

Deferred and out of this map: reclamation (freeing a swapped-out program — item 0c), aarch64 (the
DPU case — needs none of the x86 swap machinery), and every component beyond the TMM core (SSL et
al. — separate builds, separate follow-ons).
