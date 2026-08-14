# The BNK integration map — what runs, what is blocked, what is left

### A verified eBPF program is loaded over a socket into a running BNK TMM, armed at a function entry while traffic flows, and disarmed again — no rebuild, no restart. What has **not** been shown is a CVE mitigated on live traffic. This is the state of the integration and the work in front of it.

**Scope:** BNK / MBIP, x86-64, `gitswarm.f5net.com/tmm/tmm` at `10.207.3-main.bdbfc7e182`. Nothing
here is established for appliance or VE — whether those share this source tree is unverified
([`big-ip-live-surface-design.md`](big-ip-live-surface-design.md) §10).

---

## Where it stands

| | state | evidence |
|---|---|---|
| The VM, in a running TMM | **runs** | `ls_vm_init` in the binary; arms a shield at startup |
| Load a program over a socket | **runs** | [`substrate/loader-client/`](substrate/loader-client/); distinct bytecode discriminated |
| Arm a function entry under traffic | **runs** | `f3 0f 1e fa e8 …` → `ls_trampoline_entry`, both pods, 0 restarts |
| Disarm and re-arm | **runs** | nops restored, fire count stops |
| The hook is really on the request path | **measured** | `http_parse_client_headers` fired **16,000 across 16,000 requests**, 1:1 |
| Loading while traffic flows | **measured** | 10 loads during 9,000 requests, 0 failures, percentiles unchanged |
| Modifies no F5 source file | **holds** | `INIT_FUNC` registration; `http_psm.c` pristine |
| A shield changing a request's outcome | **not shown** | every program armed live returns `FALLTHROUGH` by construction |
| Per-call cost of an armed hook | **unmeasured** | §7 |
| Runtime time guard (fuel) | **absent** | §7 — the JIT ignores the instruction limit |
| Signature verification | **not built** | the loader accepts unverified programs (item 4) |
| Hook map | **not built** | entry addresses supplied by hand, and they move every rebuild (item 5) |

Reproduce any row from [`REPRODUCING.md`](REPRODUCING.md).

---

## 1 · Build side

**`-fpatchable-function-entry=5,0`**, set in `CFLAGS_OPTIMIZE` in `Makefile.overrides`. As an
optimize flag it reaches **every translation unit the TMM build compiles — 100% of the code we
own.** The separately-built components (OpenSSL, dedup, the prebuilt RPMs) are untouched because
they are different builds.

> **Three numbers, measuring three different things.** The **flag** reaches **100%** of our
> translation units. **82–97%** of *emitted* functions carry a pad — the gap is functions the
> optimiser inlined or folded at `-O2`, so that is the **hookable set**. **48.9%** is whole-binary,
> which counts other teams' separately-built components as misses and therefore measures the build
> layout rather than our coverage.

Sources, `filelist` entries and the whitelist symbols are in
[`substrate/TMM-TREE-DELTA.md`](substrate/TMM-TREE-DELTA.md).

## 2 · TMM can patch its own text

The gate everything else rested on. Write `0xcc` into a real function's pad via `/proc/self/mem`,
then **call** the function: it traps, so the write was fetched. A control run with no write does not
trap, so a pass cannot be an ambient signal.

`/proc/self/mem` rather than `mprotect`-then-store, because it is what gdb uses for breakpoints and
needs no `PROT_EXEC|PROT_WRITE` relaxation that a production node's W^X policy might refuse.

The full safe swap runs on that surface: **163M calls, 8.9M mid-patch traps handled, zero faults,
zero corrupt returns**, while the unsafe baseline faults in the millions.
[`substrate/check_selfpatch.c`](substrate/check_selfpatch.c) · `make -C substrate check-selfpatch`.

The live arm settles hugepage backing and the node's code-integrity policy too: the patch lands
and executes on the datkube node.

## 3 · The safe swap in TMM's threads

**`text_poke_bp` + `membarrier(SYNC_CORE)`.** TMM runs one pthread per core — exactly the scope
`membarrier` serialises — and the BNK node's kernel supports it. It needs **no poll-loop change**,
which is why it won.

A *poll-loop rendezvous* is the cheaper alternative per arm, since TMM's run-to-completion loop has
a natural point where no thread is inside a hooked prologue. It costs a change to the loop, and is
available if arming ever becomes frequent enough to justify one.

## 4 · SIGTRAP coexistence

TMM has its own signal handling, plus `crashagent` and `apport` in the pod. Measured on the running
pod with [`env/scripts/bnk-check-sigtrap.sh`](env/scripts/bnk-check-sigtrap.sh):

- **No poll thread blocks SIGTRAP**, so a mid-patch trap can be delivered. Had one blocked it, the
  kernel would force the default action and kill the process — that would have ended the approach,
  not been a bug to fix.
- **Three threads already catch it.** Our handler must chain to the existing one for any address
  that is not one of our pads, or we break crash reporting for faults unrelated to us.
- A non-poll housekeeping thread masks nearly every signal. Expected and harmless — it never
  executes hooked text. **Judge this per thread role**; a whole-process count reads as a false alarm.

## 5 · Arming wired to the load path

`ls_vm_load.c` takes a `LOAD` naming a target function; `ls_arm`/`ls_swap` install the trampoline on
its padded entry.

**Preparation cannot run on the loader thread.** `ubpf_create`/`ubpf_load_elf`/`ubpf_compile_ex` all
allocate, and TMM aliases `malloc` to its own per-core allocator whose spinlock is never initialised
on a thread we create — the loader spins forever. Work is handed to a TMM poll thread through a
prepare/complete structure driven by a periodic timer ([`load-path-scope.md`](load-path-scope.md) §5).

That constraint generalises and is the one to remember: **anything on a thread TMM did not create
must avoid the allocator.** Use `mmap`.

**Still stubbed:** the entry address comes from configuration, not a signed hook map. Item 5.

## 6 · Triggering a real CVE — blocked on BNK

The demonstration needs a CVE whose trigger is drivable from outside a BNK pod: on a code path
reachable through the supported configuration surface — CRDs and traffic — with no dependency on a
knob this form factor does not expose. An SPK advisory list is what would settle which candidates
qualify.

Failing that: appliance or VE, which first needs the source-tree question answered
([`big-ip-live-surface-design.md`](big-ip-live-surface-design.md) §10); or driving a trigger from
inside via a test-only hook, reported as synthetic.

Until one lands, **"it stops the crash" is unproven end to end.**

## 7 · Cost and the runtime guard

**Per-call cost is unmeasured.** The counter mean is dominated by preemption artifacts (`cycles_max`
of 1.09M against a mean of 1,134), and the bench op that would give a clean minimum still runs on
the loader thread and wedges it. Quote no per-call number until that is fixed.

Bench figures that *do* hold, with their caveats: **~10 ns JIT / ~48 ns interpreter**, for a
9-instruction program, warm cache, no contention, the VM entry **only** — no `ctx` build, no
trampoline, no poll loop. A floor for the smallest useful program, not a hook cost.

**There is no runtime time guard.** `ls_vm.c` calls `ubpf_set_instruction_limit()`, but that limit
has no effect once a program is JIT'd, and the JIT is on. The startup line reports this honestly
(`jit=1 fuel=0`). The consequence is worth stating plainly rather than leaving to be inferred: **an
armed hook is currently unbudgeted at runtime.** That is acceptable for a `FALLTHROUGH`-only program
on a warm path, and it is not acceptable for enforce mode on an attacker-reachable branch. Item 15 —
back-edge fuel in the JIT — is what closes it.

---

## The end-to-end demonstration

One BNK TMM pod, functions padded, the shield **not** compiled in:

| | step | state |
|---|---|---|
| 1 | Drive the CVE traffic → TMM crashes | **blocked** (§6) |
| 2 | Arm the verified shield over the load path — no rebuild, no restart | **runs** |
| 3 | Drive it again → no crash, fire count > 0 | **blocked** (§6) |
| 4 | Disarm → the crash returns | **runs** (the disarm half) |

Steps 2 and 4 are the mechanism and they work. Steps 1 and 3 are the outcome and they wait on a
reachable target.

## What is left

1. **A reachable CVE** (§6) — gates the demonstration.
2. **The hook map** (item 5) — a parameter classifier over DWARF against an optimised build; the
   least-proven engineering assumption in the package, and what removes hand-supplied addresses.
3. **Back-edge fuel in the JIT** (item 15) — the runtime time guard, without which no hot or
   attacker-reachable hook can be armed in enforce mode.
4. **Signature verification** (item 4) — the perimeter, and why the load socket is environment-gated
   and off by default.
5. **Per-call cost** (§7) — needs the bench op moved onto the prepare handoff.

Deferred and out of scope here: reclamation of a swapped-out program (item 0c), aarch64 (the DPU
case, which needs none of the x86 swap machinery), and every component outside the TMM core.
