# Joining the pieces into BNK — the integration map

### The mechanism is joined into a running BNK TMM. What is *not* joined is the outcome: no CVE has been shielded on live traffic. This maps what remains, grounded in what runs.

> **Status update — 2026-08-13.** When this map was written, its premise was "the pieces are proven
> on the bench; none is joined into a running TMM." That premise is now **false for the mechanism
> and still true for the outcome**, and the difference is the whole point of the map:
>
> - **§1–§5 are built and running.** A shield is loaded over a socket into an already-running BNK
>   TMM, armed at a function entry while traffic flows, and disarmed again — no rebuild, no restart.
>   A hook armed on `http_parse_client_headers` fired **exactly once per request across 16,000
>   requests**; 10 loads during 9,000 requests produced 0 failures with latency percentiles
>   unchanged; both pods, 0 restarts. The substrate modifies **no F5 source file**.
> - **§6 is not, and its premise was wrong** — see that section.
> - **Path A (designed-in call sites) was removed**, so the "floor" §0 described no longer exists.
> - **Per-call hook cost is still unmeasured.** Quote no per-call number
>   ([`load-path-scope.md`](load-path-scope.md) §7).

**State when this map was written.** Validated *components*, not an integrated whole — kept because
the bench evidence is what each in-TMM step was built on:

| piece | proven | where |
|---|---|---|
| the VM, in a real TMM | yes | BNK pod — armed a shield, ran verified bytecode |
| the shield's *decision* on the CVE condition | yes, but on a **synthetic** input | BNK pod, `LS_VM_SELFTEST` |
| trampoline (the jump target) | yes | standalone, build box |
| arming (install the jump) | yes — incl. on real private `.text` via `/proc/self/mem` | build box |
| patching TMM's own `r-xp` `.text` so execution sees it | **yes** | build box ([`substrate/check_selfpatch.c`](substrate/check_selfpatch.c), `make check-selfpatch`) |
| the safe swap (`text_poke_bp`) under contention | yes, cross-checked to the kernel — **incl. on real private `.text`** | build box (`check_swap_realtext`) |
| **the whole Path B slice joined** — VM verdict drives an armed real function | **yes**, single-thread | build box (`check_integrated`) |
| the same **under multi-core load** — safe swap + VM in the loop, armed/disarmed live | **yes, clean** (118M calls, 5.6M mid-patch traps, 0 faults/corrupt in 20s; 20-min soak) | build box (`check_swap_integrated`) |

**Joined on the bench (2026-08-13):** the real trampoline, the real VM running a PREVAIL-verified
program, and arming on a real private-`.text` function via `/proc/self/mem` now run as one flow
(`substrate/check_integrated.c`) — the VM's verdict decides whether the hooked body runs
(FALLTHROUGH → body runs; SAFE_RETURN → body skipped, caller gets the safe value; reversible). This
is the mechanism, proven end to end, single-threaded, on the bumped ubpf (`508d5e4b`) + PREVAIL
(`v0.2.6`).

**Still not joined:** blocking a **real CVE hit arriving over the wire**. Arming an unmodified
function inside a running BNK TMM while traffic flows is done (§1–§5); what remains is the outcome,
and §6 explains why it is not reachable on this target.

---

## 0 · The floor already in BNK — REMOVED, 2026-08-13

**This section described Path A, which no longer exists.** A VM compiled in with the shield armed at
a *designed-in call site* did run in the pod, and its self-test showed the shield returning "safe"
on the null-pointer condition while the same binary crashed with the shield off. It was deleted
anyway. Two reasons, and the second is the sharper one: its reach was fixed at build time, so it
could only ever shield functions someone thought to plant a call site at — which is precisely what a
CVE is not; and it mitigated the bug **whether or not anything was armed**, which makes it
impossible to demonstrate that arming did anything. See
[`mechanism-tradeoff.md`](mechanism-tradeoff.md) for the full decision record.

There is no fallback now. The patched entry is the sole mechanism.

---

## 1 · Build side — link the Path B pieces into the BNK TMM

- **Turn on `-fpatchable-function-entry=5,0`** for the BNK TMM build, via
  `CFLAGS_OPTIMIZE` in `Makefile.overrides`. Being an optimize flag, it applies to **every
  translation unit the TMM build compiles — 100% of the code we own**, with the separately-built
  components (OpenSSL, dedup, the prebuilt RPMs) untouched because they are other builds entirely.
  **Do not restate that as "it pads the TMM core (82–97%)."** Those are two different measurements
  and conflating them understates our own reach: the flag reaches 100% of our translation units,
  and **82–97% of *emitted* functions carry a pad** because at `-O2` the optimiser inlines or folds
  the rest away. The shortfall is the optimiser's, not the flag's.

  > **Unresolved, and flagged rather than smoothed over:** the file count differs across documents —
  > four say **2,039**, [`live-patch-runbook.md`](live-patch-runbook.md) says **2,041**, and the
  > current `filelist` carries **1,710** `.c`/`.S` entries with 1,705 objects built. The provenance
  > of 2,039 is not recoverable from the present tree, so all three should be treated as
  > unverified until someone re-counts against a named build. The *100%* claim does not depend on
  > the count and is checkable directly from `Makefile.overrides`.
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
([`substrate/check_selfpatch.c`](substrate/check_selfpatch.c), build box):
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

**So arming real TMM text is a syscall, not a memory-manager project.** The two narrow checks this
section left open — whether `tmm64`'s text is hugepage-backed, and whatever code-integrity policy
the node enforces — are **both settled in the affirmative by the live arm**: the patch lands and
executes on the datkube node, verified byte-for-byte (`f3 0f 1e fa e8 f0 6c 75 ff`, call target
resolving to `ls_trampoline_entry`).

## 3 · The safe swap in TMM's real threads

TMM runs N pthreads (`kern/sys.c` `pthread_create(&tmm_threads[td], …)`), one per core — exactly
the scope `membarrier(SYNC_CORE)` serialises (per-process, running siblings). Confirmed available
on the BNK node's kernel. Two forms, decide with the loop in hand:

- **`text_poke_bp` + `membarrier`** — soaked clean on the bench (§results in `safe-swap-plan.md`);
  self-contained, no poll-loop change.
- **Poll-loop rendezvous** — TMM's run-to-completion loop may offer a natural point where no thread
  is in a hooked prologue, making the swap trivially safe without the INT3 dance. Cheaper per-arm,
  but touches the loop.

**Settled: `text_poke_bp`.** It is what runs in the pod, and it needed no poll-loop change. The
rendezvous was never built — it stays on the list as a possible simplification, not a gap.

## 4 · The SIGTRAP handler must coexist with TMM

TMM has its own signal handling, a crash agent (`crashagent`) and `apport` in the pod. The
`text_poke_bp` handler catches `SIGTRAP` on the patch bytes; it must be scoped to *only* our pad
addresses and chain to TMM's existing handler for everything else, and it must not race the crash
agent. This is real integration care, not a component we can bench in isolation.

## 5 · Arming wired to the load path

**Built.** `ls_vm_load.c` takes a `LOAD` carrying a target function, and `ls_arm`/`ls_swap` install
the trampoline on its padded entry. One correction to the plan as written: preparation
(`ubpf_create`/`ubpf_load_elf`/`ubpf_compile_ex`) **cannot run on the loader thread** — TMM aliases
`malloc` to its own per-core allocator, whose spinlock is never initialized on a thread we create,
so the loader spins forever. Work is handed to a TMM poll thread through a prepare/complete
structure driven by a periodic timer ([`load-path-scope.md`](load-path-scope.md) §5).

**One piece is still stubbed:** the address comes from configuration, not from a signed hook map —
item 5 is unbuilt, and the entry address has moved with every rebuild.

## 6 · Trigger the real CVE with live traffic — BLOCKED, and the earlier premise here was wrong

**The premise this section originally stated was never verified.** It said the fault is reached by
configuring a security log profile with `${profile_name}` in its format, attaching it, and *leaving
the protocol-transfer profile unset*. That was carried forward from an earlier discussion and
asserted without checking. Two corrections:

**What the defect actually is.** The caller reads
`flow_get_listener(cf)->prot_transfer_log_profile` into a local and guards *that local*; the callee
re-reads the live listener state. So an unset profile is **not** the trigger — the guard covers it.
The window is a **check-then-reread race**: the profile is released between the caller's check and
the callee's read. And `fw_log_release_protocol_transfer_from_listener()` **frees before it nulls**,
so the window carries a use-after-free as well as a null dereference.

**Why it is not reachable on BNK.** `prot_transfer_log_profile` has **no Kubernetes CRD field** on
this form factor, so there is no supported way to attach one — and therefore no way to release one
mid-flow. The race cannot be driven from the outside here at all.

**Consequence for the demo below:** on BNK the crash→arm→no-crash→disarm sequence cannot be run
against this CVE. Closing it needs either a different target CVE that is reachable on BNK, or a form
factor (appliance/VE) where the profile is configurable. **Until one of those happens, "it stops the
crash" remains unproven end to end** — the standing negative repeated throughout this repo.

---

## The end-to-end demo, on BNK

One BNK TMM pod, functions padded, shield **not** compiled in (loaded at runtime):

1. Drive the CVE traffic → **TMM crashes** (baseline, unshielded).
2. Over the load path, arm the verified shield onto the function's padded entry — **no rebuild,
   no restart**, using the safe swap.
3. Drive the CVE traffic again → **no crash**, shield fire-count > 0.
4. Disarm → the crash returns.

That is the whole proposal, on the first target application, end to end. **Steps 2 and 4 are built
and demonstrated** — arming and disarming a real function over the load path, no rebuild, no
restart, under live traffic. **Steps 1 and 3 are not**, because the CVE they name cannot be
triggered on BNK (§6). What the mechanism does when the fault arrives is therefore still a claim,
not a result.

---

## Order of work, and the first gate

1. **§2, the patchable-text experiment — DONE (green).** Arming real TMM text is a syscall
   (`/proc/self/mem`), not a memory-manager project, and the full safe swap runs clean on real
   private `.text` (`check_swap_realtext.c`). This also de-risks §3 down to wiring the swap into
   TMM's own threads, plus the hugepage / code-integrity checks.
2. **Build side (§1) + arming wired to the loader (§5) — DONE.** Loaded and armed over a socket
   into a running TMM, under traffic.
3. **The safe swap in TMM's threads (§3) + SIGTRAP coexistence (§4) — DONE.** Arm/disarm/re-arm on
   both pods, 0 restarts.
4. **The CVE trigger (§6) — BLOCKED, not merely pending.** Not reachable on BNK; needs a different
   target CVE or a different form factor. This is the gate on the four-step demo, and the reason
   "it stops the crash" is still unproven.

Deferred and out of this map: reclamation (freeing a swapped-out program — item 0c), aarch64 (the
DPU case — needs none of the x86 swap machinery), and every component beyond the TMM core (SSL et
al. — separate builds, separate follow-ons).
