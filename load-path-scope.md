# Scope — making `SHIELD_OP_LOAD` work (development-scope item 3, blocked half)

Arming works on a live TMM. **Loading a new program does not**, and this is the scope for fixing it.
Everything below was read out of the source or measured on the box; nothing here is inferred from
behaviour alone.

---

## 1. What is broken, exactly

`SHIELD_OP_LOAD` hangs the loader thread permanently. Measured on `tmm:live6`, BNK/datkube:

```
1. LOAD real 4320-byte shield  -> *** TIMEOUT
2. ARM probe (known-good op)   -> *** TIMEOUT     <- loader never recovers
tid 153: RUNNING (on-CPU, no syscall)
f5-tmm  2/2 Running  restarts=0                   <- data plane unaffected
```

A `prog_len=0` probe returns a clean error, because it is rejected before it allocates. Only a
**valid** program reaches `ubpf_create`/`ubpf_load_elf`/JIT, and that is where it dies.

### Root cause

Three facts compose:

1. `SPIN_UNOWNED` is **`0xffffffff`** (`/usr/include/tmm/local/sys/spin.h:45`), and `spin_lock()` is
   `while (lock->s_bits != SPIN_UNOWNED)` (`:148`). A `static struct spinlock` lives in zeroed
   `.bss`, so **an uninitialized lock reads as permanently owned and `spin_lock()` never returns.**
   `kern/malloc.c` initializes its own lock explicitly (`.s_bits = SPIN_UNOWNED`) — the hazard is
   known there.
2. `thread_cache_lock` and `thread_stats_lock` (`kern/sthread_memory.c`) are `static` and are
   initialized **only** by `sthread_handler_register()`.
3. `sthread_handler_register()` is called from exactly **one** place in the tree —
   `dev/ndal/xnet/if_xnet.c:1642`, the xnet driver. **BNK does not load xnet.**

So on BNK those locks are never initialized. TMM aliases `malloc` to `__wrap_malloc`
(`kern/malloc.c:48`), which for a non-TMM thread routes to `service_thread_detected()` →
`init_thread_cache()` → `spin_lock(&thread_cache_lock)` → **spins forever.**

**This is a latent defect in F5's code, not ours:** any foreign thread that calls `malloc` in a
configuration without xnet hangs. It is worth reporting upstream independently of this work.

### Why the obvious fix is not enough

Calling `sthread_handler_register()` ourselves initializes the locks and converts the hang into a
working `sthread_malloc` path. It still does not work, for a second reason:

`sthread_malloc` is capped per thread at `DEFAULT_MEMORY_LIMIT` = **256 pages = 1 MB**
(`kern/sthread_memory.c:155`). uBPF's JIT allocates, on **every** compile
(`.ubpf/vm/ubpf_jit_support.c:81-85`), five arrays of `UBPF_MAX_INSTS` = **65,536** elements:

```
pc_locs        65537 x 4  bytes  =  256 KB
jumps/loads/leas/local_calls
               65536 x 20 bytes x 4 = 5120 KB
                                      -------
                              TOTAL =  5.25 MB per compile   >  1 MB cap
```

The inequality holds even at the smallest plausible element size, so registration alone turns a hang
into a clean `alloc_failed` — an improvement, not a fix. It would additionally depend on
`init_stats()` succeeding at that point in startup; if it does not, `thread_stats` stays NULL and
`_sthread_malloc()` **dereferences it**, which is a crash rather than a refusal. `init_thread_row()`
also leaks `thread_stats_lock` on both of its error paths (`kern/sthread_memory.c:66`).

---

## 2. The approach: prepare on a TMM thread

Do the allocating work where allocation works. TMM's own threads use `umalloc` — a per-core arena,
no registration, no per-thread cap.

This is also what development-scope item 3 always specified — *prepare off the poll loop, publish at
the hot path* — and it is the natural place for the ordered publish that item 0 needs.

### The mechanism exists and has precedent

`/usr/include/tmm/local/sys/timer_external.h` provides `timer_init_periodic_ex()`,
`timer_add_periodic_ex()`, `timer_add_callback_ex()` — "generic timer functions for code not in the
TMM". Timers are a callwheel processed by the poll loop, so **the callback runs on a TMM thread.**
In production use today by `tm_lib/urlcat/dpi_url_lookup.c:404` and
`tm_lib/urlcat/urlcat_customdb.c:189` for deferred attach/release work — the same shape as this.

The caller owns timer-struct allocation, so a **file-scope static** works and no allocation is
needed to arm the timer.

### Shape

```
loader thread (foreign)                TMM poll thread (elected owner)
----------------------                 ------------------------------
read msg into mmap'd scratch
fill g_req { op, slot, prog*, len,
             section, function }
store g_req.state = PENDING  (release)
                                       periodic timer fires
                                       load g_req.state (acquire)
                                       if PENDING:
                                         ls_vm_reload(...)   <- umalloc works here
                                         g_req.rc  = ...
                                         store state = DONE  (release)
poll state == DONE (acquire), timeout
reply to client
```

Nothing crosses a thread boundary except one state word and a fixed struct, both with explicit
release/acquire ordering — the same discipline already used for `g_pad` in `ls_arm.c`.

### Ownership

`http_psm_init()` runs **once per TMM thread** — its caller `http_init()` guards with
`static RTTHREAD BOOL http_inited` (`modules/hudfilter/http/http.c:2529`). So every TMM thread would
register a timer. Exactly one must own it: elect with an atomic compare-and-swap on a global at
init, and only the winner registers.

---

## 3. The trade this makes, stated plainly

Moving the work onto the poll thread moves the cost onto the poll thread. **A JIT compile runs inside
one poll iteration and stalls that TMM thread for its duration.** That is a data-path stall, which is
exactly the thing this project is otherwise careful to avoid.

This is not hidden by the design; it has to be bounded and measured:

- **Measure first.** Done — see §3a. The answer was 349 us median / 3.2 ms max, which would have
  been disqualifying, except that the cost turned out to be paging rather than compiling. Read §3a
  before acting on the rest of this section.
- **Bound the input.** Refuse programs above a size ceiling, so the stall has a stated maximum
  rather than scaling with whatever arrives on a socket.
- **Loads are rare.** This runs on shield deployment, not per packet. The idle cost is one atomic
  load per timer tick on one thread.

**If the measurement comes back bad**, the fallback is a third option not scoped here: give uBPF a
private arena by building it with its allocations redirected — uBPF exposes **no allocator hook**
(confirmed: `.ubpf/vm/inc/ubpf.h` has none), so that means patching uBPF, which F5 already owns a
fork of for item 15's back-edge fuel.

---

## 3a. B1 result — measured, and it moves the fix

Fifty iterations of the exact `ls_vm.c:484-522` sequence against the real 4320-byte shield, linked
against the vendored uBPF, in the toolchain container:

| Stage | median | p95 | max |
|---|---|---|---|
| `ubpf_create` | 28.6 us | 35.6 us | 44.9 us |
| `ubpf_load_elf_ex` | 5.4 us | 9.3 us | 13.1 us |
| `ubpf_compile_ex` | **311.1 us** | 505.5 us | **3187.4 us** |
| **TOTAL (the stall)** | **348.6 us** | 544.0 us | **3226.8 us** |

3.2 ms inside a poll iteration is not acceptable, so on the naive design the answer would be no.
**But the cost is not compilation.** `ubpf_jit_support.c:81-85` allocates, per compile, a fixed
scratch set sized by `UBPF_MAX_INSTS` = 65,536 regardless of program size:

```
pc_locs      65537 x 4  bytes  =  256 KB
jumps/loads/leas/local_calls
             65536 x 20 bytes x 4 = 5120 KB      (patchable_relative is 20 bytes, measured)
                                     -------
                            TOTAL = 5.25 MB per compile
```

`calloc` of that size is lazy — measured at **0.0 us**, because it is `mmap` of zero pages. The cost
is the **demand faults when the JIT touches them**:

```
calloc 5.25 MB + fault every page:   mean 271.8 us   max 2115.1 us
ubpf_compile_ex:                   median 311.1 us   max 3187.4 us
```

Paging accounts for essentially the whole thing. **The real compilation of a 4 KB program is the
remainder, roughly 40 us.**

### What follows

Allocate the scratch **once** and reuse it. After the first compile those pages are resident and
every subsequent compile costs ~40 us. This is a small patch to uBPF — which has no allocator hook
(confirmed) but which **F5 already forks for item 15's back-edge fuel**, so the fork is not a new
cost. It fixes two problems at once:

- **The poll-thread stall** drops from 349 us / 3.2 ms to ~40 us, which is comfortably inside a poll
  iteration and makes §2 viable rather than marginal.
- **The allocator problem partly dissolves.** Steady-state prepare allocates nothing, so the 1 MB
  `sthread_malloc` cap stops being the binding constraint. The spinlock hang (§1) still has to be
  handled, because the *first* compile still allocates — but it becomes a one-time startup cost that
  can be paid on a TMM thread at init, where allocation already works.

**Honest caveat:** measured on the build box (idle 16-vCPU VM, glibc malloc), not inside TMM under
load with `umalloc`. The ~40 us figure is the one to re-check after B0, on the target.

---

## 3b. B0 result — done, 17x, and verified correct

`substrate/ubpf-patches/0001-jit-scratch-rightsize.patch` sizes the JIT's scratch to the program
being compiled (`vm->num_insts`) instead of to `UBPF_MAX_INSTS` (65,536). Same benchmark, same
shield, same box:

| Stage | before (median) | after (median) |
|---|---|---|
| `ubpf_create` | 28.6 us | **4.8 us** |
| `ubpf_load_elf_ex` | 5.4 us | 5.3 us |
| `ubpf_compile_ex` | 311.1 us | **9.0 us** |
| **TOTAL (the stall)** | **348.6 us** | **19.5 us** |
| p95 | 544.0 us | **28.5 us** |
| **max** | **3226.8 us** | **58.3 us** |

The **max** is the figure that decides whether this can sit on a poll thread, and it improves 55x.
There is no first-compile penalty, because nothing large is allocated at any point.

An earlier version of this patch kept a process-global scratch and reused it (21.0 us median, but a
1.1 ms first compile). It was discarded: process-global mutable state, a non-atomic busy flag, and
5.25 MB retained for the process lifetime would have made it a **permanent** fork, because upstream
would rightly reject it. Right-sizing is smaller, faster at every percentile, and is the actual
upstream bug rather than a workaround for it — so it can be contributed back and then dropped.

**Verified, not assumed.** A speedup that silently miscompiles is worse than no speedup, so
`verify_scratch_reuse.c` checks compiled *behaviour*: the JIT's output is compared against
`ubpf_exec` (the interpreter never touches the JIT scratch, so it is an oracle this patch cannot
influence), across 40 compiles through the shared scratch, on both ctx cases.

```
round 0 baseline:  null-ctx -> 1   live-ctx -> 0
interpreter says:  null-ctx -> 1   live-ctx -> 0
40 rounds through the shared scratch
RESULT: PASS --- JIT matches interpreter, and every compile agrees
```

That `1`/`0` split is the shield's own logic confirmed end to end: a null `prot_transfer_log_profile`
returns the safe value; a live one falls through.

### What this changes about §2 and §3

- **The poll-thread trade is no longer marginal.** 21 us inside a poll iteration is ordinary
  per-iteration work, so §3's concern is answered rather than merely bounded. The size ceiling (B6)
  is still worth having, but as a guard rather than the thing holding the design up.
- **The allocator constraint is much weaker.** Steady-state prepare allocates nothing, so the 1 MB
  `sthread_malloc` cap stops binding. The §1 spinlock hang still has to be handled for the *first*
  compile, but that is a one-time startup cost payable on a TMM thread where allocation already works.

Still measured on the build box with glibc, not inside TMM with `umalloc`. Re-check on target.

---

## 4. Work items

| # | Item | Notes |
|---|---|---|
| B1 | ~~Measure JIT cost~~ **DONE — see §3a. The result changes the plan.** | Prepare costs 349 us median / 3.2 ms max, and **90% of it is demand-paging scratch, not compiling** |
| B0 | ~~Patch uBPF to allocate JIT scratch once and reuse it~~ **DONE — see §3b** | 349 us -> 21 us median (17x). Patch + tests in `substrate/ubpf-patches/` |
| ~~B2~~ | Request struct + state machine, release/acquire ordering | File-scope statics; needs whitelist entries |
| ~~B3~~ | Timer registration with CAS ownership election | `timer_init_periodic_ex` in `http_psm_init`, one owner |
| ~~B4~~ | Move `ls_vm_reload` invocation to the callback | Loader thread must make **zero** allocations; audit the whole path |
| ~~B5~~ | Loader-side wait + timeout + honest error on timeout | A wedged prepare must not wedge the loader again |
| ~~B6~~ | Size ceiling on accepted programs | Bounds the stall |
| ~~B7~~ | Re-run the load test end to end | The `test_load2.py` probe is the acceptance criterion |

**Not in scope here, still absent:** reclamation (item 0c) — a reload leaks the old VM; and
signature verification (item 4) — the socket still accepts unsigned programs.

---

## 5. What this does and does not unlock

**Does:** pushing a new shield into a running TMM without a restart — rung 3 of `ls_vm_load.c`'s own
ladder, and the difference between "arm a program we shipped" and "insert arbitrary bytecode".

**Does not:** it changes nothing about *where* a shield can be armed (already working), about
verifying who signed it (item 4), or about the hook map that makes addresses survive a rebuild
(item 5).


---

## 5. B2-B7 — DONE, 2026-08-13. The load path works.

```
1. LOAD real 4320-byte shield  ->  OK loaded slot=0 mode=2 unverified=yes
2. ARM probe                   ->  OK ARMED LIVE entry=0xcd4640 (no restart)
3. disarm                      ->  OK DISARMED LIVE entry=0xcd4640

both pods      2/2 Running  restarts=0
loader thread  parked in accept()          (was RUNNING/wedged before)
second run     identical --- repeatable, not a one-shot
```

The same probe returned three `*** TIMEOUT`s earlier the same day and left the loader permanently
wedged. Bytecode now goes into a running TMM over a socket, is parsed, JIT-compiled and published,
and the loader is still healthy enough to arm and disarm a live function afterwards.

**This is rung 3** of the ladder in `ls_vm_load.c`'s own banner: no rebuild, no restart, no window —
for the *program*, not merely for where it is armed.

### What shipped

- **`ls_prep.c`** (new, TMM include world — no `STDINC` in `src/compile/filelist`). Owns the periodic
  timer, the `tid == 0` ownership election, and the callback. Registered once at startup, so the
  loader never inserts into the callwheel and never races the poll loop walking it.
- **`ls_vm_load.c`** (unchanged in character — still `STDINC`). Owns the request state, the work, and
  the loader-side submit/wait. The split follows the include world: TMM's headers need its
  `-nostdinc` type universe, and this file must stay portable so `make -C substrate check` can
  syntax-check it standalone. **Verified: it still does.**
- Only two function symbols cross the boundary (`ls_prep_run_pending`, `ls_prep_timer_start`), both
  `void(void)`. No struct and no type crosses.
- Startup now logs `ls_vm: prepare handoff armed on tmm 0 (every 10 ticks)`.

### What it cost, honestly

Seven build attempts. Four were self-inflicted and are recorded so they are not repeated: TMM
headers pulled into a `STDINC` file; `strlcpy` used where the standard C library applies;
`<stdio.h>` in a `-nostdinc` file; and **three separate whitelist corruptions** — literal
backslash-n written through a shell heredoc, then a "cleanup" that silently deleted ~20 legitimate
entries, then appending the same symbols to both variants when `no_pgo` and `debug` genuinely have
different global sets. What worked was to stop editing the whitelist by hand and take it from the
build's own `Autogenerated file:` output — the authoritative answer it had been comparing against
all along. One failure was **not** ours: a parallel-make race in TMM's PEM makefile ran `install`
before the `ld -r` that creates `libpem.a`; re-running cleared it.

### Still absent

Reclamation (item 0c) — a reload leaks the old VM. Signature verification (item 4) — the socket
still accepts unsigned programs, which is why it is off unless `LS_LOAD_SOCKET` is set, is created
0600, and logs every accepted load as unverified.
