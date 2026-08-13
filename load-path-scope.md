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
pc_locs + jumps + loads + leas + local_calls
  = 5 x 65,536 x (4 bytes at the floor, realistically 12-16)
  = 1.3 MB minimum, ~4-5 MB in practice        >  1 MB cap
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

- **Measure first.** Time `ubpf_load_elf` + `ubpf_compile_ex` for a representative shield. If it is
  tens of microseconds, the stall is comparable to other per-iteration work and the trade is fine.
  If it is milliseconds, it is not, and the work must be chunked or moved again.
- **Bound the input.** Refuse programs above a size ceiling, so the stall has a stated maximum
  rather than scaling with whatever arrives on a socket.
- **Loads are rare.** This runs on shield deployment, not per packet. The idle cost is one atomic
  load per timer tick on one thread.

**If the measurement comes back bad**, the fallback is a third option not scoped here: give uBPF a
private arena by building it with its allocations redirected — uBPF exposes **no allocator hook**
(confirmed: `.ubpf/vm/inc/ubpf.h` has none), so that means patching uBPF, which F5 already owns a
fork of for item 15's back-edge fuel.

---

## 4. Work items

| # | Item | Notes |
|---|---|---|
| B1 | **Measure JIT cost** on the box before writing anything | Decides whether §2 is viable at all. Cheapest possible first step |
| B2 | Request struct + state machine, release/acquire ordering | File-scope statics; needs whitelist entries |
| B3 | Timer registration with CAS ownership election | `timer_init_periodic_ex` in `http_psm_init`, one owner |
| B4 | Move `ls_vm_reload` invocation to the callback | Loader thread must make **zero** allocations; audit the whole path |
| B5 | Loader-side wait + timeout + honest error on timeout | A wedged prepare must not wedge the loader again |
| B6 | Size ceiling on accepted programs | Bounds the stall |
| B7 | Re-run the load test end to end | The `test_load2.py` probe is the acceptance criterion |

**Not in scope here, still absent:** reclamation (item 0c) — a reload leaks the old VM; and
signature verification (item 4) — the socket still accepts unsigned programs.

---

## 5. What this does and does not unlock

**Does:** pushing a new shield into a running TMM without a restart — rung 3 of `ls_vm_load.c`'s own
ladder, and the difference between "arm a program we shipped" and "insert arbitrary bytecode".

**Does not:** it changes nothing about *where* a shield can be armed (already working), about
verifying who signed it (item 4), or about the hook map that makes addresses survive a rebuild
(item 5).
