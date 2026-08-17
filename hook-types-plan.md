# Bringing additional hook types into the VM

Companion to `hook-types.md`, which catalogues what exists. This is how to add to it.

Written 2026-08-17, after the per-slot trampoline made concurrent hooks of different
shapes possible for the first time.

---

## 0. Why this was not obvious --- including to the people working on it

Stated plainly because it went unsaid for weeks: **every use case discussed so far
rides ONE hook type.** Shield, reset feed, maps, ring, the CVE attempts --- all of them
are a 5-byte call over the compiler's nop pad at a function entry.

That single constraint is the common cause behind what looked like four separate
frustrations:

- **CVE mitigation kept failing on BNK.** Not a capability gap. The pad requirement
  fixes the scope to the TMM core; linked components carry no pads, so OpenSSL's 1,781
  symbols were never reachable whatever the CVE.
- **The tracepoints felt obscure.** Entry-only means a program sees a function's
  INPUTS. What it decided is structurally unavailable.
- **The first tracepoint read zeros.** Armed at entry, it read `header_count` before
  the parse wrote it. Correct behaviour, impossible use.
- **Every hook needed a ctx builder compiled into TMM.** One delivery path, so
  arguments must be flattened by the host before a verified program can see them.

Four symptoms, one cause. Worth leading with, because "we support eBPF in TMM" invites
the listener to assume the kernel's whole attach surface and then be puzzled by each
of those in turn.

---

## 1. The structural problem, before any specific hook type

Today four things are fused into one chain:

```
  pad patch  →  trampoline  →  slot  →  ctx builder  →  program  →  verdict
  ^event        ^delivery      ^dispatch  ^shape        ^policy
```

`ls_tramp_dispatch(slot, regs)` is the only entrance, `regs` is always a saved
x86-64 register block, and the ctx builder is chosen by **slot alone**. That works
because there is exactly one event source. Add a second and every layer forks.

**The refactor that has to come first** is small now and painful later: dispatch on
`(kind, slot)` rather than `slot`, and let the event source hand over something other
than a register block.

```c
enum ls_evt_kind { LS_EVT_ENTRY, LS_EVT_EXIT, LS_EVT_TIMER, LS_EVT_TRAP };

struct ls_event {
    enum ls_evt_kind kind;
    int              slot;
    const void      *raw;    /* struct ls_regs, or a timer tick, or siginfo */
};

int ls_dispatch(const struct ls_event *e);   /* -> verdict */
```

Everything downstream --- run the program, act on the verdict, emit to the ring --- is
already shared and stays shared. Only the ctx builder and the entry path differ.

**Why now rather than with the first new type:** the slot-keyed ctx builder is exactly
what produced the empty-cause bug. Slot 5 and slot 3 meant different argument shapes,
and when a shared trampoline made every hook use one slot, the wrong builder ran and
nothing said so. Adding a second event source multiplies that failure mode by the
number of kinds. The `_Static_assert`s in `ls_slots.h` cannot catch it; a typed
`kind` can.

---

## 2. The four candidates, ordered by value ÷ cost

### 2.1 Timer / periodic — cheapest, and the machinery already exists

`ls_prep` already runs on a TMM timer every 10 ticks to service the loader handoff. It
is a TMM thread, on a TMM timer, in the right allocator context. Nothing about the
event source needs building.

**What it needs:** a slot bound to `LS_EVT_TIMER`, and a ctx --- most usefully the
program's own map contents plus a tick counter, since the point is aggregation rather
than inspection.

**What it unlocks:** periodic rollups without a traffic trigger. Today a program only
runs when a request happens, so "what has been accumulating" can only be read by
draining records and aggregating outside. A timer hook lets the program do it in-place
and emit a summary --- which is what turns the reset feed's per-record stream into
rates.

**Risk:** low. It runs where the loader handoff already runs.

### 2.2 PMU counters — and this is a HELPER, not a hook type

Worth separating carefully, because conflating the two is what makes this look big.

- **PMU as a data source**: the program (or the host around it) reads a counter.
  `rdpmc` needs no syscall where the kernel permits it; `perf_event_open` plus an
  mmap'd page gives instructions-retired, cache-misses, branch-misses. **This is a
  helper and a host-side measurement, not a new event source at all.**
- **PMU overflow as an event**: a counter overflows, the kernel signals, a program
  runs. That IS a new event source, and it needs signal delivery --- see 2.4's
  objections, which apply identically.

**Do the first, not the second.** The first is the direct answer to the
per-invocation cost problem that blocks every review conversation: `rdtsc` (already in
`ls_vm.c:131`) is polluted by preemption, so the mean is meaningless and no per-call
number can be quoted. **Instructions-retired has no such failure mode** --- it counts
what executed whether or not the thread was descheduled.

**What it needs:** `perf_event_open` at init for a self-monitoring counter, mmap the
page, and read it side-by-side with `rdtsc` around the dispatch. If the kernel refuses,
fall back to `rdtsc` and say so rather than silently reporting a worse number.

**Risk:** low, and it is measurement rather than mechanism --- nothing on the verdict
path changes.

### 2.3 Exit probes — the biggest expressiveness gain

Reading a function's **outputs**. The first tracepoint attempt failed precisely here:
armed at entry, it read `header_count` before the parse wrote it, and every field was
correctly zero.

**Mechanism:** the same entry pad, but the trampoline saves the caller's return address
and substitutes a thunk; the thunk runs the exit program and jumps to the real address.

**What it needs, and this is where the cost is:**

- per-thread, per-depth storage for saved return addresses --- a hooked function can be
  entered recursively
- a depth cap and a give-up path, because `longjmp`, an exception unwind or a
  `noreturn` path abandons the frame and leaks a saved slot
- the re-entrancy story that has been on item 1's list since the beginning and is still
  unwritten

**Risk: medium-high, and it is the first hook type that can corrupt control flow rather
than merely produce a wrong record.** An entry hook that misbehaves gives a bad answer;
an exit hook that loses a return address crashes the data plane.

**Borrow or build?** This is the one place bpftime is genuinely tempting --- it has
uretprobes already. The question that settles it is narrow and testable: **can
Frida-gum's return-address machinery coexist with pad-based arming in the same
process**, or do both try to own the entry bytes? Worth an afternoon to find out before
committing to build.

### 2.4 Hardware watchpoints — the biggest scope gain, the highest risk

A debug register watches an arbitrary address, so **no compiler pad is needed**. That
lifts the one constraint that defines this mechanism's scope: outside the TMM core
nothing is padded, which is why OpenSSL's 1,781 linked symbols are unarmable whatever
CVE exists in them. This is the only candidate that changes *what can be reached* rather
than *what can be seen*.

**What it needs:**

- `perf_event_open` with a breakpoint type, or `ptrace` --- i.e. **privilege**, which is
  the catch inside an ordinary pod
- **a signal handler as the delivery path**, and that is the real objection. SIGTRAP
  arriving anywhere in a run-to-completion poll loop is a different safety problem from
  a `call` at a known instruction boundary. Async-signal-safety rules would bind the
  dispatcher, and our allocator story (no malloc on foreign threads) gets harder, not
  easier
- four debug registers on x86-64: a hard ceiling of four concurrent watchpoints

**Risk: high.** Recommend prototyping it **outside TMM** first --- a standalone process
that watches an address and runs a uBPF program from the handler --- to find out whether
the signal-context restrictions are survivable before proposing it near a data plane.

---

## 3. Recommended order

1. **The `(kind, slot)` dispatch refactor.** Cheap now, and it is the thing that makes
   the rest additive rather than forking.
2. **PMU counters as a helper.** Unblocks the number every reviewer asks for. Not a
   hook type, which is why it is fast.
3. **Timer hook.** Small, reuses existing machinery, turns a record stream into rates.
4. **Exit probes** --- after the borrow-or-build question is answered by experiment
   rather than argument.
5. **Watchpoints** --- prototype outside TMM first. Highest value, and the only one
   whose delivery path is genuinely alien to everything built so far.

---

## 4. What would make me wrong about the order

- If the CVE use case becomes the priority again, **watchpoints jump to the top**,
  because they are the only item that addresses reachability. Everything else widens
  what a program can see or say within a scope that is already fixed.
- If a per-call cost number is demanded before anything else ships, PMU moves to first
  and the refactor waits.
- If exit probes turn out to be borrowable from bpftime cheaply, they move ahead of the
  timer work on value alone.
