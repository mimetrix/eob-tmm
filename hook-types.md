# Hook types — what this VM can attach to, and what it cannot

A different axis from the use cases (`demo-options.md`). That document asks *what
questions can we answer*; this one asks *what events can we attach to at all*.

Written 2026-08-17. Every "yes" below has been run on BNK; every "no" says what would
be required rather than that it is impossible.

---

## 1. The honest headline

**Kernel eBPF attaches to roughly ten kinds of event. We attach to one.**

Everything demonstrated so far — the shield, the reset feed, the maps, the ring — sits
on a single mechanism: a 5-byte `call rel32` written over the compiler's nop pad at a
**function entry**, calling a trampoline inside the TMM process.

The `SEC("fentry/...")` naming borrows the kernel convention and **is not kernel
fentry**. It is our own pad patch. The name invites an assumption worth heading off.

---

## 2. What exists, with evidence

| type | status | evidence |
|---|---|---|
| **Function entry, pad-patched** | **live** | `rst_why` and three siblings armed on a running TMM, no restart |
| **Two pad shapes** | **live** | `check_pad_shapes.c`, 14 assertions: `endbr64`+5 nops at +4, and 5 nops at +0 for direct-call-only statics and `.isra`/`.constprop` clones |
| **Designed-in call site** | **live** | the built-in shield at `http_psm_profile_name_lookup` — 39 lines of C in `http_psm.c`, no pad needed, but it is a source edit |
| **Concurrent hooks of different shapes** | **live** | four reset functions across four slots; only possible since the per-slot trampoline landed |
| **Live arm / disarm** | **live** | `OK ARMED LIVE` / `OK DISARMED LIVE`, entry bytes restored byte-identical |
| **`rdtsc`** | **live** | `ls_vm.c:131`, a userspace counter read with no syscall |

### The three ctx shapes a program can be handed

Also a hook-type distinction, because it decides what the program can *see*:

1. **Generic 5-register.** `arg[0..4]` as flat scalars. Works on any padded function
   with no knowledge of it, and is useless for most TMM functions because nearly all
   take pointers and a verified program cannot chase one.
2. **Typed from direct arguments.** The reset family: six arguments including two
   strings, flattened by the host into a 92-byte record. No dereference of TMM state.
3. **Typed by host-side dereference.** ALPN: `ssl_alpn_match(sc, ...)` does not
   receive the ALPN bytes, it derives them from `sc`. `ls_ctx_alpn.c` repeats that
   derivation **in the ssl module's include world** and hands back flat bytes. This is
   the general escape hatch — the host does the pointer chasing, the program sees
   scalars, which is the shape PREVAIL proves easily.

---

## 3. What does not exist, and what each would take

### 3.1 Exit / return probes — the biggest expressiveness gap

Reading a function's **outputs**, not its inputs. The first tracepoint attempt failed
exactly here: armed at entry, it read `header_count` before the parse wrote it, and
every field was correctly zero.

Mechanism: return-address hijack, as `uretprobe` does. Cost: per-thread per-depth
storage for saved return addresses, a re-entrancy story that is still unwritten, and a
give-up path for `longjmp` / unwind / `noreturn`. `widening-plan.md` Phase 2.

### 3.2 PMU / perf events — and this one is undervalued

We read `rdtsc` and nothing else. The PMU offers far more, **from userspace**:

- `rdpmc` reads a performance counter with **no syscall** when the kernel permits it
  (`perf_event_paranoid`, `CR4.PCE`)
- `perf_event_open` plus an mmap'd page gives instructions-retired, cache-misses,
  branch-misses per invocation

**This is the direct answer to the per-invocation cost problem that blocks every
review conversation.** `rdtsc` is polluted by preemption — a scheduler tick inside the
measurement window destroys the mean, which is exactly why the current counters are
untrustworthy and why no per-call number can be quoted. **Instructions-retired does not
have that failure mode**: it counts what the program executed whether or not it was
descheduled. That converts "unmeasured" into a defensible number, using a userspace
read on a path that already reads a counter.

Cheapest high-value item on this page.

### 3.3 Hardware breakpoints / watchpoints — removes the pad requirement

The RapidPatch route (USENIX Sec '22). A debug register watches an arbitrary address,
so **no compiler pad is needed**.

That matters more than it sounds: the pad requirement is the single biggest structural
limit here. Entry-padding reach is **48.9%** across the whole binary — 82–97% inside
the TMM tree, **0%** in independently built components — which is why OpenSSL's 1,781
linked symbols are all unarmable regardless of what CVE exists in them.

Cost: `ptrace` or `perf_event_open`, i.e. privilege, which is the catch inside an
ordinary pod. Four debug registers on x86-64, so a hard concurrency ceiling. In
`cve-mitigation-plan.md` Phase 2, unbuilt.

### 3.4 Static tracepoints / USDT

Markers placed deliberately in TMM source rather than discovered. Proposed in
`tmm-usdt-tracepoints.md`. The HTTP tracepoint built this way was **rolled back**
because it duplicated what iRules already see — the lesson being that a designed-in
marker competes with the existing scripting surface, while a pad-patched internal
function does not.

### 3.5 Timer / periodic

The machinery exists — `ls_prep` runs on a TMM timer every 10 ticks to service the
loader handoff — but it is not exposed as an attach point a program can bind to.
Would give sampling and periodic aggregation without a traffic trigger. Small.

### 3.6 Not applicable at all

XDP, tc, socket filters, LSM, cgroup hooks. These are kernel-plane program types.
TMM has its own userspace data path and does not go through those layers, so they are
not a gap — they are a different system.

---

## 4. "Isn't this reinventing bpftime?"

Partly yes, and the honest accounting matters more than the defence.

**Hand-built here that bpftime already has:** maps, helper registration, an egress
ring, the attach machinery, and exit probes (still owed). Four subsystems. Several of
2026-08-17's bugs --- the shared slot immediate, the hook->schema mapping, the absent
ctx-ABI check --- are bugs a mature framework solved years ago.

**What the reinvention bought, and it is narrower than it first looks:**

- *Attach mechanism.* Frida-gum inline-hooks by rewriting instructions at the target
  and relocating the displaced ones. We overwrite five nops the compiler reserved, so
  NO instruction is displaced --- nothing to relocate, nothing to re-execute, and
  disarm restores byte-identical bytes. That is why arming a live data plane under
  traffic is arguable at all.
- *Review surface.* This is a security appliance heading for a formal TMA. uBPF is a
  few thousand auditable lines; bpftime brings Frida-gum AND LLVM into the data-plane
  process.
- *Fit.* Our maps are per-thread and lock-free because the hot path is
  run-to-completion. bpftime's are shared-memory across processes --- more general, and
  generality on a poll loop is a cost.

**Where that argument is weak:** it justifies not adopting bpftime WHOLESALE. It does
not justify re-deriving maps and ring buffers from first principles, which is most of
what was built.

**The question worth asking now** is not "should we have used bpftime" --- the
switching calculus is worse now that most of the reinvention is done. It is: **should
EXIT PROBES be borrowed rather than built?** That is bounded and answerable, and it
settles on one fact: can Frida-gum's uretprobe machinery coexist with pad-based arming
in the same process without both trying to own the entry bytes? If yes, take it. If
they collide --- likely --- building it stays right and the reinvention was narrower
than it appears.

---

## 5. Why this matters for the pitch

The mechanism is often described as "eBPF in TMM", which invites the listener to
assume the kernel's whole attach surface. The accurate version:

> One event source — function entry, on functions the build padded — with three ctx
> shapes, concurrent hooks, and live arm/disarm.

That is genuinely useful and it is much narrower than "eBPF". Saying so first is
cheaper than being corrected in review, and the two additions that would widen it most
are both concrete: **exit probes** for expressiveness, **PMU counters** for the number
everyone will ask for.
