# What this substrate cannot do

Written to be checked against, not read once. If you are asking "can we shield
CVE X" or "can we probe Y", work down the relevant list — most candidates fail on
the first two items, and it costs minutes to find out rather than a week.

Items are marked as one of three things, and the distinction is the point —
conflating them is how a capability gets oversold in one direction and written off
in the other:

| | |
|---|---|
| **structural** | a property of the approach; will not change |
| **unbuilt** | known how, not done |
| **gap with an identified path** | thought structural until something showed otherwise |

The third category exists because §1.1 was in the first until 2026-08-16, when the
literature showed it was really the second. Assume anything here labelled
structural may move if someone checks.

---

## Part 1 — The shield

A shield runs a verified eBPF program at a function entry and lets the host apply
its verdict. The verdict is binary: fall through, or return the hook's declared
safe value.

### 1.1 The decision must be makeable at a function entry — *with our current attach*

The program runs **before the function body**. Anything computed inside is not
available to it.

> **Corrected 2026-08-16.** This section previously called the constraint
> structural. **It is not** — it is a property of the attach mechanism we chose,
> and the literature shows the alternative.
>
> [RapidPatch (USENIX Security '22)](https://www.usenix.org/conference/usenixsecurity22/presentation/he-yi)
> hotpatches firmware with a userspace eBPF VM — architecturally our design — and
> reports **over 90% of CVEs hotpatchable**, against our 0 of 5. The difference is
> not the VM. It is that RapidPatch **combines hardware breakpoints with
> instrumentation** (the ARM FPB unit, Kprobes on Linux) and treats function-entry
> patch points as only *one* of its deployment methods. A hardware breakpoint sits
> at the instruction where a dangerous condition becomes computable, which is where
> most memory-safety bugs actually live.
>
> x86_64 gives four hardware debug registers, and `ls_swap.c` already handles
> `SIGTRAP` for the arming path — so arbitrary-address attach is a new *use* of
> machinery we have, not a new mechanism. Four simultaneous arbitrary patch points
> is ample for CVE work.
>
> Until that exists, everything in this section holds. It is a **known gap with an
> identified path**, not a property of the approach.

This is the filter people underestimate. A vulnerability that only becomes
apparent after three transformations inside a 400-line function has nowhere to
attach — there is no boundary at which the dangerous state exists and the damage
has not yet been done.

The ALPN shield squeaked through only because the bytes were *derivable*: the
host could call TMM's own `ssl_ext_get_by_type` and reproduce the function's
first ten lines. That is not typical, and budget for it.

Corollary that cost us a day: hooking a parser at entry and reading its
**outputs** returns zeros, correctly. `parse_watch.bpf.c` is kept as the worked
example of a program that verifies clean and is useless.

### 1.1b No maps, no helpers — *unimplemented, not unsupported*

> **Corrected 2026-08-17.** This document and several design docs described maps
> and helpers as things our eBPF *does not support*. They are things we **never
> implemented**. uBPF has `ubpf_register()`; we never called it.
>
> And the assumption that made it look expensive was wrong. Tested directly
> (`substrate/shields/exp/map_probe.bpf.c`): a program declaring a standard
> `SEC("maps")` hash and calling `bpf_map_lookup_elem` / `bpf_map_update_elem`
> **passes PREVAIL unchanged**, with every gate on. PREVAIL parsed the maps
> section, resolved the descriptor, type-checked both helpers against its built-in
> prototypes, tracked the null check, and proved the accesses in bounds — no
> custom platform, no prototype table, no patch.
>
> Helper IDs 1/2/3 are the standard BPF map helpers and PREVAIL's linux platform
> already knows their signatures. Implementing those IDs with those semantics
> needs **no verifier work at all**.
>
> This matters because "a program cannot keep state" is the single biggest
> constraint on what any of this can express — rate limiting, "has this client
> done this before", correlation across requests are all currently inexpressible.
> It was recorded as a ceiling; it is a gap. See
> [`../widening-plan.md`](../widening-plan.md) Phase 1.

### 1.2 The predicate must be bounded, and the verifier means it

PREVAIL refuses:

- loops bounded by attacker-supplied values
- unbounded trip counts of any kind
- pointer chasing

Note what the first one implies: **the verifier refuses the exact mistake most
memory-safety bugs are.** The ALPN bug is a loop trusting an attacker's length
byte; PREVAIL would not admit a loop bounded by an attacker's length byte. The
fix is a constant trip count or a full unroll, and `-O2` will happily make the
attacker-driven index the induction variable if you write it naively — verify the
object, not the source.

### 1.3 Ninety-six bytes

PREVAIL's `fentry`/`tracing` program type describes a **96-byte ctx**. An access
past it fails verification outright ("Upper bound must be at most 96"). A first
version of the ALPN ctx used 256 bytes of extension data and was rejected.

So a program inspects **at most ~88 bytes of attacker-controlled input directly**.
Anything larger must be reduced by the host — into a verdict, a summary, or a
truncation flag the program can refuse on — before the program sees it.

### 1.3b It can refuse, but it cannot redirect

The verdict is binary: fall through, or return the hook's declared safe value.

RapidPatch's patches carry `OP_DROP`, `OP_REDIRECT` and `OP_PASS` — they can send
execution somewhere else, not merely decline. Several fix shapes that are
expressible as a redirect are not expressible as a refusal, so this narrows the
addressable set independently of §1.1. Also unbuilt rather than impossible.

### 1.4 It cannot write

A shield selects an outcome. It cannot repair a structure, fix up a length field,
free a pointer, or modify the request. Any CVE whose fix is "correct the state and
continue" is out of scope; only "refuse this input" is expressible.

The ctx is a per-invocation **stack copy** for this reason. PREVAIL cannot express
a read-only region (finding O1), so a verified program may write every byte it is
handed. Handing it a view onto live TMM state would turn the safety mechanism into
an argument-injection primitive.

### 1.4b What the comparable systems do

Two reference points worth holding, because both are narrower than "eBPF patches
CVEs" and both are honest about it:

- **Cloudflare** mitigated CVE-2022-0492 in production by attaching to the
  **`cred_prepare` LSM hook** — a purpose-built security decision point, not an
  arbitrary function — and checking syscall number, `CLONE_NEWUSER` and
  `CAP_SYS_ADMIN`. ~10% overhead on that path. They state the limit directly:
  this works "for syscall interception at LSM hooks, not all vulnerability types."
  TMM has no LSM equivalent; the nearest thing is a designed-in call site, which
  costs a build.
- **livepatch / kpatch** remains the mainstream answer for real kernel CVEs:
  full **function replacement** via ftrace. Strictly more powerful than either
  approach and correspondingly heavier — and it fails on gcc inter-procedural
  optimisation, which is the same inlining problem in §1.6.

### 1.5 Fix shapes that work, and that do not

**Expressible:** bounds and length validation · null checks · range and type
checks · integer-overflow-in-size-calculation, *if* the operands are visible at
entry · oversized-input rejection.

**Not expressible:** use-after-free, double-free, refcount errors (nothing at
entry says a pointer is freed later) · races and TOCTOU (the bug is the
interleaving, not the input) · crypto and algorithmic flaws · anything needing
cross-call state.

That split is structural. It is not a roadmap item.

### 1.6 Inlined functions are permanently unreachable

No symbol, no entry pad, nothing to arm. `http1x_psm_method`,
`http1x_psm_header_count` and `http1x_psm_header_crnl` are all defined in
`http1x.h` and folded into their callers.

`ls_arm` now handles both pad shapes (`endbr64`+5 nops at +4, and 5 nops at +0),
which recovered 4,611 file-scope statics — but genuinely inlined code stays out
of reach.

### 1.7 Reachability dominates everything

Four of five CVE candidates screened against the live cluster returned
`fired = 0`: `hudproxy/memcached`, `hudfilter/http/http_psm.c`, `hudfilter/quic`,
and the original `prot_transfer_log` CVE. All are compiled into the BNK binary
and all sit behind configuration BNK does not expose.

**This is not a failure rate.** If the code is unreachable, the CVE is not
exploitable there either. But it does mean bug-tracker findings are a poor
sampling frame: static-analysis results cluster in rarely-exercised code
*precisely because* nobody found them by running it.

**Always run the reachability probe before writing anything.** Arm the function
with `dev_probe`, drive traffic, check `fired > 0`. Fifteen minutes.

### 1.8 Unbuilt, not impossible

- **No runtime fuel guard.** `ubpf_set_instruction_limit` has no effect on JIT'd
  programs and the JIT is on, so an armed program is **unbudgeted at runtime**.
  Acceptable for an observer on a warm path; not acceptable for enforce on an
  attacker-reachable one.
- **Per-call cost unmeasured.** The bench op that would give a clean number
  wedges the loader thread.
- **No signature verification.** The loader accepts unverified programs whenever
  `LS_LOAD_SOCKET` is set, which is why it is env-gated and off by default.

---

## Part 2 — The probe

A tracepoint is a chosen structure at a chosen point, feeding two independent
consumers: a verified program (counters) and a shared-memory ring (records).

### 2.1 It cannot alter traffic, by construction

`ls_tp_emit` returns `void`. The call site has no way to receive a verdict and
therefore none to act on one — a program behind a tracepoint cannot change a
request **even if armed in ENFORCE**.

That is deliberate and structural rather than a mode setting, because relying on
MONITOR alone already went wrong once: a tracepoint armed under a stale ENFORCE
setting turned 200s into 404s.

### 2.2 Adding a tracepoint costs a source edit and a build

Unlike the shield, a tracepoint is a **designed-in call site**. It modifies an F5
source file and requires a rebuild, a repackage and a rollout. It is a build-time
decision about what TMM should expose, not something armed on a running system.

The shield's "modifies no F5 source" property does **not** extend to tracepoints.
Two files are edited today: `http.c` and `http1x.c`.

### 2.3 The program still sees only 96 bytes

Section 1.3 applies unchanged. Today the record and the program's ctx are the
**same buffer**, so the 44-byte record is bounded by what the program can read.

Decoupling them — letting the ring carry a larger record than the program
inspects — is possible and unbuilt. Until then, "what can be egressed" is capped
by "what can be verified over".

### 2.4 The state must exist at the call site, and moving the site changes what you see

Snapshot timing is a real design axis, not a detail. Moving the ALPN-adjacent
HTTP capture earlier — to catch the parser's verdict before it was overwritten —
**lost `hdr_bytes`**, because `xbuf_merge` had not run yet.

You cannot generally have both the pre-state and the post-state from one point.
Choose, and record which you chose.

### 2.5 Loss is bounded and counted, never silent

The ring is `STREAM` policy: when full it **drops the new record and increments a
counter**. The data plane never waits on a consumer — that is the whole point —
but under sustained load faster than the drain, records are lost.

A counted gap, never a silent one. Any analysis over these records must read
`drops` alongside them or it is quietly wrong.

### 2.6 Record counts from a pulled segment are cumulative

`ls_tp_dump.py` and `ls_drain` reading a **copied** segment advance
`consumer_pos` in the copy, never in TMM's live segment. Every pull re-delivers
the entire history.

Quote the **counters** (`fired`, `safe_returns`) for rates — they come from TMM
and are exact. Quote the **records** for content. Fixing this properly is the
sidecar, which is unbuilt.

### 2.7 Ordering is per-ring, not global

One ring per thread, so ordering holds within a ring and not across them. `seq` is
atomic and gives a global order for a consumer that needs one; a consumer treating
rings as independent partitions does not need it. Visible in real output, where
ring 0's records precede ring 1's regardless of `seq`.

### 2.8 Schema drift is a real failure mode

The record layout is transcribed in four places: the host header, the program's
copy, `ls_tp_dump.py` and `ls_drain.c`. `_Static_assert`s and the segment version
check catch a mismatch; nothing catches a *semantic* change that keeps the size
the same. Bump `LS_TP_SCHEMA_HTTP` whenever meaning changes, not just size.

### 2.9 Per-request cost is real, and unmeasured in TMM

Shared memory removes the *dependency* on a consumer, not the *cost*. Each
request pays a `clock_gettime` (vDSO), the record build, a 72-byte ring write, and
the program call. Measured in the harness at 83–1209 ns for the ring write alone;
**never measured inside TMM's poll loop**, which is the number that matters.

There is also cache footprint — 72 bytes per request into a 64 KB per-thread ring
— which no microbenchmark will show you.

---

## Part 3 — Both

### 3.1 The control plane is entirely out of scope

The substrate is compiled **into the TMM process** and arms entries in TMM's own
`.text`. BNK's control plane is separate processes, largely Go. No pads, no VM, no
trampoline, different address space. Nothing here reaches it, and the approach
does not extend there without starting over.

### 3.2 Addresses move with every build

Packaging re-links the binary, so build-tree addresses are not the pod's. Always
resolve from the **matching `tmm-debuginfo` package** and check the build IDs
agree. Arming a stale address **succeeds** — pads are everywhere — which is the
silent failure the hook map exists to prevent.

### 3.3 A deliberately vulnerable build exists

`tmm:vuln-alpn`. See [`VULNERABLE-BUILD.md`](VULNERABLE-BUILD.md). Never present a
result from it without saying so.
