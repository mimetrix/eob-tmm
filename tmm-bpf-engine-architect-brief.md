# The eBPF engine in TMM

**Capabilities, current results, limits, and candidate extensions.**
Prepared for architecture review · 2026-08-18

Every capability described as working has been exercised on a live TMM, and the supporting
observation is cited. Every limit is stated with its consequence. Unmeasured quantities are
identified as unmeasured rather than estimated — and where a bound is all the measurement supports, it is given as a bound.

---

## 1. Mechanism

`-fpatchable-function-entry=5,0` is applied to TMM's optimisation flags, so every function
TMM compiles carries five reserved `nop` bytes at its entry. Arming a hook at run time
overwrites those five bytes with a `call rel32` to a per-slot trampoline.

```
DISARMED   f3 0f 1e fa   90 90 90 90 90   41 55 4d 63 c0
                         └─ compiler pad ─┘
ARMED      f3 0f 1e fa   e8 79 fb fd fe   41 55 4d 63 c0
                         └── call rel32 ──┘
```

The trampoline preserves the six argument registers, calls into C, and acts on the returned
verdict: continue into the function body, or skip it and return a declared safe value.

**No instruction is displaced.** This is the property that distinguishes the approach from
inline hooking. Because only reserved padding is overwritten, there is nothing to relocate,
no instruction decoder is required inside the process, and there is no interval during which
another thread's program counter can lie within bytes being rewritten. Disarming restores
the original bytes exactly, and that equality is asserted rather than assumed.

**Execution.** Two existing open-source components do the work, both vendored into the build
tree:

- **uBPF** — an eBPF bytecode interpreter with a simple JIT, roughly four thousand lines,
  designed to be embedded in a host process. It runs inside TMM.
- **PREVAIL** — a static verifier for eBPF bytecode. It proves memory safety and termination
  of a program *before* the program is allowed to load, which is what makes accepting a
  third-party program into the data plane arguable at all.

The division matters: PREVAIL runs at admission time, off the data path. uBPF is the only
part that executes per invocation.

**uBPF carries one local patch, and the vendored revision is not recorded.** Both facts
belong in a review of this component rather than in a footnote:

- `vm/ubpf_jit_support.c` is modified. Upstream sizes five JIT scratch arrays to
  `UBPF_MAX_INSTS` (65,536) on every compile regardless of program size — 5.25 MB per
  compile, of which faulting the pages in measured at roughly 272 µs, about 90% of compile
  time for a 4 KB program. The patch sizes them to the program. It is preserved in
  `substrate/ubpf-patches/` and is an upstream bug, so upstreaming it deletes the patch.
- A second patch is anticipated and not written: back-edge fuel in the JIT, for a time bound
  under `ENFORCE` (`development-scope.md` item 15). **The question was never whether to
  fork, but how many patches and whether each has a way out.**
- **The vendored copy has no version control history**, so the exact upstream revision it
  derives from cannot be stated. Two documents cite pins that do not match it. This is a
  reproducibility defect, not a licensing one, and it is tracked in `REPRODUCING.md`.

PREVAIL is used unmodified, and that is now checked rather than asserted — no tracked file in the vendored checkout differs. The binary in use reports **v0.2.5**, matching its own revision `06769f7b`; an earlier claim of v0.2.6 was wrong. For a component entering a Threat Model
Analysis, the reviewable surface is a few thousand auditable lines rather than a compiler
toolchain, and that was the governing consideration.

---

## 2. Changes to the TMM source tree

**The source tree changes substantially.** The repository elsewhere uses the shorthand "no
F5 source file is modified"; that phrase is too narrow to be useful here and it understates
the integration, so the actual delta is set out below.

| change | scale |
|---|---|
| **New files added into `src/base/` and `src/modules/hudfilter/ssl/`** | **46 files, 7,780 lines**, compiled into `tmm` — counted as the untracked files under those two directories, which is one `git status` |
| `src/compile/filelist` | +13 lines — those translation units, plus a `UBPF` cflags variable |
| `src/compile/default_whitelist_x86_64` | +33 lines — the mutable globals introduced |
| `src/compile/debug_whitelist_x86_64` | +33 lines — the same set |
| `Makefile.overrides` | new file, consumed at a sanctioned extension point (`Makefile.inc:116` includes it when present) |
| `.ubpf/` | the vendored interpreter and its static library, built inside the toolchain container so the C library matches |

**What was avoided is one thing, not a headline:** no existing F5 function body is edited.
The substrate reaches its own initialisation through `INIT_FUNC(INIT_LATE, …)` — the same
linker-set mechanism `urlcat`, `pem_lib` and `license_pgo_gen` use — rather than being called
from a line inserted into TMM's own logic. That keeps the diff reviewable and confines merge
exposure to the four configuration files above. It does **not** mean the tree is untouched.

**The one line in `Makefile.overrides`, and the defect it used to carry:**

```make
CFLAGS_OPTIMIZE += -fpatchable-function-entry=5,0
```

It was written `:=  -O2 -fpatchable-function-entry=5,0`. That assignment replaces rather than
appends, and `Makefile.inc:96-100` selects `-Os` when `VADC_TRIAL=yes` and `-O2` otherwise —
so the override silently forced a VADC trial build from `-Os` to `-O2`, a change in build
behaviour beyond adding a flag. **Corrected to `+=` on 2026-08-18** and verified by expanding
both configurations: the default build's flags are unchanged, and `VADC_TRIAL=yes` now keeps
`-Os`. The optimisation level is left as the tree selected it, which is the property that
matters — this file adds a flag and decides nothing else.

**Size cost of the padding: 0.182%** of the binary — 74,048 functions at five bytes. A pad
costs nothing at run time until it is armed.

**What the build gains beyond that flag: three generated files and one container layer.**
Arming by name needs to know where a function is, whether its entry can be patched, and what
it takes as arguments — none of which can be worked out at arming time on a stripped binary.
So the build emits a hook index, a full hook map, and a signature index, each keyed to the
binary's build id and each refused against any other. They are generated from the **packaged**
binary rather than the build tree's, because packaging re-links and every address moves;
since the packaged binary only exists after `make container`, they cannot be part of the
runtime image build and are layered on top of it. That is also why no F5 build stage is
replaced or reordered. It costs 2m9s of build time and nothing at run time.
[`build-pipeline.md`](build-pipeline.md) is the whole of it — stages, gates, costs, and the
six things it still does not do.

**One earlier integration did edit F5 source, and was rolled back.** A designed-in HTTP
tracepoint added call sites to `http.c` and `http1x.c`. It worked and was removed: every
field it captured was already visible to an iRule, so it competed with an existing surface
while carrying a source-edit cost. The patch is retained in the repository as a record,
unapplied.

## 3. Demonstrated results

All of the following have been observed on a running TMM on the BNK lab cluster.

| result | supporting observation |
|---|---|
| A verified program is loaded into a running TMM and armed at a function entry with no rebuild and no restart | `OK ARMED LIVE entry=0x144ff04 slot=5 (no restart)`. The address is quoted from the build in front of you, not carried between builds — see the build-identity row below |
| The hook is disarmed and the entry bytes are byte-identical to their original state | bytes read from `/proc/<pid>/mem` before, during and after; equality asserted programmatically |
| The hook fires exactly once per event | a hook on `http_parse_client_headers` fired once per request across 16,000 requests through the proxy |
| TMM's own connection-teardown decisions are reported | `rst_why` and three sibling functions, 1,090 call sites; records carry file, line, error code, reason code, cause string and a flow cookie |
| The reported cause and line agree with an independent code path | packet capture showed TMM's own RST payload carrying the same cause string and line number as the record, produced by code sharing nothing with the hook |
| HTTP/2 stream-abort decisions are reported | `http2_stream_abort` armed and fired; records carry the source literals `malformed content-length` and `Content-Length Exceeded` |
| Two independent hooks corroborate a single decision | `http2_stream_abort` reported `malformed content-length` six times while `rst_why` at `http2.c:1773` reported the same reason six times |
| Hooks of differing argument shapes run concurrently | twelve trampoline slots; the four reset functions, HTTP/2 abort, TLS error, ALPN and HTTP parse coexist |
| Programs hold state across invocations | per-thread hash maps, allowing questions of the form "has this site done this N times" |
| A program performs rate limiting inside the data plane | 86 qualifying events produced 2 emitted records; the program measured its own windows at 16.0 ms and 10.8 ms |
| Hooks are armed by symbol name, gated on build identity | `rst_why` has occupied three different addresses across three builds of identical source; the index carries the build ID of the binary it describes and a mismatch is refused |
| A shield expresses a real security fix | `alpn_guard` reinstates the bounds check added by commit `c806f1b2e8` to `ssl_alpn_match`; PREVAIL admits it |
| **A probe is generated for a function nobody prepared anything for, and armed, in one sitting** | Name a function; the build's signature index gives its parameters; `mk_probe.py` emits the record layout and the program; clang and PREVAIL accept it; the bytes travel over the loader socket with no file placed in the container. **0.04 s** to generate, against **1 m 54 s** for the same lookup against raw debug information. `mrhttp_proxy_route_message` fired 36 times for 36 requests |
| **A program dereferences its own pointer arguments** | `bpf_probe_read` is registered, so a generated probe reads a `char *` or a struct head itself rather than needing host C compiled into TMM. Observed: `…ffff0b0b0b64` in a `struct uflow` blob, which is `::ffff:11.11.11.100` — the client address |
| **A record identifies the function that produced it** | Previously the trampoline chose its context builder from the SLOT NUMBER, so a generated probe landing in a reset function's slot had its registers read as `rst_why`'s arguments and published fiction under that name — and `ls_ctx_rst_build` walks argument two as a string for up to 256 bytes, making it a wild read on the data path. Builders now register against the function they serve; an unregistered function gets the raw registers and no dereference |
| **A per-call cost floor is measured** | ≤ **11 ns** of program execution on the JIT path (26–28 cycles at 2.60 GHz). Bounded by the `rdtsc` pair that measures it, so the four smallest programs are indistinguishable from each other; `bpf_probe_read` at 26 ns and a maps-plus-clock-plus-emit program at 105 ns are resolvable. Corroborated by an off-TMM harness that recorded 10 ns |
| **The walkthrough runs end to end** | Seven moves, every command echoed, on the live cluster: nops → armed → decisions reported → target chosen from the index → disarmed byte-identical → an in-plane rate decision at 30:1 → a generated probe armed and reporting. `env/scripts/bnk-demo.sh` and `bnk-demo-generate.sh` |

**Addressable surface**, measured against the shipped binary:

| | count |
|---|---|
| functions armable via the compiler pad | **41,143** |
| functions armable only by displacement (unimplemented) | 30,009 |
| total entries in the generated index | 71,157 *(per build --- 71,169 on the 2026-08-19 rebuild)* |
| distinct symbol names | 70,029 |

---

## 4. Current capabilities

**Observation of decisions that no other surface exposes.** Falcon and comparable
kernel-eBPF agents attach to kernel hooks — syscalls, tc, XDP, kprobes, LSM. TMM runs its
own network stack in userspace, and its internal decisions traverse none of those hooks. A
kernel agent can observe the container, the host and the process; it cannot observe a single
decision TMM makes.

The extent to which such an agent sees TMM's *traffic* is deployment-dependent. Where TMM
owns the NIC and bypasses the kernel — classic BIG-IP, and any DPDK-style datapath — a
kernel agent sees no packets either. On the BNK lab cluster the pod presents kernel network
devices (Multus `net1` and `net2`) with no hugepages, so packets do traverse kernel
interfaces there. The claim that holds across both deployments concerns **decisions** rather
than packets: `rst_why` electing to tear down a connection, `http2_stream_abort` electing to
kill a stream, `ssl__err` electing an alert. None of these is a kernel event in any
configuration.

The same decisions are unavailable to **iRules**, and that is checkable rather than
asserted: `tclrule.c` defines the event set, and a reset following a failed parse raises no
HTTP event at all because no request object exists to raise one against. Where an event does
exist it need not carry the reason — `CLIENTSSL_HANDSHAKE_FAILED` is raised as
`tclrule_execute(hn, uflow, …)` with the node and the flow and nothing else, so an iRule
learns *that* a handshake failed and never *why*.

**No claim is made here about WASM.** It is absent from TMM's source tree, its `filelist`,
its build configuration and its component manifest, and from every image in the lab cluster.
If a WASM tier exists elsewhere in the product it is in a component not examined here, which
would put it in a different process — but that is an inference and it is not this document's
to make.

**Interception of a call before a vulnerable body executes.** A program inspects the
arguments and selects `SAFE_RETURN`; the function does not run. The mitigation ships as an
object rather than as a release.

**Staged enforcement.** Three modes exist: `DISABLE`, `MONITOR` — evaluate and count, apply
nothing — and `ENFORCE`. A customer can be shown the records a shield *would* have acted on,
at what rate and on which flows, before it acts on anything.

**Decisions informed by state and elapsed time.** Per-thread maps and a monotonic clock
helper allow a program to express "five occurrences at this site within the last second" and
to emit only on that condition.

---

## 5. Limits

| limit | consequence |
|---|---|
| **A single event source** | Function entry only, on padded functions. Kernel eBPF offers approximately ten attach types |
| **No exit or return probes** | A program observes a function's inputs. Return values, and therefore in-TMM latency, are structurally unavailable |
| **Padded functions only** | 30,009 index entries require displacement, which is designed and unimplemented. OpenSSL and every separately built component fall in this set |
| **Per-invocation cost: a floor, not the data-path cost** | Program execution is ≤ 11 ns on the JIT path, and that figure is bounded by the measurement rather than the program. What an armed hook costs *on the data path* — the trampoline's register save and restore, the call and return, cache effects under real traffic — is **not** in it. `rdtsc` means remain meaningless (one pair spanning a context switch gave 130,720 cycles against a minimum of 132) and `perf_event_paranoid=4` still blocks hardware counters. Quote the floor as a floor |
| **The safe return value is a fixed `0`** | Per-function safe values are unimplemented. An incorrect safe value converts a crash into silent misbehaviour. The mechanism is correct only for return types that fit in `rax` |
| **The loader socket authenticates the program, not the peer** | Signature verification is built and running: an Ed25519 signature over the 112-byte binding is checked in TMM before admission, and unsigned, re-signed and altered programs are all refused (measured on a live TMM, 2026-08-20). What remains is one level out — anything able to reach the socket may ask, the key is baked in at build time with no revocation path, and a debug environment variable can disable the check. Those, not the missing signature, are now the gap to anything customer-facing |
| **No audit trail** | Arming events — who, what, when, which mode, what outcome — are not durably recorded |
| **The JIT does not consult the bounds callback** | Interpreter and JIT do not agree on memory safety, and the JIT is what the lab runs |
| **Three helpers, two map types** | Map lookup, update and delete; hash maps and an event-output handle. Four maps per program, 256 entries, keys to 16 bytes, values to 32. No iteration, so a program can accumulate state but cannot summarise it |
| **A 96-byte context ceiling** | Measured: a read at byte 95 of a 96-byte context verifies; byte 99 of a 100-byte context is refused. This is why the reset record carries a flow cookie rather than a 5-tuple |
| **Flow cardinality, not identity** | The cookie distinguishes same-flow from different-flow; it does not identify a client |
| **Reachability is per-site and must be measured** | Five candidate sites were compiled into the binary and never executed on BNK's traffic path. A non-zero fire count under load is the only proof |

**The interaction between verifier and runtime is the limit most worth examining.** uBPF's
documentation states that PREVAIL "assumes that r1 points to a valid memory region", while
uBPF "doesn't enforce any particular context layout" and "memory safety depends on the
program". The defence in this implementation is a chain of admission-time identity checks —
ELF section name, function symbol, context ABI version, build ID, and symbol ambiguity — and
not a runtime bounds check. Signature verification is therefore load-bearing rather than merely
desirable — which is why it was built, and why the failure that mattered during that work was not
cryptographic at all: an image shipped with a client too old to send a signature, and TMM refused
every load correctly while looking broken.

---

## 6. Candidate extensions

Ordered by value against cost.

### Near term

| # | extension | effect | risk |
|---|---|---|---|
| 1 | Array maps | The appropriate structure for dense, small key spaces such as alert codes and error enums | none |
| 2 | `.data` / `.rodata` relocation | A threshold becomes a load-time parameter rather than a recompilation; the relocation callback already exists | none |
| 3 | PMU counters as a helper | The remaining half of the per-invocation question. A floor is now measured; instructions-retired would give the *data-path* figure, and it is not subject to the preemption artefact that makes `rdtsc` means unusable | none — measurement rather than mechanism. Note `perf_event_paranoid=4` blocks it today, and the watchpoint prototype found `CAP_PERFMON` insufficient at that setting |
| 4 | Map iteration | A program can summarise its own accumulated state rather than only adding to it | low |

### Medium term

| # | extension | effect | risk |
|---|---|---|---|
| 5 | Audit trail, and key management for the signing key | Signature verification is **done**; what is missing is the record of who armed what, when, in which mode, with what outcome — and a key lifecycle that is not "compiled in at build time" | Low technically; the key half is principally a process question, and it is the half that decides whether this is shippable |
| 6 | Safe-return policy table | Makes suppression admissible, and refuses hooks whose return type does not fit `rax` | Low, and it removes an existing hazard |
| 7 | Exit and return probes | Function outputs: in-TMM latency, and what a function decided rather than what it was asked | **Medium to high — the first extension able to corrupt control flow.** Requires per-thread, per-depth return-address storage, a depth limit, and an abandonment path for `longjmp`, unwind and `noreturn` |

### Longer term

| # | extension | effect | risk |
|---|---|---|---|
| 8 | Displacement (inline hooking) | The 30,009 unpadded entries, OpenSSL included. Leading bytes are copied verbatim and a `jmp rel32` written over them; relocatability is determined offline by the index generator, so the runtime remains a memory copy and a jump with no decoder in the data path | Medium — a check on executing threads' program counters is required before patching |
| 9 | Hardware watchpoints | Any address, with no pad required. The only route to code F5 does not compile — the 1,781 linked OpenSSL symbols included | **Prototyped 2026-08-20, outside TMM — [`prototype/watchpoint/`](prototype/watchpoint/). Three corrections.** Delivery does **not** require a signal: `perf_event_open` breakpoints sample into a ring another thread drains, so nothing runs in the watched thread. The privilege ask is **`CAP_SYS_ADMIN`**, not the narrow `CAP_PERFMON`, which is refused at `perf_event_paranoid=4` — that may settle the question on its own. Four is exact (`ENOSPC` on the fifth). And the per-hit cost is **501 ns on aarch64, 4,755 ns on the x86 KVM guest**, against ≤ 11 ns for a pad hook: 45× at best. So it is the reach mechanism for rare events, and unusable per-request — 16,000 requests would cost 8–88 ms of pure trap |
| 10 | Timer or periodic hook | **Deprioritised.** The clock and event-output helpers already provide in-place aggregation, which was this extension's purpose | Low, and now largely redundant |

### Considered and declined

- **LLVM-based JIT.** A substantial dependency inside a data-plane process entering a TMA.
  The auditability of uBPF's simple JIT is central to the case for the approach.
- **Shared-memory cross-process maps.** The present maps are per-thread and lock-free by
  construction; sharing them introduces a lock on the poll loop.
- **A third-party inline-hooking library** (Frida-gum, the instrumentation engine used by
  the Frida dynamic-analysis toolkit). Evaluated and found to work inside TMM, including on
  unpadded OpenSSL functions and under TMM's own allocator — so it would have reached the
  30,009 entries the compiler pad cannot. Declined on supply-chain grounds: 753 object files
  drawn from 9 upstream projects, without verified provenance, linked into a security
  appliance's data plane. The decision was about provenance, not capability.

---

## 7. Anticipated questions

**What is the per-invocation cost?** A **floor** of ≤ 11 ns for program execution on the JIT
path, and I would rather give you the floor with its boundary than a confident number. It is
26–28 cycles at 2.60 GHz, and the `rdtsc` pair doing the measuring costs about that much on its
own — the tell is that a program which builds and emits a record came in *below* one that returns
immediately, which is impossible. So the four smallest programs are indistinguishable and the
honest form of the answer is an upper bound. Two that clear the instrument: `bpf_probe_read` at
26 ns, and a maps-plus-clock-plus-emit program at 105 ns. An off-TMM harness independently
recorded 10 ns.

What is **not** in that figure: the trampoline's register save and restore, the call and the
return, and cache effects under real traffic. So it is not a per-packet cost, and extension 3
(instructions-retired via the PMU) is what would give one — `rdtsc` means remain useless, one
pair spanning a context switch having produced 130,720 cycles against a minimum of 132.

Getting this far required fixing the instrument: the benchmark op locked the loader thread
because it allocated on a thread where TMM's allocator freezes, and it timed the *interpreter*
while every armed hook runs JIT-compiled code — so the figure it used to produce was several
times too pessimistic and described a path nothing executes.

The other known cost is the 0.182% size increase from the padding, which has no run-time
component until a hook is armed.

**What happens when a program is wrong?** Admission fails closed; invocation fails open. A
program faulting at run time falls through and the fault is counted, on the principle that a
shield unable to run must not take the flow with it. The hazardous case is not a fault but
an incorrect safe return value, which extension 6 addresses.

**Can this take TMM down?** In `ENFORCE`, on a hook whose return type does not fit `rax`,
yes — by returning a value the caller misinterprets. This is why the first version is
restricted to trivial return types and why the safe-return policy table is on the list.
Arming and disarming have been exercised repeatedly under traffic with byte-identical
restoration.

**Why not a `tmstat` counter or a log line?** Because the question is usually correlation
rather than counting: `tmstat` holds totals with no link to the request that produced them.
Four tests are applied before adopting a hook — is it a decision, is the reason already
logged, does it raise an iRule event, are there enough call sites. `ssl__err`, at 475 call
sites, fails the second: its reason is already emitted to syslog at warning level with more
detail than an entry hook receives.

**Why build this rather than adopt something off the shelf?** Partly it was not necessary
to: the two components that do the hard work — the bytecode interpreter and the verifier —
are existing open-source projects, used unmodified. What was built here is the layer between
them and TMM: the entry patching, the trampoline, the per-thread maps, the egress ring, and
the argument-flattening that lets a verified program see scalars instead of TMM pointers.

There is a mature open-source project that packages all of that together for userspace
processes. It was assessed and not adopted, for three reasons specific to this target. Its
attach mechanism rewrites instructions at the target and relocates the ones it overwrote,
where this approach overwrites reserved padding and displaces nothing. It brings a
compiler-based JIT into the hosting process, which is a large dependency for a component
entering a TMA. And its data structures are shared across processes, where TMM's
run-to-completion, core-pinned model wants per-thread structures with no locking on the poll
loop.

That reasoning justifies not adopting it wholesale. It does not justify having derived ring
buffers and hash maps from first principles, and the accounting for what was rebuilt
unnecessarily is set out in `hook-types.md` §4.

**What is the minimum required to make this shippable?** An audit trail and a key lifecycle,
together with the safe-return policy table if enforcement is in scope. Signature verification
itself was the largest of these and is now built and measured — which moved the answer rather
than shortening it: a signature says a program came from the holder of a key, and says nothing
about who asked for it to be armed, when, or on which build. The remaining items on the
extension list are capability rather than admissibility.
