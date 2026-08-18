# The eBPF engine in TMM: what it does, what it has done, and what it could do

For a review by senior TMM architects. Written 2026-08-18.

**Rule this follows:** every "does" below has been run on a live TMM and the evidence is
named. Every "could" is labelled with what it costs and what it risks. Anything unmeasured
says so — there are several, and they are the questions this audience will ask first.

---

## 1. The mechanism, in one page

`-fpatchable-function-entry=5,0` is added to `CFLAGS_OPTIMIZE`. Every function TMM compiles
gets five reserved `nop` bytes at its entry. At run time, arming a hook overwrites those
five bytes with `call rel32` to a per-slot trampoline.

```
DISARMED   f3 0f 1e fa   90 90 90 90 90   41 55 4d 63 c0
                         └─ the compiler's pad ─┘
ARMED      f3 0f 1e fa   e8 79 fb fd fe   41 55 4d 63 c0
                         └── call rel32 ──┘
```

The trampoline saves the six argument registers, calls into C, and acts on a verdict:
fall through to the function body, or skip it and return a declared safe value.

**Why this shape and not inline hooking.** Nothing is displaced. No instruction is moved,
so there is nothing to relocate, no decoder in the process, and no window where another
thread's program counter is inside bytes being rewritten. Disarm is a byte-for-byte
restore — **asserted, not assumed**. That is the entire reason arming a live data plane
under traffic is arguable rather than reckless.

**What runs the program.** uBPF (`~4k lines, interpreter + simple JIT`) inside the TMM
process, with programs verified ahead of time by PREVAIL. Both are vendored **unmodified** —
zero forks, zero commits ahead of upstream. That was a deliberate choice for a component
heading into a TMA: the reviewable surface is a few thousand auditable lines, not LLVM.

**What it adds to the tree.** New files, `filelist` and whitelist entries, and one compiler
flag. **No F5 source file is modified.**

---

## 2. What it has already done — on a live TMM, with evidence

| # | result | evidence |
|---|---|---|
| 1 | A verified program loaded into a **running** TMM and armed at a function entry, no rebuild, no restart | `OK ARMED LIVE entry=0x144f604 slot=5 (no restart)` |
| 2 | Disarmed again, entry bytes **byte-identical** | read from `/proc/<pid>/mem` before/armed/after; equality asserted by the script, exit non-zero if not |
| 3 | Fires exactly once per event | a hook on `http_parse_client_headers` fired once per request across **16,000 requests** through the proxy |
| 4 | Reports TMM's own reset decisions | `rst_why` + 3 siblings, **1,116 call sites**; records carry file, line, `err`, reason, cause string, flow cookie |
| 5 | Cross-checked against an **independent oracle** | `tcpdump` showed TMM's own RST payload carrying the same cause *and* line as our record, from a code path sharing nothing with ours |
| 6 | Reports HTTP/2 stream aborts | `http2_stream_abort` armed and fired; records carry the real literals — `"malformed content-length"`, `"Content-Length Exceeded"` |
| 7 | Two hooks corroborate one decision | `h2abort` reported `malformed content-length` 6× and `rst_why` at `http2.c:1773` reported the same reason 6× — different functions, different hooks, same event |
| 8 | Concurrent hooks of different argument shapes | 12 trampoline slots; reset family (4 slots), h2abort, ssl__err, ALPN, parse live together |
| 9 | State across invocations | per-thread hash maps; a program answers "has this site done this N times", which no stateless program can express |
| 10 | **Rate limiting decided inside the data plane** | `rate_gate`: 86 events → **2** emitted records, windows measured at 16.0 ms and 10.8 ms by the program itself |
| 11 | Arming by **name**, build-ID gated | `rst_why` has sat at three different addresses across three builds of the same source; the index carries the build ID and a mismatch is refused |
| 12 | A shield expressing a real security fix | `alpn_guard` restores the bounds check F5's own commit `c806f1b2e8` added to `ssl_alpn_match`; PREVAIL admits it |

**Scale of the addressable surface**, from the index generated against the shipped binary:

| | count |
|---|---|
| functions armable **today** (padded) | **41,143** |
| armable only by displacement (**unbuilt**) | 30,009 |
| total entries in the index | 71,157 |
| distinct symbol names | 70,029 |

---

## 3. What it can do today

**Observe a decision no other surface can see.** This is the core claim and it is
structural, not incidental:

> Falcon and every kernel-eBPF agent attach to kernel hooks — syscalls, tc, XDP, kprobes,
> LSM. **TMM has its own userspace data path and traverses none of them.** So a kernel
> agent sees the container, the host, the process and the packets on the wire, and not one
> decision TMM makes about them.

`rst_why` decides, at 1,116 sites, to tear a connection down — with a source line and a
human-written reason. None of that crosses the boundary a kernel agent watches, and none
of it is reachable from iRules or WASM.

**Refuse a call before a vulnerable body runs.** The program inspects the arguments and
selects `SAFE_RETURN`; the function never executes. That is a mitigation that ships as a
signed object rather than as a release.

**Do it in `MONITOR` first.** Three modes: `DISABLE`, `MONITOR` (evaluate and count, apply
nothing), `ENFORCE`. So a customer can be shown what *would* have been refused, at what
rate, before anything takes effect.

**Decide with state and with time.** Per-thread maps plus a clock helper mean a program can
express "five times in the last second at this site" and emit only then — 43:1 reduction
measured.

---

## 4. What it cannot do — the list this audience will ask for

| limit | detail |
|---|---|
| **One event source** | Function **entry** only, on padded functions. Kernel eBPF has ~10 attach types; this has one |
| **No exit probes** | A program sees a function's INPUTS. What it returned is structurally unavailable — no latency, no return-value inspection |
| **Padded functions only** | 30,009 entries need displacement, which is designed and **not built**. OpenSSL and every separately-built component are in that set |
| **Per-invocation cost UNMEASURED** | `rdtsc` is preemption-polluted so the mean is meaningless; `perf_event_paranoid=4` on the node blocks hardware counters. **Quote no per-call number** |
| **Safe return value hardcoded `0`** | Per-function safe values are unbuilt. A wrong safe value converts a crash into *silent misbehaviour*. Only correct for return types that fit in `rax` |
| **No signature verification** | The loader accepts any program and announces it on every load. Lab only. This is the single largest gap between what runs and what could ship |
| **No audit trail** | Who armed what, when, in which mode, with what result, is not recorded durably |
| **JIT skips the bounds callback** | The interpreter and the JIT do not agree on memory safety, and the lab runs the JIT |
| **Three helpers, one map type** | lookup/update/delete, hash only, 4 maps × 256 entries, key ≤16 B, value ≤32 B. No iteration, so a program can accumulate and never summarise |
| **96-byte context ceiling** | **Measured**, not folklore: a read at byte 95 of a 96-byte ctx verifies; byte 99 of a 100-byte ctx is refused. It is why the reset record carries a flow *cookie* and not a 5-tuple |
| **Flow cardinality, not identity** | The cookie answers "same flow or not"; it does not say which client |
| **Reachability is per-site and must be measured** | Five CVE candidates were compiled into the binary and never executed on BNK's path. `fired > 0` under traffic is the only proof |

**The one worth dwelling on** is the JIT and the verifier. uBPF's own
`docs/VerifiedPrograms.md` states PREVAIL *"assumes that r1 points to a valid memory
region"* while uBPF *"doesn't enforce any particular context layout"* and *"memory safety
depends on the program"*. Our defence is a chain of **admission-time identity checks** —
ELF section name, function symbol, ctx ABI version, build ID, symbol ambiguity — not a
runtime bounds check. That is what makes signature verification load-bearing rather than
merely desirable.

---

## 5. What it could do, with development

Ordered by value ÷ cost. The first four are small.

### Near term — small, and two of them are one helper each

| # | extension | what it unlocks | risk |
|---|---|---|---|
| 1 | **Array maps** | The right shape for dense small key spaces (alert codes, error enums). A 256-entry hash for 16 dense keys is the wrong tool | none |
| 2 | **`.data`/`.rodata` relocation** | A threshold becomes a load-time parameter instead of a recompile. The relocation callback already exists | none |
| 3 | **PMU counters as a helper** | The direct answer to the unmeasured per-call cost. `rdtsc` is preemption-polluted; instructions-retired is not | none — measurement, not mechanism |
| 4 | **Map iteration** | A program can summarise its own accumulated state instead of only adding to it | low |

### Medium — real capability, real cost

| # | extension | what it unlocks | risk |
|---|---|---|---|
| 5 | **Signature verification + audit trail** | Everything customer-facing. Nothing ships without this | low technically; it is a key-management and process question |
| 6 | **Safe-return policy table** | Turns "suppress a code path" from a lab trick into something admissible, and refuses hooks whose return type does not fit `rax` | low, and it removes a live hazard |
| 7 | **Exit / return probes** | Reading a function's **outputs**: latency inside TMM, and what it DECIDED rather than what it was asked | **medium-high — the first that can corrupt control flow.** Needs per-thread per-depth return-address storage, a depth cap, and a give-up path for `longjmp`/unwind/`noreturn` |

### Longer — changes what can be reached

| # | extension | what it unlocks | risk |
|---|---|---|---|
| 8 | **Displacement (inline hooking)** | The 30,009 unpadded entries, OpenSSL included. Leading bytes are copied verbatim and a `jmp rel32` written over them; relocatability is decided **offline** by the hook-map generator, so the runtime stays a memcpy and a jump with no decoder in the data plane | medium — a live-PC check is required before patching |
| 9 | **Hardware watchpoints** | Any address, no pad needed. The only route to code we do not compile | **high.** Needs privilege, four debug registers, and SIGTRAP delivery into a run-to-completion poll loop — a different safety problem entirely |
| 10 | **Timer / periodic hook** | **Deprioritised.** Items 1–4 plus the clock and emit helpers already deliver in-place aggregation, which is what this was for | low, and now largely redundant |

### Deliberately not on this list

- **LLVM JIT** (bpftime's) — a large dependency inside a data-plane process heading for a
  TMA. uBPF's auditability is most of the argument for the whole approach.
- **Shared-memory cross-process maps** — ours are per-thread and lock-free by construction;
  sharing means a lock on the poll loop.
- **Frida-gum inline hooking** — tested 2026-08-17. It works, hooks unpadded OpenSSL, and
  survives TMM's allocator. Rejected on the supply-chain gate (753 objects, 9 projects,
  unverified provenance), **not** on capability.

---

## 6. Questions this room will ask

**"What does it cost per invocation?"** Unmeasured, and we will not quote a number. `rdtsc`
is preemption-polluted; the node blocks hardware counters (`perf_event_paranoid=4`).
Extension 3 fixes it. What *is* known: the size tax of the pads is **0.182%** of the binary
(74,048 functions × 5 bytes), and a pad costs nothing at run time until armed.

**"What happens if the program is wrong?"** Admission fails closed; invocation fails open. A
program that faults at run time falls through and the fault is counted — a shield that
cannot run must not take the flow with it. The dangerous case is not a fault, it is a
**wrong safe return value**, which is extension 6.

**"Can it take TMM down?"** Today, in `ENFORCE`, on a hook with a non-trivial return type —
yes, by returning a value the caller misinterprets. That is why v1 is restricted to trivial
returns and why the policy table matters. Arming and disarming themselves have been
exercised repeatedly under traffic with byte-identical restore.

**"Why not just add a tmstat counter / a log line?"** Because the question is usually
correlation, not counting. `tmstat` holds totals with no link to the request that caused
them. And the screen we apply before adopting a hook has four tests, of which the second
disqualified our own first choice: is it a decision · **is it already logged** · does it
raise an iRule event · are there enough sites. `ssl__err` (475 sites) failed on test 2 —
its reason is already in syslog at `LOG_WARNING` with more detail than an entry hook gets.

**"Is this reinventing bpftime?"** Partly, and the honest accounting is in `hook-types.md`
§4. Maps, helper registration, the egress ring and the attach machinery were hand-built.
What the reinvention bought is narrower than it looks: an attach mechanism that displaces
no instruction, a reviewable surface for a TMA, and per-thread lock-free structures that
suit a run-to-completion poll loop. It does **not** justify re-deriving ring buffers from
first principles.

**"What is the smallest thing that would make this shippable?"** Signature verification and
an audit trail (extension 5), plus the safe-return policy table (extension 6) if
enforcement is in scope. Everything else on the list is capability, not admissibility.
