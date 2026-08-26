# What building it found — the embedded VM, in a real TMM

### A catalogue of findings from actually integrating uBPF into TMM, building it, and running it in a pod. Measurements, defects and corrections, each with what it does and does not support.

Everything here came from doing it rather than reasoning about it, on **2026-08-12**. The
proposal documents make design claims; this records what the work returned, including the parts
that contradicted the claims — and the parts where an earlier entry in this very file was wrong
and had to be replaced.

**What was built was a working prototype and nothing more.** It was never meant to be
submittable, and it is not: it uses system headers TMM forbids, raw C types where TMM requires
its own, and multiple return points where TMM requires one. That is not a shortfall — an
instrument is not a product. The prototype's output is this document, and the code was how it
was obtained. What a submittable change would require is recorded separately in
[`env/tmm-build-environment.md`](env/tmm-build-environment.md), as reconnaissance for a later
effort rather than as a list of things left undone.

> **Updated 2026-08-14.** That paragraph describes the 2026-08-12 prototype and stays as written,
> but the substrate has since moved past every objection in it. It now respects TMM's include-world
> split (`ls_prep.c` carries the `-nostdinc` half, `ls_vm_load.c` the `STDINC` half, and only a
> `void(void)` crosses), registers itself through TMM's own `INIT_FUNC` linker set, and **modifies
> nothing spliced into TMM's own logic** — `http_psm.c` is pristine, though the tree gains 39 files
> and three edited build-configuration files. What a submittable change requires is no longer
> only reconnaissance: see [`substrate/TMM-TREE-DELTA.md`](substrate/TMM-TREE-DELTA.md).

Scope throughout: **BNK / MBIP**, x86-64, `tmm/tmm` at `e2104734a9`, on an Intel Xeon Gold 6348
@ 2.60 GHz. Nothing here transfers to the appliance or VE builds without being redone —
they are separate compilations, and a compilation is what most of these numbers are about.

Companions: [`env/tmm-build-environment.md`](env/tmm-build-environment.md) for the environment
and the full narrative, [`env/bnk-dev-runbook.md`](env/bnk-dev-runbook.md) for the commands,
[`design-review-findings.md`](design-review-findings.md) for the O-series findings this
references.

---

## 1 · What was established

**The VM lives in TMM.** uBPF builds inside TMM's own toolchain container with the same gcc
11.4, links against TMM's objects, instantiates per TMM instance, and is called from a real
data-path function. Verified in the binary rather than inferred from a build succeeding:
`nm` finds `ls_vm_init/arm/call/fini` and 45 `ubpf_*` functions, and `objdump` finds
`call <ls_vm_call>` inside `http_psm_profile_name_lookup` at `0xcbd9ba`.

**The integration is 39 additive lines in one data-path source file.**

| tracked file | change |
|---|---|
| `src/modules/hudfilter/http/http_psm.c` | **+39, −0** |
| `src/compile/filelist` | +4 |
| `src/compile/{debug,default}_whitelist_x86_64` | +21, −2 each |
| | **81 insertions, 4 deletions, 4 files** |

Plus ten new files under `src/base/`. **No existing line of F5 code was changed anywhere**; the
four deletions are whitelist churn. That is the scale of the *integration* — not of the
mechanism, since the trampoline, pad rewriting and safe point (items 0–2) are not in it.

**A verified program runs, and its verdict is correct.** The shield compiles with clang 18,
passes PREVAIL with `--termination --no-division-by-zero --strict`, and inside a running TMM pod
returns `SAFE_RETURN` on the CVE condition and `FALLTHROUGH` on the healthy case.

**Its `ctx` came from the build's DWARF**, not from someone typing out a struct — `pahole` read
`fw_log_profile_protocol_transfer` (name at offset 0, size 48) and `http_psm_log_data` (32
bytes, `scb` at 24) out of `tmm64.no_pgo.debug`. That layout is a property of one build, which
is the whole reason it must be generated.

---

## 2 · Measurements

### 2.1 Invocation cost

| path | min | mean | max | ns @ 2.6 GHz (min) |
|---|---|---|---|---|
| interpreter | 126 | 240 | 2,471,618 | **48** |
| **JIT** (extended mode) | **26** | **74** | 233,286 | **10** |

Same program, same box, one environment variable apart. **~4.8× at the floor**, and the tail
falls by an order of magnitude — which matters more for a p99 argument than the floor does.

**Carry these caveats or do not use the number:** a 9-instruction program, warm cache, no
contention, `ubpf_exec`/the JIT entry **only** — no `ctx` build, no trampoline, no poll loop.
It is a **floor, for the smallest useful program**.

Against `big-ip-live-surface-design.md` §11's *"order tens of nanoseconds… emphatically not
comparable to a C `if`"*: both halves survive. 10 ns is tens of ns; against a sub-nanosecond C
`if` it remains roughly an order of magnitude more expensive.

### 2.2 The budget pass is ~6× optimistic

`substrate/budget_pass.py` priced this exact program at **~21 cycles**. It costs **126** in the
interpreter. The tool's docstring already says it is uncalibrated and orders programs rather
than predicting nanoseconds — but *"we know it is uncalibrated"* and *"it is wrong by 6× on the
first real program"* are different statements, and only the second is evidence.

This is also the **first calibration point that tool has ever had**. One point cannot separate
fixed entry cost from per-instruction cost; a fit needs many programs of varying length and
opcode mix, and separately for interpreter and JIT, which are different machines.

### 2.3 Footprint

Like-for-like, both `tmm64.no_pgo`, both plain `-O2`:

```
binary  56,449,248 -> 56,558,560    +109,312   +0.19%
  .text                              +81,920   +0.27%
  .rodata                            +14,464   +0.13%
  .data                               +6,912   +5.55%
  .bss                            +1,313,600  +15.62%   <- self-inflicted, since fixed
```

**The whole VM costs +0.27% of `.text`** — less than the entry-padding flag's +0.476%. *The
engine is cheaper in code than the mechanism for attaching to it,* and both are under one
percent. Image size will not be the objection.

The `.bss` figure was two statically-sized worst-case buffers (1 MB + 256 KB) for memory used
only at load time, in a process that runs **one instance per core** — ~21 MB of zero-filled
pages on a 16-core box. Both now allocate on demand.

### 2.4 Entry padding, and what it reaches

`-fpatchable-function-entry=5,0` compiles cleanly across 2,039 files under `-Wall -Werror` —
which was genuinely open beforehand. Cost: **+0.476% `.text`**, **3.97 effective bytes per
padded entry against 5 nominal** (alignment absorbs 21%).

But it reaches only **48.9%** of the shipped binary's functions:

| source | padded |
|---|---|
| `src/compile` (the TMM tree) | 82% |
| the TMM RPM's own build | 97% |
| ~two dozen separately-built F5 components | **0%** |
| vendored third party (OpenSSL, regex, json-c) | **0%** |

**TMM is assembled, not compiled — but into ONE binary.** Roughly half its functions come from
builds that never saw the TMM build's flags, and three components arrive from Artifactory as
**prebuilt RPMs**. Crucially they are **statically linked into the single `tmm64` executable** —
~2,000 OpenSSL functions (`X509_`/`EVP_`/`ASN1_`) are verified defined inside it, not separate
`.so`s or processes. So "separate" means separate *build*, not separate program: the paddable
set is about half the hookable set, and closing the gap is another *build* turning the flag on,
after which the same runtime mechanism reaches it — coordination, not new machinery.

Scoped to the data plane the gap narrows and sharpens: it is dominated by **OpenSSL/`crypto`**
(788 symbols, TLS record and handshake) with per-flow `dedup` second, while `afm`'s unpadded
portion is the background sweeper rather than per-packet enforcement.

### 2.5 The hookable set

**119,555** out-of-line functions in the BNK build (42,215 global, 77,340 local; ~113,604
excluding obvious third party), with 92 `.constprop`, 76 `.isra`, 126 `.part` clones and full
DWARF. Reproduced byte-identically on a second, independently provisioned machine — which is
what makes it a property of the build rather than of one box.

**Condition 1 of §10.1 is verified**, in the unfavourable case: `http_psm_profile_name_lookup`
is a `static bool` — the shape most likely to be dissolved into its caller — and it survives
`-O2` as symbol type `t`.

---

## 3 · Defects found in the tools we depend on

### 3.1 uBPF's stack-usage contract is documented backwards (O13)

`ubpf.h` says: *"If the callback returns 0 or there is no callback registered, the eBPF
interpreter/JITer assume that the local function uses the maximum stack available according to
the spec (512K)."* Neither holds. No calculator gives **256**; a calculator returning **0** is
recorded as `CUSTOM` with value 0 and the function gets a **zero-byte frame** — the 16-byte
alignment guard passes it (`0 % 16 == 0`) and nothing else rejects it, in the interpreter or
either JIT backend.

A host that read the header and returned 0 meaning "assume the worst" would get the best case.

### 3.2 The verifier and the runtime name the program differently (O14)

**PREVAIL selects by ELF section name; uBPF selects by function symbol name** —
`strcmp(rf.name, main_function_name)` at `ubpf_loader.c:271`, where `rf.name` comes from the
symbol table, while uBPF's own header calls that parameter `main_section_name`.

So *"PREVAIL verified this object"* and *"uBPF is running this program"* are assertions about
**two different identities**, and nothing in the chain is positioned to notice a divergence: the
signature covers bytes, the verifier covers a section, the loader resolves a symbol. In an
object with several functions, one can be verified and another loaded.

`ls_vm_arm()` now requires both names and reads the object's symbol table to refuse unless the
named function is defined in the named section. **The design consequence is larger than the
fix:** the hook map and the signed binding must carry both identities. `struct shield_binding`
currently carries one.

### 3.3 `ubpf_exec` never runs JIT-compiled code

`ubpf_exec` and `ubpf_exec_ex` always interpret. A compiled program is reachable **only**
through the pointer `ubpf_compile` returns. Code that compiles and then calls `ubpf_exec` JITs
the program and discards the result — which is exactly what happened here, and the tell was a
"JIT" measurement identical to the interpreter.

### 3.4 `ubpf_exec` opens a 4 KB stack frame per invocation

It declares `uint64_t stack[UBPF_EBPF_STACK_SIZE/8]` as a **local**, so every invocation opens a
4 KB frame at whatever depth the caller is at. That is finding O7's hazard — filed against the
JIT prologue — present on the interpreter path too. `ubpf_exec_ex` takes the stack from the
caller; both paths now use one per-instance buffer, and the JIT uses **extended** mode because
`ubpf.h` says basic mode "automatically allocates a stack".

**It did not, however, cost anything measurable** — see §5.2.

---

## 4 · Findings about TMM itself

### 4.1 TMM has zero tracepoints, and 1,621 `tmstat` call sites

No `DTRACE_PROBE`, `STAP_PROBE` or `sys/sdt.h` anywhere, and — the test that settles it —
**zero `.note.stapsdt` entries in the shipped binary**. Every row of the tracepoint catalog is
net-new.

But TMM is far from unobservable, and the incumbent is not logging:

| mechanism | call sites |
|---|---|
| **`tmstat_*`** | **1,621** |
| `errdefs_*` | 500 |
| `logger()` / `logger_binary()` | 274 / 136 |
| `TRACE_*` | 71 |

Counters belong in `tmstat`. A new counter surface beside a mature one that is already
everywhere is the first thing a reviewer will say. And the catalog never argues the case for
USDT *against* the incumbent — USDT buys external attachability (`perf`, `bpftrace`), `tmstat`
buys native integration. Probably both, chosen per row.

### 4.2 The build whitelists mutable global state — and it is a manifest, not an allowlist

`src/compile/Makefile:1626` runs `bin/diff-globals` against a per-architecture, per-build-type
list. `bin/print-globals` extracts `.data`, `.bss` and COMMON symbols — deliberately **not**
functions. It is an allowlist of **global mutable state**, and it is checked with `diff -u`, so
**removing** tracked state fails the build exactly as adding it does.

Embedding the VM adds **ten** entries: `g_slots`, `g_ready`, `ls_ptlog_slot`, `g_prog_stack`
(ours) and `_initialized`, `register_map`, `_ubpf_instruction_filter`,
`_ubpf_filter_instruction_lookup_table`, plus two `ebpf_*_enumerated` opcode tables (uBPF's).

Ours should move into TMM's per-instance structure before anyone is asked to approve them. The
manifest exists so that new global mutable state in a per-core data plane gets argued for, and
"it was the shortest path to a link" is not the argument.

### 4.3 The hooked function has no caller, and that is the point

`http_psm_profile_name_lookup` appears nowhere in the source except its own definition. It is
registered by token-pasting at `http_psm.c:1238`:

```c
#define PSM_KEY(E, S) {(E), "\"${" #S "}\",", sizeof(#S) + 5, http_psm_ ## S ## _lookup}
PSM_KEY(ERRDEFS_KEY_PROFILE_NAME, profile_name),
```

— an entry in a **key → formatter table** for `errdefs`, reached when a log format string
contains `${profile_name}`, in the CEF security-event record builder for HTTP.

Three consequences. It is **data-plane** code, not control plane: it runs in TMM, per-request,
on a live flow whose `scb` it is handed. The bug's shape is a **control-plane misconfiguration
that detonates on the data path** — the NULL comes from a listener with no protocol-transfer log
profile — which is a good advertisement for a data-plane shield, since the fix has to land where
the crash is. And it is an independent argument for publishing the hookable set as a build
artifact: **nothing in the source says this function is called**, so neither an engineer nor
`grep` can enumerate reachable functions. Only the build can.

### 4.4 Other build facts worth knowing

- **`yq` is load-bearing.** The Makefile resolves every image coordinate from
  `input-manifest.yml` through it; missing, `_start` runs `docker run … :v`.
- **A global `CFLAGS +=` does not reach most files.** `filelist`'s
  `INSTRUMENT = CFLAGS +=` gives nearly every object a target-specific `CFLAGS` that shadows
  the global. It reached 344 compile lines and not the one that mattered.
- **`%zu` does not work.** TMM builds `-fno-builtin-printf` with `-Wno-format`; a size printed
  with `%zu` came out as hex with a stray `u`.
- **The Artifactory token is load-bearing**, contrary to an earlier assumption here: the build
  `wget`s `tmstat`, `libbigpacket` and `tcpdump` RPMs, which return **401 anonymous, 200 with
  the token**.

---

## 5 · Where the work corrected itself

Recorded because the corrections are more informative than the results, and because a document
that only lists what went right is not evidence.

### 5.1 A shield verdict obtained under the wrong program type

The first PASS was under PREVAIL's **`socket_filter` fallback**, whose descriptor is `__sk_buff`
— 192 bytes with pointer slots at 76/80/140. The shield's `ctx` is 24 bytes and reads offsets 0,
8 and 20, so it verified while touching none of the interesting structure: a small box fitting
inside a big one. This is finding **O3**, and the section prefix `filter/` matches nothing in
PREVAIL's table.

`fentry/` selects `tracing` — 96 bytes, **no pointer slots** — which is an honest description of
an entry hook receiving argument values. All four verdicts held under it, which is what makes
them worth quoting. `check_shields.py` now fails the build if a section name stops matching a
real prefix. **The repo already said this** in the now-retired `development-scope-code.md`; it was written
and then not consulted.

### 5.2 A hypothesis the measurement killed

This file previously recorded that `ubpf_exec`'s 4 KB per-invocation frame was *"very likely a
real share of the 126-cycle floor"*. **It is not.** Moving to a per-instance stack left the floor
unchanged (126→126, 138→132). Allocating stack is a `sub rsp, N`; untouched pages never fault
in. The change remains correct for O7, but it buys nothing measurable and the earlier claim
should not be repeated.

### 5.3 A plausible wrong answer, dressed as a careful one

§10.1 and §14 both explained a symbol's absence from the build with a three-way argument about
product editions, and even enumerated why the zero was uninformative. All three were beside the
point: **the symbol was invented.** `fw_log_prot_transfer_emit` never existed. Worse, §14
concluded condition 1 "remains unverified" when it had been verified — the sentence contained
no number, so a value-based sweep would never have found it.

### 5.4 Instrumentation that reported success it had not earned

- **`budget_pass.py` read an empty `.text`** and returned "ok, under budget" for a program it
  never examined — in the one component whose job is to fail closed.
- **`check_skeletons.py` filtered stderr for `": error:"`**, but a missing include is
  `": fatal error:"`, so a block that never compiled was reported green.
- **`FIRST INVOCATION --- the hook is reached`** printed with no traffic flowing, because the
  self-test calls `ls_vm_call()`, the same entry point the real hook uses. The harness reached
  the hook, not a packet. The counted path and the test path must be separated.

### 5.5 Stale artifacts, three times

Comparing against a previously extracted binary produced a confidently wrong answer on three
separate occasions — a `no_pgo` binary against a `debug` one (+11 MB of `.text`, all build-type
difference), a debug file against a binary with a different build-id, and a copy pulled before a
deploy reporting `0` for knobs we had watched work. **Re-extract; never reuse.** Check build-ids
before trusting a symbol address.

---

## 6 · What is still not established

> **Read this section as of 2026-08-12; two entries have since been answered.** Marked inline
> rather than deleted, because what was blocking and how it cleared is part of the record.

- ~~**Traffic has never reached the hook.**~~ **Answered 2026-08-13.** The connection refusals were
  a routing problem, not a hook problem. A hook armed on `http_parse_client_headers` then fired
  **exactly once per request across 16,000 requests** — 1:1, so the hook demonstrably sits on the
  request path. What that does *not* show is a shield changing an outcome: every program armed live
  so far returns `FALLTHROUGH` by construction.
- **The crash is not demonstrated with a captured exit code.** The shield's *decision* is
  demonstrated in both directions; the consequence of not shielding is inferred from a container
  that dies at init under one environment variable and is replaced.
- **Nothing about cost at rate.** Throughput, latency tail, i-cache MPKI and i-TLB — the three
  columns of `design-review-findings.md` §4 that the size measurement does not touch.
- **aarch64.** Every number here is x86-64.
- **The appliance and VE builds.** Same source tree, different compilations; the pattern
  transfers, the measurements do not.
- ~~**Everything above rung 1.**~~ **Partly answered 2026-08-13.** Changing a shield no longer
  means a rebuild: a program is loaded over a socket into a running TMM and armed while traffic
  flows. The second half of the sentence is untouched and is now the whole of the objection — **the
  load path is unauthenticated**, so no configuration that could ship may use it. Item 4.
