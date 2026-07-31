# Design-review findings — three architect reviews, and what they change

### What a senior TMM architect finds when they read the whole proposal. Organised by disposition, not by reviewer.

**Status:** Review register · dispositions tracked here, fixes land in the docs they affect
**Origin:** Three independent reviews (strategy docs · engineering scope · explainers + catalogs), each in the role of a 20-year TMM developer. The third verified load-bearing claims against the **uBPF and PREVAIL sources vendored in this repo** — so a number of findings are demonstrable rather than arguable.
**Companion:** [`engine-hard-problems.md`](engine-hard-problems.md) (problems we already knew about) · [`development-scope.md`](development-scope.md) / [`development-scope-code.md`](development-scope-code.md) (what the effort numbers apply to)

---

## The verdict, stated first

All three reviewers would **fund a feasibility phase**. None would fund the twelve-item build as scoped. Their shared reasoning:

- **The mechanism is the right shape** — patchable entry pad, trampoline, signed per-build hook map, monitor-before-enforce, signing gate as the perimeter.
- **The `ctx` model as written does not work**, and that is provable from PREVAIL's own source, not a matter of taste.
- **The effort estimate is low by roughly 5×** — and the two items most likely to sink a TMM design review were not on the list at all.
- The reframe that matters: *"the subsystem you are adding is not the VM — it is a code-patching, live-text, dynamic-code-loading facility in the crown-jewel process, with its own build-pipeline toolchain and a permanent per-build ABI."* That is a subsystem, it is worth building, and describing it as smaller than it is doesn't make it easier to fund — it makes the funding collapse in month nine.

---

## 1 · Demonstrably broken — verified against source or empirically

### 1.1 Fixed already

| # | Finding | Fix |
|---|---|---|
| F1 | **`prototype/hook-point-map.json` omitted the `mode` field of `struct ls_ctx`.** Real offsets are `opcode 0, payload_len 2, avail_len 4, mode 8, head 12`; any tool re-deriving offsets by packing the field list computed `head` at **8**. A shield reading `head[0..15]` would have read `mode`'s four bytes plus twelve of `head`. The ctx-versioning failure mode the design warns about, realised in the artifact the docs cite as validated — with every check green, because a hash of a wrong map is a wrong map. | Field restored; authoritative `field_offsets` + `ctx_size` added; **`make check-offsets`** generates `_Static_assert`s from the map's own offsets and compiles them against the real header. Verified in both directions. (`5f55d3a`) |
| F2 | **The shield program chased two levels of TMM heap pointer.** `ebpf_transformer.cpp:488-492` — a load from `ctx` yields `T_NUM`, an unconstrained number; dereferencing `T_NUM` is rejected unconditionally, and **a NULL check cannot promote a number to a pointer**. So the worked example was rejected *with or without* its guards, and the claim that "PREVAIL requires a NULL-check before every dereference" inverted what actually happens. | The program sees **resolved scalars only**. The hook map declares a bounded pointer walk; the host's generated ctx-builder follows it in native C, NULL-checked per step. Validity argument: the walk is restricted to the chain the hooked function is *itself about to dereference*, so stale pointers would have faulted in the body regardless. (`3cb4b1f`) |
| F3 | **Safe-return eligibility was classified by return type alone**, so a `void` function went straight to enforce-capable. `void` means no return value to fake, **not** no side effects to lose. | Two gates: skippability (side effects; closed by default; unanalysed = refused) then return kind. (`3cb4b1f`) |

### 1.2 Open — each changes the design

| # | Finding | Source | Disposition |
|---|---|---|---|
| O1 | **PREVAIL permits `ctx` writes.** The descriptor is four ints (`size/data/end/meta`); `writable: []` is not something PREVAIL consumes, and with no pointer slots *every byte of ctx is writable by a verified program*. Compose with "the ctx **is** the saved register frame" + "restore registers on fall-through" and a signed, verified, nominally read-only base-tier program becomes an **argument-injection primitive into live TMM code paths** — delivered by the safety mechanism. | `ebpf_base.h:70-75`, `ebpf_checker.cpp:362-364` | **ctx must be a copy** into per-core scratch, discarded on fall-through. Stop claiming read-only enforcement we cannot express. Cheap fix, mandatory. |
| O2 | **`--program-type` does not exist.** Program type is deduced from the ELF **section-name prefix** against a compiled-in C++ table; the fallback is `socket_filter`. Registering a TMM program type is a PREVAIL patch set — a fork by any name, with a rebase cost per release. | `main.cpp:59-148`, `linux_platform.cpp:172-200` | Either own the patch set as a scoped item, or **reuse PREVAIL's existing `tracing` type** (12 u64 args, nothing dereferenced) and change nothing. The latter is free and forces O5 to resolve honestly. |
| O3 | **The prototype's green verify gate is weaker evidence than claimed.** With no program type it falls back to `socket_filter`'s 192-byte `__sk_buff`; the prototype's 28-byte `ls_ctx` loads pass because they fit inside 192 bytes and miss the pointer slots. It demonstrates that a small struct fits in a big one, not that a TMM ctx model verifies. | `linux_platform.cpp`, `minimm.c:146` | State the limit in `prototype/README.md` and `TOOLCHAIN.md`. |
| O4 | **`--termination` is off by default** and the prototype does not pass it — so the demonstrated pipeline proves memory safety, **not** termination, while hard-problems §1 rests on "PREVAIL proves halting." When enabled, the bound is **100,000 loop iterations** ≈ 300µs at ~10 instr/iter on a 3GHz core. | `config.hpp:57`, `syntax.hpp:465` | Pass `--termination` in the prototype. Quantify the 100k bound in §1 — it is a **better** argument for the budget pass than the current prose. |
| O5 | **Base tier vs. the worked example.** Reaching a pointed-to struct needs `bpf_probe_read` — a helper. "No helpers" and "this worked example" cannot both be true. | — | Decide in writing: (i) ctx is scalar argument values only (fentry model) and the CVE example is a scalar predicate — **now done**, F2 — or (ii) day one includes a bounded fault-tolerant `probe_read` helper, with the §4 surface it brings. Every real fentry-style shield eventually needs (ii). |
| O6 | **Fuel does not work under JIT.** `ubpf_set_instruction_limit` — *"It has no effect on JIT'd programs."* And wall-clock, which §1 calls "the piece you can't skip," is **unmeasurable at hot-hook granularity on aarch64** (`CNTVCT_EL0` at tens of MHz → 10–40ns tick against a budget of tens of ns). | `ubpf.h:769-771` | The trilemma in §7. A good answer exists — patch uBPF's JIT for back-edge fuel, own it, upstream it, move item 15 to day one — but it costs "reused as-is" on the second of three components. |
| O7 | **`ubpf_compile`'s prologue does `sub rsp, 4096` unconditionally, with no stack probe** — a 4KiB frame at arbitrary depth in TMM's call graph, able to step clean over a single guard page. | `ubpf.h:46,53`, `ubpf_jit_x86_64.c:1744-1746` | Use `ubpf_compile_ex` / `ubpf_jit_ex_fn` with a per-core preallocated program stack. |
| O8 | **The loader message is not authenticated except on LOAD.** `shield_msg` has nowhere to put the binding, so `shield_binding_of()` cannot exist. `prog_len` is attacker-influenced and read **before** authentication. `SET_MODE`/`STATUS`/`REVOKE` are unauthenticated at the TMM boundary, and with no nonce or epoch a captured `LOAD` replays after a `REVOKE` — **the kill switch is defeatable by replay**. | `shield_abi.h:104-112`, `development-scope-code.md:336,373-385,449` | Binding in the message with asserted offsets; validate `prog_len` against the received length as statement one; sign *every* op including `op`/`mode`/a monotonic epoch. |
| O9 | **The budget pass's decoder is wrong.** It reads the whole **ELF file** as instructions (first 8 bytes are `\x7fELF`), strides 8 bytes blindly so `lddw` (16-byte) mis-decodes into garbage instructions and garbage branch targets, and never treats `exit` as a terminator. | `development-scope-code.md:754-788` | Rewrite against `.text`; handle `lddw`; fix the CFG. |
| O10 | **`prevail_loop_bounds()` cannot be implemented.** PREVAIL exposes **one aggregate number** (`max_loop_count`, the max over all loops), not a per-loop-header map. Without it the sound bound is `total_instructions × max_loop_count` — useless at the 100k default. | `result.hpp:146`, `fwd_analyzer.cpp:133-138` | Third fork pressure, or accept a coarser bound and say so. |
| O11 | **The cost model's worked number contradicts its own table** (652 instructions → "800 cycles" is 1.23 cycles/instr with `load: 4` in the table and 64 loads in the loop), and a per-op table under-counts memory catastrophically — one L3 miss is 200+ cycles. | `development-scope-code.md:749-802` | Say in the **headline**, not the footnote: this is a relative sanity check, not a WCET bound. Stop calling it WCET-lite. |

---

## 2 · Wrong about TMM / BIG-IP — cheap to fix, and each one makes the argument stronger

These are the sentences that lose a technical room. Every fix below is *more* compelling than what it replaces.

| # | Claim as written | Reality | Better claim |
|---|---|---|---|
| T1 | "Standard capture is **blind** to TMM's fast path… the only viable tap is in-process" | `tcpdump -i 0.0` works today; `:p`/`:n`/`:0.0` give pre/post-TMM views; `tcpdump --f5 ssl` exports session secrets. TMM already implements a capture path. | "Existing capture is a packet tap at the interface boundary. What it cannot give you is **post-parse, post-decrypt state at an arbitrary internal hook**." The `tmmdump` pitch survives and gets more interesting. |
| T2 | "would have taken TMM down **until the next maintenance window**" | `sod` restarts TMM in seconds; HA fails over. | "A **remotely triggerable, repeatable crash-loop** — every trigger drops every flow on that TMM and can flap HA." Worse, and true. |
| T3 | "every count — **a crash that didn't happen**" | A NULL deref kills the process once, then restarts. 251 fires ≠ 251 prevented crashes. | "every count is a **flow that reached the faulting path**" + a line on CMP/DAG explaining uneven per-TMM distribution. |
| T4 | `CVE-2026-22548` presented in body text as a February 2026 advisory | Fabricated; the disclaimer is a footnote above it. SIRT will look it up. | Use a **real, published, closed** F5 advisory and work the example against its actual patch diff. Doubles as the shieldability study. |
| T5 | "`bd` is a process we own and have symbols for" → easiest Phase 1 | `bd` is **multi-threaded C++**: no poll loop, no safe point, mangled names, references and by-value structs in signatures, RAII destructors a skipped body silently doesn't run. | Phase 1 belongs on a **designed-in call site on a cold TMM path** — which is also what actually proves the in-TMM spine. |
| T6 | "Enforcement plugins (`bd`/WAF, APM, AFM, DoS)… plugin-process internals" | **AFM and DoS enforcement are in TMM**; APM is split; `bd` is the separate one. | Split the row. Lumping them makes the scope look 4× smaller than it is. |
| T7 | "the kernel is **structurally blind** to TMM" | Kernel eBPF *can* attach to TMM — uprobes/USDT on `tmm` work today. | "Kernel eBPF can attach but **cannot afford to** (per-hit kernel transition inside a run-to-completion loop) and **cannot enforce** (no `bpf_override_return` on uprobes)." Same conclusion, survives someone who has run `bpftrace` on `tmm`. |
| T8 | iRules "TCL, **runtime-bounded**" | A runaway rule spinning in the TCL VM is a documented cause of a stalled TMM and a watchdog restart. And we reject WASM's fuel kill as "not a proof" two pages later. | "Unbounded in practice; a runaway rule is a documented TMM-restart cause." That is *our* argument, not our competitor's. |
| T9 | Control plane = native daemons + JVM | Three runtimes: native, **JVM** (Tomcat, `restjavad`/`icrd`), **Node** (`restnoded`/iControl LX). `tmsh` is a per-invocation shell, not a daemon. | Runtime inventory with CVE count per runtime; drop `tmsh` as a shield target. |
| T10 | "The signal leaves the box; the data never does — and that's **provable**" | PREVAIL proves memory-safety over declared regions. It proves nothing about whether a returned scalar encodes payload. | Three mechanisms, none called a proof: host-owned schema-checked sink, declared window, signed extractor review. |
| T11 | TMM's blindness = "**none**"; sees "**every** flow, decrypted" | Offloaded flows, FastL4, SSL pass-through, client-SSL-only virtuals, non-terminated UDP/QUIC, per-box scope. | Delete "none"; state the real bounds; note it is *still* the least-blind vantage. |
| T12 | "no rebuild, no reboot, **no release train**" (hero) | The mechanism itself rides a release train; the walkthrough says so honestly, the hero doesn't. | Add "once the enabling build ships." One clause. |
| T13 | "retarget a program from a TMM parser to an httpd request path by changing only the hook name" | Different ctx, different verifier, different helpers. It wouldn't compile. | Cut the clause; keep "one DSL, two engines." |
| T14 | "an unarmed function boundary is a nop pad — **free**" | Pads cost i-cache and i-TLB footprint on an i-cache-sensitive process, unconditionally, for every customer forever. | "Free at *runtime*; the pads have a **build-time footprint cost** we have measured" — see §4. |
| T15 | Memory pools / poll-loop stats have "**no** surface at all" | All in `tmctl`/`tmstat` and every qkview. | "Already counted, but not **conditional** — you can read the aggregate, you can't say 'record the last 200 samples leading into the stall.'" True and better. |
| T16 | "The exposure window is a solved problem everywhere the kernel can reach" | No industry practice of eBPF-shielding kernel CVEs in production. | Name the real precedent (ftrace/livepatch, error injection) and claim the *idea* is established, not the practice. |
| T17 | "Block a live exploit **in hours**" | Author → verify → budget → **HSM release signing** → distribute → monitor → enforce. Signing is not hours-scale today. | "**Days** — and here is the specific ask: a pre-authorised shield-signing path so it can be hours." |

---

## 3 · Missing specifications

**The item that isn't on the list, and is the most expensive one.**

- **Item 0 — the safe point itself.** Every in-TMM item is predicated on "a safe point between poll-loop iterations that dequeues and processes `shield_msg`." It does not exist in TMM today. Building it means a per-instance message queue reachable from the config channel, **a new check in the poll loop** (one load + branch per iteration, on the loop this org has rejected proposals for touching), and a bounded work budget for the handler — because as sketched, `do_load` performs `ubpf_load_elf` + `ubpf_compile` *at the safe point*, i.e. a full ELF parse and a JIT compile inline in the poll loop. Milliseconds, during which the loop is not polling: a visible latency spike and possibly a dropped heartbeat / HA event. **Move compile and page population off the safe point**; leave it publishing a pointer and patching a few bytes.

**Mechanism gaps.**

- **Live text.** No document contains `mprotect`, W^X, or page protection in connection with *text*. Open questions with different answers: is TMM's text shared or private across instances (shared ⇒ patching one patches all, and there is no cross-instance safe point; private file-backed ⇒ **COW of the whole page per instance**, 2MiB per patched page if hugepage-backed, and the iTLB win is gone); SELinux `execmem`/`execmod` policy on a hardened appliance; **code-integrity / FIPS self-test / image-hash mismatch the moment a shield arms**; and re-protect return values currently dropped, so an error path leaves TMM text permanently writable.
- **x86-64 patching is not atomic.** A 5-byte `JMP rel32` cannot be written by one store; this is why Linux has `text_poke_bp()` (int3 → IPI/sync → patch → sync → replace first byte). "Atomic patch + i-cache flush" cites the conclusion and skips the mechanism. aarch64 *is* a single aligned 4-byte store — but needs per-core cache maintenance + `ISB`, and an 8-byte pad **cannot hold an arbitrary-range branch**, so the trampoline must be linked in `B` range as a build-checked constraint (the "veneer" answer is unanswerable as written, because nothing reserves in-range space).
- **Register save is under-specified in ways that corrupt or crash.** Missing: **FP/SIMD** (`xmm0-7`/`v0-v7` — a hooked function taking a `double`, and `tramp_dispatch` is C); **`rax`** (varargs vector count — and the worked example hooks a *log* function); **`x8`** (indirect result location); `r10`, `x18`; **stack-passed arguments**, which a "ctx over saved registers" cannot see at all; and **CET-IBT / BTI** — jumping to `entry + pad_bytes` is an indirect branch into mid-function with no `ENDBR64`/`BTI` landing pad, which is an immediate fault on hardened builds. Also **CFI/`.eh_frame`** on the stub, or every backtrace through a hooked function is garbage.
- **"Execute the instructions the pad displaced"** — nothing is displaced; the pad is nops. Delete it; the deletion makes the design simpler.
- **Unload while executing.** Disarm and `ubpf_destroy` in consecutive statements, and `slot->armed/mode/fn` are plain non-atomic fields read on the hot path. Needs an **epoch / quiescence** scheme (disarm, advance per-core epoch at each safe point, free when all cores have passed) — ten lines, standard, and its absence is the difference between "delicate" and "will eventually crash a customer."
- **Re-entrancy.** No guard in `tramp_dispatch`. Arm a shield on a logging function and the loader's own error path (`log_warn`) re-enters it. The worked example hooks a log function.
- **Inlining, LTO, ICF, IPA clones.** Unmentioned anywhere. At `-O2`, `-fipa-icf` folds identical functions so arming "A" arms "B" and name→address is not a function; `ipa-cp`/`ipa-sra` produce `foo.constprop.0` clones with **different signatures**; fully-inlined statics have no `low_pc` at all — and item 5's `hookable()` test drops exactly those. **The hookable set is optimizer-determined**, and guaranteeing a function is hookable means `noinline` — a *source change*, which undercuts "no source modification."
- **`path_class` is a claim about traffic that a CVE shield systematically violates.** The worked example's "cold" hook is a log function on a malformed-input path — the path the attacker drives. At line rate it is the hottest code on the box, running an unbudgeted program with no watchdog. `path_class` must be **static structure ∧ adversarial reachability**: anything reachable from unauthenticated input at attacker-controlled rate is `hot`, full stop.
- **All-or-nothing arming across TMM instances** has one clause and no semantics. Partially armed = still crashable (the attacker's flow only has to hash to the unarmed instance), and identical traffic gets different treatment by disaggregation.

**Platform and lifecycle gaps.**

- **vCMP / F5OS tenants / chassis.** Named as a concern, absent from all seventeen items. Per guest: whose hook map, whose signing authority, whose audit trail, whose change window — and how a newly joining TMM/blade/guest is armed *before* it takes traffic.
- **HA.** Failover to a peer on a different build = failover **into** the unshielded vulnerability.
- **ISSU.** A new TMM starts with an empty shield set, so there is nothing to "expire"; the real problem is who re-verifies and re-pushes, and **the window where the new instance takes traffic with nothing armed**.
- **Core dumps / qkview / debuggability.** Zero coverage. Backtraces through the trampoline, PC inside an anonymous JIT mapping, on-disk text ≠ in-memory text (breaking symbolisation and integrity checks), armed-shield inventory in the dump and in qkview. Absent this, support escalates for a global disable after the first field crash.
- **Memory accounting.** uBPF `malloc`s and `mmap(PROT_EXEC)`s; TMM has its own preconfigured allocator with strict accounting. `SHIELD_MAX_SHIELDS 64` has no memory model behind it.
- **Distribution.** Items 9–11 run sign → push → load, all in-box. Nothing covers F5 → customer fleet: versioned distribution, pinning, rollback. (The AWAF attack-signature channel is the obvious analog: signed, versioned, live, fast cadence, established customer trust — and it decouples mitigation cadence from hotfix cadence, which is the point of the exercise.)
- **Per-build shield multiplication.** A per-build `ctx` means **per-build shields**: one CVE across six supported branches is six verified, budgeted, signed, tested artifacts — with possibly different hookable sets. "A few lines of C per CVE" quietly becomes "a few lines × N builds."
- **Testing.** Not one of the seventeen items is a test item. Minimum bar: arm-every-hook soak under full traffic asserting zero delta; arm/disarm churn under load; hook-map offset round-trip gating the build (**now built** — `make check-offsets`); differential fuzzing of both `binding_serialize` implementations and of the pre-auth message parser; and an adversarial negative corpus for PREVAIL — which is also the verifier-auditability deliverable, at no extra cost.
- **Performance regression gating.** No baseline, no budget, no CI gate — for a data-plane feature. This is what a TMM review leads with.

---

## 4 · The measurement that gates everything

All three reviewers independently asked for the same thing first, and one made it their price of admission:

> Build TMM once with `-fpatchable-function-entry`, **arm nothing**, and report: **pps / CPS / p99.9 latency / text size / i-cache MPKI** deltas on at least one x86-64 and one aarch64 platform. Also: **how many of the functions you would want to hook survived inlining as named symbols**, and **whether TMM's `.text` is shared or private across instances, and whether it is on huge pages**.

Why it gates: every affordability claim in the package — "free when dark," "one predictable branch," "tens of nanoseconds is noise," "small, bounded" — is currently unmeasured, and the flag is the **largest irreversible commitment** on the page. It touches every function in the image, interacts with ICF and LTO, and **cannot be opted out of at runtime** by a jitter-sensitive customer (the only true opt-out is a second build variant, with all the release engineering that implies). Estimated cost of the pads alone: 5–8 bytes × O(10⁵) functions, concentrated at entries where the fetch stream is coldest — 3–8% text inflation is plausible, and a 1–3% pps regression is a shippable-product blocker on its own.

**Kill criterion: >~1% pps.** Above that, the mechanism needs to change (pads on an allowlisted subset of translation units, not the whole binary) and everything downstream changes with it. Two engineer-weeks, and it converts the package from a proposal into a result.

---

## 5 · Effort, restated honestly

Senior-engineer-months, assuming people who have shipped in TMM:

| Item | As scoped | Realistic | Why |
|---|---|---|---|
| **0 · safe point** | *not listed* | **4–8** | New poll-loop check, per-instance queue, moving JIT off the safe point. Needs the most senior person and the most political capital. |
| **0b · the flag** | *"build-system configuration, not code"* | **1 experiment + 2–4 fallout** | §4. Whole-image rebuild, ICF, asm/third-party TUs, regression review. |
| 1 · trampoline | "≈ a page per arch" | **3–5 per arch** | Full clobber set incl. FP/SIMD, IBT/BTI, varargs/`x8`, CFI so dumps survive, ctx copy, re-entrancy guard, burst form, test matrix. |
| 2 · arm/disarm | "small" | **4–8 + TMA** | W^X relaxation in TMM's memory manager, shared-vs-private text, hugepage COW, code-integrity interaction, per-arch `text_poke`-grade patching. If the memory manager changes, two quarters. |
| 3 · loader handler | "hundreds of lines" | **4–6** (1.5–3k lines) | Missing epoch/quiescence, re-entrancy, memory accounting, `do_set_mode`, ISSU. |
| 5 · hook-map generator | "tool" | **6–12** | The sleeper. A **SysV/AAPCS parameter classifier** from DWARF (struct-by-value splitting, HFA/HVA, stack spill, unions) against an LTO'd `-O2` build with clones, ICF folds and inlined statics. Permanent maintenance tail. |
| 6 · ctx descriptors | "40 lines" | **tool 2–4 + PREVAIL 3–6 + forever** | O1/O2, DWARF-true offsets, a C++ platform-table entry. The doc is right that it's the largest *ongoing* surface and 10× low on the *initial*. |
| 7 · safe-return table | "tool + process" | **3–6** | `caller_null_checked` is whole-program call-site analysis; plus typedef/enum resolution; plus the human review process. |
| 8 · budget pass | "conventional… tool" | **4–8**, partly not implementable as specified | O9/O10/O11 + per-µarch calibration on ≥2 ISAs. Most likely item to be quietly replaced by a constant. |
| 9–12 | "conventional" | **6–10 total** — fair | Genuinely the easy part. |
| 15 · runtime deadline | "optional, staged" | **must be day one** | O6 + §3's `path_class` finding. |
| — | *not listed* | **2–4** | Core dumps / qkview / debuggability. |

**Total for a defensible v1 on two architectures: 50–80 SEM — 6–8 people, 12–18 months**, plus TMA and certification engagement.

**Overstated (easier than presented — say so, it helps):** a designed-in **USDT catalog needs no VM at all** (static markers + a host reader gets most of the observability value with none of §3's risk — and it is what the TMM org will accept first); **control-plane uprobes** are nearly off-the-shelf and cover the bulk of disclosed CVEs; **auto-retirement** is a local version/build/hotfix read plus a boot-location hook, not a polling subsystem; **evidence counters** are table stakes, not a staged tier.

---

## 6 · What is genuinely strong — and mostly buried

Ranked by how much it would help to move it forward.

1. **"The signature, not the verifier, is the security perimeter."** The best argument in the package — it converts "you put a JIT in the crown jewel" from traffic-borne RCE into supply-chain/insider risk. Currently on pages 3 and 4; `cve-mitigation` reduces it to "Signed by F5," bullet 2 of 4. **Move it to page 1 of every document.**
2. **Signing the binding, not the bytes** — `prog_sha256 · hook · build_min..max · mode_ceiling · expires_with`. Concrete, cheap, and the complete answer to replay and privilege escalation. `mode_ceiling` in particular signals real thought.
3. **Signing last, conditional on the verify and budget reports**, with the report's hash cross-checked against the bytes. "The signature *is* the attestation" is the pattern most teams get wrong.
4. **The iRule reachability test** — does an event fire *before* the vulnerable code; is the condition observable in the iRule data model at that event; does the flow reach the iRule VM. Exactly how a TMM engineer reasons, and the ASCII coverage map is **the most persuasive artifact in the set**. Lead with this, not the programmability-spectrum table.
5. **"Monitor mode is not a safe soak" for crash-class shields** — the first true positive in production both confirms the predicate *and* crashes the box. Non-obvious, correct, and it shows deployment thinking rather than demo thinking.
6. **Refusing arbitrary override; declaring un-shieldable CVEs out of scope.** "Better to declare a CVE out of scope than ship a shield that returns into an inconsistent TMM."
7. **The entry-pad-at-+0 choice, whose best property is unstated:** patching *before* the prologue means `x30`/`[rsp]` still holds the caller's return address, so `SAFE_RETURN` is a bare `ret` — no frame to unwind, no epilogue to synthesise, no shadow stack to fix. **That is why this is tractable where a return-boundary hook would not be.** Say it.
8. **Entry-pad hooking catches every caller**, including indirect calls through function pointers and calls from hand-written asm.
9. **Operational discipline:** `load` refuses `enforce`; promotion is separately authorised with a stricter role; a warning when promoting a shield that has never fired; `fired[]` deliberately not cleared on disarm ("the evidence outlives the shield"); all-or-nothing fan-out with unwind. Field-earned, all of it.
10. **Item 7's two refusals** — a status-code return where 0 means success is not safe-returnable, and unannotated defaults to observe-only — plus the `rationale` field recording what is lost per function. The most mature idea in the scope doc.
11. **Fail-dark everywhere, eleven distinct rejection codes.** The error taxonomy *is* the item.
12. **Offload and form-factor honesty** — naming the coverage gradient before someone else does, and noting it applies equally to iRules and kernel eBPF.
13. **The licensing analysis** — the GPLv2-kernel-verifier counterfactual as the *reason* permissive PREVAIL matters, plus PPL/APRON/ELINA copyleft risk and an SBOM gate. Most proposals don't get within a mile of this.
14. **Observe-mode diagnostics with governance as the feature** — context minimisation, residency, time-boxing, tamper-evident log. The version a customer security team will actually sign.
15. **A working prototype whose verify gate rejects a deliberately unsafe program.** Show it in the room before any slide.
16. **The "claim to retire" device** — naming *termination ≠ WCET*, *the ctx ABI is the actual project*, *maps don't work like Linux*. This is what earns credibility with this audience.
17. **The verifier-auditability ask** — and it is nearly free: PREVAIL already ships `-v`, `--failure-slice`, `--asm`, `--dot`, `--line-info`. The soundness-evidence package can be built on existing flags.
18. **Two real, checkable artifacts.** `shield_abi.h` compiles with every assert holding; the schema validates the map. **The reason F1 was findable at all is that these files exist** — the argument for writing candidate code, vindicated.

---

## 7 · The three questions to answer before anything else

1. **Measure the flag** (§4). Two weeks. Kill criterion >1% pps.
2. **The retrospective shieldability study.** Take the last three years of *real* F5 data-plane advisories — every TMM and `bd` CVE. Per CVE: was there a reachable boundary exposing the triggering condition in its arguments; which named function; what the safe outcome was; would the predicate have had an acceptable false-positive rate. Report **N shieldable, M not, and the M-list reasons**. A couple of weeks of SIRT-plus-engineering, and it either makes the program obviously fundable or right-sizes it. (If the answer is "3 of 40, all in `bd`," that is a different, smaller, still-worthwhile project.)
3. **The trilemma — pick one, in the room, not in month nine.** With no preemption, enforcing a time bound needs fuel; fuel has no effect under uBPF's JIT; wall-clock is unmeasurable at hot-hook granularity on aarch64. **Which do you give up: the run-to-completion loop, the unmodified uBPF, or enforce mode?** The available good answer — fork uBPF's JIT for back-edge fuel, own it, upstream it — costs "reused as-is" on one of the three reused components.

**And the question with no answer in any document:** who owns the safe-return policy for every hookable TMM function, *in perpetuity*, and what mechanical gate catches it when someone edits one of those functions two releases from now? Skipping a body is a per-function proof obligation over buffer ownership, refcounts, locks held on entry, flow-state advancement, and divergence from the mirrored connflow. There is no test for the absence of an obligation you didn't think of. The failure mode: a shield blocks the CVE, passes red team, ships, and leaks a packet buffer at 40k conn/sec on one customer's traffic mix three weeks later — presenting as a memory-pressure TMM restart with no attribution back to the shield.

**The answer that was offered, and that reframes the proposal:** v1 enforce-capable boundaries are limited to an explicitly annotated allow-list of leaf functions that own no buffer, hold no lock and advance no flow state — with a CI check that fails the build if a listed function gains a callee, a lock, or a non-trivial return — and **everything else is observe-only, or uses a designed-in call site where the drop branch already exists in TMOS source.** That is a smaller product than the README describes, and it is the one both reviewers said they would approve.

---

## 8 · The recommended path

A **feasibility phase**: one quarter, ~4 engineers, three deliverables.

1. **The dark-cost measurement** and the text-mapping determination (§4). Kill criterion >1% pps.
2. **A `ctx` model that actually verifies.** Reuse PREVAIL's `tracing` program type, copy the ctx into per-core scratch, and express the worked CVE as a scalar predicate against it. If the CVE class we care about *needs* pointer chasing, then day one includes a bounded `probe_read` helper and the §4 threat surface grows — decide that now, on paper, with SIRT in the room.
3. **One hook armed end-to-end on one architecture in a lab TMM**, with core dumps and backtraces still working through the trampoline.

If all three land, the rest is a real, fundable 12–18-month program for 6–8 people, and it is worth doing: the mechanism is right, and the operational discipline around monitor-before-enforce, signed bindings and safe-return rationale is better than most things that ship. If any of the three fails, a quarter was spent instead of two years.

---

*A review register. Findings are recorded here; fixes land in the documents they affect and are marked in this table as they do. Detailed method & claims are held in a separate invention disclosure.*
