# Development scope — what F5 actually builds

Everything the embedded-eBPF substrate needs **beyond what is reused** (compile, verify, execute —
clang, PREVAIL, uBPF). One of those three is not reused *as-is*: time safety needs a back-edge-fuel
patch to uBPF's JIT (item 15, [`engine-hard-problems.md`](engine-hard-problems.md) §1), so uBPF is
reuse-plus-a-fork that F5 owns. Derived from the worked example
([`explainers/cve-shield-walkthrough.html`](explainers/cve-shield-walkthrough.html)); step numbers
below refer to that walkthrough. Companion to
[`engine-hard-problems.md`](engine-hard-problems.md), which covers *why* the flagged items are
hard — this doc covers *what gets written, where it runs, and how often*.

The organizing fact: **nothing on this list recurs per CVE except the shield program itself** (a
few lines of C). Everything else is written once or generated automatically per build.

**The honest size, up front.** A defensible v1 on two CPU architectures is **subsystem-scale
work, not a feature**, plus the TMA (Threat Model Analysis) and the
certification engagement ([`engine-hard-problems.md`](engine-hard-problems.md) §6.1). The item
*list* below is right; the size classes in §6 are shape, not effort, and read against what each
item actually requires, several are low — and two of the largest items were missing altogether.
`design-review-findings.md` §5 ranks them rather than pricing them. Earlier drafts of this doc described the whole
thing as "hundreds of lines, not subsystems." **That framing is retired.** What is being added is
not a VM: it is a code-patching, live-text, dynamic-code-loading facility inside the crown-jewel
process, with its own build-pipeline toolchain and a permanent per-build ABI.

**Candidate code for every day-one item** (1–12 plus the shield program) is in
[`development-scope-code.md`](development-scope-code.md) — one skeleton per item, each with an
explicit real / stubbed / TODO breakdown. The artifacts worth having as real files rather than
blocks live in [`substrate/`](substrate/) and are verified by `make -C substrate check`.

---

## 0. Reused — explicitly *not* developed (with one bounded exception)

| Component | Role | License | Status |
|---|---|---|---|
| **uBPF** | the VM + JIT (~150 KB) | Apache-2.0 | the calls item 3 is built on are the library's **real public API**, not invented for this proposal: `ubpf_create` / `ubpf_load_elf` / `ubpf_exec` (`vm/inc/ubpf.h:129, 458, 510` in the gitignored `ubpf/` clone), with `ubpf_compile_ex` (`:575`) as the JIT path — the *extended* mode, because the basic `ubpf_compile` (`:553`) emits a prologue that takes an unprobed 4 KiB stack frame. **No runnable demonstration ships in this repo** — read this cell as an API-surface claim, checkable against uBPF's own header, and *not* as evidence that the load-and-run path has been stood up. **No longer reused as-is.** The F5 fork carries a **real patch, not just a planned one**:
`substrate/ubpf-patches/0001-jit-scratch-rightsize.patch` sizes the JIT's scratch to the program
being compiled rather than to `UBPF_MAX_INSTS`, cutting prepare from 349 us to 19.5 us median and
its worst case from 3.2 ms to 58 us (measured; see `load-path-scope.md` §3a/§3b). Item 15's
back-edge-fuel patch is still to come and is why the fork was always going to exist, so this rides
along rather than adding a burden — but "three unmodified upstream components" is no longer
accurate, and each patch is a merge cost at every pin bump. **This one is an upstream bug**
(65,536-entry scratch for any program size, when the real count is available at the call site), so
it has a way out: contribute it, and the patch disappears |
| **PREVAIL** | the static verifier | MIT **+ Apache-2.0** (the clone ships both `LICENSE` files, plus `external/{CLI11,bpf_conformance,libbtf}`; the SBOM/license scan is a Phase-1 gate per `big-ip-live-shield-design.md` §13) | stock, driven as a CLI invocation — `-q [--section <s>]` (`src/main.cpp:65, 74`). **No verify gate is demonstrated in this repo.** O3 in [`design-review-findings.md`](design-review-findings.md) records the ctx-model limit that any future demonstration has to clear, and it is a property of PREVAIL, not of any one harness |
| **clang** | C → eBPF bytecode | — | standard toolchain |

Nobody at F5 writes a VM, a verifier, or a compiler. **What this repo no longer shows is that any of
it runs.** An earlier revision carried a prototype — a small relay that loaded and ran a shield
through the real uBPF API, plus a verify-gate track that invoked PREVAIL — and this paragraph cited
it as demonstrating the load-and-run half of item 3. That prototype has been removed, and the
demonstration went with it. The reuse argument above now rests on the two upstream projects' public
APIs; it no longer rests on anything executable here.
So: "reused, not written" stands for PREVAIL and clang and stands *with a fork* for uBPF, and
**"already works in our hands" is not currently shown** — a
loss of evidence, and the state of the reuse case until something runnable is stood
up again. The JIT's own properties (item 15's fuel, its unprobed 4 KiB stack frame) were open
questions before and remain so; they were never measured even while the prototype existed, because
it ran the interpreter.

---

## 1. In-TMM data-plane code — ships in the substrate build

The delicate systems work: small, but must be exactly right.

**Read this section as a common core plus a conditional half.** "Safe point" was one label over three
separate guarantees, and only the first is needed in every variant. Which of the others are needed
depends on a question F5 answers, not this document — so items 0b, 1b and 2's second and third forms
are **conditional work**, and the list says so rather than pricing them as settled.

0. **The publish protocol** *(step 4)* — **unconditional.** The trampoline loads a slot per
   invocation, so publishing a program is one ordered word store and `REVOKE` is a store of `NULL`. What is net-new is the ordering discipline
   (release on the publishing side, acquire on the trampoline's reads) and the rule that a slot is
   never half-written. **No text is modified and no rendezvous is involved.** Small, and required
   whatever else is or is not built.
0b. **A cross-core rendezvous** — **conditional: needed only to modify live text.** On x86-64 a 5-byte
   `JMP rel32` is not a single store and another core may be fetching those bytes. Two ways to get the
   guarantee: a checkpoint-and-acknowledge in the poll loop, which **does not exist in TMM today**, or
   rebuild `text_poke_bp()` in userspace — a `SIGTRAP` handler on the data-plane threads plus
   `membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE)` for the core-serialization half. The poll-loop
   form is far simpler to reason about, because no core is mid-prologue when the bytes change. On
   aarch64 a 4-byte aligned `NOP`↔`B` swap is inside the architecture's concurrent-modification set —
   other cores observe old or new, both valid — so **this item is x86-64 work, not both-architecture
   work.**
0c. **Reclamation** *(step 13)* — **three forms, pick one.** Disarming is easy; knowing the last core has
   *left* a program's JIT'd code is a separate problem. A per-core epoch bumped once per poll iteration is
   nearly free, amortized across a whole packet batch, and needs the poll loop. Without it: read-side
   markers plus a fence per invocation, which moves the cost onto the hot path; or **accept the leak**,
   which is then a real deliverable — a per-hook cap, a counter, and a documented ceiling on loads per
   boot. Bounded leak is defensible for a program loaded twice a year and not for one reloaded hourly,
   so this choice belongs to the use case, not to the substrate.

**And one capability has no substitute, which is worth naming because the rest of this section is a list
of trade-offs.** Everything above can be bought another way at a price. **An atomic multi-slot change
cannot.** TMM is run-to-completion per packet, so between poll iterations no packet is mid-processing: a
checkpoint is the only place several slots can be flipped and the loop resumed with no core having
observed a half-applied set. Without one, slots are stored to independently, and a packet already in
flight past hook A will see old-A/new-B whatever is done — a generation counter the trampoline consults
does not fix that, it only moves cost onto the hot path and still cannot rewind a packet already past A.
**This is forfeited rather than blocking**, because the day-one design is one program per hook with
chaining refused (`engine-hard-problems.md` §3.1), so nothing currently needs two slots to change
together. It is the capability to keep in view if coordinated multi-hook policy ever becomes a
requirement.

1. **The trampoline** *(walkthrough step 2)* — per CPU architecture: save the hooked function's
   argument registers per the ABI, build the `ctx`, call the JIT'd program, bump the fire
   counter, apply the verdict (safe-return vs. fall-through), restore. ≈ a page of code per
   architecture, generic across all functions.
   **This used to split by hook kind. It no longer does.** The easier half — a designed-in call site,
   where the surrounding code is C and the compiler owns the calling convention — has been removed from
   the TMM tree. What remains is the **patched function entry**, where there is no C frame to borrow: the
   argument registers must be saved and restored by hand per ABI. So the per-architecture assembly is
   **unconditional**, not conditional on 0b, and the arch-generic C shim (item 1a) survives only as the
   dispatch half that the assembly calls into. If 0c is answered with read-side markers rather than a
   poll-loop epoch, this also carries a store and a fence per invocation.
2. **Arm/disarm routine** *(step 2)* — **one line in an earlier draft; three different
   implementations, and the choice is not this document's to make.** All three arm and disarm a hook;
   they differ in what they must coordinate and what they cost when dark.

   | Form | What arming *is* | Needs 0b? | Cost when nothing is armed | What it gives up |
   |---|---|---|---|---|
   | **A · designed-in call site** — ~~offered~~ **REMOVED, 2026-08-13** | an ordered word store into the slot | **no** | one load + branch per site | reach is fixed at build time — only points someone chose in advance. **This is disqualifying for CVE work**, whose defining case is a function nobody thought to edit. Deleted from the TMM tree rather than left as a second path |
   | **B · patch the entry on demand** | write a jump into the reserved pad, then flush the instruction cache | **yes**, on x86-64 | ~free — the pad is no-ops | nothing; this is the form that reaches any padded entry with no designed-in call site |
   | **C · patch once at startup, arm by flag** | a flag store; the pad already calls a dispatcher | **no** — patched while still single-threaded | a permanent call + load + branch on **every** function in the set, armed or not | the hookable set is fixed at process start, so reaching a new function needs a restart |

   Form B is the one that carries ftrace's discipline on live text — proven pattern, not research —
   and the only one whose reach is decided at load time rather than at build or boot. Form C is worth
   naming because it buys wide coverage with no rendezvous ever, and because if TMM instances share one
   executable mapping then a pad patch is necessarily global while slot state stays per-instance, which
   makes patch-once-then-flag-arm the natural shape. **Whether that mapping is shared is an F5 fact this
   repo does not have**, and it selects between B and C.
3. **The loader handler** *(steps 4, 10, 13)* — **not a safe-point handler, and the earlier name
   overstated it.** Everything expensive runs on a control thread where allocation, logging and
   ordinary error handling are available; only the publish of item 0 touches the hot path. Processes
   `shield_msg`
   (`LOAD · SET_MODE · STATUS · REVOKE`). **Every op is authenticated, not only `LOAD`**: the
   signature must cover the op, the requested mode and a **monotonic epoch**, or a captured `LOAD`
   replays after a `REVOKE` and the kill switch is defeatable. Then hook-map lookup → arm.
   `ubpf_load_elf` and the JIT compile run **on the control thread** — a full ELF parse plus a code
   generation pass inline in the poll loop is milliseconds of not polling — leaving the hot path to
   publish a pointer and, in form B only, patch a few bytes. Plus the unglamorous rest that is real
   work: **all error paths fail-dark** (no partial arm), expiry enforcement (auto-retire on build
   match), per-shield state (per-core fire counters, mode flags). **`ubpf_destroy` is item 0c, not this
   item** — an earlier draft listed "VM teardown on unload" here, which reads as a call this handler can
   simply make; it cannot, until something establishes that no core is still inside the code being
   freed.
3a. **VM hardening configuration** *(step 4)* — **small, and it was missing from this list rather than
   from the design.** uBPF's runtime checks are **per-VM state**, so they take the library's defaults
   unless the loader sets them. Read from `ubpf/vm/ubpf_vm.c` (`ubpf_create`): bounds check **on**,
   read-only bytecode **on**, undefined-behaviour check **off**, **constant blinding off**. Blinding is
   the JIT-spray mitigation — without it a bytecode immediate reaches the JIT'd buffer verbatim, so a
   program the verifier admits can still place native instruction bytes into an executable mapping
   inside TMM. Three `ubpf_toggle_*` calls, all real public API, plus the policy decision about what the
   settings must be and a guard that no VM is ever created without them. **The architecture asymmetry is
   the real content:** `ubpf.h` states blinding is *"ARM64: Not yet implemented … will have no effect,"*
   so an aarch64 build has no JIT-spray mitigation at all. That converges with item 15 — fuel is
   enforceable only in the interpreter — on the same answer: an **interpreter-only high-assurance build**
   is the stronger aarch64 posture, and choosing it is a build-configuration deliverable rather than a
   code one.

4. **Signature verification in TMM** *(steps 3, 10)* — checking the signed binding against the
   baked-in public key before any bytecode is touched. Possibly reusable from F5's existing
   signed-artifact verification; net-new integration either way.

## 2. Build-pipeline tooling — runs at F5, per TMOS build

Written once; their *outputs* regenerate automatically every build (maintenance-free artifacts).

5. **Hook-map generator** *(step 3)* — from the build's debug info (DWARF/BTF): named symbol →
   entry address + typed argument layout. Output is signed and shipped with the build. **Entry
   addresses are only needed by form B**; in form A or C the map degenerates to the catalog's typed
   layouts, which are authored rather than extracted, so the DWARF half of this tool is conditional
   work while the `ctx`-layout half is not.
6. **ctx-descriptor emission for PREVAIL** *(steps 3, 7)* — turning those typed layouts into the
   program-type descriptor stock PREVAIL verifies against. **Flagged honestly: this is
   hard-problems §2 — the ctx/helper/program-type ABI is the real 90% of the work.**
   Mechanically simple per hook; the discipline and versioning around it is the substrate's
   largest ongoing engineering surface. One constraint sits in front of the tool: PREVAIL has
   **no `--program-type` option** — the type comes from the ELF section-name prefix matched against a
   table compiled into the binary, fallback `socket_filter` — so day one either rides PREVAIL's
   existing `tracing` type (twelve u64 argument slots, nothing dereferenceable) or F5 owns a patch
   set registering a TMM type, with a per-release rebase cost on the one reused component the trust
   story wants unforked.
6a. **Verifier/runtime geometry reconciliation** *(steps 3, 7)* — **net-new, and the same class of
   problem as item 6: the verifier's model of the host has to match the host, or the proof is about a
   different machine.** PREVAIL proves memory safety against a *declared* stack geometry; uBPF provides
   an *actual* one; they do not presently agree. From `ebpf-verifier/src/config.hpp`:
   `subprogram_stack_size = 512`, `max_call_stack_frames = 8`. From `ubpf/vm/inc/ubpf.h`:
   `UBPF_MAX_CALL_DEPTH 8` and `UBPF_EBPF_STACK_SIZE = depth × 512`, but
   `UBPF_EBPF_LOCAL_FUNCTION_STACK_SIZE 256`. Where PREVAIL's "subprogram" and uBPF's "local function"
   denote the same frame, a program admitted under the defaults may use **twice the stack the runtime
   provides** — and that is the one failure mode a signature cannot catch, because the artifact is
   authentic and the proof is valid; it is just a proof about different hardware. The work: establish
   whether the two notions correspond, pin both sides to one number, pass it explicitly on each side
   (`--stack-size`, and the compile-time constant), and add a **build-time assertion that fails if they
   diverge** rather than trusting two upstreams to keep agreeing. The same reasoning applies to the rest
   of PREVAIL's defaults — `check_for_termination = false`, `strict = false`,
   `allow_division_by_zero = true` — which makes the admission pipeline's verifier invocation a
   **specification to be reviewed**, not a command line someone types.

7. **Safe-return policy table** *(steps 3, 12)* — **two gates, in this order, and the order is the
   whole point.** *Gate 1 — skippability:* may this body be skipped at all? Closed by default; any
   lock held across it, refcount moved, flow state advanced, input consumed, out-param written or
   allocation made disqualifies the function **whatever it returns**, and *unanalysed* means
   observe-only, because absence of evidence is not evidence of absence. *Gate 2 — the return
   value:* reached only for a body that already cleared gate 1. Classifying by return type is
   backwards, and **`void` is the hardest case, not the trivial one**: a void function is called
   entirely for its side effects, so skipping it discards all of them and the signature tells you
   nothing about what they were. The worked CVE proves it — its vulnerable function returns nothing
   and *still* emits a log. A v1 restriction phrased as "enforce only where returns are trivial
   (`void`/benign)" is precisely the inversion this now blocks.
   **This is enforced in code, not asserted in prose:** `enum shield_skippable` is gate 1 and sits
   ahead of `kind` in `struct shield_sr_policy`, `shield_sr_enforce_capable()` requires both gates
   ([`substrate/shield_abi.h`](substrate/shield_abi.h)),
   [`check_sr_gates.c`](substrate/check_sr_gates.c) asserts five cases — including the
   `void` + unanalysed case the retired model accepted — and
   [`hook_map.schema.json`](substrate/hook_map.schema.json) requires `skippable` alongside
   `kind`. `make -C substrate check` fails on regression. The residual work is partly
   tooling, partly one-time human annotation; the honest v1 hand-audits a short candidate list
   rather than trusting a tool to prove absence of side effects across TMM.
   **The size of this item is set by the hook surface, so the fork changes it more than any other tool.**
   Gate 1 must be answered for every hook that could ever enforce. In form B that is every entry the
   optimiser emitted, which is why "hand-audit a short list" reads as a v1 compromise. In form A or C it
   is the catalog — a finite, curated, versioned list — and hand-auditing it is not a compromise but the
   whole job, done once per entry and reviewed like any other ABI.

**The designed-in USDT** (userland statically-defined tracing) **tracepoint catalog** — hook kind (1),
proposed in [`tmm-usdt-tracepoints.md`](tmm-usdt-tracepoints.md): per-stage placement and a stable,
versioned `ctx` ABI. Per-catalog-entry annotation work, distinct from the auto-generated
function-boundary hook map above. **An earlier draft filed this under "also in scope over time." That
was right only for form B.** In form A or C the catalog is what carries reach — it is the entire hook
surface — so it moves to day one and its coverage decides what the mechanism can ever do. It is also
the more stable artifact of the two: a hand-curated versioned list does not shift when the optimiser's
inlining decisions change between builds.

*(The `-fpatchable-function-entry` flag itself is build-system configuration, not code.)*

## 3. Control-plane / F5-infrastructure code

Conventional engineering — no novel machinery.

8. **Budget pass** *(step 8; hard-problems §1)* — admission-time cost estimator + gate: CFG
   longest-path over the verified bytecode → a cycle *estimate*, compared against the hook's
   per-invocation budget. A build artifact, off the data path; fail-closed. Real code:
   [`substrate/budget_pass.py`](substrate/budget_pass.py), exercised by `make -C substrate check`
   against a **built-in self-test** — six hand-assembled programs in a synthesized ELF, since this
   repo ships no compiled shield objects for it to price. It is an estimate, not a worst-case
   execution time (WCET) bound — which is why item 15's fuel is the enforcement half and is day one.
9. **Signing-service integration** *(step 9)* — the binding format
   (`prog hash · hook · build range · mode ceiling · expiry`) wired into F5's existing
   HSM-backed (hardware security module) release-signing flow. New manifest, existing infrastructure.
10. **Loader daemon side** *(steps 4, 10)* — pushing `shield_msg` over the **existing**
    control-plane config channel (the path profiles/iRules already ride), per-core fan-out,
    status/counter collection.
11. **Operator front-end** *(steps 10, 11, 12)* — a thin `tmsh` subcommand / iControl endpoint on
    the existing management surface (illustrated as `shieldctl` in the walkthrough — **not** a
    new standalone tool). Fills the struct; reads the counters.
12. **Audit trail** *(step 4)* — every op logged: who loaded/flipped/revoked what, when.

## 4. Staged tiers — 13, 14, 16, 17 are follow-ons; **15 is day one**

13. **Rate-limited per-firing log line** in the trampoline (evidence tier 2).
14. **Egress ring + drain agent** — per-core single-producer/single-consumer (SPSC) shared-memory
    ring for per-event records (flow tuple + timestamp), drained off the hot path; enables
    out-of-band synthesis of a
    suppressed log entry. Already designed:
    [`data-plane-egress-primitives.md`](data-plane-egress-primitives.md).
14a. **The sink and the view — not covered by any item above, and the gap is worth stating in the list
    rather than discovered later.** Items 13 and 14 are **transport**: a rate-limited log line, and a
    per-core ring drained off the hot path. Neither says where a record *lands* or what *renders* it, and
    nothing else here does either. Concretely, as this repo stands:
    [`tmm-usdt-tracepoints.md`](tmm-usdt-tracepoints.md) defines **41 tracepoints** in its tables (45 names appear if prose mentions are counted, which they should not be) with typed `ctx` fields;
    **no dashboard, view, or metric schema is specified anywhere**; both sinks are open questions in their
    own items (*"identify the existing TMOS audit sink"*, *"a decision about which sink"*); and the two
    consumers named — `tmmtrace` and `tmmdump` — are **placeholder names for proposed utilities**, so the
    consumer side is proposed rather than specified.
    **What that leaves visible on day one is item 11's `status` and nothing else**: per-hook mode, armed
    state, epoch, and per-core fire counters with their total. That is enough to answer *"is the shield
    working"* and nothing else — it is a kill-switch console, not observability.
    Note the asymmetry it creates. TMM's **existing** poll-loop and memory-pool counters already land in
    `tmctl`/`tmstat` and every qkview (`design-review-findings.md` T15). New tracepoints inherit none of
    that: a signal that has no sink and no view is, from an operator's seat, indistinguishable from a
    signal that was never collected. **And this bites the catalog's primary stated use case**, since that
    document leads with observability, debug and RCA as its lens, and CVE shields as a peer consumer. The
    shield half has a console; the observability half does not.

15. **Back-edge fuel — a uBPF JIT patch. Day one, not optional.** The runtime half of time safety
    (hard-problems §1), and the one item in this section that is not a follow-on. **Fuel is the
    mechanism**: uBPF's own API states that `ubpf_set_instruction_limit` *"has no effect on JIT'd
    programs,"* so enforcing a bound means patching uBPF's JIT — the single place the "reused
    as-is" claim does not hold. A **wall-clock deadline is *reporting*, not enforcement**: on
    aarch64 `CNTVCT_EL0` ticks at tens of MHz (10–40 ns granularity) against a hot hook's budget of
    tens of nanoseconds, so it is unmeasurable at the granularity that matters. Required for any
    hook reachable from unauthenticated input — which **includes the worked example's log site**: a
    log function on a malformed-input path is the path an attacker drives, i.e. adversarially `hot`
    whatever its structural `path_class` says. Known corner: the instruction limit *does* work in
    uBPF's **interpreter**, so an interpreter-only high-assurance build has enforceable fuel today
    with no fork.
16. **Canary auto-unload** — health-metric-driven auto-revoke (verified ≠ correct;
    hard-problems §4).
17. **Authoring DSL** (domain-specific language) — a bpftrace-style one-liner front-end, **proposed
    and unbuilt**. Convenience only: it emits the same bytecode the C path produces, so it adds no
    capability and no security
    surface of its own. An earlier revision described it as already-working code, citing a prototype
    front-end since removed; nothing of it survives here, and it is a follow-on like the rest of this
    tier. Called **`tmmtrace`** here and throughout, with **`tmmdump`** as its capture sibling — both
    **placeholder names for proposed utilities**, nothing by either name existing here or in any product
    ([`tmm-usdt-tracepoints.md`](tmm-usdt-tracepoints.md) carries the note on the names). **The tool is
    still wanted; what was not ready was a prototype of it**, which is why nothing by that name is in
    this repo and why an earlier revision of this document was wrong to cite one as working code.
    Two further corrections in place: this item once said the DSL was "left unnamed deliberately,"
    false the moment five other documents named it; and the interim name `dptrace` scoped it to the
    data plane, which is wrong in the other direction — see the explainer, where the `tmm:` half is the
    net-new one precisely because `bpftrace` already authors for kernel eBPF on the control plane.

## 5. Recurring cost — per CVE, forever

**The shield program: a few lines of C** *(step 6)*. That is the entire marginal cost of each
new mitigation. Nothing else on this list is ever written again.

---

## 6. Shape summary

| # | Item | Runs | Written | Size class | Status |
|---|---|---|---|---|---|
| 0 | publish protocol (ordered slot store) | TMM, per publish | once | small — **unconditional** | **stub** — today a single atomic store: atomic *per call*, not an ordered cross-core publish |
| 0b | cross-core rendezvous | TMM poll loop, *or* `SIGTRAP` + `membarrier` | once, x86-64 only | **conditional on form B** | **stub** |
| 0c | reclamation — epoch · markers · capped leak | TMM | once | small, three forms | **stub** — a swapped-out program is never freed; bounded by load count |
| 1a | dispatch shim (arch-generic C half of the trampoline) | TMM hot path (when armed) | once, arch-generic | small, C | **live** — trampoline entered from a patched function in a running TMM (`ls_tramp.c`) |
| 1b | asm trampoline, patched entry | TMM hot path (when armed) | once per arch | ~1 page of asm — **conditional on form B** | **live** — call target verified as `ls_trampoline_entry` (`ls_tramp_asm.c`) |
| 2 | arm/disarm | depends on form (A · B · C) | once per arch in form B | store · patch · flag | **live, 2026-08-13** — armed / disarmed / re-armed a running TMM's own `.text` at `0xcd5400`, both pods, **zero restarts** (`ls_arm.c`, `ls_swap.c`) |
| 3 | loader handler | **control thread**; publish at hot path | once | hundreds of lines | **live, 2026-08-13** — arm/disarm *and* `SHIELD_OP_LOAD` all proven against a running TMM. Preparation runs on a TMM thread via `ls_prep.c`; see `load-path-scope.md` §5 |
| 3a | VM hardening config (`ubpf_toggle_*`) | TMM, at load | once + a build-variant decision | small | **stub** |
| 4 | sig verify in TMM | TMM, at load | once (or reused) | small | **not written** — declared in `shield_abi.h`, no implementation. The trust perimeter; gates the TMA |
| 5 | hook-map generator | build pipeline | once | tool — DWARF half conditional | **not written** — schema + instance exist (`hook_map.schema.json`, `hook-point-map.json`); the DWARF→map generator does not. Addresses are resolved by hand today |
| — | **USDT tracepoint catalog** | build pipeline + annotation | once + per entry | **day one in form A/C** | **documented, not wired** — 41 tracepoints in `tmm-usdt-tracepoints.md`; no sink (see 14a) |
| 6 | ctx descriptors for PREVAIL | build pipeline | once + **ongoing discipline** (§2) | tool + process | **partial** — one hook's `ctx` generated by hand (`ls_ctx_http_psm.h`); no generator |
| 6a | verifier/runtime geometry reconciliation | build pipeline | once + a build-time assertion | small, and load-bearing | **stub** — `check_vm_geometry.py` checks it; the build-time assertion is not in the build |
| 7 | safe-return table | build pipeline | once + annotations | tool + process | **not written** — `check_sr_gates.c` exercises the idea on the bench only |
| 8 | budget pass | admission (at F5) | once | tool | **built** — `budget_pass.py`; refuses loop back-edges outright (O10) rather than pricing them |
| 9 | signing integration | F5 infra | once | integration | **not written** — pairs with item 4 |
| 10 | loader daemon side | control plane | once | conventional | **partial** — a dev client (`arm_all.py`) fans out to per-instance sockets; no daemon |
| 11 | operator front-end | control plane | once | thin | **not written** |
| 12 | audit trail | control plane | once | conventional | **not written** |
| 15 | back-edge fuel (uBPF JIT patch) | TMM, per program invocation | **day one** | small patch, owned fork | **not written** — no fork patch exists. Unblocked today only because item 8 refuses looping programs; that ceases to hold the moment one is wanted |
| 13, 14, 16, 17 | staged tiers | various | staged | staged | **not started** — staged by decision |
| 14a | **the sink and the view** | control plane / off-box | *unspecified — see §4* | **gap, not an estimate** | **gap** — unchanged |
| — | **shield program** | TMM, via VM | **per CVE** | **a few lines of C** | **built** — `demo_pass` / `demo_block` verify and run; the CVE shield itself is per-CVE work |

**Status vocabulary.** *Live* = has run inside a TMM process that was already running, on BNK/datkube.
*In the TMM build* = compiled into the padded binary and bench-proven only. *Partial* = works on one
path, not the whole item. *Stub* = a placeholder committed deliberately (`748c4db`), so the shape is
visible and the gap is not silently missing.

**What "live" does and does not yet cover.** On 2026-08-13 the arm landed on a running TMM: five nop
bytes at `http_psm_profile_name_lookup` (`0xcd5400`) replaced with `call rel32` to `ls_trampoline_entry`
(`0x42c0f9`), reversed to nops, and re-armed — on both pods, with no restart and no container
restart. What that establishes is that **the patch mechanism works on a live process**. It does *not*
yet establish that a shield changes the outcome of a request: no traffic has been driven through the
hooked function while armed. That is the next step, and until it runs, "live" here means
live-patched, not live-shielded.

**Item 3's allocator problem, recorded because it is not obvious and it will recur.** TMM aliases
`malloc`/`calloc`/`free` to its own allocator (`src/kern/malloc.c:48`), which routes every allocation
through per-thread or per-core state. A thread we create has none of it, and worse, the spinlocks
that path takes are only initialised by `sthread_handler_register()` — called from exactly one site
in the tree (`dev/ndal/xnet/if_xnet.c:1642`), and BNK does not load xnet. Since `SPIN_UNOWNED` is
`0xffffffff` and a `static struct spinlock` is zeroed `.bss`, an uninitialised lock reads as
permanently owned, so **any allocation on a foreign thread spins on-CPU forever.** Measured, not
inferred, and a latent defect in F5's code worth reporting upstream.

**Resolved 2026-08-13.** Preparation no longer happens on the loader thread: it is handed to a TMM
thread through a periodic timer (`ls_prep.c`), where `umalloc` works. That made this substrate
**rung 3** of `ls_vm_load.c`'s own ladder — no rebuild, no restart, no window, for the *program*
rather than only for where it is armed. The rule that produced the bug still stands for any future
helper thread: **grep the whole reachable path for `malloc|calloc|realloc|strdup|free` before
putting code on a thread TMM did not create.**

The **Size class** column is *shape*, not effort: it says how much code an item is, not how long it
takes to get right. Items 1–4: delicate, small, must be exactly right. Items 5–7: tooling with one
hard design decision (§2). Items 8–12: conventional control-plane engineering. Items 13, 14, 16, 17:
staged follow-ons; **item 15 is day one**.

**Items 3a and 6a were added late, and how they were found is worth recording.** Neither came from
reviewing this list. Both came from reading the vendored sources of the two components the proposal
reuses — and both are cases where a **default is the defect**: uBPF ships its JIT-spray mitigation off,
and PREVAIL's assumed stack geometry does not match uBPF's. Nothing in a document review would have
surfaced either, which is the argument for doing that reading before, not after, anything is designed.

**What the fork does and does not touch.** Unaffected either way: items 4, 6, 8–12, and 15 — signature
verification, the `ctx`/program-type ABI, the budget pass, the whole control plane, and back-edge fuel
all sit on the far side of the decision. Item 6 stays hard-problems §2 whichever form is chosen, and
item 15 stays day one. What the decision moves is **reach and where the delicate code lives**: form B
buys any padded entry with no designed-in call site, at the price of live-text patching, per-architecture assembly, and
0b; forms A and C give that up and spend the difference on the catalog instead. Filed this way so a
"no" on the poll loop narrows the mechanism rather than ending the list.

What the reuse buys is narrow: nobody at F5 writes a VM, a verifier or a compiler. It does
**not** make this small. An earlier draft of this doc closed with "nothing is a subsystem on the
scale of 'write a VM or a verifier'" — **retired**, because the subsystem being added is a
code-patching, live-text, dynamic-code-loading facility inside the crown-jewel process, carrying its
own build-pipeline toolchain and a permanent per-build ABI.
That is **subsystem-scale work for a defensible v1 on two architectures**, and this document
deliberately does not convert it into months or people — see
[`engine-hard-problems.md`](engine-hard-problems.md) §6.1 and
[`design-review-findings.md`](design-review-findings.md) §5, which rank the items by how far the
original scoping was off without pricing them.

---

*A design proposal. Security-review-worthy items feed the formal TMA (Threat Model Analysis),
a gating prerequisite.*
