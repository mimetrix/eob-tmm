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
| **uBPF** | the VM + JIT (~150 KB) | Apache-2.0 | the calls item 3 is built on are the library's **real public API**, not invented for this proposal: `ubpf_create` / `ubpf_load_elf` / `ubpf_exec` (`vm/inc/ubpf.h:129, 458, 510` in the gitignored `ubpf/` clone), with `ubpf_compile_ex` (`:575`) as the JIT path — the *extended* mode, because the basic `ubpf_compile` (`:553`) emits a prologue that takes an unprobed 4 KiB stack frame. **No runnable demonstration ships in this repo** — read this cell as an API-surface claim, checkable against uBPF's own header, and *not* as evidence that the load-and-run path has been stood up. Reused as-is **except** item 15's JIT back-edge-fuel patch — F5-owned, upstreamable |
| **PREVAIL** | the static verifier | MIT **+ Apache-2.0** (the clone ships both `LICENSE` files, plus `external/{CLI11,bpf_conformance,libbtf}`; the SBOM/license scan is a Phase-1 gate per `big-ip-live-shield-design.md` §13) | stock, driven as a CLI invocation — `-q [--section <s>]` (`src/main.cpp:65, 74`). **No verify gate is demonstrated in this repo.** O3 in [`design-review-findings.md`](design-review-findings.md) records the ctx-model limit that any future demonstration has to clear, and it is a property of PREVAIL, not of any one harness |
| **clang** | C → eBPF bytecode | — | standard toolchain |

Nobody at F5 writes a VM, a verifier, or a compiler. **What this repo no longer shows is that any of
it runs.** An earlier revision carried a prototype — a small relay that loaded and ran a shield
through the real uBPF API, plus a verify-gate track that invoked PREVAIL — and this paragraph cited
it as demonstrating the load-and-run half of item 3. That prototype has been removed, and the
demonstration went with it. The reuse argument above now rests on the two upstream projects' public
APIs; it no longer rests on anything executable here.
So: "reused, not written" stands, and **"already works in our hands" is not currently shown** — a
loss of evidence, and the state of the reuse case until something runnable is stood
up again. The JIT's own properties (item 15's fuel, its unprobed 4 KiB stack frame) were open
questions before and remain so; they were never measured even while the prototype existed, because
it ran the interpreter.

---

## 1. In-TMM data-plane code — ships in the substrate build

The delicate systems work: small, but must be exactly right.

1. **The trampoline** *(walkthrough step 2)* — per CPU architecture: save the hooked function's
   argument registers per the ABI, build the `ctx`, call the JIT'd program, bump the fire
   counter, apply the verdict (safe-return vs. fall-through), restore. ≈ a page of code per
   architecture, generic across all functions.
2. **Arm/disarm routine** *(step 2)* — patch the nop pad, flush the instruction cache,
   coordinated across cores at the safe point. "Atomic patch" is the wrong shorthand on
   x86-64, where a 5-byte `JMP rel32` cannot be written by one store: the mechanism is a
   rendezvous, as in Linux's `text_poke_bp()` (breakpoint → IPI/sync → patch → sync →
   restore the first byte). aarch64's aligned 4-byte branch *is* a single store, so the two
   architectures need different code here. Same discipline the kernel's ftrace has used on
   live text for years — proven pattern, not research.
3. **The safe-point loader handler** *(steps 4, 10, 13)* — processes `shield_msg`
   (`LOAD · SET_MODE · STATUS · REVOKE`). **Every op is authenticated, not only `LOAD`**: the
   signature must cover the op, the requested mode and a **monotonic epoch**, or a captured `LOAD`
   replays after a `REVOKE` and the kill switch is defeatable. Then hook-map lookup → arm.
   `ubpf_load_elf` and the JIT compile run **off** the safe point — a full ELF parse plus a code
   generation pass inline in the poll loop is milliseconds of not polling — leaving the safe point
   to publish a pointer and patch a few bytes. Plus the unglamorous rest that is real work: **all
   error paths fail-dark** (no partial arm), expiry enforcement (auto-retire on build match),
   per-shield state (per-core fire counters, mode flags, VM teardown on unload).
4. **Signature verification in TMM** *(steps 3, 10)* — checking the signed binding against the
   baked-in public key before any bytecode is touched. Possibly reusable from F5's existing
   signed-artifact verification; net-new integration either way.

## 2. Build-pipeline tooling — runs at F5, per TMOS build

Written once; their *outputs* regenerate automatically every build (maintenance-free artifacts).

5. **Hook-map generator** *(step 3)* — from the build's debug info (DWARF/BTF): named symbol →
   entry address + typed argument layout. Output is signed and shipped with the build.
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

*Also in this section's scope over time:* the **designed-in USDT** (userland statically-defined
tracing) **tracepoint catalog** — hook
kind (1), proposed in [`tmm-usdt-tracepoints.md`](tmm-usdt-tracepoints.md): per-stage placement
and a stable, versioned `ctx` ABI. Per-catalog-entry annotation work, distinct from the
auto-generated function-boundary hook map above.

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
    tier. Left unnamed deliberately — the removed tool's name read as a shipped TMM component.

## 5. Recurring cost — per CVE, forever

**The shield program: a few lines of C** *(step 6)*. That is the entire marginal cost of each
new mitigation. Nothing else on this list is ever written again.

---

## 6. Shape summary

| # | Item | Runs | Written | Size class |
|---|---|---|---|---|
| 1 | trampoline | TMM hot path (when armed) | once per arch | ~1 page |
| 2 | arm/disarm | TMM, safe point | once | small |
| 3 | loader handler | TMM, safe point | once | hundreds of lines |
| 4 | sig verify in TMM | TMM, at load | once (or reused) | small |
| 5 | hook-map generator | build pipeline | once | tool |
| 6 | ctx descriptors for PREVAIL | build pipeline | once + **ongoing discipline** (§2) | tool + process |
| 7 | safe-return table | build pipeline | once + annotations | tool + process |
| 8 | budget pass | admission (at F5) | once | tool |
| 9 | signing integration | F5 infra | once | integration |
| 10 | loader daemon side | control plane | once | conventional |
| 11 | operator front-end | control plane | once | thin |
| 12 | audit trail | control plane | once | conventional |
| 15 | back-edge fuel (uBPF JIT patch) | TMM, per program invocation | **day one** | small patch, owned fork |
| 13, 14, 16, 17 | staged tiers | various | staged | staged |
| — | **shield program** | TMM, via VM | **per CVE** | **a few lines of C** |

The **Size class** column is *shape*, not effort: it says how much code an item is, not how long it
takes to get right. Items 1–4: delicate, small, must be exactly right. Items 5–7: tooling with one
hard design decision (§2). Items 8–12: conventional control-plane engineering. Items 13, 14, 16, 17:
staged follow-ons; **item 15 is day one**.

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
