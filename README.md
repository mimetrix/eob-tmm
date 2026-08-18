# eob-tmm — the embedded eBPF substrate in TMM

A **verified, dynamic, in-data-plane programmability surface** for F5 BIG-IP: embed a
userspace eBPF VM ([uBPF](https://github.com/iovisor/ubpf)) inside TMM and attach small
programs at **function-boundary probes**: any padded function that survived the build as its own
out-of-line body, reached by rewriting its patchable-entry pad into a call to an F5 trampoline at
run time. Programs either **observe** internal state (a tracepoint) or **act** on a verdict the host
applies (a datapath control) — each one **statically proven safe before it loads**.

**The substrate modifies no F5 source file.** It adds new files, `filelist` and whitelist entries, and
one compiler flag — nothing else. Startup registers itself through TMM's own `INIT_FUNC` linker set,
the same mechanism `urlcat` and `pem_lib` use, so no existing file calls into the VM.
([`substrate/TMM-TREE-DELTA.md`](substrate/TMM-TREE-DELTA.md) is the complete delta; it is checkable
in one `git status`.) The single mechanism is the patched entry — the alternative that was also on
the table, and why it lost, is in [`mechanism-tradeoff.md`](mechanism-tradeoff.md).

**Why this matters, in one sentence:** whoever shortens the distance from **code commit to code
deployed** wins. TMM — BIG-IP's data-plane microkernel — already changes behaviour at runtime through
config, profiles, WAF (web application firewall) policy, iRules and an arriving WASM surface — each acting on the
**curated traffic model the proxy chose to expose**. A change that has to reach the code's own internals — a parser's error branch, a
plugin handoff, a counter or steering decision at a stage the model does not expose, the condition behind a
crash — has one path: a build. Which is why a new metric, a diagnostic
probe, a steering decision and a mitigation for a live CVE (Common Vulnerabilities and Exposures entry)
all cost the same thing. This changes the unit of change from **a release** to
**a signed artifact** — one that applies with **no restart and no failover**, and that `REVOKE` reverses by
restoring the original bytes at a safe point. The verifier is what makes that safe enough to allow on the
data-plane path.
**The use cases, ordered by what is proven rather than by what is urgent** (this ordering was
reversed until 2026-08-16, and the reversal cost real time):

| | status |
|---|---|
| **Debugging and root-cause analysis** — arm any armable function on a running TMM, count invocations, disarm | **works today.** Needs nothing unbuilt |
| **Data probe** — a chosen structure at a chosen point, counters plus records out through shared memory | **works today.** One build to place a tracepoint |
| **CVE mitigation** — the same mechanism pointed at an emergency | mechanism proven; **no mitigation demonstrated.** See below |

The first two need almost none of the hard machinery. Signature verification, the safe-return policy
table, a runtime budget guard and the TMA-grade argument exist because a shield **acts**; observation
only reads. So the continuous cases justify the machinery and the shield is what the same machinery
enables when an emergency arrives — not the reason to build any of it. See
[`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) §3–§4.

The second hook kind is what makes an *unforeseen* CVE addressable: **no bug-specific tracepoint has to
have been anticipated**, and no recompile is needed once the enabling build ships. Note carefully that
this is narrower than "any CVE is shieldable," and deliberately so.

**That assumption now has data, and it is not encouraging.** Five candidates were screened against a
live TMM on 2026-08-15/16. **All five failed**, none of them on the mechanism:

| candidate | why it failed |
|---|---|
| `prot_transfer_log` | no CRD exposes the gate |
| `hudproxy/memcached` | hudproxy never entered on BNK |
| `hudfilter/http/http_psm.c` | PSM does not run |
| `hudfilter/quic` | no QUIC listener |
| `ssl_alpn_match` (ALPN overread) | function runs 2×/handshake — but **malformed input never reaches it**; TMM rejects the ClientHello earlier |

A candidate must clear **seven** gates: compiled in → the function executes → **the malformed input
reaches it** → the fix is a bounded predicate → it fits in 88 bytes → it is decidable at function entry
→ the function is not inlined. Nothing in a CVE description predicts gates 2 and 3, which is what
killed all five. Note also that the last one failed a gate that was not on the checklist until it
failed — "the function executes" and "an attacker can steer malformed input into it" are different
questions.

The retrospective study across published advisories still has not been done, and would now be
worth more than another candidate. See [`substrate/LIMITATIONS.md`](substrate/LIMITATIONS.md) for the
full constraint list, and note that **OpenSSL is linked in without entry pads** — 1,781 symbols, none
armable — so the crypto library underneath F5's TLS handling is out of reach entirely.

This repo holds design proposals, visual explainers, and the **substrate sources that are built into
TMM**, plus candidate ABI (application binary interface) artifacts that compile and check themselves.
**As of 2026-08-13 the mechanism runs in a live TMM** on BNK/datkube: a shield is loaded over a
socket into an already-running process, armed at a function entry while traffic flows, and disarmed
again — no rebuild, no restart. What the repo itself still does not contain is a self-contained
runnable demo; the sources here are compiled into TMM elsewhere, and `make -C substrate check`
exercises the bench harnesses, not a data plane. A **CVE shield** — a vendor-authored runtime
mitigations that apply before the patched build does — is the *first instance* of the substrate, not the
whole of it.

## Where this fits: TMM's programmability spectrum

TMM's defining strength is **dynamic programmability** — changing the data plane's
behavior at runtime, no rebuild or reboot. iRules and WASM established that. Embedded
eBPF is the *continuation* of it, reaching a layer the others cannot:

| Surface | Programs… | Best at | Safety of dynamic change |
|---|---|---|---|
| **iRules** | traffic logic at proxy events | connection / L7 decisions | TCL, **unbounded in practice** — a runaway rule is a documented cause of a stalled TMM and a watchdog restart |
| **WASM** | rich extensions | complex custom logic, transforms | sandbox *confinement* — memory-isolated, with no static bound on what it reads; execution time bounded by runtime fuel |
| **Embedded eBPF** | the data plane's **own code & internal state** | verified probes, controls, deep telemetry | **statically verified before load** (memory-safe; terminating only when `--termination` is passed, and then to a 100,000-iteration ceiling — a bound, not a budget); execution *time* bounded by an admission-time budget pass over the verified bytecode plus a **fuel-metered runtime guard** |

eBPF is the only surface that is **dynamically loadable *and* statically proven safe** —
which is what makes it trustworthy on the most sensitive paths (the data-plane hot path,
inline security controls), exactly where dynamic change is otherwise hardest to allow — with
the signing gate as the security perimeter and the budget pass plus a fuel-metered runtime guard as
the time perimeter. Two notes on that: **eBPF's proof is not a time bound** — termination is not a
WCET (worst-case execution time), so fuel is our mechanism too, not an optional extra — and
the fuel guard needs a uBPF JIT patch F5 owns, because `ubpf_set_instruction_limit` has no effect on
JIT'd programs.

> The value prop is not "we added eBPF." It is: *TMM's power is dynamic programmability;
> eBPF extends that power to the code/instrumentation layer, and is the one surface whose
> runtime changes are provably safe.*

**Why TMM specifically.** What makes an embedded verified VM fit TMM, and not every fast data plane,
starts with **TMM being a proxy rather than a
packet-forwarding plane**. A forwarder's unit of work is the packet, with a per-packet budget in
single-digit nanoseconds — bytecode is a meaningful fraction of that. TMM's unit of work is a flow, a
connection, a request: it spends **microseconds where a forwarder spends nanoseconds**, so a hook
costing tens of nanoseconds is noise there. **Read that as the cheapest tier, not the only one:** the
pre-L7 classes this exists for — fragment reassembly, TCP state, TLS record parsing — fault *per
packet*, before any request exists, and a proxy still has hundreds of nanoseconds there where a
forwarder has tens. That tier is affordable with measurement and sign-off; a pure FastL4 fast path is
not affordable at all. Three tiers, not two (`engine-hard-problems.md` §1.1). A proxy also *has state
worth looking at* — listeners, profiles, parser state, plugin internals — which is the other reason
its CVEs are reachable at all. Three more preconditions
follow from being a shipped product: **F5 owns the source** (so the hook capability is compiled in and the signed
hook map comes out of the build), **it's a closed appliance** (so a mitigation that might put the
data plane into a **crash-loop** is unshippable — `sod` restarts TMM in seconds and HA (high
availability) fails over, so the harm that matters is a fault the traffic keeps re-triggering, dropping
every flow on that TMM each time and flapping HA — which is why the proof is a requirement, not
overhead), and **the alternative to a shield is a build**, which has to be installed: restart or
failover, regression risk, a rollback plan. Full argument in
[`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) §1.1.

## Reproducing the live result

[`REPRODUCING.md`](REPRODUCING.md) is the path from a clean checkout to a shield loaded and armed in
a running TMM — and, just as importantly, the three places this repo is **not** sufficient: it is
not the TMM source tree, not the cluster, and not a signed pipeline.

## What the substrate enables

One verified engine, resident in the process and reachable from any padded function the build emitted
as its own out-of-line body and listed in its hook map, opens several use-case families
(substrate §3–§4), of which CVE shielding is only one. (The engine does not move to the code:
arming rewrites a function's entry pad into a call to a single shared trampoline, and what exists
per hook is a slot — a program, a mode, a counter.)

- **Observability, on-demand** — *bpftrace-for-TMM*: deep telemetry for a specific
  condition / flow / tenant, on then off; per-flow latency across internal stages; a
  *flight recorder* that snapshots state when an error branch fires; new metrics as
  bytecode, no TMOS (BIG-IP's operating system) rev.
- **Diagnostics & field support** — ship a customer a *signed probe* to characterize a
  production issue in situ, then remove it — no debug build, and often no need to wait for a repro.
  It does **not** replace core-dump analysis: a probe only answers a question someone already thought
  to ask, and a dump is what you fall back on when you had no hypothesis. See the debuggability item in
  [`engine-hard-problems.md`](engine-hard-problems.md) §5, which also covers how the trampoline can
  *degrade* a dump if the CFI (control-flow integrity) and JIT-symbol work is skipped.
- **Security beyond CVE shields** — behavioral exploit detection on internal state;
  protocol-anomaly detection at the parser (pre-event); adaptive rate-limiting, which composes from
  DROP or SAMPLE plus host-side state rather than being an outcome of its own.
- **Lightweight policy / steering** — mirror-selection, A/B, member-steering driven by
  internal signals (decision in eBPF; heavy logic stays in iRules/WASM).
- **Self-tuning / performance** — read internal load and nudge a knob; live hot-path profiling.
- **CVE shielding** — the flagship first consumer of the surface; see below.

The differentiated asset is the compiled-in **attach capability** (patchable entries +
trampoline) plus **where** in TMM a hook earns its keep — the hook-point
catalog spanning L3/L4, the TLS record layer, L7 parse, the enforcement path (`bd`/WAF out-of-process;
**AFM (Advanced Firewall Manager) and DoS (denial-of-service) enforcement run inside TMM**, so the
enforcement path is only partly out-of-process), LB / persistence, and cross-cutting runtime (poll loop, memory pools, the poll
loop's own iteration accounting). Most are read-only
tracepoints that can graduate to active controls once the signal is trusted.

## The CVE shield — the surface's first consumer

The motivating application: **surgical, reversible, vendor-signed mitigations that block a
specific exploit path** until the patched build is installed. A shield
is a **crash mitigation, not a hot-patch**: the host takes a safe outcome (e.g. skip the
vulnerable function's body); the corrected behaviour returns with the patch.
There is a precedent for the idea: Cisco's Live Protect ships signed eBPF shields for NX-OS,
loaded into that platform's Linux kernel. Applied to BIG-IP, the same technique reaches the
**control plane** — httpd, MCPD and the other resident C daemons are ordinary Linux processes — and
stops there. It does
not reach **TMM**. Not because the kernel cannot see TMM: a uprobe on the `tmm` binary attaches
today. It is that a uprobe traps into the kernel on every hit, which a run-to-completion poll
loop cannot afford, and that the kernel forbids overriding a return from a uprobe, so it could
never *act* even where it can watch. Meanwhile the most damaging data-plane CVEs — malformed-input
crashes, parser bugs, **traffic-borne remote code execution (RCE)** — arbitrary code execution triggered
purely by sending traffic through the data path, needing no credentials and no management-plane access —
are exactly the ones inside TMM, and iRules reach only
part of that path. An in-process VM is the only form that is both affordable per invocation and
able to take an outcome.

> The `bpftime` *injection* model was evaluated and rejected — its syscall interposition
> never reliably engaged, and the kernel forbids `bpf_override_return` on uprobes
> (design §3, §3.1).

## The mechanism

The substrate spans **two eBPF execution engines, chosen by what the kernel can see** —
under one signed catalog and lifecycle (design §5).

**Current scope: the proxy data plane only.** Work targets **TMM**, and the second bullet below is
where it lands. The control/management plane in the first bullet — and, in the containerized form
factor, the companion microservices that make up a BIG-IP Next deployment alongside the `f5-tmm` pod —
are **deferred, not dismissed**: they are a different engine (kernel eBPF via uprobes), a different
verifier (the kernel's), and in the JVM and Node cases a different probe surface again, so each is its
own effort with its own trust story. Keeping them out of scope for now is what makes the data-plane
argument testable: one engine, one verifier, one binary we build ourselves. The catalog in
[`tmm-usdt-tracepoints.md`](tmm-usdt-tracepoints.md) is scoped to the data plane for the same reason
(§2.1). The first bullet is retained because the *lifecycle* — one signed catalog, one revocation
path — has to span both eventually, and designing it as if TMM were the only consumer would be a
mistake to unpick later.

- **Control / management plane — three runtimes, so three implementations.** The resident native C
  daemons (httpd, MCPD, logging, SNMP) are ordinary processes, so shields there are **kernel-space
  eBPF** attached via uprobes, gated by the kernel's own verifier; this is the direct Cisco/NX-OS
  analog, and F5 already ships kernel eBPF ("eob"). iControl REST (`restjavad`/`icrd`) runs on the
  **JVM**, needing a separate JVMTI/USDT probe surface; iControl LX (`restnoded`) runs on **Node**,
  needing a third again. `tmsh` is not in this list — it is a per-invocation shell, not a resident
  daemon, so an entry probe on it would be a category error; what `tmsh` drives is shielded in MCPD,
  where the change actually lands.
- **Data plane (TMM)** — attachable by kernel eBPF, but neither affordable nor enforceable there (the
  per-hit trap and the return-override rule above), so shields are **userspace
  eBPF** run by an embedded uBPF VM: the trampoline **calls the VM like a library** from a patched
  function entry and acts on the return — no kernel, no injection, no added privileges. Each program is
  **statically verified by [PREVAIL](https://github.com/vbpf/ebpf-verifier)** (the verifier from
  eBPF-for-Windows) **in F5's admission pipeline, before it is signed** — failing closed on any
  nonzero verdict. Note the order, because it is the whole security argument: verification precedes
  signing, and on the box the gate is the **signature over the binding**, so only F5-signed bytecode
  ever reaches the in-TMM JIT. The verifier is not the perimeter; the signature is.

In both engines the host owns a fixed, enumerated set of six outcomes — **PASS · DROP · RESET ·
SAFE-RETURN** (skip the hooked function's body) **· STEER · SAMPLE** — defined once in
[`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) §2. The signed program only chooses among
them; it cannot invent control flow. **`observe` is not a seventh outcome:** it is the host declining
to *apply* whichever outcome the program selected while still counting it, with the same program
unchanged.

Verification — the kernel's built-in verifier or PREVAIL — is a **safety** gate (memory-safe; and
terminating only where the termination check is actually enabled), *not* a security gate. The security layer — mandatory signing, authorization
tiers, capability/context confinement, exfiltration control, audit/revocation/kill-switch,
resource governance — lives *around* the VM (substrate §6.3; note that the design doc's §8 covers
the signing lifecycle only, and substrate §6.4 says outright that authorization tiers, confinement,
exfiltration control and attestation are **not** yet specified there).

## Contents

| Path | What it is |
|---|---|
| [`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) | The substrate: programmability spectrum, use-case families, hook-point catalog, and the security model |
| [`big-ip-live-surface-design.md`](big-ip-live-surface-design.md) | The Live Surface design — threat model, hook-point map, modes, and trust/validation lifecycle (signing, verify-before-load, auto-retirement) |
| [`data-plane-intelligence.md`](data-plane-intelligence.md) | The proxy as AI's sensory organ — the unique post-decrypt data vantage as a product moat, the sense→learn→act flywheel, tiered use-cases, and a reference architecture for the API-discovery MVP (value captured *in the product*, not sold as a feed) |
| [`cve-survey-bnk.md`](cve-survey-bnk.md) | **Read-only Bugzilla survey, 2026-08-18.** The 39 CVEs tracked against BNK are all in sidecars and base-OS packages — none in TMM, so no hooking mechanism reaches them. The right target is the 45 in-TMM `Exploitable` findings (~9 distinct), which are already padded. Includes the bug→finding-hash→fix-commit pipeline that yields a shield predicate without embargoed access |
| [`hook-types.md`](hook-types.md) | **What the VM can attach to, and what it cannot.** Kernel eBPF has ~10 event sources; this has ONE — function entry on padded functions. The three ctx shapes, what exit probes / PMU counters / hardware watchpoints would each take, and an honest accounting of what was reinvented rather than borrowed from bpftime |
| [`hook-types-plan.md`](hook-types-plan.md) | **How to add hook types.** The `(kind, slot)` dispatch refactor that has to come first, then timer / PMU-as-a-helper / exit probes / hardware watchpoints — each with honest cost and risk, and what would reorder them |
| [`rst-why-feed.md`](rst-why-feed.md) | **Measured, not proposed.** The reset feed running end to end on BNK: how to trigger a reset four ways, the records each produces, the TMM source lines they resolve to (`RST_WHY(scb->uf, "Closing")` at `http_mr_proxy.c:993`), what this answers that a counter cannot — and the four limits, including the cause string the trampoline does not forward |
| [`data-plane-egress-primitives.md`](data-plane-egress-primitives.md) | How data leaves the embedded VM — a per-core, single-producer, shared-memory ring; the **host emits, the program only signals** (no helpers, stock verifier). Prior-art review (DPDK `rte_ring`, kernel BPF ringbuf, bpftime), and the record-layout / backpressure / wakeup / crash design |
| [`development-scope.md`](development-scope.md) | **What F5 actually builds** beyond the reused OSS (uBPF/PREVAIL/clang) — in-TMM code, build-pipeline tooling, control-plane pieces, optional tiers, and the one recurring per-CVE cost (a few lines of C). Keyed to the walkthrough's step numbers |
| [`bnk-integration-map.md`](bnk-integration-map.md) | **Joining the pieces into BNK.** Honest state (validated components, not an integrated whole), the unbuilt work to get one BNK TMM shielding a live CVE end to end, and the first gate: can TMM patch its own text so execution sees it |
| [`safe-swap-plan.md`](safe-swap-plan.md) | **The plan for Path B's last piece.** Rewriting a function entry into a hook while cores execute it: the three hazards, why stress-testing alone is weak evidence for a race, the candidate mechanisms (recommend the kernel's `text_poke_bp` protocol), a stress harness that must be proven to catch the *unsafe* version first, and the iterate-till-right ladder |
| [`mechanism-tradeoff.md`](mechanism-tradeoff.md) | **The fork, as a trade matrix.** Designed-in call sites vs patched function entries — the two ways a program reaches a function, decided across hookable-set size, the CVE pitch, poll-loop cost, padding footprint, security surface and what's built today. The two axes that force the choice, the ~49%-reach caveat for the patched path, the hybrid, and the questions that would settle it |
| [`tmm-integration-findings.md`](tmm-integration-findings.md) | **What building it found.** The catalogue from actually integrating uBPF into TMM, building it and running it in a pod: invocation cost (10 ns JIT / 48 ns interpreter), footprint (+0.27% `.text`), the entry-padding coverage gap, four defects in uBPF and PREVAIL, four findings about TMM's own build — and a section on where the work corrected itself, because the corrections are more informative than the results |
| [`design-review-findings.md`](design-review-findings.md) | **A structured self-review, and what it changes** — the register. Demonstrably-broken items (several verified against the uBPF and PREVAIL sources cloned into the working tree), wrong-about-TMM claims, missing specifications, the measurement that gates everything, honest scope restatement (a subsystem, not "hundreds of lines"), what is strong and currently buried, and the questions that would decide this before anything is built — two to settle on paper, three to prove in a lab, and the experiment that comes first |
| [`development-scope-code.md`](development-scope-code.md) | **Candidate code** for every day-one scope item (1–12 + the shield program) — skeletons scaled to each item's size class, each with a real / stubbed / TODO breakdown, plus a naming-reconciliation table. Backed by the checked artifacts in [`substrate/`](substrate/) — which is also where several of these skeletons were caught being wrong |
| [`engine-hard-problems.md`](engine-hard-problems.md) | The problems the pitch glosses — **termination ≠ WCET**, the **ctx/helper/program-type ABI is the real 90%**, **maps under CMP + HA mirroring**, and **verifier soundness as a data-plane RCE surface** (with the signing gate as the real perimeter). Honest mitigations, day-one vs. deferred — the "what a security review will ask" register |
| [`substrate/`](substrate/) | **The artifacts that check themselves** — the loader/binding ABI as a header whose `_Static_assert`s pin the wire layout, the hook-map JSON Schema plus an example map, an admission-time budget pass with a self-test, an offset check, and a guard that fails the build if the safe-return two-gate rule regresses. `make -C substrate check` runs all of it |
| [`substrate/shields/`](substrate/shields/) | **The eBPF programs we author** — the CVE shield for the real NULL-deref at `http_psm.c:806`, plus three programs that exist to pin the verifier's gates. The `ctx` header is **generated from a real build's DWARF** rather than hand-written, which is what a shield needs to be trustworthy: the layout is a property of one build. `make -C substrate check` compiles each and asserts PREVAIL's verdict |
| [`explainers/README.md`](explainers/README.md) | **The reading map** — which artifact answers which question, the intended order, and what to hand a skeptic first. Start here when circulating |
| [`explainers/`](explainers/) | Visual explainers (HTML), one job each. [`programmable-dataplane-engine.html`](explainers/programmable-dataplane-engine.html) — **the engine** (the generic verified-eBPF utility in TMM); [`cve-mitigation.html`](explainers/cve-mitigation.html) — data-plane **CVE mitigation** (the shield); [`cve-shield-walkthrough.html`](explainers/cve-shield-walkthrough.html) — a **worked example**: shielding a real TMM NULL-deref crash class step by step; [`engine-hard-problems.html`](explainers/engine-hard-problems.html) — the **engineering register** (the hard problems, honestly scoped) |
| [`tmm-usdt-tracepoints.md`](tmm-usdt-tracepoints.md) | A proposed catalog of designed-in USDT-style (user statically defined tracing) tracepoints for TMM — observability, debug, and RCA features, by data-path stage |

## What is actually checkable here

Two different things are checkable, and they should not be conflated. **In this repo**,
[`substrate/`](substrate/) holds items from the scope that are **real files rather than illustrative
blocks** — they compile, validate, and run under `make -C substrate check`. **In a live TMM**, the
same sources are compiled in and have been exercised on BNK/datkube: load, arm, disarm, and a hook
firing 1:1 with requests through the proxy. The second set is not reproducible from this repo alone —
it needs the TMM build tree and the cluster. `make -C substrate check` runs eight checks with
nothing but a C compiler, Python 3, and — for the last one — a BPF-capable clang and a built
PREVAIL (it skips loudly rather than silently passing if either is missing):

1. **`shield_abi.h` compiles standalone and asserts its own wire layout** — fifteen `_Static_assert`s
   pinning `struct shield_msg` and `struct shield_binding` byte for byte.
2. **The hook-map schema is valid, and the example map validates against it** — and the check reports
   which product-only fields a given instance is not yet emitting rather than silently passing.
3. **The example map's declared `ctx` offsets are compiled against the real header**, so a wrong offset
   fails rather than being trusted. This check exists because there *was* a wrong offset here.
4. **The budget pass runs its own self-test** — six hand-assembled eBPF programs wrapped in a
   synthesized ELF, covering `lddw`'s 16-byte form, longest-path over a branch, a fail-closed
   over-budget rejection, and refusing a loop rather than guessing its trip count.
5. **The safe-return two-gate rule is asserted, not just documented** — five cases, and the build fails
   if an unanalysed function body is ever treated as enforce-capable.
6. **The candidate skeletons are handed to a compiler** — 12 of 13 C blocks in
   `development-scope-code.md` compile against the ABI header and platform stubs; an opt-out is
   reported, never silent. Nothing is linked or run.
7. **The verifier's model of the runtime is compared against the runtime** — PREVAIL's per-subprogram
   stack frame against uBPF's, parsed from both vendored trees at run time. This one reports two
   standing findings and `make gate` fails on them, on purpose: item 6a is open.
8. **The shields in [`substrate/shields/`](substrate/shields/) are compiled and put to PREVAIL, with
   each verdict asserted** — the CVE shield must pass, two rejection programs must fail, and a
   surprise in either direction fails the build. The dangerous direction is a rejection program that
   starts passing.

**Why that is the whole of it.** Writing these for real has already caught four defects
that the prose versions carried unnoticed: a signature documented as covering a binding the message
could not carry; a replay that defeated the kill switch; a safe-return model inverted so that `void`
looked like the easy case; and a hook map declaring offsets that did not match its own header. That is
the argument for these files existing. It is *not* an argument that the mechanism works.

**What is and is not demonstrated, precisely.** As of 2026-08-12 a shield **is** compiled here and a
verifier **does** reach a verdict on it: `clang -O2 -g -target bpf` produces a 9-instruction program,
PREVAIL passes it with `--termination --no-division-by-zero --strict`, and the budget pass prices it at
~21 cycles against a budget of 800. Its `ctx` is generated from the DWARF of a TMM built from source on
2026-08-12 (BNK form factor), so the offsets come from a real binary rather than from someone typing out
a struct. **That paragraph described the state before 2026-08-13 and is superseded.** The trampoline, the
loader, arming and the safe swap now exist and run in a live TMM; a shield armed on
`http_parse_client_headers` fired exactly once per request across 16,000 requests through the proxy.

What is still *not* measured is the **per-call cost** of an armed hook. The counter mean is dominated
by preemption artifacts (single calls of 1.09M and 3.14M cycles — an `rdtsc` pair spanning a context
switch, not shield work), and the bench op that would give a clean minimum currently wedges the
loader thread. So per-call performance claims remain design claims awaiting measurement; see
[`load-path-scope.md`](load-path-scope.md) §7 for exactly what was and was not established.

## Notes

- The third-party clones `ubpf/` and `ebpf-verifier/` are **not** vendored here — clone them yourself
  if you want to check the source citations in [`design-review-findings.md`](design-review-findings.md)
  (they are gitignored, and the register pins the commit of each).
- An earlier version of this repo carried a working prototype: a TCP relay with a synthetic crash bug,
  a designed-in hook, a uBPF track and a PREVAIL verify gate. **It was removed deliberately.** Its
  name read as an F5 component and invited the wrong question — whether it was cut-down TMM source —
  and a toy relay standing in for TMM invites an argument about the analogy rather than the design.
  The stated cost at the time — "the verify gate is no longer demonstrable here" — **no longer
  applies:** `make -C substrate check-shields` compiles each candidate program and asserts PREVAIL's
  verdict on it in **both** directions, so a rejection test that starts passing fails the build.
- Nothing here is production TMM source.
