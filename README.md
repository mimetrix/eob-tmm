# eob-tmm — the embedded eBPF substrate in TMM

A **verified, dynamic, in-data-plane programmability surface** for F5 BIG-IP: embed a
userspace eBPF VM ([uBPF](https://github.com/iovisor/ubpf)) inside TMM and attach small
programs at **two kinds of hook** — a curated set of designed-in **hook points**, and
**function-boundary probes** at any function that survived the build as its own out-of-line
body (patchable-entry pad → F5 trampoline). Programs either **observe** internal state (a
tracepoint) or **act** on a verdict the host applies (a datapath control) — each one
**statically proven safe before it loads**.

**Why this matters, in one sentence:** whoever shortens the distance from **code commit to code
deployed** wins. TMM — BIG-IP's data-plane microkernel — already changes behaviour at runtime through
config, profiles, WAF policy, iRules and an arriving WASM surface — each acting on the
**curated traffic model the proxy chose to expose**. A change that has to reach the code's own internals — a parser's error branch, a
plugin handoff, the condition behind a crash — has one path: a build. Which is why a new metric, a diagnostic
probe, a steering decision and a mitigation for a live CVE all cost the same thing. This changes the unit of change from **a release** to
**a signed artifact** — one that applies with **no restart and no failover**, and that `REVOKE` reverses in
seconds. The verifier is what makes that safe enough to allow on the data-plane path.
**CVE mitigation is the first use case because it is the most urgent, not because it is the only one** —
see [`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) §3–§4 for the rest.

The second hook kind is what makes an *unforeseen* CVE addressable: **no bug-specific tracepoint has to
have been anticipated**, and no recompile is needed once the enabling build ships. Note carefully that
this is narrower than "any CVE is shieldable," and deliberately so — a reachable boundary must exist
before the fault, expose the triggering condition through a declared walk, offer a safe outcome, and fit
its budget (design §10.1). **What fraction of real data-plane advisories clear those bars is not yet
known**, and the retrospective study that would answer it needs no engineering and is the most decisive
thing missing from this proposal.

This repo holds design proposals, visual explainers, and a small set of **candidate ABI artifacts
that compile and check themselves**. It does **not** contain a running implementation: nothing here
executes a shield. **Live Shield** —
vendor-authored runtime CVE mitigations between patch windows — is the *first instance*
of the substrate, not the whole of it.

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
the time perimeter. Two honest notes on that, since both are load-bearing: **eBPF's proof is not a
time bound** — termination is not a WCET, so fuel is our mechanism too, not an optional extra — and
the fuel guard needs a uBPF JIT patch F5 owns, because `ubpf_set_instruction_limit` has no effect on
JIT'd programs.

> The value prop is not "we added eBPF." It is: *TMM's power is dynamic programmability;
> eBPF extends that power to the code/instrumentation layer, and is the one surface whose
> runtime changes are provably safe.*

**Why TMM specifically.** An embedded verified VM isn't the right answer for every fast data plane;
it's the right answer for this one, and the reason starts with **TMM being a proxy rather than a
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
follow from being a shipped product: **F5 owns the source** (so hooks are designed in and the signed
hook map comes out of the build), **it's a closed appliance** (so a mitigation that might put the
data plane into a **crash-loop** is unshippable — `sod` restarts TMM in seconds and HA fails over, so
the harm that matters is a fault the traffic keeps re-triggering, dropping every flow on that TMM each
time and flapping HA — which is why the proof is a requirement, not overhead), and **a rebuild costs a
maintenance window** rather than a `make`. Full argument in
[`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) §1.1.

## What the substrate enables

A verified VM at designed-in hook points — and, via function-boundary probes, at any function the
build emitted as its own out-of-line body and listed in its hook map — opens several use-case
families (substrate §3–§4),
of which CVE shielding is only one:

- **Observability, on-demand** — *bpftrace-for-TMM*: deep telemetry for a specific
  condition / flow / tenant, on then off; per-flow latency across internal stages; a
  *flight recorder* that snapshots state when an error branch fires; new metrics as
  bytecode, no TMOS rev.
- **Diagnostics & field support** — ship a customer a *signed probe* to characterize a
  production issue in situ, then remove it — no debug build, and often no need to wait for a repro.
  It does **not** replace core-dump analysis: a probe only answers a question someone already thought
  to ask, and a dump is what you fall back on when you had no hypothesis. See the debuggability item in
  [`engine-hard-problems.md`](engine-hard-problems.md) §5, which also covers how the trampoline can
  *degrade* a dump if the CFI and JIT-symbol work is skipped.
- **Security beyond CVE shields** — behavioral exploit detection on internal state;
  protocol-anomaly detection at the parser (pre-event); adaptive rate-limiting, which composes from
  DROP or SAMPLE plus host-side state rather than being an outcome of its own.
- **Lightweight policy / steering** — mirror-selection, A/B, member-steering driven by
  internal signals (decision in eBPF; heavy logic stays in iRules/WASM).
- **Self-tuning / performance** — read internal load and nudge a knob; live hot-path profiling.
- **Live Shield (CVE mitigation)** — the flagship first instance; see below.

The differentiated asset is the compiled-in **attach capability** (patchable entries +
trampoline) plus **where** in TMM a hook earns its keep — the hook-point
catalog spanning L3/L4, the TLS record layer, L7 parse, the enforcement path (`bd`/WAF out-of-process; **AFM and DoS
enforcement run inside TMM**, which is easy to lose sight of and roughly quadruples the surface that
phrase implies), LB / persistence, and cross-cutting runtime (poll loop, memory pools, the poll
loop's own iteration accounting). Most are read-only
tracepoints that can graduate to active controls once the signal is trusted.

## Live Shield — the first instance

The motivating application: **surgical, reversible, vendor-signed mitigations that block a
specific exploit path between maintenance windows**, until the patched build ships. A shield
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
under one signed catalog and lifecycle (design §5):

- **Control / management plane — three runtimes, so three implementations.** The resident native C
  daemons (httpd, MCPD, logging, SNMP) are ordinary processes, so shields there are **kernel-space
  eBPF** attached via uprobes, gated by the kernel's own verifier; this is the direct Cisco/NX-OS
  analog, and F5 already ships kernel eBPF ("eob"). iControl REST (`restjavad`/`icrd`) runs on the
  **JVM**, needing a separate JVMTI/USDT probe surface; iControl LX (`restnoded`) runs on **Node**,
  needing a third again. `tmsh` is not in this list — it is a per-invocation shell, not a resident
  daemon, so an entry probe on it would be a category error; what `tmsh` drives is shielded in MCPD,
  where the change actually lands.
- **Data plane (TMM)** — kernel eBPF *can* attach to TMM (a uprobe on `tmm` works today) but cannot
  afford to (a kernel trap per hit inside a run-to-completion loop) and cannot enforce (no return
  override on uprobes), so shields are **userspace
  eBPF** run by an embedded uBPF VM: the host **calls the VM like a library** at a designed-in
  hook and acts on the return — no kernel, no injection, no added privileges. Each program is
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
| [`big-ip-live-shield-design.md`](big-ip-live-shield-design.md) | The Live Shield design — threat model, hook-point map, modes, and trust/validation lifecycle (signing, verify-before-load, auto-retirement) |
| [`data-plane-intelligence.md`](data-plane-intelligence.md) | The proxy as AI's sensory organ — the unique post-decrypt data vantage as a product moat, the sense→learn→act flywheel, tiered use-cases, and a reference architecture for the API-discovery MVP (value captured *in the product*, not sold as a feed) |
| [`data-plane-egress-primitives.md`](data-plane-egress-primitives.md) | How data leaves the embedded VM — a per-core, single-producer, shared-memory ring; the **host emits, the program only signals** (no helpers, stock verifier). Prior-art review (DPDK `rte_ring`, kernel BPF ringbuf, bpftime), and the record-layout / backpressure / wakeup / crash design |
| [`development-scope.md`](development-scope.md) | **What F5 actually builds** beyond the reused OSS (uBPF/PREVAIL/clang) — in-TMM code, build-pipeline tooling, control-plane pieces, optional tiers, and the one recurring per-CVE cost (a few lines of C). Keyed to the walkthrough's step numbers |
| [`design-review-findings.md`](design-review-findings.md) | **Three architect reviews and what they change** — the register. Demonstrably-broken items (several verified against the uBPF and PREVAIL sources cloned into the working tree), wrong-about-TMM claims, missing specifications, the measurement that gates everything, honest scope restatement (a subsystem, not "hundreds of lines"), what's genuinely strong and currently buried, and the questions that would decide this before anything is built — two to settle on paper, three to prove in a lab, and the experiment that comes first |
| [`development-scope-code.md`](development-scope-code.md) | **Candidate code** for every day-one scope item (1–12 + the shield program) — skeletons scaled to each item's size class, each with a real / stubbed / TODO breakdown, plus a naming-reconciliation table. Backed by the checked artifacts in [`substrate/`](substrate/) — which is also where several of these skeletons were caught being wrong |
| [`engine-hard-problems.md`](engine-hard-problems.md) | The load-bearing problems the pitch glosses — **termination ≠ WCET**, the **ctx/helper/program-type ABI is the real 90%**, **maps under CMP + HA mirroring**, and **verifier soundness as a data-plane RCE surface** (with the signing gate as the real perimeter). Honest mitigations, day-one vs. deferred — the "what a security review will ask" register |
| [`substrate/`](substrate/) | **The artifacts that check themselves** — the loader/binding ABI as a header whose `_Static_assert`s pin the wire layout, the hook-map JSON Schema plus an example map, an admission-time budget pass with a self-test, an offset check, and a guard that fails the build if the safe-return two-gate rule regresses. `make -C substrate check` runs all of it |
| [`explainers/README.md`](explainers/README.md) | **The reading map** — which artifact answers which question, the intended order, and what to hand a skeptic first. Start here when circulating |
| [`explainers/one-pager.html`](explainers/one-pager.html) | **The one-pager** — the whole proposal on a single printable sheet, ending on the feasibility-phase ask |
| [`explainers/`](explainers/) | Visual explainers (HTML), one job each. [`programmable-dataplane-engine.html`](explainers/programmable-dataplane-engine.html) — **the engine** (the generic verified-eBPF utility in TMM); [`cve-mitigation.html`](explainers/cve-mitigation.html) — data-plane **CVE mitigation** (the shield); [`cve-shield-walkthrough.html`](explainers/cve-shield-walkthrough.html) — a **worked example**: shielding a real TMM NULL-deref crash class step by step; [`engine-hard-problems.html`](explainers/engine-hard-problems.html) — the **engineering register** (the load-bearing hard problems, honestly scoped) |
| [`tmm-usdt-tracepoints.md`](tmm-usdt-tracepoints.md) | A proposed catalog of designed-in USDT-style tracepoints for TMM — observability, debug, and RCA features, by data-path stage |

## What is actually checkable here

There is no prototype in this repo, and no claim in these documents rests on one. What there is, in
[`substrate/`](substrate/), is the handful of items from the scope that are worth having as **real
files rather than illustrative blocks** — because their value is precisely that they compile, validate,
and run. `make -C substrate check` runs five checks with nothing but a C compiler and Python 3:

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

**Why that is the whole of it, stated plainly.** Writing these for real has already caught four defects
that the prose versions carried unnoticed: a signature documented as covering a binding the message
could not carry; a replay that defeated the kill switch; a safe-return model inverted so that `void`
looked like the easy case; and a hook map declaring offsets that did not match its own header. That is
the argument for these files existing. It is *not* an argument that the mechanism works — **no shield
is compiled, verified, loaded, or executed anywhere in this repo**, and every performance and behaviour
claim in these documents is a design claim awaiting measurement.

## Notes

- The third-party clones `ubpf/` and `ebpf-verifier/` are **not** vendored here — clone them yourself
  if you want to check the source citations in [`design-review-findings.md`](design-review-findings.md)
  (they are gitignored, and the register pins the commit of each).
- An earlier version of this repo carried a working prototype: a TCP relay with a synthetic crash bug,
  a designed-in hook, a uBPF track and a PREVAIL verify gate. **It was removed deliberately.** Its
  name read as an F5 component and invited the wrong question — whether it was cut-down TMM source —
  and a toy relay standing in for TMM invites an argument about the analogy rather than the design.
  The cost of removing it is real and worth stating: the verify gate is no longer demonstrable here.
- This repo holds design proposals and candidate artifacts. Nothing here is production TMM source.
