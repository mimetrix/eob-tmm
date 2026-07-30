# eob-tmm — the embedded eBPF substrate in TMM

A **verified, dynamic, in-data-plane programmability surface** for F5 BIG-IP: embed a
userspace eBPF VM ([uBPF](https://github.com/iovisor/ubpf)) inside TMM, expose a curated
set of designed-in **hook points**, and run small programs that either **observe**
internal state (a tracepoint) or **act** on a verdict the host applies (a datapath
control) — each one **statically proven safe before it loads**.

This repo holds the design proposals and a working prototype. **Live Shield** —
vendor-authored runtime CVE mitigations between patch windows — is the *first instance*
of the substrate, not the whole of it.

## Where this fits: TMM's programmability spectrum

TMM's defining strength is **dynamic programmability** — changing the data plane's
behavior at runtime, no rebuild or reboot. iRules and WASM established that. Embedded
eBPF is the *continuation* of it, reaching a layer the others cannot:

| Surface | Programs… | Best at | Safety of dynamic change |
|---|---|---|---|
| **iRules** | traffic logic at proxy events | connection / L7 decisions | TCL, runtime-bounded; can misbehave / be costly |
| **WASM** | rich extensions | complex custom logic, transforms | sandbox isolation; can hang (fuel-killed) |
| **Embedded eBPF** | the data plane's **own code & internal state** | verified probes, controls, deep telemetry | **statically verified before load** — provably bounded + terminating |

eBPF is the only surface that is **dynamically loadable *and* statically proven safe** —
which is what makes it trustworthy on the most sensitive paths (the data-plane hot path,
inline security controls), exactly where dynamic change is otherwise hardest to allow.

> The value prop is not "we added eBPF." It is: *TMM's power is dynamic programmability;
> eBPF extends that power to the code/instrumentation layer, and is the one surface whose
> runtime changes are provably safe.*

## What the substrate enables

A verified VM at designed-in hook points opens several use-case families (substrate §3–§4),
of which CVE shielding is only one:

- **Observability, on-demand** — *bpftrace-for-TMM*: deep telemetry for a specific
  condition / flow / tenant, on then off; per-flow latency across internal stages; a
  *flight recorder* that snapshots state when an error branch fires; new metrics as
  bytecode, no TMOS rev.
- **Diagnostics & field support** — ship a customer a *signed probe* to characterize a
  production issue in situ, then remove it. No debug build, no core-dump archaeology.
- **Security beyond CVE shields** — behavioral exploit detection on internal state;
  protocol-anomaly detection at the parser (pre-event); adaptive rate-limit / circuit-break.
- **Lightweight policy / steering** — mirror-selection, A/B, member-steering driven by
  internal signals (decision in eBPF; heavy logic stays in iRules/WASM).
- **Self-tuning / performance** — read internal load and nudge a knob; live hot-path profiling.
- **Live Shield (CVE mitigation)** — the flagship first instance; see below.

The differentiated asset is **where** in TMM a hook earns its keep — the hook-point
catalog spanning L3/L4, the TLS record layer, L7 parse, the enforcement plugins, LB /
persistence, and cross-cutting runtime (poll loop, memory, scheduler). Most are read-only
tracepoints that can graduate to active controls once the signal is trusted.

## Live Shield — the first instance

The motivating application: **surgical, reversible, vendor-signed mitigations that block a
specific exploit path between maintenance windows**, until the patched build ships.
Cisco's Live Protect embeds eBPF shields in NX-OS's Linux kernel — which covers BIG-IP's
**control plane** but is structurally **blind to TMM**, F5's data-plane microkernel that
bypasses the Linux kernel entirely. The most damaging data-plane CVEs (malformed-input
crashes, parser bugs, traffic-borne RCE) live exactly where kernel eBPF cannot see, and
iRules only reach part of that path. Embedding the VM *in* the data plane closes that gap.

> The `bpftime` *injection* model was evaluated and rejected — its syscall interposition
> never reliably engaged, and the kernel forbids `bpf_override_return` on uprobes
> (design §2.3).

## The mechanism

The substrate spans **two eBPF execution engines, chosen by what the kernel can see** —
under one signed catalog and lifecycle (design §5):

- **Control / management plane** — the native Linux daemons (httpd, tmsh, MCPD) are ordinary
  processes, so shields are **kernel-space eBPF** attached via uprobes, gated by the kernel's
  own verifier. This is the direct Cisco/NX-OS analog; F5 already ships kernel eBPF ("eob").
  iControl REST (`restjavad`/`icrd`) runs on the JVM, so it uses a separate JVMTI/USDT probe
  surface instead.
- **Data plane (TMM)** — the kernel is structurally blind to TMM, so shields are **userspace
  eBPF** run by an embedded uBPF VM: the host **calls the VM like a library** at a designed-in
  hook and acts on the return — no kernel, no injection, no added privileges. Each program is
  **statically verified before load** by [PREVAIL](https://github.com/vbpf/ebpf-verifier) (the
  verifier from eBPF-for-Windows), failing closed on any nonzero verdict.

In both engines the host owns an enumerated set of outcomes (pass / observe / enforce-drop);
the signed program only chooses among them — it cannot invent control flow.

Verification — the kernel's built-in verifier or PREVAIL — is a **safety** gate (memory-safe +
terminating), *not* a security gate. The security layer — mandatory signing, authorization
tiers, capability/context confinement, exfiltration control, audit/revocation/kill-switch,
resource governance — lives *around* the VM (substrate §6, design §8).

## Contents

| Path | What it is |
|---|---|
| [`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) | The substrate: programmability spectrum, use-case families, hook-point catalog, and the security model |
| [`big-ip-live-shield-design.md`](big-ip-live-shield-design.md) | The Live Shield design — threat model, hook-point map, modes, and trust/validation lifecycle (signing, verify-before-load, auto-retirement) |
| [`data-plane-intelligence.md`](data-plane-intelligence.md) | The proxy as AI's sensory organ — the unique post-decrypt data vantage as a product moat, the sense→learn→act flywheel, tiered use-cases, and a reference architecture for the API-discovery MVP (value captured *in the product*, not sold as a feed) |
| [`data-plane-egress-primitives.md`](data-plane-egress-primitives.md) | How data leaves the embedded VM — a per-core, single-producer, shared-memory ring; the **host emits, the program only signals** (no helpers, stock verifier). Prior-art review (DPDK `rte_ring`, kernel BPF ringbuf, bpftime), and the record-layout / backpressure / wakeup / crash design |
| [`development-scope.md`](development-scope.md) | **What F5 actually builds** beyond the reused OSS (uBPF/PREVAIL/clang) — in-TMM code, build-pipeline tooling, control-plane pieces, optional tiers, and the one recurring per-CVE cost (a few lines of C). Keyed to the walkthrough's step numbers |
| [`engine-hard-problems.md`](engine-hard-problems.md) | The load-bearing problems the pitch glosses — **termination ≠ WCET**, the **ctx/helper/program-type ABI is the real 90%**, **maps under CMP + HA mirroring**, and **verifier soundness as a data-plane RCE surface** (with the signing gate as the real perimeter). Honest mitigations, day-one vs. deferred — the "what a security review will ask" register |
| [`p4-on-tmm.md`](p4-on-tmm.md) | Exploratory design note — the **P4 → uBPF** path (p4c's uBPF backend) as a front-end for packet-granular programs on TMM, **P4 as a portable IR** across software (uBPF) and hardware offload, the budget pass as a **software-vs-silicon placement decision**, and uBPF-vs-WASM. Honestly scoped: a future front-end on the deferred helper/map tier |
| [`prototype/`](prototype/) | A minimal data-plane relay with a synthetic CVE, a designed-in hook point, and a runnable proof of the substrate mechanism |
| [`prototype/tmmtrace`](prototype/tmmtrace) | **tmmtrace** — a bpftrace-style front-end to the embedded VM: one grammar spanning observe (tracepoint) and filter (CVE shield), with compile → verify → run |
| [`explainers/`](explainers/) | Visual explainers (HTML), one job each — each with a Teams-pasteable `.teams.md` companion. [`programmable-dataplane-engine.html`](explainers/programmable-dataplane-engine.html) — **the engine** (the generic verified-eBPF utility in TMM); [`cve-mitigation.html`](explainers/cve-mitigation.html) — data-plane **CVE mitigation** (the shield); [`cve-shield-walkthrough.html`](explainers/cve-shield-walkthrough.html) — a **worked example**: shielding a real TMM NULL-deref CVE step by step; [`engine-hard-problems.html`](explainers/engine-hard-problems.html) — the **engineering register** (the load-bearing hard problems, honestly scoped) |
| [`tmm-usdt-tracepoints.md`](tmm-usdt-tracepoints.md) | A proposed catalog of designed-in USDT-style tracepoints for TMM — observability, debug, and RCA features, by data-path stage |

## Prototype at a glance

The prototype is a transparent TCP relay reproducing the *structural* properties the substrate
depends on (kernel-bypass-style poll loop, inline eval stage, a designed-in hook point).
Three tracks:

1. **Reference** — shield logic compiled into the host (plain C); proves the lifecycle.
2. **uBPF** — the program as eBPF bytecode run by the embedded VM, in both **enforce** and
   **observe** (tracepoint) modes; enforce holds, monitor crashes.
3. **PREVAIL gate** — the good program verifies and loads; a deliberately-unsafe one is
   rejected before load.

Over the top, **`tmmtrace`** is a bpftrace-style front-end: write a one-liner and it compiles to a
shield, runs the verify gate, and drives the VM in observe *or* filter mode — one grammar for
*explore → shield*. It is also the natural target for **AI-assisted authoring** (CVE → predicate →
verify → replay); see [`explainers/`](explainers/).

See [`prototype/README.md`](prototype/README.md) for build & run of all three tracks — Track 1
needs no dependencies; the uBPF and verify-gate tracks include Rocky Linux 8.10 container
builds — and [`prototype/TOOLCHAIN.md`](prototype/TOOLCHAIN.md) for the end-to-end
source → bytecode → verify → load → run pipeline.

## Notes

- The third-party clones `ubpf/` and `ebpf-verifier/` are **not** vendored here — clone them
  yourself as described in the prototype README (they're gitignored).
- This repo holds design proposals and proof-of-concept code. Patent/invention disclosure
  artifacts are kept out by policy (and gitignored).
