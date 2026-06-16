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

Rather than inject, the host **calls the VM like a library** at a designed-in hook and acts
on the return. The host owns an enumerated set of outcomes (pass / observe / enforce-drop);
the signed program only chooses among them — it cannot invent control flow. Every program is
**statically verified before load** by [PREVAIL](https://github.com/vbpf/ebpf-verifier) (the
verifier from eBPF-for-Windows), failing closed on any nonzero verdict. No kernel, no
injection, no added privileges.

Verification is a **safety** gate (memory-safe + terminating), *not* a security gate. The
security layer — mandatory signing, authorization tiers, capability/context confinement,
exfiltration control, audit/revocation/kill-switch, resource governance — lives *around* the
VM (substrate §6, design §8).

## Contents

| Path | What it is |
|---|---|
| [`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) | The substrate: programmability spectrum, use-case families, hook-point catalog, and the security model |
| [`big-ip-live-shield-design.md`](big-ip-live-shield-design.md) | The Live Shield design — threat model, hook-point map, modes, and trust/validation lifecycle (signing, verify-before-load, auto-retirement) |
| [`prototype/`](prototype/) | **minimm** — a "mini-TMM" relay with a synthetic CVE, a designed-in hook point, and a runnable proof of the substrate mechanism |

## Prototype at a glance

`minimm` is a transparent TCP relay reproducing the *structural* properties the substrate
depends on (kernel-bypass-style poll loop, inline eval stage, a designed-in hook point).
Three tracks:

1. **Reference** — shield logic compiled into the host (plain C); proves the lifecycle.
2. **uBPF** — the program as eBPF bytecode run by the embedded VM, in both **enforce** and
   **observe** (tracepoint) modes; enforce holds, monitor crashes.
3. **PREVAIL gate** — the good program verifies and loads; a deliberately-unsafe one is
   rejected before load.

```bash
cd prototype
make -C minimm && ./demo.sh        # Track 1, no dependencies
```

See [`prototype/README.md`](prototype/README.md) for the uBPF and verify-gate tracks (and
the Rocky Linux 8.10 container builds), and [`prototype/TOOLCHAIN.md`](prototype/TOOLCHAIN.md)
for the end-to-end source → bytecode → verify → load → run pipeline.

## Notes

- The third-party clones `ubpf/` and `ebpf-verifier/` are **not** vendored here — clone them
  yourself as described in the prototype README (they're gitignored).
- This repo holds design proposals and proof-of-concept code. Patent/invention disclosure
  artifacts are kept out by policy (and gitignored).
