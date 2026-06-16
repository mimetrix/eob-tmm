# eob-tmm — embedded eBPF on TMM ("Live Shield")

Design proposal and working prototype for **vendor-authored, on-box runtime
compensating controls** on F5 BIG-IP — surgical, reversible mitigations that block
a specific exploit path **between maintenance windows**, until the permanent patched
build ships. Explicitly *not* a patch and *not* a replacement for lifecycle discipline:
a finger-in-the-dike while the disclosure-to-exploitation window keeps shrinking.

## The problem in one paragraph

Cisco's Live Protect embeds eBPF shields in NX-OS's Linux kernel. That model covers
the BIG-IP **control plane** (RHEL-family Linux — httpd, iControl REST, MCPD), but is
structurally **blind to TMM** — F5's own data-plane microkernel, which bypasses the
Linux kernel entirely for the traffic path. The most damaging data-plane CVEs
(malformed-input crashes, parser bugs, traffic-borne RCE) live exactly where
kernel-based instrumentation cannot see, and iRules only reach part of that path.

## The approach

Rather than inject into the kernel, **embed a userspace eBPF VM ([uBPF](https://github.com/iovisor/ubpf))
inside the data plane** and call it at designed-in hook points. The host owns an
enumerated set of outcomes (pass / monitor / enforce-drop); the signed shield bytecode
only chooses among them. Every shield is **statically verified before load** by
[PREVAIL](https://github.com/vbpf/ebpf-verifier) (the verifier from eBPF-for-Windows),
failing closed on any nonzero verdict. No kernel, no injection, no added privileges.

> The `bpftime` *injection* model was evaluated and rejected — its syscall interposition
> never reliably engaged, and the kernel forbids `bpf_override_return` on uprobes. See
> the design doc §2.3.

## Contents

| Path | What it is |
|---|---|
| [`big-ip-live-shield-design.md`](big-ip-live-shield-design.md) | The Live Shield design proposal — threat model, hook-point catalog, security & lifecycle (signing, verify-before-load, auto-retirement) |
| [`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) | The broader embedded-eBPF substrate; Live Shield is its first instance |
| [`prototype/`](prototype/) | **minimm** — a "mini-TMM" bent-pipe relay with a synthetic CVE, a designed-in hook point, and a runnable proof of the mechanism |

## Prototype at a glance

`minimm` is a transparent TCP relay reproducing the *structural* properties Live Shield
depends on (kernel-bypass-style poll loop, inline eval stage, a designed-in hook point).
It ships three tracks:

1. **Reference** — shield logic compiled into the host (plain C); proves the lifecycle.
2. **uBPF** — the shield as eBPF bytecode run by the embedded VM; enforce holds, monitor crashes.
3. **PREVAIL gate** — the good shield verifies and loads; a deliberately-unsafe shield is rejected before load.

```bash
cd prototype
make -C minimm && ./demo.sh        # Track 1, no dependencies
```

See [`prototype/README.md`](prototype/README.md) for the uBPF and verify-gate tracks
(and the container builds on Rocky Linux 8.10).

## Notes

- The third-party clones `ubpf/` and `ebpf-verifier/` are **not** vendored here — clone
  them yourself as described in the prototype README (they're gitignored).
- This repo holds design proposals and proof-of-concept code. Patent/invention
  disclosure artifacts are kept out by policy (and gitignored).
