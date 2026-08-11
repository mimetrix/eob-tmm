# BIG-IP VE boot attempt — 2026-07-17

## What we tried

Booted `BIGIP-21.1.0.1-0.0.26` (the newest TMOS release in the `sjc-stack`
catalog — see [openstack-cli-reference.md](openstack-cli-reference.md#picking-a-big-ip-image))
on flavor `F5-BIGIP-small`, mgmt NIC on `AdminNetwork`, dataplane NIC on
`AllTestVLANs`, unlicensed.

## What we found

Console log confirmed:
```
BIG-IP 21.1.0.1 Build 0.0.26
Kernel 3.10.0-862.14.4.el7.ve.x86_64 on an x86_64
```

**This kills the eBPF plan for this image.** Kernel 3.10 predates BTF
entirely (BTF/CO-RE landed upstream around 4.18+) — this is a RHEL
7-class kernel (~2018-era backports). At best it might carry some very
limited classic-BPF/early-XDP backport; no CO-RE, and likely minimal
modern eBPF program-type support at all. Confirming exactly what (if
anything) it supports wasn't reached because we couldn't get a shell:

- SSH `PasswordAuthentication` is disabled (server only offers
  `publickey`/`keyboard-interactive`).
- `root`/`default` (conventional TMOS console default) failed via
  keyboard-interactive.
- Our OpenStack keypair's public key did not grant `publickey` auth —
  cloud-init services were present (symlinked) per the console log, but
  showed no evidence of actually executing (no metadata/config-drive
  fetch logged), so the key likely never got injected.
- Relaunched with `--user-data` (a `chpasswd` script) + `--config-drive
  true` to force a known root/admin password — this attempt was
  interrupted (killed the instance) before we found out whether it
  worked, per the decision below.

## Decision: pause and find a different base image

User's read: worth finding a BIG-IP image built on a **Rocky Linux
8.10** base instead of this RHEL7/kernel-3.10 one — Rocky 8's kernel
line (4.18+) does support `CONFIG_DEBUG_INFO_BTF` and modern eBPF/CO-RE,
which is the actual prerequisite for any of this project's plans. User
has put out an internal request to find the right image/version.
Instance was deleted; **resume once that image is identified** — same
process in openstack-cli-reference.md applies (image selection
method, network gotcha, user-data for credentials), just swap the image
ID and re-verify kernel/BTF before going further.

## Open question for next session

Even once we're on a Rocky 8.10-based image and can prove CO-RE/BTF
eBPF works on the **management-plane** kernel, that still doesn't touch
TMM's actual dataplane (see
[archive-eob-bigip/01-bigip-form-factors-and-ebpf-surface.md](archive-eob-bigip/01-bigip-form-factors-and-ebpf-surface.md))
— TMM's kernel-bypass packet path stays invisible to standard kernel
eBPF hooks regardless of host kernel version. The Rocky-base image gets
us a working eBPF *toolchain* on the box; whether/how to observe TMM
itself (candidate function calls, USDT tracepoints) is a separate,
harder research question still ahead.
