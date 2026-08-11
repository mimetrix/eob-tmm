# Environment notes

## This dev sandbox: build-only, cannot load/run eBPF

Checked directly (2026-07-17):

- Kernel 6.15.9 (aarch64), `/sys/kernel/btf/vmlinux` present → CO-RE
  header generation works fine here.
- `clang` 14, `bpftool` 7.1.0, `make`, `gcc`, Go 1.25 all present.
- No `libbpf-dev` package available (not in the apt sources, and no
  root/sudo to install anything anyway) → headers vendored directly from
  the upstream libbpf v1.5.0 release tarball into `bpf/headers/`
  (`bpf_helpers.h`, `bpf_helper_defs.h`, `bpf_tracing.h`, `bpf_core_read.h`,
  `bpf_endian.h`, BSD-2-Clause licensed) instead.
- Runs as uid 1001, non-root, no sudo binary at all.
- `capsh --print` shows `cap_bpf`, `cap_net_admin`, `cap_perfmon`,
  `cap_sys_admin`, `cap_sys_resource`, etc. all struck from the **bounding
  set** (`!cap_bpf`, ...) — meaning even a hypothetical root shell in this
  container could not add them back. Confirmed empirically: the built
  `xdpcount` loader fails at `rlimit.RemoveMemlock()` with "operation not
  permitted" — the correct/expected failure point, not a bug.

**Implication:** this sandbox is for writing, compiling, and code-genning
eBPF programs (`go generate`, `go build`, `bpftool btf dump`) only.
Attaching/loading/running anything needs a real privileged target —
a VM, an OCP node (privileged pod / DaemonSet), or a BIG-IP VE instance.

## OpenStack access — superseded

This section originally recorded a 2026-07-17 snapshot: password-based auth
against the SJC stack only, a single `clouds.yaml` cloud named `openstack`,
and an end-to-end check that failed with "No password entered". **All of
that has been replaced** and the details were removed from here rather than
left to contradict the current setup:

- **Auth** is now an **application credential** per stack, not a password.
- **Two stacks** are configured (`sjc`, `sea`), selected via `OS_CLOUD`.
- The auth chain was re-verified on **both** stacks on 2026-08-11.

Current, authoritative sources — do not re-derive from this file:

- [`tmm-build-environment.md`](tmm-build-environment.md) — endpoints for
  both stacks, the credential runbook, TLS/`verify: false` rationale, and
  failure modes.
- [`openstack-cli-reference.md`](openstack-cli-reference.md) — CLI install,
  image selection, network gotchas, instance launch.
- [`scripts/bootstrap-openstack-cli.sh`](scripts/bootstrap-openstack-cli.sh)
  — the venv/pip bootstrap that this section used to describe in prose
  (still accurate as to *why*: no root, no system pip, no `ensurepip`).

## OCP / Kubernetes

Session hook shows `oc` already logged in, plus `kubectl` on PATH. Not
yet explored which cluster/project this points at or whether it's the
BNK target environment — next step once we're actually driving toward a
BNK experiment.
