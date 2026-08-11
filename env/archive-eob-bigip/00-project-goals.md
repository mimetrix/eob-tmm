# Project goals

This is a learning + prototyping project for using eBPF to enhance or
complement the BIG-IP product line, across its three form factors:

- **BIG-IP (appliance)** — physical hardware running TMOS.
- **BIG-IP VE** — TMOS as a virtual machine (KVM/ESXi/cloud images).
- **BNK** — BIG-IP Next for Kubernetes, TMOS-derived data plane deployed
  as containers on a Kubernetes cluster.

The near-term goal is to get comfortable with eBPF mechanics (program
types, maps, CO-RE, verifier behavior, attach points) using small,
self-contained programs, then start mapping specific BIG-IP problems
(observability, traffic classification, security enforcement, control
plane tracing) onto real attach points on each form factor.

See [01-bigip-form-factors-and-ebpf-surface.md](01-bigip-form-factors-and-ebpf-surface.md)
for where eBPF plausibly fits per form factor,
[02-environment-notes.md](02-environment-notes.md) for what does/doesn't
work in the current dev sandbox, and
[03-openstack-cli-reference.md](03-openstack-cli-reference.md) /
[04-bigip-ve-boot-attempt-2026-07-17.md](04-bigip-ve-boot-attempt-2026-07-17.md)
for the OpenStack (`sjc-stack`) side of things — provisioning a real
BIG-IP VE to test against,
[05-tmm-build-environment.md](05-tmm-build-environment.md) for the current
push (standing up a TMM **build** host), and
[06-bigip-mcp-server.md](06-bigip-mcp-server.md) for a downstream backlog
item.

## Status

- [x] Repo scaffolded: Go + `cilium/ebpf` (bpf2go), vendored libbpf headers,
      CO-RE via generated `vmlinux.h`.
- [x] First program (`bpf/xdpcount`): XDP packet counter (total/TCP/UDP),
      per-CPU array map. Compiles and builds end to end.
- [ ] Attach/run validated on a real privileged host (blocked on
      environment access — see docs/02).
- [x] OpenStack (`sjc-stack`) CLI access working — application credential,
      image/network/flavor discovery all confirmed (docs/03).
- [ ] **Blocked**: booted the newest available BIG-IP VE image
      (`BIGIP-21.1.0.1-0.0.26`) and found its host kernel is `3.10.0-862`
      (RHEL7-class, pre-BTF) — no CO-RE eBPF possible on that kernel.
      Need a TMOS image built on a **Rocky Linux 8.10** base instead
      (kernel 4.18+, BTF-capable). User has an internal request out for
      the right image/version; resume once identified. Details in
      docs/04.
- [ ] **Current push (2026-08-11)**: stand up an OpenStack instance to
      **build TMM**, then ship the artifact to a separate run target.
      Both `sjc-stack` and `sea-stack` confirmed reachable; blocked on
      application credentials, and on internal guidance for kernel
      version / recommended VM image. See docs/05.
- [ ] First BIG-IP-relevant use case picked and scoped.
- [ ] Backlog: stand up the BIG-IP MCP Server once a stable TMM exists
      (docs/06).
- [ ] TMM dataplane observability approach (candidate function calls,
      USDT tracepoints) — not yet started, see open question in docs/04.
