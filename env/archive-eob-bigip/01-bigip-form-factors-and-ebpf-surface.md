# BIG-IP form factors and where eBPF plausibly fits

This is a working hypothesis, not verified fact — flagged assumptions
should be checked against actual TMOS internals / F5 internal docs before
being relied on.

## The general shape

TMOS's data plane (TMM — Traffic Management Microkernel) is, as I
understand it, a userspace, largely kernel-bypass packet processing
engine (comparable in spirit to DPDK): it grabs NICs directly for
line-rate throughput rather than pushing every packet through the
standard Linux network stack. **[assumption, verify]** If that's
accurate, standard kernel-hook eBPF (XDP, tc, socket filters) has *no
visibility into TMM's actual data path* on any form factor — it can't see
packets TMM owns exclusively.

Where a normal Linux kernel *is* present and doing normal things is the
**management plane**: SSH/tmsh, iControl REST, config daemons, logging,
the base OS around TMM. That's directly reachable by conventional eBPF
(kprobes/uprobes, tracepoints, tc/XDP on management-plane interfaces,
cgroup hooks).

## Per form factor

### BNK (BIG-IP Next for Kubernetes)
Most promising near-term target. It's deployed as containers on a
standard Kubernetes cluster with a standard Linux kernel underneath
(this repo's `oc`/`kubectl` access is presumably for exactly this). Even
if TMM's own fast path stays opaque, there's real value in:
- eBPF-based observability of the *node* and *pod* network stack around
  BNK (e.g. tc/XDP counters on veth/pod interfaces, socket-level latency
  tracing) — same techniques as this repo's `xdpcount` example.
- CNI-adjacent enhancements (Cilium-style) that sit alongside BNK rather
  than inside it.
- kprobe/tracepoint-based tracing of the control-plane processes BNK runs
  as containers.

### BIG-IP VE
Same TMM-bypass caveat applies to the data path. But VE runs as a full
VM with a real (if customized) Linux kernel host OS around TMM, so
management-plane and host-level observability (VM network interfaces,
hypervisor-facing virtio/vhost paths, host-side tc/XDP) are viable
targets, likely more accessible for experimentation than the physical
appliance since you can freely spin up/tear down VE instances.

### BIG-IP appliance
Same architectural shape as VE but with less freedom to experiment
(shared hardware, custom NICs/DPDK drivers, harder to get root/dev
access). Good target for *validated* ideas, not for initial exploration.

## Realistic starting point

Given the above, the practical entry point is: build eBPF fluency on
generic Linux first (this repo's early programs), then move to BNK/K8s
node-level observability where the kernel path is real and reachable,
and only later investigate whether/how TMM exposes any hook points
(shared memory maps, control-plane IPC, custom NIC driver hooks) that
eBPF could actually attach to. That last part needs real TMOS internals
knowledge this project doesn't have yet — treat it as a research
question, not an assumption to build on.
