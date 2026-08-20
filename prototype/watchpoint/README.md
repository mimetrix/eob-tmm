# Hardware watchpoints, prototyped outside TMM

`hook-types-plan.md` §2.4 ranks hardware watchpoints as the biggest scope gain available and
recommends prototyping them **outside TMM first** — "to find out whether the signal-context
restrictions are survivable before proposing it near a data plane." This is that prototype.

Two programs, both self-contained, neither touching TMM: `wp_probe.c` asks what the kernel
permits, `wp_cost.c` measures what a hit costs the watched thread.

---

## What it changes about the plan

**The plan's central objection does not apply to the mechanism we actually have.** §2.4 says
the real problem is "a signal handler as the delivery path … SIGTRAP arriving anywhere in a
run-to-completion poll loop." That assumes signal delivery. `perf_event_open` with
`PERF_TYPE_BREAKPOINT` can instead **sample into an mmap'd ring buffer that a different thread
drains** — the watched thread takes the trap and continues, no handler runs in it, and
async-signal-safety never enters the picture.

Verified on both architectures: samples appear in the ring with no handler installed.

**But the cost makes the reach argument moot for anything frequent**, which the plan suspected
and could not quantify: §2.5 says the per-hit ratio "is large … but it is UNMEASURED here and no
number should be quoted for it." It is measured below, and it is 45× to 440×.

---

## 1 · What the kernel permits

`perf_event_paranoid` is **4** on both x86 boxes here — more restrictive than anything the Linux
tree defines (−1…3). That turns out to be a privilege gate, not an off-switch:

| condition | result |
|---|---|
| unprivileged, paranoid=4 | **REFUSED** (`EACCES`) |
| `CAP_PERFMON`, paranoid=4 | **REFUSED** — the narrow capability meant for this is not enough |
| `CAP_SYS_ADMIN`, paranoid=4 | permitted |
| root, paranoid=4 | permitted |
| unprivileged, paranoid=2 | permitted |

So deploying this needs either **`CAP_SYS_ADMIN` in the pod** — effectively root-equivalent, and
a hard sell for a data-plane container — or the **node's sysctl relaxed to ≤ 2**, which is a
host-level change outside the product's control. `CAP_PERFMON` exists precisely for
performance-monitoring access and does **not** suffice at this setting; that is worth knowing
before anyone proposes it as the narrow ask.

## 2 · Concurrency ceiling: exactly four

Confirmed by arming until refusal, on both architectures: the fifth returns `ENOSPC`. Four
debug registers, four concurrent watchpoints, per thread. Not a soft limit to be tuned.

## 3 · Per-hit cost to the watched thread

200,000 stores per pass, timed with the watchpoint disarmed and then armed, five passes. The
difference is what the trap costs the thread that took it.

| host | steady-state per hit |
|---|---|
| x86_64, KVM guest (where TMM runs) | **4,755 – 5,534 ns** |
| aarch64 sandbox | **501 – 512 ns** |

**The x86 figure is inflated by virtualisation and should not be quoted as the hardware cost.**
That box is a KVM guest (`systemd-detect-virt: kvm`, `hypervisor` in cpuinfo), and a debug
exception in a guest can exit to the hypervisor. The order-of-magnitude gap between the two
hosts is the evidence for that. Bare metal is likely far closer to the aarch64 number; nobody
here has bare metal to check on, so both are reported and neither is presented as *the* answer.

Against this project's own hook, measured the same week: **≤ 11 ns**, a direct `call` with no
kernel involvement (`load-path-scope.md` §7). So the ratio is **roughly 45× at best and 440× on
the box that matters**.

One artifact worth stating: after the first pass the ring is full and nothing drains it, so
later passes produce 0 sample bytes — yet the cost is unchanged. That says the **trap** dominates,
not writing the sample, which is the more useful conclusion than a tidier measurement would have
given.

---

## 4 · What this settles

**§2.5's frequency-versus-reach split is confirmed, with numbers.** Its claim was that pads and
watchpoints are not competing mechanisms because the discriminator is frequency. At 45–440× per
hit and a hard ceiling of four, a watchpoint on a per-request site is not viable — `rst_why`
fires on every teardown, and 16,000 requests through the proxy would cost between 8 and 88
milliseconds of pure trap. On a rare path it is irrelevant: an exploit attempt that fires once
costs five microseconds, and nobody can measure that.

So the honest positioning:

- **Pad-based arming** stays the mechanism for observability — per-request rates, unbounded
  sites, no privilege.
- **Watchpoints** are the mechanism for reach — the 1,781 OpenSSL symbols and everything else
  built without entry padding, which pads can never touch whatever flaw is found there.

They are complementary, and this prototype is the first evidence for that rather than an
argument for it.

## 5 · What is still unknown

- **Behaviour inside a run-to-completion poll loop.** Measured here in a tight store loop, not
  in TMM. A 5 µs stall in the poll loop is a different question from 5 µs in a benchmark.
- **Whether a uBPF program can usefully run from the consumer thread.** Deliberately not
  attempted: the cost result makes it the wrong next question. If watchpoints are for rare
  events, the consumer has microseconds to spare and running a program there is unremarkable.
- **Bare-metal cost.** Both hosts available are virtualised.
- **Whether `CAP_SYS_ADMIN` in a data-plane pod is acceptable at all.** That is a security
  review's call, not a measurement, and it may end the discussion regardless of the numbers.

## Running it

```bash
gcc -O2 -Wall -Wextra -o wp_probe wp_probe.c && sudo ./wp_probe
gcc -O2 -Wall -Wextra -o wp_cost  wp_cost.c  && sudo ./wp_cost
```

`sudo` because of the table in §1. Unprivileged, both print the refusal and stop.
