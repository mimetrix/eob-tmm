# Ground truth: every claim about our own system, with its evidence tier

Anchor for the evidence discipline this project works under. A claim not on this page, or on it
without a tier, is not a claim yet.

## The tiers

| tier | means |
|---|---|
| **MEASURED** | observed, with the artifact named. The reader can re-run it |
| **SHIPPED-UNVALIDATED** | the code is deployed and runs; the *outcome* it exists for has not been demonstrated |
| **ROADMAP** | designed, costed, not built |
| **IDEA** | proposed, not costed. Argument only |
| **FALSIFIED** | was claimed, is now known false. Kept with the artifact that killed it — see `CONTESTED-PREMISES.md` |

## Witnessing: who saw it

Tracked separately from tier, and it matters as much. A counter our own code incremented is
weaker evidence than something an independent tool observed, and conflating the two is how
"the hook fired" becomes "the hook works".

| witness | means |
|---|---|
| **SELF** | our code reported it. A slot counter, a log line we emit |
| **KERNEL** | the kernel or the OS reported it. `/proc/<pid>/mem`, `perf_event_open`, `readelf`, an exit status |
| **INDEPENDENT** | a tool with no shared code path. `tcpdump`, PREVAIL, `nm`, a second hook corroborating the first |

---

## Mechanism

| claim | tier | witness | anchor |
|---|---|---|---|
| A verified program loads into a running TMM and arms at a function entry, no rebuild, no restart | MEASURED | KERNEL | entry bytes read from `/proc/<pid>/mem` before and after; `load-path-scope.md` |
| Disarming restores the entry byte-for-byte | MEASURED | KERNEL | `90 90 90 90 90` → `e8 …` → `90 90 90 90 90`, read from process memory, both pods |
| Five bytes change; nothing is displaced | MEASURED | KERNEL | `endbr64` and the first real instruction read unchanged either side of the pad |
| A hook fires exactly once per event | MEASURED | SELF | `fired` counter 1:1 with request count across 16,000 requests. **Self-reported** — the counter is ours |
| …corroborated independently | MEASURED | INDEPENDENT | packet capture carried the same cause string and line number as the record, via code sharing nothing with the hook |
| Arming by name is gated on build identity | MEASURED | KERNEL | build ID read from `/proc/<pid>/exe`; mismatch refused. `rst_why` occupied 4 distinct addresses across 4 builds of identical source |
| Records identify the function that produced them | MEASURED | SELF | was FALSIFIED before 2026-08-19 — see `CONTESTED-PREMISES.md` #1 |

## Cost

| claim | tier | witness | anchor |
|---|---|---|---|
| Program execution ≤ 11 ns on the JIT path | MEASURED (as an **upper bound**) | SELF | `ls-load.py bench`, `path=jit`, min 26–28 cycles at 2.60 GHz. Bounded by the `rdtsc` pair measuring it: a record-building program timed *below* one that returns immediately, which is impossible. `load-path-scope.md` §7 |
| `bpf_probe_read` ≈ 26 ns, maps+clock+emit ≈ 105 ns | MEASURED | SELF | same op; these clear the instrument floor and are resolvable |
| ~10 ns JIT / ~48 ns interpreter | MEASURED | INDEPENDENT | an off-TMM harness recorded this months earlier by a different method; agrees with the above |
| **What an armed hook costs on the data path** | **NOT ESTABLISHED** | — | the floor excludes the trampoline's register save/restore, the call and return, and cache effects under traffic |
| Padding costs 0.182% of binary size | MEASURED | KERNEL | section sizes from the linked binary |

## Reach

| claim | tier | witness | anchor |
|---|---|---|---|
| ~41k functions armable via the pad; ~30k need displacement | MEASURED | KERNEL | generated per build from the packaged binary. **Counts move every build** — 41,148 then 41,160. Count from the image, per `env/bnk-dev-runbook.md` §12f |
| OpenSSL's 1,781 linked symbols are unreachable | MEASURED | KERNEL | no entry padding outside TMM core; the index records them as displacement-only |
| Displacement reaches them | ROADMAP | — | designed, unimplemented |
| Hardware watchpoints reach any address | MEASURED, outside TMM | KERNEL | `prototype/watchpoint/`, `perf_event_open` |

## Watchpoints (prototyped outside TMM, 2026-08-20)

| claim | tier | witness | anchor |
|---|---|---|---|
| Delivery needs no signal handler — samples land in a ring another thread drains | MEASURED | KERNEL | `wp_probe.c`; samples present with nothing installed to catch a signal |
| Requires `CAP_SYS_ADMIN`; `CAP_PERFMON` is refused at `perf_event_paranoid=4` | MEASURED | KERNEL | `EACCES` under `setpriv --ambient-caps=+perfmon`; permitted under `+sys_admin` |
| Exactly four concurrent | MEASURED | KERNEL | `ENOSPC` on the fifth, both architectures |
| 501 ns/hit aarch64, 4,755 ns/hit x86 KVM guest | MEASURED | KERNEL | `wp_cost.c`. The x86 figure is inflated by debug exceptions exiting to the hypervisor; **neither host is bare metal** |
| Viable for rare high-reach events, not per-request | MEASURED (arithmetic on the above) | — | 16,000 requests → 8–88 ms of pure trap |

## Shippability

| claim | tier | witness | anchor |
|---|---|---|---|
| Programs are signature-verified before loading | **FALSIFIED / not built** | — | the loader accepts anything and prints `unverified=yes` on every load. This is the principal gap to anything customer-facing |
| Arming is audited | ROADMAP | — | nothing durably records who armed what, when, against which build |
| A CVE is mitigated on live traffic | **NOT DEMONSTRATED** | — | the mechanism is proven; no advisory has been mitigated end to end. The BNK target is not reachable on this cluster |
| `alpn_guard` expresses a real fix | SHIPPED-UNVALIDATED | INDEPENDENT | reinstates the bounds check from commit `c806f1b2e8`; PREVAIL admits it. Never exercised against a live exploit |

## Borrowed code

| claim | tier | witness | anchor |
|---|---|---|---|
| uBPF is `iovisor/ubpf @ c900ed9f` plus one recorded patch | MEASURED | KERNEL | `substrate/check_vendor_pin.sh` — git revision compared, patch applied to it cleanly |
| PREVAIL is `vbpf/ebpf-verifier @ 06769f7b` (v0.2.5), unmodified | MEASURED | KERNEL | same check; no tracked file differs; the binary reports `v0.2.5` |
| The uBPF revision "cannot be stated" | **FALSIFIED** | — | `CONTESTED-PREMISES.md` #6 |
