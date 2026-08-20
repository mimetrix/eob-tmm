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
| Ed25519 signature verification refuses tampered, unsigned and wrong-key programs | MEASURED | KERNEL | `make -C substrate check-sig` — 16 assertions from freshly generated keys, covering every falsifier pre-registered in `02-RESEARCH-PARAMETERS.md` P6 (F6a–F6d) |
| A build with no key refuses **every** load, including valid ones | MEASURED | KERNEL | same check, second configuration. Fail-closed is asserted, not inferred from a failing test |
| Signature verification on the **loader thread** | **FALSIFIED** | KERNEL | shipped 2026-08-20 and wedged the loader on the first signed load; no log line, so the hang was inside verify. TMM overrides `malloc` globally. `CONTESTED-PREMISES.md` #10 |
| Signature verification runs in the deployed loader without hanging it | MEASURED | SELF | F6e passes on build `bf7f7002`: a signed program loads, `ls_sig:` logs the binding/sig/key it verified, and `status` answers immediately afterwards. Verification runs behind the prepare handoff, not on the loader thread |
| A signed program loads, arms and fires on a live TMM | MEASURED | SELF+KERNEL | `OK loaded slot=5`, `OK ARMED LIVE`, `fired=26`/`fired=15` on the two pods, records decoded (`tcp.c:3193 "ICMP unreachable received"`), entry bytes restored to nops after disarm |
| A tampered program body is refused | MEASURED | SELF | one flipped bit → `signature is valid but the program body does not match the hash it commits to` |
| A tampered signature is refused | MEASURED | SELF | one flipped bit → `signature is INVALID for these bytes and this key`. Distinct message from the body case, which is the point of separating them |
| An unsigned program is refused | MEASURED | SELF | the client refuses before sending, naming the missing `.sig` and how to produce it |
| `LS_SIG_ENFORCE` admits a bad program and says so | MEASURED | SELF | toggled on: startup logs `SIGNATURE ENFORCEMENT IS OFF`, and the tampered load logs `SIGNATURE CHECK FAILED (…) AND ADMITTED ANYWAY`. Toggled off: refused again |
| The loader's own statements about verification are true | MEASURED | SELF | build `92454510`, `env/scripts/bnk-test-signatures.sh` — 16 of 16 assertions. A sweep for the two known stale strings found **four**: the reply's `unverified=yes`, the "signature verified" line printed *before* verification ran, the startup banner announcing `accepts UNVERIFIED programs`, and two client docstrings. All replaced and verified absent from the shipped binary |
| The distinguishing refusal message is on the **log**, not the wire | MEASURED | SELF | deliberate: the reply is a generic refusal so a forger cannot use it as an oracle for which half of a forgery to fix. My first test asserted against the reply and recorded two failures that were the design working |
| A hook fires exactly once per request — **re-measured on this build** | MEASURED | SELF | `fired` 34 → 44 for exactly 10 requests. The suite's apparent 34-for-20 was my misreading: `fired` is **cumulative and is not reset by a fresh `load`** (`gen` increments, the counter does not) |
| Arming is audited | MEASURED | SELF+KERNEL | build `1c913003`, **11 of 11** in `env/scripts/bnk-test-audit.sh` plus **21 of 21** off-TMM in `make -C substrate check-audit`. One record per control-plane operation: op, slot, hook, program hash, build range, mode ceiling, expiry, and the verdict the caller received *verbatim*. F7g is now shown rather than argued — 10 of 10 round trips answered after records were emitted, on the thread whose allocator wedged signature verification two days earlier |
| …and an operation cannot escape the trail | MEASURED | SELF | a deliberately malformed 3-byte request — sent by opening the socket directly, because the client will not do it — is recorded as `op=MALFORMED`. The early-return paths were the ones most likely to leak |
| …and ARM is recorded as `op=ARM` | MEASURED | SELF | **was FALSIFIED on the first live run**: ARM and DISARM printed as `op_4099`/`op_4100`, so the one record a reader would look for did not name itself. No off-TMM assertion had asked, because the test built messages from the four ops in the product ABI enum — which is exactly the set already named |
| The audit record names a hook by symbol | **FALSIFIED** | — | an ARM record carries `hook=0x1451204`, an address. The client resolves the name against the per-build index before sending, so TMM never sees the symbol. Accurate and less useful than it looks; fixing it is a wire-format change belonging with the operator front-end (item 11) |
| …and the "who" is kernel-attested, not self-reported | MEASURED, off-TMM | KERNEL | `SO_PEERCRED` gives the pid, uid and gid the kernel recorded at `connect()`; the test asserts the recorded pid against `getpid()` over a socketpair. **This is attribution within a trust domain, not authentication across one** — everything in this container is uid 0, so uid distinguishes nothing |
| …and the record names the same build the arming gate compares | MEASURED, off-TMM | KERNEL | the GNU build ID is read from `/proc/self/exe`, not from `__DATE__`/`__TIME__`. A binary with no build-id note makes the test **fail** rather than skip: an unexercised ELF parse inside an audit trail is not a pass |
| The audit trail is tamper-evident | **NOT CLAIMED** | — | a sequence number makes a *deleted* record visible as a gap and does nothing about a rewritten one; a hash chain would not help, since anything able to rewrite the log can recompute it. Durability comes from the sink — stderr, which here is the container log stream collected off-box. The `LS_AUDIT_PATH` file sink is weaker on purpose |
| The audit trail identifies a person | **NOT CLAIMED** | — | `peer_pid` names a process. Under `kubectl exec` that process is spawned by an API call this code cannot see. Closing it needs a signed operator identity on the wire |
| A CVE is mitigated on live traffic | **NOT DEMONSTRATED** | — | the mechanism is proven; no advisory has been mitigated end to end. The BNK target is not reachable on this cluster |
| `alpn_guard` expresses a real fix | SHIPPED-UNVALIDATED | INDEPENDENT | reinstates the bounds check from commit `c806f1b2e8`; PREVAIL admits it. Never exercised against a live exploit |

## Reproducibility

| claim | tier | witness | anchor |
|---|---|---|---|
| A fresh clone reaches a clean check | MEASURED | SELF | 2026-08-20: clone into an empty directory, `./bootstrap.sh`, `make -C substrate check` → exit 0, **59 ok, 0 failures, 3 loud skips**. `REPRODUCING.md` |
| …and it did **not** before that date | **FALSIFIED** | SELF | the same command failed 4 targets on `fatal error: ubpf.h`, and `REPRODUCING.md` claimed it ran "on any Linux host with a C compiler, Python 3 and clang". uBPF and PREVAIL are vendored and gitignored — present on every machine this was developed on, absent on every machine it would be reproduced on |
| The uBPF include path was correct | **FALSIFIED** | SELF | `-I../ubpf/vm` for the *generated* `ubpf_config.h` worked only because this tree had once been configured in-source, leaving a second copy there. A fresh `cmake -S . -B build` writes only `build/vm`, so on a clean clone the path was wrong and the error read as a missing dependency |
| Exit 0 from `make check` means every check ran | **NO** | — | on aarch64 the load-bearing self-patch and live-arm proofs **skip**, and without PREVAIL built `check_shields` skips. Both say so in the output. A skipped verifier is not a passing verifier |
| The vendored revisions are what the docs say | MEASURED | INDEPENDENT | `substrate/check_vendor_pin.sh`, 6 assertions, reading the pins from `substrate/vendor.pins` — one definition, which `bootstrap.sh` also uses to create the trees the check verifies |
| This repo can reproduce the live results | **NO** | — | it builds bench harnesses. The live arm needs F5's TMM tree, the toolchain container, a build box and a cluster — `env/bnk-dev-runbook.md` |

## Borrowed code

| claim | tier | witness | anchor |
|---|---|---|---|
| uBPF is `iovisor/ubpf @ c900ed9f` plus one recorded patch | MEASURED | KERNEL | `substrate/check_vendor_pin.sh` — git revision compared, patch applied to it cleanly |
| PREVAIL is `vbpf/ebpf-verifier @ 06769f7b` (v0.2.5), unmodified | MEASURED | KERNEL | same check; no tracked file differs; the binary reports `v0.2.5` |
| The uBPF revision "cannot be stated" | **FALSIFIED** | — | `CONTESTED-PREMISES.md` #6 |
