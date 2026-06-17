# Live Shield prototype

A runnable stand-in for the **Live Shield** design (`../big-ip-live-shield-design.md`) and
the broader **embedded-eBPF substrate** (`../embedded-ebpf-substrate.md`), built so the
mechanism can be exercised without real TMM source or TMM-expert time.

Two tracks:

| Track | Shield runtime | Deps | Proves |
|---|---|---|---|
| **1 — reference** | shield logic compiled into the host (plain C) | none (gcc) | the lifecycle: hook point → predicate → monitor/enforce → drop-before-crash, evidence counters, mode toggle |
| **2 — real model** | the shield as **eBPF bytecode run by an embedded userspace VM (uBPF)**, gated by the **PREVAIL** verifier; host calls the VM at the hook point and acts on the return | uBPF + PREVAIL | the actual TMM model (`design §3.1, §6.1, §9`): verified userspace eBPF reaching a **kernel-bypass** data plane — no kernel, no injection, no privileges; `filter` (enforce) **and** `observe` (tracepoint) modes |

> **Why embed uBPF rather than inject (bpftime)?** TMM bypasses the kernel and F5 owns
> TMM's source, so you *embed* the VM and call it at a designed-in hook point. The
> bpftime *injection* model was **evaluated and rejected** — its syscall interposition
> never reliably engaged, and the kernel forbids `bpf_override_return` on uprobes anyway.
> uBPF is the proven embeddable VM (the engine in Microsoft's eBPF-for-Windows, and under
> bpftime). See `design §2.3` / §3.1.

## What `minimm` is

`minimm` = "mini-TMM": a transparent TCP **bent-pipe relay** (client → minimm →
upstream) with a single-threaded epoll poll loop, an inline eval stage on the
client→upstream path, a designed-in hook point (`ls_request_eval_decision`), and a
deliberately vulnerable parser. It reproduces the *structural* properties of TMM the
design depends on — nothing more.

**Synthetic CVE:** frame wire format (big-endian) `[2B opcode][2B payload_len][payload]`.
`process_frame()` dispatches on `opcode` through a 4-entry handler table **with no bounds
check**; `opcode >= 4` indexes out of bounds and calls a wild pointer → the relay dies
(data plane down). The predicate is `opcode >= N_HANDLERS`; the shield drops such frames
before dispatch.

## Layout

```
prototype/
  minimm/
    minimm.c        bent-pipe relay; hook point builds: reference / uBPF-filter / uBPF-observe
    ls_shield.h     the shield ABI (ls_ctx, verdicts, shared map, hook-point decl)
    Makefile        make (reference) | make ubpf (minimm-ubpf + minimm-trace)
  shields/
    ls_shield_ubpf.bpf.c  the Live Shield as eBPF bytecode (filter / enforce)
    ls_trace_ubpf.bpf.c   an observe-mode tracepoint + flight-recorder trigger (telemetry, never drops)
    ls_shield_bad.bpf.c   a deliberately-unsafe shield (OOB read) the verifier must reject
  client.py         sends benign / attack / arbitrary-opcode frames
  demo.sh           Track 1 (reference shield)
  demo-ubpf.sh      Track 2 (embedded uBPF VM): enforce holds, monitor crashes, flight recorder (§3.1)
  demo-verify.sh    §9 gate: PREVAIL verifies the good shield, rejects the bad one
  Containerfile         Rocky 8.10, pure uBPF (clean: gcc + clang + libelf)
  Containerfile.verify  Rocky 8.10, uBPF + PREVAIL verify gate
  hook-point-map.json   illustrative per-build hook-point map (design §5.3)
  TOOLCHAIN.md          bytecode -> verify -> load -> run pipeline (tools/artifacts per stage)
  ../ubpf/            uBPF clone (the embedded VM); libubpf.a built by minimm/Makefile
  ../ebpf-verifier/   PREVAIL clone (the verifier); prevail-cli built separately
```

## Track 1 — run now, no dependencies

```bash
make -C minimm        # builds the reference-shield binary
./demo.sh
```
Expected — **monitor**: attack detected (`hits=1`) but not blocked, relay **segfaults**
(`design §7.1`); **enforce**: attack dropped (`enforced=1`), relay **survives**, benign
traffic still bends through.

## Track 2 — embedded uBPF VM

The shield is compiled to **eBPF bytecode** and executed by **uBPF embedded inside
minimm**: minimm calls the VM at the hook point and acts on the return. This is the TMM
model — the eBPF runs in a VM in the (kernel-bypassing) data-plane process itself.
For the full source → bytecode → verify → load → run pipeline (the exact tool and
artifact at each stage), see [`TOOLCHAIN.md`](TOOLCHAIN.md).

Prereq (the Makefile builds `libubpf.a` from this clone):
```bash
git clone --depth 1 https://github.com/iovisor/ubpf.git ../ubpf
```
Build + run locally:
```bash
make -C minimm ubpf      # libubpf.a + shields + minimm-ubpf (filter) + minimm-trace (observe)
./demo-ubpf.sh
```
Or in a container on the realistic base OS (**Rocky Linux 8.10** — just gcc + clang + libelf):
```bash
podman build -t eob-ubpf -f Containerfile .
podman run --rm eob-ubpf /work/prototype/demo-ubpf.sh    # Track 2
podman run --rm eob-ubpf /work/prototype/demo.sh         # Track 1
```
No `--privileged`, no caps, no kernel eBPF — entirely userspace.

At the hook point (`minimm.c`, `LS_UBPF`):
```c
ubpf_exec(g_vm, &ctx, sizeof(ctx), &ret);   // run the shield bytecode
// ret: 0=PASS, 1=match/monitor (pass), 2=match/enforce -> host returns LS_DROP
```
The host owns the enumerated outcomes (§6.1); the shield only chooses among them.

**Observe mode (tracepoint).** `minimm-trace` (built by `make ubpf`, `LS_TRACE`) runs the
same VM at the same hook but treats the return as *telemetry* (histogrammed into the shared
map) and **never** changes flow — eBPF observability reaching data-plane internals that
kernel `eob` can't see. Same substrate, different host use of the result.

**Flight recorder (observe-mode, substrate §3.1).** The same observe program also keeps a
**ring of recent frames** in the shared map and **arms a dump** (it ORs `LS_FR_TRIGGER` into
its return) when it sees the crash precondition. The host freezes and prints the run-up
*into* the failure at the hook — *before* the relay crashes (observe never blocks) — and
because the ring is shm-backed it **survives the crash** for post-mortem:
```bash
minimm-trace ctl flightrec    # dump the ring from shm, after the data plane is gone
```
This is the core-dump's blind spot: you get the frames leading up to the fault, not just the
wreckage. The `demo-ubpf.sh` flight-recorder section shows both the live dump and the
post-mortem read.

**Combined play (enforce + flight recorder).** The recorder isn't observe-only — arm it in the
enforce build with `LS_FLIGHTREC=1` and the *same* attack is **dropped** (relay survives) while
the run-up into the blocked attempt is **captured**: "blocked it *and* kept the forensics" (§3.1).
Because the recorder carries a steady-state cost (§3.1 / design §11), it's opt-in rather than
always-on. The `demo-ubpf.sh` combined-play section shows it — contrast it with the observe-only
run, which captures the run-up but then crashes.

### §9 verify-before-load gate (PREVAIL)

uBPF runs whatever bytecode it's given, so the §9 safety gate adds a **static verifier that
must pass before the VM loads a shield**. We use **PREVAIL** (`vbpf/ebpf-verifier`, the
verifier in eBPF-for-Windows). minimm's `ls_verify()` runs it on the shield object first and
**refuses to load on a nonzero verdict (fail closed)**.

Build PREVAIL (C++23 → modern compiler; clone next to `prototype/`):
```bash
git clone --recurse-submodules https://github.com/vbpf/ebpf-verifier.git ../ebpf-verifier
cmake -S ../ebpf-verifier -B ../ebpf-verifier/build -Dprevail_ENABLE_TESTS=OFF
cmake --build ../ebpf-verifier/build --target prevail-cli      # -> ../ebpf-verifier/bin/prevail
```
Run the gate demo:
```bash
./demo-verify.sh           # auto-finds ../ebpf-verifier/bin/prevail, or set LS_VERIFIER=
```
Expected:
```
GOOD shield: verifying... -> loaded (verified) -> enforce -> attack dropped, relay ALIVE
BAD  shield: verifying... -> shield REJECTED by verifier (fail closed) -> never loaded
```
The gate is env-wired: `LS_VERIFIER=<prevail> LS_VERIFY_SECTION=.text minimm-ubpf relay ...`.
In a container, `Containerfile.verify` builds uBPF + PREVAIL and presets `LS_VERIFIER`
(PREVAIL's C++23 needs `gcc-toolset-13` + modern Boost headers, so it's heavier than the
pure-uBPF `Containerfile`):
```bash
podman build -t eob-verify -f Containerfile.verify .
podman run --rm eob-verify /work/prototype/demo-verify.sh
```

## What is validated where

- **Track 1** — built and run: monitor-crashes / enforce-holds both confirmed.
- **Track 2 (uBPF)** — built and run: shield bytecode loads into uBPF and decides; enforce
  holds, monitor crashes; `minimm-trace` histograms opcodes in observe mode. Verified on
  the dev box **and** in the Rocky 8.10 container.
- **§9 gate (PREVAIL)** — built and run: good shield verified + enforced; unsafe shield
  rejected (fail closed) before load.

## Caveats / honest notes

- The **monitor** crash is exercised via an opcode that reliably faults; on a real system
  the crash class is the malformed-input path the shield guards.
- Locally the prototype uses uBPF's **interpreter** (`ubpf_exec`) for portability; on a
  perf-sensitive path you'd use uBPF's **JIT** (`design §11`).
- The bpftime *injection* approach was evaluated and rejected (above); its artifacts have
  been removed — only the "rejected, and why" note remains, in the design doc (`§2.3`).
- This is a mechanism prototype, not the design's full trust/lifecycle machinery (signing,
  SIRT validation, auto-retirement, HA config-sync, per-CPU telemetry). Those are
  `design §7–§9` and `substrate §6`.
```
