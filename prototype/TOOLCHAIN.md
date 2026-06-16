# Shield toolchain — bytecode → verify → load → run

End-to-end view of how a Live Shield goes from eBPF C source to a decision in the
data plane, as the prototype actually does it. This is the pipeline; for *running*
the demos see [`README.md`](README.md). Everything here is what the
[`minimm/Makefile`](minimm/Makefile), the demo scripts, and `minimm.c`'s
`ls_verify()` / `ls_ubpf_init()` really do — no aspirational steps.

## The pipeline

```
 ls_shield_ubpf.bpf.c                                    host owns the outcomes (§6.1)
   (eBPF C source)                                       shield only picks among them
        │                                                          ▲
        │ clang -O2 -target bpf                                    │
        ▼                                                          │
 ls_shield_ubpf.bpf.o ──► PREVAIL verify ──► ubpf_create +    ──► ubpf_exec(vm, &ctx,
   (eBPF bytecode, ELF)    (§9 gate,          ubpf_load_elf         sizeof ctx, &ret)
                            fail-closed)       (link: libubpf.a      ret: 0 PASS · 1 monitor
                                               + -lelf)                   · 2 enforce→DROP
```

Empty hook with no shield loaded = one predictable branch. Each stage below names
its tool, exact invocation, the artifact it produces, and the one prerequisite
that isn't obvious.

## Stage 1 — compile shield to eBPF bytecode

| | |
|---|---|
| **Tool** | `clang` with the BPF target |
| **Invocation** | `clang -O2 -target bpf $(BPF_SYS) -c ../shields/ls_shield_ubpf.bpf.c -o ../shields/ls_shield_ubpf.bpf.o` |
| **Artifact** | `*.bpf.o` — eBPF bytecode in an ELF object |
| **Prereq** | `clang` only (no `bpftool`, no kernel headers). |

The non-obvious bit is `BPF_SYS`. The BPF target still needs to resolve standard
headers; the Makefile sets:

```make
BPF_SYS ?= -idirafter /usr/include/$(shell uname -m)-linux-gnu -idirafter /usr/include
```

`-idirafter` puts these *after* the compiler's own includes (multiarch dir on
Debian/Ubuntu, plain `/usr/include` on el8) — harmless if a path is absent. Three
shields are compiled the same way: the good filter (`ls_shield_ubpf`), the
observe-mode tracepoint (`ls_trace_ubpf`), and the deliberately-unsafe one
(`ls_shield_bad`) that exists only to prove the verifier rejects it.

## Stage 2 — verify before load (§9 gate, fail-closed)

| | |
|---|---|
| **Tool** | PREVAIL (`prevail` CLI, the verifier from eBPF-for-Windows) |
| **Invocation** | `prevail -q --section .text ls_shield_ubpf.bpf.o` (run by `ls_verify()` via `execlp`) |
| **Artifact** | a verdict — exit status only; nonzero ⇒ refuse to load |
| **Prereq** | PREVAIL is C++23: needs a modern compiler (`gcc-toolset-13`) + modern Boost headers; el8's base gcc 8.5 / Boost 1.66 are too old. |

> **This gate is *safety*, not *security*.** PREVAIL proves the program is
> memory-safe and terminating — it will not crash or hang TMM. It proves *nothing*
> about whether the program is malicious within the rules, or was loaded by the
> wrong party. Signing, authorization tiers, load-path hardening, audit/revocation,
> and resource governance are the security layer *around* the VM — see
> [`../embedded-ebpf-substrate.md`](../embedded-ebpf-substrate.md) §6 and
> [`../big-ip-live-shield-design.md`](../big-ip-live-shield-design.md) §8.

In the prototype the gate is **env-wired** and the verifier runs as a **subprocess**:

```
LS_VERIFIER=/path/to/prevail LS_VERIFY_SECTION=.text  minimm-ubpf relay ...
```

`ls_verify()` (`minimm.c`) `execlp`'s `LS_VERIFIER` on the `.bpf.o`; a nonzero
verdict makes `ls_ubpf_init()` **refuse to load** (`shield REJECTED by verifier
(fail closed)`). If `LS_VERIFIER` is unset the gate is *skipped* — the hook is real,
but the verifier is the product's, not the prototype's. Build PREVAIL:

```bash
git clone --recurse-submodules https://github.com/vbpf/ebpf-verifier.git ../ebpf-verifier
cmake -S ../ebpf-verifier -B ../ebpf-verifier/build -Dprevail_ENABLE_TESTS=OFF
cmake --build ../ebpf-verifier/build --target prevail-cli   # -> ../ebpf-verifier/bin/prevail
```

## Stage 3 — link the embedded uBPF VM

| | |
|---|---|
| **Tool** | `cc` + `ar` (uBPF built straight from source — no cmake/externals) |
| **Invocation** | `make ubpf` → builds `libubpf.a`, then links `minimm-ubpf` |
| **Artifact** | `libubpf.a` and the `minimm-ubpf` / `minimm-trace` binaries |
| **Prereq** | `libelf` (uBPF's ELF loader); uBPF clone at `../ubpf` (`UBPF_DIR`). |

The Makefile builds the static lib without uBPF's cmake/externals:

```make
printf '#pragma once\n#define UBPF_HAS_ELF_H\n' > $(UBPF_DIR)/vm/ubpf_config.h
cd $(UBPF_DIR) && cc -c -O2 -fPIC -Ivm -Ivm/inc $(ls vm/*.c | grep -v '/test.c') \
  && ar rcs libubpf.a *.o
```

then links the host against it:

```make
cc $(CFLAGS) -DLS_UBPF -I$(UBPF_DIR)/vm/inc -I$(UBPF_DIR)/vm \
   -o minimm-ubpf minimm.c $(UBPF_LIB) -lelf $(LDFLAGS)
```

`-DLS_UBPF` selects the filter/enforce hook build; `-DLS_TRACE` selects the
observe-mode `minimm-trace` (same VM, same hook, return treated as telemetry).

## Stage 4 — load and run at the hook point

uBPF is a **library call**, not an injection technique. The host loads the
(verified) object and executes it inline at the designed-in hook:

```c
g_vm = ubpf_create();
ubpf_load_elf(g_vm, buf, n, &err);          // after ls_verify() passed
...
ubpf_exec(g_vm, &ctx, sizeof(ctx), &ret);   // at ls_request_eval_decision
// ret: 0 = PASS · 1 = match/monitor (pass) · 2 = match/enforce -> host returns LS_DROP
```

The **host owns the enumerated outcomes** (§6.1) — `LS_PASS` / `LS_DROP`; the shield
only chooses among them via its return value. uBPF has no native maps, so mode and
hit/enforce counters live in host memory that the host reads and the shield updates
through registered helpers.

## Prerequisite summary

| Track | Needs | Base image proven |
|---|---|---|
| Stages 1+3+4 (pure uBPF) | `gcc`, `clang`, `make`, `libelf`, `python3` | Rocky 8.10 — [`Containerfile`](Containerfile) |
| add Stage 2 (verify gate) | + `cmake`, `gcc-toolset-13`, modern Boost (1.84) headers | Rocky 8.10 — [`Containerfile.verify`](Containerfile.verify) |

The verify image is heavier *only* because PREVAIL is C++23; uBPF + minimm still
build with base gcc 8.5.

## Prototype → product mapping

| Stage | Prototype | Product (design §11/§9/§5.3) |
|---|---|---|
| Execute | uBPF **interpreter** (`ubpf_exec`), for portability | uBPF **JIT** — indirect call into native code, ~tens of ns; required on hot-path hooks |
| Verify | `prevail` CLI as a **subprocess**, env-wired (`LS_VERIFIER`) | verifier **embedded** as the designed-in load gate, fail-closed |
| Hook | one hook (`ls_request_eval_decision`), no `path_class` | hook-point **catalog** with per-build map + `path_class` (`hot`/`warm`/`cold`) |
| State | host memory counters in `/dev/shm` | **per-CPU** state on hot paths (no cache-line contention across core-pinned TMM) |

See [`../big-ip-live-shield-design.md`](../big-ip-live-shield-design.md) §9 (verify
gate), §11 (performance / `path_class`), and §5.3 (hook-point map).
