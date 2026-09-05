# eob-tmm — a verified, build-decoupled programmability substrate for TMM

An embedded userspace eBPF engine inside F5 BIG-IP's data-plane microkernel (TMM), and the
portable programs — **live surfaces** — that run on it. A live surface attaches to a **running**
data plane, reads or acts on its internal state, and is **proven safe before it runs**. Written
once, a surface runs on **any build**; it is loaded and removed with **no rebuild and no restart**.

It is the class of technology that made the Linux kernel programmable (eBPF), brought inside TMM —
where iRules and WASM already changed traffic behavior at runtime, this reaches the layer they
can't: the data plane's own functions and internal state.

## What it does that iRules, WASM, and kernel eBPF cannot

| | today's options | live surfaces |
|---|---|---|
| **Where it attaches** | fixed events / curated hooks | **any function** in the data plane |
| **What it reads** | curated variables | **any internal field**, by name |
| **Changing it** | reconfigure, or rebuild | **load / unload live**, no restart |
| **Across builds** | — | **write once, runs on any build** (offsets resolved at load) |
| **Safety** | interpreter/runtime limits | **statically proven** before it runs, then **F5-signed** |

Kernel eBPF can *watch* the `tmm` binary from outside, but it traps into the kernel on every hit
(a run-to-completion poll loop can't afford it) and can't override a return — so it can never
*act*. An in-process engine is the only form that is both affordable per invocation and able to
take an outcome.

## The live-surface family

One engine hosts four kinds of surface. Each is portable bytecode over a generic register context;
each names the TMM fields it needs and is relocated to the running build's own type information at
load.

- **probe** — attach to an internal function no iRule can hook, read its internal state, count or
  sample. Sees what no tool exposes.
- **trace** — the same, but stream a record per event off-box through an egress ring.
- **debug** — ad-hoc introspection: read any named field of a live connection, re-point to a
  different field or function by loading a different program. *Dynamic tracing for the data plane.*
- **shield** — return a verdict the host applies (e.g. skip a vulnerable function's body): a
  surgical, reversible, vendor-signed mitigation for a live threat until the patched build ships.

## Status

*Tiers per [`GROUND_TRUTH.md`](GROUND_TRUTH.md); MEASURED = witnessed on a live TMM or the pinned
toolchain.*

- **Proven live (MEASURED).** On a running BIG-IP Next TMM, a surface is relocated against the
  binary's own type information, verified, signed, and **armed on live traffic with no restart** —
  it fires once per request, reads internal state, and is removed cleanly while traffic keeps
  flowing. The same bytecode relocates and runs across builds with different layouts.
- **Verified engine (MEASURED).** Every program is statically checked (memory-safe, bounded) by
  [PREVAIL](https://github.com/vbpf/ebpf-verifier) before it is signed; only F5-signed bytecode
  reaches the in-TMM JIT. The signature is the perimeter, not the verifier.
- **Armed-hook cost floor (MEASURED).** ~1484 cycles (~570 ns) per fire, dominated by the VM and a
  range-checked memory read; the attach mechanism itself is below measurement resolution.
- **Not yet.** A CVE mitigated end-to-end on live traffic; production-traffic hardening; and the
  threat-model review that gates the enforcement (shield) surface. Named plainly, not hidden.

## How it's built — two independent processes

The two never touch, and that separation is the point.

- **The TMM image** carries only build artifacts: the engine and the entry pads that make live
  attachment possible — and, since 2026-09-04, **no type information**. The shipped ELF holds
  0 bytes of `.BTF`; offsets are resolved at sign time instead. See
  **[`docs/TMM-BUILD.md`](docs/TMM-BUILD.md)** and its one-picture summary,
  **[`docs/pipeline.svg`](docs/pipeline.svg)**.
- **Bytecode** is authored, compiled, verified, and signed as a **completely independent process**,
  with its field offsets resolved and baked there, then loaded over a socket into a running TMM — see
  **[`docs/BYTECODE-BUILD.md`](docs/BYTECODE-BUILD.md)**. A new attach point or a new field to read
  is a new program in minutes, not a build.

This repo holds the substrate **sources that are compiled into TMM elsewhere**, the surface
bytecode, the design record, and the visual explainers. It is not the TMM source tree and not the
cluster; reproducing the live result needs both.

## How claims are governed

The output is meant to be *argued with*. Five binding rules:

1. **No cached file, no claim.** Every external statement cites a file in
   [`evidence/cache/`](evidence/cache/) with a SHA-256 ([`SOURCES.md`](SOURCES.md)); an
   unretrievable source is recorded as such, never paraphrased.
2. **Tier every own-system claim** — MEASURED · SHIPPED-UNVALIDATED · ROADMAP · IDEA · FALSIFIED —
   in [`GROUND_TRUTH.md`](GROUND_TRUTH.md), and track *who witnessed it* separately.
3. **Falsifier-first.** Open questions pre-register what would kill them
   ([`02-RESEARCH-PARAMETERS.md`](02-RESEARCH-PARAMETERS.md)).
4. **Being wrong is recorded, not tidied away** ([`CONTESTED-PREMISES.md`](CONTESTED-PREMISES.md)).
5. **Reproduce in the authoritative place before claiming** — the pinned toolchain, the build box,
   a stable pod. A fast convenient check is a hint, not a finding.

## Where to read

| Start here | |
|---|---|
| [`docs/TMM-BUILD.md`](docs/TMM-BUILD.md) | how the image and its build artifacts are made |
| [`docs/BYTECODE-BUILD.md`](docs/BYTECODE-BUILD.md) | how a surface is authored, verified, signed, and loaded |
| [`co-re-plan.md`](co-re-plan.md) | the build-decoupled architecture, the surface test matrix, and the build assumptions |
| [`substrate/`](substrate/) | the sources compiled into TMM (engine, trampoline, loader, relocator) and the surfaces in [`substrate/surfaces/`](substrate/surfaces/) |
| [`explainers/`](explainers/) | visual explainers, one job each, plus the product one-pager |

**The design record** — the reasoning behind the architecture, the hook-point catalog, the security
model, and the threat-model register — lives in the root design docs and is indexed by
[`DOC-STATUS.md`](DOC-STATUS.md), which marks each document's era so a reader knows whether a page is
current or predates the build.

---

*Nothing here is production TMM source. Patent and invention-disclosure artifacts are kept out of
this repo by policy.*
