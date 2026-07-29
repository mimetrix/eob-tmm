# P4 on TMM — a portable packet language on the embedded eBPF engine

### The `P4 → uBPF` path brings standard, portable packet programming to TMM's packet-granular stages — and positions the same program to offload to P4-capable hardware later. An exploratory front-end, not part of the base-tier proposal.

**Status:** Exploratory / design note · **Companions:** [`README.md`](README.md), the engine explainer (`explainers/programmable-dataplane-engine.html`), [`engine-hard-problems.md`](engine-hard-problems.md) (§2 the ctx/helper ABI — P4 lives on the tier deferred there), [`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md)
**Audience:** TMM core engineering, architecture, product

---

## 1. The idea in one line

The engine's substrate is **verified eBPF bytecode**, and P4 already compiles to it: `p4c` (the maintained P4 reference compiler, `p4lang/p4c`) ships a **uBPF backend**. So P4 becomes *one front-end* to the engine — alongside a bpftrace-style DSL and C — for authoring **packet-granular** programs that run verified and inline in TMM. The chain is `P4 → p4c-ubpf → eBPF bytecode → PREVAIL verify → sign → load`, identical to every other program the engine runs.

## 2. What it is — and what it is not

- **It is:** P4-authored **match/action logic running at TMM's packet-granular hooks** (L3/L4 ingress and the connection table, the TLS **record** layer, forwarding/steering), over the packet plus maps — the same model **Oko / p4rt-OVS** used in Open vSwitch.
- **It is not:** "TMM as a full P4 pipeline / switch." P4's *parse → match-action → deparse* model assumes it **owns the pipeline**; TMM already owns its parser and forwarding. `p4c-ubpf` compiles P4 *down onto* the "program-at-a-hook-over-a-packet" model — it does not turn TMM into a Tofino.
- **The distinction that matters is granularity, not switch-vs-proxy.** A switch is almost entirely per-packet/flow-forwarding (P4-native). A proxy like TMM spans **both** per-packet/flow stages (P4-friendly) **and** stream/L7/stateful stages (not P4's model). The hook catalog already covers that whole range — `tmm:l4:*`, `tmm:tls:record` (packet-granular) through `tmm:l7:*`, `tmm:bd:*` (stream/L7). P4 rides the first half.

## 3. Use cases where P4 makes sense

The "programmable switch" slice of what TMM does:

- **Novel / emerging encapsulations without a release** — a new overlay or tunnel header (Geneve options, VXLAN-GPE, **SRv6** segment lists, a custom L2/L3 encap). P4 exists precisely to declare a header format and how to process it; ship it as a loaded program, not a TMOS rev.
- **In-band Network Telemetry (INT)** — P4 is *the* language for INT; TMM inserts/extracts INT metadata and joins a telemetry fabric.
- **Packet-level steering / NAT / rewrite** — custom backend-selection hashes, header rewrites, ECN/DSCP marking, expressed in the language networking engineers already know.
- **Ingress pre-filter / scrubbing** — match packet patterns and drop/rate-limit *before* the expensive proxy path (the packet-granular sibling of the shield).

**Not** for: anything L7 / stream / stateful (HTTP semantics, TLS, cross-connection logic) — that is C or a DSL over an L7 `ctx`, not P4.

## 4. The strategic angle — P4 as a portable IR across software and silicon

P4 is the language of programmable **NICs / DPUs / FPGAs**. That makes it more than "another front-end": author once in P4 and the *same* program is positioned to

- **run in software today** — `p4c → uBPF`, inline in TMM (BIG-IP VE and the software path everywhere), and
- **offload to P4-capable hardware tomorrow** — a DPU / SmartNIC / FPGA on the appliance or BIG-IP Next path.

That plays directly into the VE / appliance / BNK **form-factor spectrum**: the same authored logic lands where each box can run it. "BIG-IP speaks P4" is a recognizable, standards-based differentiator for the programmable-data-plane audience — and it's honest, because it's scoped to the packet-granular stages P4 actually models.

## 5. P4 and the poll-loop budget — a stress test *and* a placement decision

A P4 program is not a base-tier one-liner. It **parses headers** (field loads), does **match-action table
lookups** (hash/map accesses), **rewrites** headers (memory writes), maybe recomputes checksums, and deparses.
That is real per-packet work — so P4 is exactly the kind of workload that **exercises the poll-loop time budget**
(`engine-hard-problems.md` §1), where a trivial `ctx → value` program never would. That cuts two useful ways:

- **A validation workload.** P4 gives the budget pass and the runtime deadline a *realistic, non-trivial* thing to
  prove themselves against — a genuine stress test, not a toy. If the time-safety machinery holds for P4-authored
  packet pipelines, it holds.
- **The budget pass becomes a placement decision.** Because P4 programs are heavier, some will *exceed* a hot
  per-packet hook's budget. The admission-time budget pass then does more than accept/reject — it **routes**: a P4
  program that fits the software budget runs inline in uBPF; one that doesn't is steered to a looser (cold/warm)
  hook, run only on the headroom of BIG-IP VE, **or offloaded to P4-capable hardware** (the portable-IR angle of
  §4). *The same static budget analysis that keeps the poll loop safe is what decides software-uBPF-vs-silicon
  placement for a P4 program.*

Honest guidance: **lightweight packet-granular P4** (steer, mark, INT insert, a small rewrite) is a natural fit
inline; **heavy multi-table pipelines** belong on VE headroom, cold hooks, or a DPU/FPGA — and the budget pass is
what tells you which, per hook, per box.

## 6. uBPF vs. WASM for this — not close, for this slice

For packet processing / P4 / hot-path, **uBPF**, clearly:

| | uBPF (eBPF) | WASM |
|---|---|---|
| **P4 toolchain** | `p4c` has a **uBPF backend** — the path exists | P4 → WASM is not a real, standard path |
| **Safety on the hot path** | **verified** — PREVAIL *proves* bounded + memory-safe → a static, WCET-adjacent bound | memory-safe, but **not** termination-proven; bounded by a **runtime fuel/gas kill** — a runtime kill, not a proof |
| **Weight / per-packet cost** | tiny, near-native, lean JIT | heavier runtime, larger memory, higher per-call cost |
| **Poll-loop fit** | budgetable *before load* (see `engine-hard-problems.md` §1) | only interruptible mid-run — the hard part in an un-preemptible loop |

The decisive one is verifiability: on a per-packet poll loop, *"we can prove it's bounded"* beats *"we kill it if it runs too long."*

**It is not either/or — it is the tiered model the engine already proposes:**
- **uBPF** → the verified, bounded, **packet-granular / data-plane** slice — **P4's natural home.**
- **WASM** → **rich, expressive L7 extensions** — complex application logic, heavy parsing, business rules where full-language expressiveness (Rust/Go/C++) earns its weight and a runtime kill is acceptable. P4 has nothing to say at L7 anyway.

## 7. What it requires (honest scoping — mostly Phase 2)

P4 on TMM is a front-end **unlocked by the richer tier, not free at the base tier:**

- The **base tier** (read-only `ctx`, no helpers) *cannot* express a P4 program that **rewrites headers** or keeps **register state**. P4 needs a `ctx` that **exposes packet bytes/headers**, **packet-write**, and **BPF maps** (stateful) — i.e. the **helper/map tier** that `engine-hard-problems.md` §2 deliberately defers. So P4 arrives with that tier, not before it.
- New work: wire the `p4c` uBPF backend into the toolchain, map P4's model onto TMM's **hook + `ctx`** model, and route its output through the existing verify → sign → load pipeline. `p4c` is maintained; the *mapping* is the new part.
- **Verification is inherited, not bypassed:** `p4c-ubpf` emits ordinary eBPF bytecode, so it clears PREVAIL like any other program (fail-closed) and rides the same signing, budget-pass, and lifecycle discipline. P4 does not get a shortcut around the safety machinery.

## 8. Precedent

- **DPDK `librte_bpf`** (mainline, maintained) — verified eBPF run inline on packets at a device's RX/TX. The living dataplane precedent.
- **eBPF-for-Windows** (Microsoft, production) — **uBPF + PREVAIL**, the exact two libraries this proposal reuses.
- **Oko / p4rt-OVS** (Orange Labs, ~2018–2020, now **dormant**) — `P4 → uBPF` as Open vSwitch **actions / stateful filters** with maps and a default verifier. Proves the `P4 → uBPF`-in-a-software-dataplane path end to end — but treat as **research prototype, not production**.

## 9. Status

Exploratory. A **future front-end the substrate enables**, gated behind the packet-write/map (helper) tier; **not part of the base-tier proposal.** Captured to keep the idea — and its honest scoping — on record.

---

> **IP note.** Novel method & claims are held in a separate invention disclosure (gitignored),
> per policy; this document is engineering rigor only.
