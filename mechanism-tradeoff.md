# Two mechanisms, one decision — a trade matrix

### The hooking mechanism is a fork, not a detail. Both paths share the same engine (uBPF + PREVAIL + the ctx-from-DWARF pipeline, all validated); they differ only in *how a program reaches a function*. That difference decides the hookable set, the poll-loop cost, the security-review surface, and whether the CVE pitch survives.

Grounded in the 2026-08-12/13 integration: measurements are marked **[measured]**, everything
else is **[estimate]** or a design fact. Scope: BNK / MBIP, whose mainline is **x86-64**
(the running pod is amd64; aarch64 is the DPU case).

---

## The two paths

**Path A — designed-in call sites.** F5 plants an explicit call into the VM at chosen functions,
in TMM source. Arming is one ordered store to a slot; no text is modified. **This is what runs
in the pod today** (39 lines in `http_psm.c`), validated end to end.

**Path B — patched function entries.** The compiler reserves a pad at every function entry
(`-fpatchable-function-entry`); arming rewrites the pad into a `call` to a trampoline. Hooks a
function *nobody edited*. **Trampoline and arming are validated in isolation on hardware; the
cross-core coordination (safe point) is not built.**

They are not mutually exclusive — see *The hybrid* below — but the matrix treats them as the
poles they are.

---

## The matrix

| Dimension | Path A — designed-in call sites | Path B — patched function entries |
|---|---|---|
| **What it can hook** | Only functions F5 planted a call site at — today the 41-point catalog | Any function surviving as an out-of-line symbol *with the pad* |
| **Hookable-set size (BNK)** | Whatever is planted (tens) | **48.9% of the shipped binary [measured]** — 82–97% inside the TMM tree, **0% in OpenSSL/crypto, dedup, the components** |
| **The CVE pitch** ("CVE lands, ship a signed shield, no window") | **Fails for a novel function** — no call site there → needs a source change + full TMM release | **Delivers it** — ship a signed program to fielded systems, no rebuild |
| **Latency to shield an uncovered function** | A full release cycle (source change, rebuild, requalify, ship) | A signed-shield push |
| **Poll-loop impact** | **None** — the call site is compiled in; hot path already reads a slot | **Cross-core coordination required on x86** — the safe point, or a membarrier-based live-patch. aarch64 is free |
| **Entry-padding cost** | **None — no flag needed** | **`-fpatchable-function-entry` image-wide: +0.476% `.text` [measured]** at 49% reach, ~+0.97% at full; i-cache/i-TLB cost **[unmeasured]** — paid by every customer whether or not a shield ever loads |
| **Live text modification** | No | Yes — W^X relaxation over real text, hugepage COW, code-integrity interaction; **cannot self-patch MAP_PRIVATE text [measured]**, so the memory manager must supply the mapping |
| **Security-review / TMA surface** | Lighter — no self-modifying code in a security appliance | Heavier — live self-modifying code is a red flag that must be justified hard |
| **Per-architecture** | Both, no safe point either | x86-64 owes coordination (BNK mainline); aarch64 free (`NOP`↔`B` in the concurrent-mod set) |
| **Built / validated today** | **Running in TMM, measured**: 10 ns JIT / 48 ns interpreter, +0.27% `.text` [measured] | Trampoline + arming validated in isolation on hardware; safe point **not built** |
| **Effort remaining** | Small — mostly the ordering discipline (item 0), already in `ls_vm.c` | The safe point is "among the largest" items and touches the one loop everything runs through; TMA-gated |
| **Arming-event risk** | Trivially safe (a store) | Rare crash at arm time if coordination is wrong — unacceptable to ship without the safe point |
| **Observability use case** (the tracepoint catalog) | **This IS the product** — planned points are the right answer | Overkill; not what the catalog needs |

---

## The axes that actually force the choice

Most rows above are consequences of two root differences:

**1 · Does F5 have to know the target in advance?** Path A can only shield what was anticipated;
Path B can shield what wasn't. For **observability and known-hotspot hardening**, anticipation is
fine — you plan where you want visibility. For **novel-CVE response**, anticipation is the whole
problem, and Path A collapses to "ship a normal patch." This is the single most decisive axis.

**2 · Is live text modified?** Everything expensive about Path B — the padding cost, the W^X
work, the safe point, the heavier TMA — flows from touching executable code while cores run it.
Path A pays none of it because it modifies no text. This is the axis that decides *cost and
review*, not *capability*.

Note they cut opposite ways: A wins on cost and review, B wins on capability. There is no
dominant path — which is why it is a decision rather than an optimisation.

---

## The uncomfortable finding for Path B

Even at full commitment, Path B's reach on BNK is **bounded at ~49% and the gap is exactly the
wrong half**: OpenSSL/`crypto` (TLS record and handshake — a prime CVE surface) is **0% padded
[measured]**, because it is a separately-built component that never saw the TMM build's flags.
Closing that is not a flag — it is getting other teams (and prebuilt-RPM producers) to rebuild.
So Path B does **not** by itself deliver "hook any function"; it delivers "hook any function in
the TMM tree, plus whatever components adopt the flag." That caveat belongs in the decision, not
after it.

The partial mitigation is real but coarse (`tmm-usdt-tracepoints.md` §2.1): a shield can sit on
the *TMM function that calls into* OpenSSL rather than inside it — the caller is in the 82–97%
bucket. That observes the call, not the interior state.

---

## The hybrid

The paths compose, and the likely honest answer is **A now, B later, scoped**:

- **Ship Path A** for the observability/tracepoint catalog and for shields at anticipated
  hot-spots. It runs today, costs +0.27% and no padding, and needs no safe point. It is a real
  deliverable for the observability half of the proposal on its own.
- **Build Path B** only if the product commits to novel-CVE response on arbitrary functions —
  and price the safe point (poll-loop rendezvous *vs* membarrier-based live-patch) and the
  padding cost before committing, since both are load-bearing and one touches the hot loop.

The hybrid's cost is that Path B's padding is image-wide: you cannot get B's capability on a
*subset* of functions without paying the padding on all of them. So "A plus B for a few hooks"
still carries B's whole build-time footprint.

---

## What would settle it — questions before commitment

1. **Is the target novel-CVE response, or observability + planned hardening?** If the latter,
   Path A is sufficient and B is unjustified cost. This is the product question, and it is not
   ours to answer.
2. **What is the padding's runtime cost at rate?** [unmeasured] — the i-cache/i-TLB half of §4.
   B's whole footprint case rests on it, and it needs a running TMM under load.
3. **Which coordination form for B?** Poll-loop rendezvous (touches the loop, simplest to prove)
   vs membarrier-based (leaves the loop alone, more parts). Price both before choosing.
4. **Is ~49% reach, with OpenSSL at 0%, acceptable for the CVE claim** — or does B also require a
   cross-component padding rollout to be worth building?

The engine is proven either way. This decision is only about how programs reach functions, and
the cost of each answer is now measured rather than assumed.
