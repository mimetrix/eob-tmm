# Two mechanisms, one decision — a trade matrix

### The hooking mechanism is a fork, not a detail. Both paths share the same engine (uBPF + PREVAIL + the ctx-from-DWARF pipeline, all validated); they differ only in *how a program reaches a function*. That difference decides the hookable set, the poll-loop cost, the security-review surface, and whether the CVE pitch survives.

**The mission is CVE shielding — that is where this started, and it comes first.** Observability
(the tracepoint catalog), steering and self-tuning are peer consumers of the same engine, but
they are **deferred until CVE shielding works**. So they carry no weight in the decision below;
anything that reads as "Path A is fine because it serves observability" is out of scope until the
CVE path is settled. The weighting is entirely: which path shields a live CVE.

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
| **Hookable-set size (BNK)** | Whatever is planted (tens) | **82–97% of the TMM core [measured]** — the part we own. Whole-binary is 48.9% only because other teams' builds (OpenSSL, dedup, components) have not adopted yet; each is an independent follow-on, not a wall |
| **The CVE pitch** ("CVE lands, ship a signed shield, no window") | Fails unless a call site was planted there → source change + full release | **Delivers it only if the function was padded.** Padded (TMM tree): signed-shield push, no rebuild. Unpadded (OpenSSL, components): needs a rebuild too — same as A |
| **Latency to shield an uncovered function** | A full release cycle (source change, rebuild, requalify, ship) | A signed-shield push |
| **Poll-loop impact** | **None** — the call site is compiled in; hot path already reads a slot | **Cross-core coordination required on x86** — the safe point, or a membarrier-based live-patch. aarch64 is free |
| **Entry-padding cost** | **None — no flag needed** | **`-fpatchable-function-entry` image-wide: +0.476% `.text` [measured]** at 49% reach, ~+0.97% at full; i-cache/i-TLB cost **[unmeasured]** — paid by every customer whether or not a shield ever loads |
| **Live text modification** | No | Yes — but **self-patch of private `r-xp` text via `/proc/self/mem` is proven [measured]** (the earlier "cannot" was a flawed readback test); the safe swap runs clean on real private `.text`. Remaining TMM-specifics: hugepage-backed text and the node's code-integrity policy |
| **Security-review / TMA surface** | Lighter — no self-modifying code in a security appliance | Heavier — live self-modifying code is a red flag that must be justified hard |
| **Per-architecture** | Both, no safe point either | x86-64 owes coordination (BNK mainline); aarch64 free (`NOP`↔`B` in the concurrent-mod set) |
| **Built / validated today** | **Running in TMM, measured**: 10 ns JIT / 48 ns interpreter, +0.27% `.text` [measured] | Trampoline + arming validated in isolation on hardware; safe point **not built** |
| **Effort remaining** | Small — mostly the ordering discipline (item 0), already in `ls_vm.c` | The safe point is "among the largest" items and touches the one loop everything runs through; TMA-gated |
| **Arming-event risk** | Trivially safe (a store) | Rare crash at arm time if coordination is wrong — unacceptable to ship without the safe point |
| **Against the CVE mission** | Live shields **only where a call site was pre-planted** — hardens a chosen risk surface, cannot reach a CVE outside it without a rebuild | Live shields **anywhere padded** — the whole TMM tree, not OpenSSL. The mission path, bounded by reach |
| **Observability (DEFERRED)** | Would be the right mechanism for the tracepoint catalog — but tracepoints come *after* CVE shielding works, so this row does not weigh in the decision | Overkill for the catalog |

---

## The axes that actually force the choice

**Anticipation is not one of them — both paths anticipate, and hanging the decision on it is a
non sequitur.** Path A plants a call site at chosen functions; Path B plants a pad at *every*
function via `-fpatchable-function-entry`. The pad is itself a build-time plan. Neither can hook
a function that was not prepared when the binary was built — which is exactly why Path B's reach
is bounded at 49% and OpenSSL, unpadded, is unhookable by either path without a rebuild. "Hook
any function nobody planned for" overstates it: B hooks any function that was *padded*.

What actually differs is the **granularity of the build-time preparation**, and it drives
everything:

**1 · Per-function vs per-build preparation.** Path A prepares *selectively* — someone places N
call sites at functions they chose. Path B prepares *by the compiler flag*, which pads **every**
function in **every build that uses it** — no one picks functions, but each *build* decides. The
flag is not selective; the coverage is. TMM's binary is statically assembled from many
separately-compiled pieces, and only the TMM build turns the flag on: **82–97% of the TMM tree
is padded, 0% of OpenSSL/dedup/the components, because those are other builds** (three arrive as
prebuilt RPMs). So the 49% is not a limit on the flag or the mechanism — it is *how much of the
shipped binary was compiled by a flagged build*. Closing the OpenSSL gap is not runtime work; it
is getting another *build* to turn the flag on.

**2 · Is live text modified?** Everything expensive about Path B beyond the padding — the W^X
work, the safe point, the heavier TMA — flows from rewriting executable bytes while cores run
them. Path A pays none of it because a call site is ordinary compiled code. This axis decides
*cost and review*; axis 1 decides *reach and footprint*.

Where B genuinely beats A, stated precisely: for a novel CVE **in an already-padded function**,
B ships a signed shield with no rebuild, where A needs a release to add the call site. That is a
real and valuable window — but it is bounded by axis 1, not unbounded.

## Reach is per-component adoption, not a wall — and the core is ours

**First, one fact that makes this simpler than it sounds: it is all one binary.** OpenSSL, the
F5 crypto component, dedup and the rest are **statically linked into the single TMM executable**
— verified: ~2,000 OpenSSL functions (`X509_`, `EVP_`, `ASN1_`, …) are defined right inside
`tmm64`, not loaded as separate `.so` files, not separate processes. At runtime it is all one
TMM, in one address space. "Separate" means separate *build*, not separate *program*. So there
is no cross-process problem to solve: once a contributing build turns the flag on, its functions
get the same entry gap and the **same hooking machinery reaches them with nothing new to build**.
The federated rollout is purely "each build flips the flag," not "shield a different program."


The 48.9%-of-the-whole-binary number mixes two scopes that should stay separate. TMM's binary is
built by several teams: the **TMM core** (ours), OpenSSL, dedup, and the rest, each a separate
development. The mechanism is adopted **per build**, so:

- **On the TMM core — the part we own — reach is essentially complete: 82–97% [measured].** That
  is the deliverable, and Path B covers it.
- **OpenSSL and the other components are independent tracks.** Each adopts the same mechanism on
  its own schedule. Their 0% today is "they have not adopted yet," not "the approach cannot reach
  them." We do not control those builds and are not gated on them.

So full product coverage is a **federated rollout** — component by component, each team
independent, the TMM core first. That is a cleaner story than a single monolithic reach number:
we prove it on the core, and every other component is a well-defined follow-on that copies the
pattern.

**The one honest caveat, and it is about the customer, not us:** a CVE in a component that has
not adopted yet cannot be live-shielded until that component's build comes on board. Until then,
such a CVE still needs a normal patch. So the "no-window" property grows as components adopt; it
is not all-or-nothing, and it is not blocked on the TMM core team.

The coarse stopgap while a component is unadopted (`tmm-usdt-tracepoints.md` §2.1): a shield can
sit on the *TMM-core function that calls into* that component rather than inside it — the caller
is on our side, in the 82–97%. It sees the call, not the component's internal state.

## The hybrid## The hybrid — and why it is not a 50/50

For the **CVE mission**, Path B is the only path that delivers live shielding of an
unrestricted-but-padded set; Path A shields only where a call site was pre-planted. So the
honest shape is not "pick one" but **B is the mission, A is a floor**:

- **Path A is already banked** — it runs today, costs +0.27% and no padding, needs no safe
  point, and gives live shields at pre-selected risk surfaces (the logging path, parsers,
  wherever F5 plants points) plus the whole observability catalog. It is a real capability, but
  as a *CVE* answer it only covers what was pre-planted.
- **Path B is what the mission actually asked for** — and the decision is whether its reach
  (49% today, OpenSSL at 0%) and its cost (the safe point, image-wide padding, a heavier TMA)
  are worth it, and whether the OpenSSL gap must be closed by a cross-component padding rollout
  before the CVE claim holds.

The catch that keeps this from being free: the flag is **all-or-nothing per build**. It pads
every function in a build that uses it, so you cannot pad "just the CVE-prone functions" in the
TMM build — turning the flag on pads the whole TMM tree, and turning it on for OpenSSL means
rebuilding OpenSSL with it. So "keep A, add B for a handful of functions" still carries the full
padding footprint of every build you flag, even when the *hooking* is selective.

## What would settle it — questions before commitment

1. **Is live shielding of an arbitrary (padded) function actually required, or is
   pre-planted-hotspot shielding enough for the CVE mission?** If a small set of known risk
   surfaces covers the real exposure, Path A's pre-planted shields may suffice and B's cost is
   unjustified. If the mission is "any CVE, anywhere, no window," only B delivers it — bounded by
   reach. This is the product's call, weighted by the CVE goal it started from.
2. **What is the padding's runtime cost at rate?** [unmeasured] — the i-cache/i-TLB half of §4.
   B's whole footprint case rests on it, and it needs a running TMM under load.
3. **Which coordination form for B?** Poll-loop rendezvous (touches the loop, simplest to prove)
   vs membarrier-based (leaves the loop alone, more parts). Price both before choosing.
4. **Is ~49% reach, with OpenSSL at 0%, acceptable for the CVE claim** — or does B also require a
   cross-component padding rollout to be worth building?

The engine is proven either way. This decision is only about how programs reach functions, and
the cost of each answer is now measured rather than assumed.
