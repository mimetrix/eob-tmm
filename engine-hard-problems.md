# Embedded eBPF Engine — Hard Problems & Engineering Register

### The problems the explainers gloss — real-time, interface & scope, distributed state, security, certification, operations. What building this entails, surfaced up front: what's day-one vs. deferred, and the honest mitigations

**Status:** Proposal / engineering rigor · **Companions:** [`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) (the substrate + security model), [`big-ip-live-surface-design.md`](big-ip-live-surface-design.md) (lifecycle, signing, OSS posture), [`data-plane-egress-primitives.md`](data-plane-egress-primitives.md) (the SPSC egress ring), `development-scope.md` (what F5 actually builds), `explainers/cve-shield-walkthrough.html` (the worked example)
**Audience:** TMM core engineering, architecture, F5 SIRT / security review, product & certification

---

The pitch is "verified ⇒ safe, stock PREVAIL, no helpers." That is true as far as it goes, and it
is the *floor* — but the hard parts of *building* it span several places the explainers understate:
real-time behavior, interface and scope, shared state, the trust surface, and productization —
**engineering as much as security.** This is the register, surfaced up front rather than waiting for
a review to reveal it, with where each problem lands. **None is a show-stopper** — each has a known
mitigation and a day-one/deferred path. They are the work to do.

> **This design is not self-certifying.** Everything here is the engineering input to a **formal
> Threat Model Analysis (TMA)** by F5 security — a **gating prerequisite** before implementation,
> not a formality. The verifier/JIT-in-the-data-plane surface (§4) in particular must be
> threat-modeled and signed off. Read this register as *what to bring to that review*, not a
> substitute for it.

## 1. Termination is not WCET

**The claim to retire:** "PREVAIL proves the program is bounded, so it can't hang the poll loop."

PREVAIL proves **halting** — it bounds loop iterations via abstract interpretation, so it
*handles* loops (unlike the original kernel verifier's unroll-or-reject rule) and guarantees the
program terminates. That is safety + termination. It is **not** a **worst-case execution time
(WCET)** — the longest wall-clock time the program can actually take on the hardware.
"Halts in a finite number of steps" says nothing about fitting the budget at the hook it runs on, and even
a static **instruction-count** bound is not WCET (memory stalls, JIT variance, cache effects all
dominate).

And the resource being protected is unforgiving. TMM's poll loop is **single-threaded,
un-preemptible, run-to-completion** — there is no OS underneath to preempt an overrunning hook.
Every hook borrows cycles from the *same* loop, so a hook that cannot be preempted must be
*provably short*, and the budget is a **scheduler concern**: one misjudged hook starves every flow
on that core.

**Day-one mitigations — and note: no helpers, no verifier change.** Time-safety is enforced
*around* the verifier, not inside it: PREVAIL's job is unchanged, and nothing here needs a new
helper (helpers add capability, not time-safety — a helper call only adds cost). The work is
**two layers** — a static **post-verifier step** at admission (free at runtime) and a live
**runtime guardian** (small cost) — because *how many* instructions a program runs is provable
ahead of time, but *how long* they take is not.

- **A post-verifier budget pass — work to be done.** After PREVAIL clears a program (safety +
  termination), a load-time pass — running out-of-band with verification, never in TMM — bounds
  the program's cost and gates on the hook's budget:
  1. The program is already verified, so its control-flow graph is finite and every loop carries a
     proven iteration bound — which makes a **longest-path instruction count** over the CFG
     computable (an instruction-count bound rather than a time bound, tractable precisely because unbounded code was already rejected).
     PREVAIL's loop bounds are *reused* here, not recomputed.
  2. Map that count to a conservative **cycle estimate** via a per-target cost model (a per-opcode
     cycle cost, with loads and stores costed above register operations) and compare to the hook's
     **budget** — a cycle allowance
     per hook and path class. **The budget is per *invocation*, and what makes an invocation affordable is
     its rate**: cost-per-invocation × invocations-per-unit-of-work must fit the loop's headroom for
     that unit of work. `path_class` *is* the rate class — `hot` fires per packet, `warm` per
     connection or per request, `cold` per exceptional event. The same program is therefore noise
     against a request measured in microseconds, a measurable fraction of a packet measured in
     hundreds of nanoseconds, and a problem if it was budgeted per request and turns out to fire per
     packet; §1.1 sets out the three rate tiers and what is affordable at each. (The last case is
     also the adversarial one in §5: an attacker changes a hook's *rate* without touching a line of
     code.)
  3. Over budget → **reject, fail closed.**
  The pass, the per-hook budget table, and the cost model are **new build work** — a stage added
  to the load pipeline (`author → clang → PREVAIL → budget pass → sign → load`), F5-owned.
- **A runtime guard — also new work, and irreducible.** A static instruction count
  is *not* wall-clock time (cache, memory stalls, JIT variance) — bounding *how many* instructions
  run cannot bound *how long* they take. So something must stop a slow run from stalling the poll
  loop as it executes — bounded-cost preemption for a loop with no OS to preempt it. *Which* mechanism
  is the trilemma below, not a settled matter. This layer has a small runtime cost and **cannot be moved to admission time.**
  Runtime/JIT engineering, not verifier or helper.
- **And the trilemma.** With **no preemption**, three
  mechanisms could enforce a time bound, and each costs something claimed elsewhere. **Fuel** (a
  counter at loop back-edges) is cheap and deterministic — but uBPF's own API documents that the
  instruction limit *"has no effect on JIT'd programs"* (`ubpf.h`, on
  `ubpf_set_instruction_limit`), so fuel means **patching uBPF's JIT**, which costs the
  "reused (uBPF with an F5 patch; see substrate/ubpf-patches/)" claim on one of the three reused components (uBPF now with an F5 patch). **Wall-clock** reads a clock at
  back-edges — but on aarch64 the architectural generic timer (`CNTFRQ_EL0`) ticks at tens of MHz,
  a granularity of tens of nanoseconds, against a hot hook's budget of tens of nanoseconds, so it is
  **not measurable at the granularity that matters** on that architecture. **Signals/timers** cost a
  syscall per invocation plus delivery jitter — unusable in this loop. So the position is that
  **fuel is the mechanism, not the optional extra**, and the wall-clock deadline is *reporting*
  rather than enforcement (earlier drafts of this register had that backwards). The choice — give up
  the run-to-completion loop, the unmodified uBPF, or enforcement on hot hooks — belongs before
  implementation rather than during it. The available answer is to fork uBPF's JIT for back-edge
  fuel, own it, and upstream it. One known corner: uBPF's instruction limit *does* work in the
  **interpreter** — only the JIT ignores it — so an interpreter-only high-assurance build (§4) has
  enforceable fuel with no fork.
- **The budget pass is also a placement decision, not just a gate.** Once a program's cost is
  estimated at admission, "over budget" need not mean "rejected outright" — it can mean *not here*.
  The same analysis that protects the poll loop can **route**: a program that fits runs inline at
  the hot hook it asked for; one that doesn't can be admitted at a looser cold/warm hook, admitted
  only where there is headroom (a Virtual Edition deployment rather than a loaded appliance), or
  declined in favour of doing that work somewhere else entirely — including capable hardware, where
  an offload path exists. So the pass has two possible outputs: a reject/accept boolean, or a cost
  estimate that also says *where* a given program belongs.
- **`path_class` is an assumption an adversary can break.** A hook's rate class is a claim about code
  structure, not about traffic. An attacker who can drive the malformed input that reaches a `cold`
  error branch turns it into the hottest path on the box — same program, same hook, a rate class it was
  never budgeted for. So for anything reachable from unauthenticated input, read `path_class` as
  **structure ∧ adversarial reachability**, and treat it as `hot` regardless of where it sits in the
  code. This is why the runtime guard is gating for attacker-reachable hooks rather than staged.
- **Interpreter mode** for the most sensitive builds makes per-instruction cost predictable (and
  see §4 — it also shrinks the native-code surface).

**And the budgets are measurable rather than guessed.** Setting a per-hook budget, and catching one at
risk, is itself an *observability* task, and it is what a few **designed-in USDTs** (user
statically-defined tracepoints) would expose: per-iteration poll-loop duration (`tmm:rt:poll_iter`),
per-hook execution cost (`tmm:sched:hook_cost`), and a stall/overrun tripwire (`tmm:rt:poll_stall`) —
and note that the middle one is the measurement every budget in this document is currently an
*assumption* about. An iteration's time decomposition exists only inside the poll loop, because from
outside it there is no iteration boundary to measure against, which is why the hook is what tells you
what the hook costs ([`tmm-usdt-tracepoints.md`](tmm-usdt-tracepoints.md) §9.2). The engine ends up
**instrumenting the loop it runs in** — the same surface that makes this problem tractable is the
observability capability the engine exists to provide.

## 1.1 What is affordable per *packet*, and which per-packet work needs this mechanism

**The claim to retire:** "TMM's unit of work is a flow or a request, measured in microseconds, so a hook
costing tens of nanoseconds is noise."

That sentence is **carrying more weight than it can.** It is the argument for why bytecode fits a proxy
where it did not fit a packet forwarder, and for that it holds. But it justifies cost against the
*per-request* budget while this proposal claims its differentiating value in **pre-L7 CVE classes —
fragment reassembly, TCP option and state handling, TLS record parsing, protocol framers** (design §2.1, §2.2).
Those fault **per packet or per record, before any request exists**. So the affordability argument and
the value argument are currently made about two different budgets: the cheap case is described and the
valuable case is not costed.

**Three tiers, not two.** The forwarder/proxy dichotomy is too coarse for our own purposes, because TMM
contains all three of these:

| Rate | Budget available per invocation | A hook costing tens of ns is | Verdict |
|---|---|---|---|
| **Per connection / per request** (`warm`) | microseconds — the proxy is doing TCP, TLS and L7 work | noise | the easy case, and where the cheapest wins are |
| **Per packet inside the proxy path** (`hot`) — TCP reassembly, TLS records, L7 framing | hundreds of nanoseconds; a proxy's packet already costs far more than a forwarder's | a measurable fraction | **available with measurement and explicit sign-off** — not free, not excluded |
| **Per packet on a pure fast path** — FastL4, offload escalation, simple forwarding | tens of nanoseconds | a large fraction | **concede this one.** Here the objection that sank bytecode in packet forwarders applies to us too |

Stating the middle tier is the point. It is where the flagship CVE classes live, and collapsing it into
either neighbour is what produced the contradiction: fold it upward and per-packet work looks free, fold
it downward and we have argued our own differentiator out of scope.

**Which per-packet work needs this mechanism.** Some of it is not reachable any other way, which is
why it cannot simply be deferred:

- **Pre-connection faults.** A fragment-reassembly or TCP-state crash happens before a connection
  exists, so there is no per-request boundary to hook. iRules cannot reach these either — that is the design's §2.1 hole this mechanism exists to fill.
- **Per-record, not per-request.** A TLS record-layer parse fault fires per record; records neither
  align with nor nest inside requests.
- **Connectionless protocols.** DNS over UDP and QUIC datagrams are per-packet by construction, and DNS
  is the canonical unauthenticated amplification surface.
- **Sub-request framing.** An HTTP/2 frame hook is finer-grained than a request by an order of magnitude.
- **Distributions that cannot be reconstructed later.** Packet-size and inter-arrival histograms are
  per-packet facts; a per-request summary has already destroyed them.

**Four levers make per-packet tractable, and they support different claims:**

1. **Condition-scoped placement** — hook the exceptional branch (fragment present, record-parse error)
   rather than the common path. This reduces **steady-state** cost close to zero and **does not reduce
   the worst case**, because adversarial reachability means an attacker makes that branch the common
   path (§1, §5). Claim it as a steady-state argument only; anyone who claims it as a bound is wrong.
2. **Burst-capable invocation** — TMM already batches on receive, so a burst invocation form amortises
   per-invocation overhead across *K* packets and lets the budget pass reason per burst. This is the
   mechanism per-packet enforcement rests on, and §5 files it as a concern rather than as the enabling
   mechanism it is.
3. **Sampling divisor** — applies to observability, not to enforcement. You cannot block one in N
   instances of an exploit.
4. **Time-boxing, which applies only to mitigation** — a CVE shield is armed for an exposure window, not
   forever. **A throughput cost bounded by that window is a different trade from the same cost
   permanently.** It does not transfer to telemetry, which is by nature always-on.

**What each of these rests on.** Every line below is conditional on measurement nobody has taken:

- **Per-packet observability with a sampling divisor** — the mechanism is understood and the cost is
  adjustable downward by construction.
- **Per-packet enforcement on an exceptional branch, time-boxed** — where the flagship CVEs sit, and
  conditional on the back-edge fuel guard existing (§1), since an unbudgeted program on an
  attacker-driven branch is the worst case in this register.
- **Per-packet enforcement on the common path at line rate** — not established without the burst form.
- **Anything on a FastL4 or fully offloaded path** — out of reach; it never enters TMM software
  (design §10).

**And this is where the second measurement comes from.** An earlier version of the measurement plan asked
only for the **always-on cost of the pads with nothing armed** — the right first number, but it says
nothing about **an armed hook on a per-packet path**, which is what decides whether the middle tier
above is available. It reuses the same build and rig with one hook live, so the flag measurement is
specified as two numbers rather than one: the idle cost, then the armed cost at rate
(`design-review-findings.md` §4).

## 2. The context / helper / program-type ABI is the actual project

**The claim to retire:** "the base tier is a trivial pure function of `ctx`."

The VM is the small part. The work is **interface design**: TMM's **`ctx`** (what a program sees —
which fields of the flow, the buffer, the profile), the **verified helper surface** (map access,
connection-table lookup, pool select, header rewrite), and the **map model**. For a designed-in
USDT, that `ctx` is a *permanent, versioned* interface — ship it in the per-build hook-point map
plus BTF (BPF Type Format, the compiler-emitted type description) and you carry it forever. For a function-boundary probe, the `ctx` is the function's typed
arguments — **build-specific, regenerated and re-validated every build** from the signed hook
map; more reach, a looser contract. Getting either wrong is expensive. Even the base-tier
read-only `ctx` is real design work.

**The good news, stated precisely:** this work is exactly the input PREVAIL is designed to
consume. The verifier task is **"write the program-type descriptor"** (`ctx` layout + memory
regions + helper prototypes), **not "modify the verifier."** So the *no-verifier-fork* claim
survives — but the effort estimate in the explainers does not.

**With one correction to how "write the descriptor" is usually pictured, and it is not cosmetic.**
PREVAIL's context descriptor is four integers — `size`, `data`, `end`, `meta`
(`ebpf_ctx_descriptor_t`, `src/spec/ebpf_base.h`) — and there is no field
in it for *this region is read-only*. The verifier's own source is explicit that it rejects only
context writes that might overlap a pointer slot, and that "real programs do write" the scalar fields.
Our `ctx` has no pointer slots, so the consequence is blunt: **a verified program can write every byte
of its `ctx`.** If the `ctx` handed to it were the live argument frame, then a signed, verified,
nominally read-only observe-mode program would be an **argument-injection primitive into live TMM code
paths — delivered by the safety mechanism.** So the rule belongs in the ABI rather than in a
reviewer's memory:

> The host builds the `ctx` as a **per-core scratch copy**, hands the program the copy, and
> **discards it on fall-through**. Never a live view of TMM state. The copy is the cost, and the copy
> is the thing to measure.

There is also no `--program-type` flag to point at a descriptor with: PREVAIL deduces the type from
the ELF (Executable and Linkable Format) **section-name prefix** against a compiled-in table, falling
back to `socket_filter`. So "no
verifier fork" is true under one specific choice — ride the existing **`tracing`** type and emit into
a matching section — and false under the other, where registering a named TMM type is a patch set with
a per-release rebase cost. Day one takes the first. Say which one is meant, because the two have very
different maintenance stories and the phrase "stock PREVAIL" hides the difference.

**Measured 2026-08-14, and it redirects this item.** The framing "a function-boundary probe's `ctx`
is the function's typed arguments" is true and, taken literally, nearly useless. Sampling 388
functions from the build's own hookable set:

| parameter kind | share | what DWARF gives us |
|---|---|---|
| scalar, including resolved typedefs (`UINT32`, `BOOL`, `hud_msg_t`) | ~25% | the value; pass it straight through |
| **typed pointer** | **~61%** | **the pointee's full layout** — enough to generate a dereference |
| `void *`, and typedefs to it (`bwc_policy_t`) | ~14% | nothing; the type information is genuinely absent |

**Functions whose parameters are *all* scalars: 2 of 388.** So a generator that emits a struct of the
formal parameters produces something a program cannot use, for essentially every hook — eBPF cannot
chase an unbounded pointer and PREVAIL will not admit a program that tries.

The worked example shows what is actually required. `http_psm_profile_name_lookup` has the signature
`_Bool(enum errdefs_key, void *, errdefs_append, void *)`, and its hand-written `ctx` carries four
fields of which **one** is a formal parameter; the rest are a walked pointer chain, a dereference,
and a measured length.

**So the deliverable is codegen, not a struct.** From DWARF, emit the trampoline's **ctx-builder in
host C**: dereference typed pointers, flatten the fields the hook needs, hand the program scalars.
The program stays a bounded predicate over flat memory, which is the canonical case PREVAIL already
proves — so this reaches **stock verifier, no fork**, by moving the pointer-chasing to the host
rather than by extending the verifier to permit it.

That puts roughly **86%** of parameters within mechanical reach and leaves the `void *` residue as
the honest hard part: those need per-hook human knowledge of what the pointer points to, exactly as
the worked example did. **Which hooks are worth that effort is a curation question, not a tooling
one** — and it is the same question the USDT catalog answers for the anticipated surface.

**Put concretely, the designed-in half of that interface *is* a catalog of well-defined USDTs** — one per hook,
each a curated `ctx` — and the other half is the per-build typed-argument map that **function-boundary probes**
read. Together they are the ceiling on what the engine can observe or enforce: the USDT catalog bounds the
*anticipated* surface; function-boundary probes extend reach to any function that survived the build as its own out-of-line body, was emitted by a build that reserved the pad (§2.1 of `tmm-usdt-tracepoints.md` — about half the shipped binary comes from component builds that did not), and whose arguments expose the
fault. Getting both right *is* the project.

**Day-one vs. deferred:**

- **Day-one:** a minimal, **read-only `ctx` per hook** (curated fields, no helpers) + its
  program-type descriptor for PREVAIL, plus the auto-generated typed-arg `ctx` for
  function-boundary probes (from the signed per-build hook map). Genuine work — but **not a blank page**: TMM's code already holds the state
  these USDTs expose (the connection table, the TLS record layer, the L7 parser state, the `bd`/plugin internals,
  the poll-loop counters), so the first USDTs are a *curated window onto structures that already exist* and the
  surface can begin the day the engine lands.
- **Deferred, per use case:** every helper is a new ABI to secure, a new verifier prototype, and
  a new soundness surface. Add helpers only when a use case forces it; `ctx`-first, helpers-later.

## 3. Maps under CMP and connection mirroring

**The claim to retire:** "maps work like they do in Linux."

TMM is not one kernel — it is **N core-pinned instances per box** (CMP, clustered
multiprocessing), plus **connection mirroring to an HA (high-availability) peer**. So map/state semantics (per-CPU vs. shared, and reconciliation with
TMM's *existing* flow-state sync) are a harder concurrency problem than the Linux single-kernel
case, not an easier one.

**Day-one vs. deferred:**

- **With the helper tier (deferred): per-CPU maps only**, no cross-TMM sharing — the base tier
  has no map access at all. Per-CPU matches TMM's core-pinned model — no locking — and aligns
  with the SPSC-per-core egress rings already specified in
  [`data-plane-egress-primitives.md`](data-plane-egress-primitives.md).
- **Failover state rides TMM's existing mirroring channel**, not a bolted-on eBPF-map sync.
  Do not reinvent HA state replication inside the map layer.
- **Deferred / governed:** shared *writable* maps across TMMs need an explicit concurrency +
  reconciliation model. Read-mostly *config* maps (published from the control plane, in the
  read-copy-update style) are the easier first step if sharing is ever required.

**The trap:** treating eBPF maps as if TMM were a single Linux kernel. It is N kernels with their
own state-sync fabric; the map model must defer to that fabric, not compete with it.

## 3.1 More than one program armed at once

**The claim to retire:** "a shield is a bounded predicate at one hook, so N shields are just N
bounded predicates."

**And before the problems, the answer in one table, because "are simultaneous handlers supported?" has
six different meanings and they do not all get the same answer:**

| What is being asked | Supported? | Mechanism, or why not |
|---|---|---|
| Several **different hooks** armed at once, one program each | **Yes** | Up to `SHIELD_MAX_SHIELDS` concurrently loaded (64 in the candidate ABI). Bounded not by that count but by a **global armed-cost ceiling**, because a flow pays the *sum* of the hooks it traverses, not the maximum. |
| **The same program on every TMM instance** at once | **Yes, and unavoidable** | Arming a hook arms it everywhere, so N copies execute in parallel on disjoint flows. This is why all-or-nothing arming matters: a partially armed set is not "mostly protected" — an attacker only has to reach the instance that missed. |
| **Two or more programs chained on one hook** | **No — refused by design** | One program slot per hook; the candidate ABI requires a second `LOAD` on an armed hook to be refused with `SHIELD_ERR_BUSY` rather than overwriting (`substrate/shield_abi.h`, `struct hook_slot`). Replacing a shield is `REVOKE` then `LOAD`, explicitly. Deferred rather than forbidden forever — see below for why the blocker is outcome composition and not plumbing. |
| **Two handlers running at the same instant on one core** | **No — impossible by construction** | The poll loop is single-threaded, un-preemptible and run-to-completion. This is not a restriction the design imposes; it is the property that *lets* per-core counters skip atomics and one `ctx` scratch buffer per core suffice (§3.2). |
| **A handler re-entered while already on the stack** | **Possible by nesting, and guarded** | Hook A's generated ctx-builder calls a function carrying hook B, whose builder reaches back into A. A per-core depth guard covers it, and covers it *completely*, because there is no parallel entry to also worry about. |
| **Two hooks both firing within one unit of work** | **Yes — and it is an accounting problem, not a race** | Run-to-completion serialises them; their costs add. That is the cumulative-budget item below, and its fix is a ceiling, not memory ordering. |

So: **concurrent hooks yes, concurrent programs at one hook no, and true simultaneity within a core is
not a thing that can happen.** The rest of this section is the five consequences of the first two rows,
and §3.2 is the concurrency model the fourth and fifth rows rest on.

Every cost and safety argument in this register is written for **one program at one hook**. The
moment two are armed, five things appear that no single-hook analysis covers.

**0. What "one VM" and "many VMs" actually mean, because the wording invites a wrong picture.** uBPF's
`struct ubpf_vm` holds **one program**: `insts`, `num_insts` and `jitted` are all singular
(`ubpf/vm/ubpf_int.h`). With one program per hook, that means **one VM per armed hook** — not per
catalogued hook, and not per core. A catalog of two hundred tracepoints with three shields loaded is
three VMs. What a VM costs is **memory** — the struct, the bytecode, the JIT'd code buffer — not a
thread, a stack, or a scheduling context, and a VM whose program is never called costs nothing at
runtime. **Nor is the VM on the hot path at all.** `ubpf_compile` is called once at load and returns a
native function pointer; `hook_slot` stores that pointer (`shield_jit_fn`,
[`substrate/shield_abi.h`](substrate/shield_abi.h)) and the trampoline calls it directly. No bytecode is
walked and no VM object is dereferenced per packet. The JIT'd code is shared read-only across cores;
what is per-core is the **scratch stack** passed as `ubpf_jit_ex_fn`'s third and fourth arguments —
which is why the extended JIT form is the required one. **Open:** whether the VM set is per address
space or per TMM instance, because if instances are separate processes the count and the memory both
multiply by instance — the same shared-mapping question that selects the arm/disarm form
(`development-scope.md` §1 item 2), and the reason memory accounting is on the
loader handler's list.

**1. One program per hook, and say so.** `struct hook_slot` holds a single `shield_jit_fn`, so
overwriting it in `trampoline_arm(slot, fn, mode)` is the structurally easy behaviour and the wrong
one: it **silently replaces a live shield**, disarming a mitigation an operator believes is running,
with the fire counter resetting to zero as evidence — indistinguishable from "no matches." The
candidate ABI header records the requirement (refuse with `SHIELD_ERR_BUSY`); day one is the loader
enforcing it, so the operator gets "that hook is occupied by shield X" rather than a silent swap.
Replacing a shield is then explicit: `REVOKE` then `LOAD`.

**2. If chaining is ever wanted, outcome composition is the hard part, not the plumbing.** Running
several programs at one hook is easy; deciding what their answers *mean* together is not. Two
programs, one selecting `PASS` and one `SAFE-RETURN` — which wins? The only defensible rule is
**most-restrictive-wins with a declared total order over the outcome set**, because any
"first-match" or "last-loaded" rule makes behaviour depend on load order, and load order depends on
config-sync arrival order, which is not the same on two HA peers. That is a real specification, and
it is deferred deliberately: v1 has no chaining, and the enumerated outcome set stays a choice made
by exactly one program.

**3. The budget is per hook; nothing bounds the sum — and the sum is not the interesting number
anyway.** The admission budget pass (§1) gates a program against *its hook's* allowance. Arm sixty
of them and every one passes while the loop's headroom is gone. Worse, the per-hook framing quietly
assumes independence, and hooks on the same flow's path are the opposite of independent: **a flow's
added cost is the sum of every armed hook it traverses**, not the maximum. So the real quantity is
per-unit-of-work and it is not knowable at admission time, because it depends on which *other*
hooks are armed and on the path this particular flow takes. Day one: a **global armed-cost ceiling**
maintained by the loader — admission subtracts from a per-`path_class` allowance and refuses the
load that would exceed it — plus the measured, reported per-flow figure from the runtime guard, since
the static sum is an over-estimate for any flow that skips some hooks and an under-estimate for none.

**4. One shield can silently mask another, and the evidence looks like safety.** If shield A takes
`SAFE-RETURN` at a function whose body *contains* hook B,
then B never executes, its fire counter stays at zero, and zero is indistinguishable from "nothing
matched." An operator reading `STATUS` sees a quiet hook and concludes there is no threat on that
path, when in fact the path is no longer being reached. It is the same **false-success** shape as a
partially-inlined function whose out-of-line counter climbs while the inlined call sites run
unshielded — and it is worse here, because the masking is caused by our own mitigation. Day one:
the hook map already knows the static call graph, so **flag hook pairs where one is reachable from
the other's body and refuse to arm both in enforce mode without explicit acknowledgement**; and
report a masked hook as `masked`, never as zero.

**5. Mutual re-entrancy, not just self re-entrancy.** The self case is already recorded in
`design-review-findings.md` §3: a shield on a logging function is re-entered by the loader's own
error path. Two armed hooks generalise it — hook A's trampoline or generated ctx-builder calls a
function carrying hook B, whose builder calls something carrying hook A. A single per-core "in
trampoline" depth guard handles both cases and is the day-one answer; the alternative, proving the
builders' call graph is acyclic, is a per-build analysis that adds nothing.

**Day-one vs. deferred:**

- **Day-one:** one program per hook with an explicit busy rejection; a per-core re-entrancy depth
  guard; a global armed-cost ceiling; masked-hook detection from the static call graph, and `masked`
  as a distinct `STATUS` state from zero-fires.
- **Deferred:** chaining more than one program at a hook, and with it a declared total order over
  the outcome set. Not needed for CVE mitigation, and it is the piece that turns HA config-sync
  arrival order into observable behaviour, so it should not be taken on casually.

## 3.2 Handlers running at the same time

**The claim to retire:** nothing — this one was never claimed either way, which is the problem. §3.1
covers what happens when several programs are *armed*. This covers what happens when they *run*, which
is a different question, and the answer was scattered across these documents as a performance argument
rather than stated as a concurrency model.

**Within one TMM instance there is no concurrency at all.** The poll loop is single-threaded,
un-preemptible and run-to-completion, so a handler runs to completion before anything else runs on that
core. Three simplifications elsewhere depend on that property:

- **Per-core fire counters need no atomics.** Not because atomics are slow — because there is exactly
  one writer per counter and it cannot be interrupted mid-increment.
- **One `ctx` scratch buffer per core is enough**, rather than one per invocation. Nothing else on that
  core can be between the builder and the program.
- **A handler can only be entered twice by *nesting*, never by parallel entry** — which is why §3.1's
  per-core depth guard is a sufficient answer to re-entrancy rather than a partial one.

**Across TMM instances there is full N-way parallelism.** Arming a hook arms it on every instance, so N
copies of the same program execute simultaneously, on disjoint flows. Three consequences:

- **Anything shared between instances is a real concurrency problem**, which is §3 — and it is the
  reason the base tier has no maps at all rather than a lock discipline.
- **`STATUS` must aggregate N counter sets, and a single summed number destroys information.** Skew
  across instances is *diagnostic*, not noise: disaggregation decides which instance a flow lands on, so
  an even spread and a spike on one instance mean different things. Report per-instance and let the
  operator sum.
- **All-or-nothing arming matters *because* of this.** A partially armed set is not "mostly protected":
  identical traffic gets different treatment depending on which instance it hashed to, and an attacker
  only has to reach an unarmed one.

**The one real seam is the loader against a running handler.** The single place where something *does*
happen concurrently with a handler is the control plane mutating a slot while that slot's program is
executing on another core — arm, disarm, mode change, unload. `slot->armed`, `slot->mode` and `slot->fn`
are read on the hot path and written by the loader, so they need a defined memory ordering rather than
plain accesses, and freeing a VM needs quiescence: disarm, advance a per-core epoch at each safe point,
free only once every core has passed it. That gap is already recorded in the review register; what §3.1
and this section add is *why* it is the only such gap — everything else is serialised by the loop.

**And the fixes for the two do not overlap.** Two hooks firing within one unit of work is the
cumulative-cost item in §3.1, and its fix is a global armed-cost ceiling; the loader-versus-handler
seam above is fixed by memory ordering and quiescence.

**Day-one vs. deferred:**

- **Day-one:** acquire/release ordering on the slot fields the trampoline reads; the epoch/quiescence
  scheme before any unload path exists; per-instance `STATUS` rather than a pre-summed total; and
  all-or-nothing arming with a defined behaviour when one instance fails to arm.
- **Deferred:** anything that makes state shared *between* instances (§3). The single-writer-per-core
  property above is doing a lot of work, and a shared writable map is what spends it.

## 4. Verifier soundness is a data-plane remote-code-execution surface

Throughout this section, **traffic-borne RCE** means **remote code execution triggered purely by sending
traffic through the data path** — no credentials, no management-plane access, no local foothold. It is the
worst class precisely because it needs nothing from the attacker but reachability, and it is what the
signing gate below trades away for supply-chain and insider risk.

**This is the one a security review fixates on.** uBPF JITs native code into
TMM's address space — the crown-jewel process of a security appliance. An **unsound PREVAIL** or
a **buggy JIT** is arbitrary execution inside TMM. Linux has burned through many verifier CVEs;
embedding the mechanism relocates eBPF's single biggest risk class into the data plane.[^src]

**The perimeter is the signing gate, not the verifier — and the design already implies it.**
Only **F5-signed bytecode ever reaches the in-TMM JIT** — PREVAIL runs earlier, inside F5's
admission pipeline, never on attacker-supplied input. Therefore a verifier-soundness bug is
**not remotely triggerable by traffic** — exploiting it *also* requires compromising the signing
key. That collapses the risk from **traffic-borne RCE** to **supply-chain / insider**, a
different and much smaller tier. State it explicitly: *the signing gate keeps attacker-controlled
input away from the JIT entirely, and the verifier never runs on-box at all.*

**Defense-in-depth residual (because the signing gate is the perimeter):**

- **Signing-key protection** — HSM-backed, F5 root of trust. This is the real perimeter now;
  treat it accordingly.
- **JIT hardening** — W^X, guard pages; consider validating JIT output before execution.
- **Interpreter-only high-assurance build** — trade JIT speed for a smaller (or zero) native-code
  surface on the most sensitive deployments.
- **Tracked CVE surface** — keep PREVAIL/uBPF current; carry both in the SBOM (software bill of
  materials), which ties to the open-source posture in the shield design §13.

**The open item: make the verifier auditable, not just trusted.** "How do you know the verifier is
sound?" has no satisfying answer of the form *"it's widely used."* The answer that does work is
**inspectability** — tooling that steps through the abstract interpretation so a reviewer can see
why a program was accepted, and so the verifier itself can be unit-tested against adversarial
inputs. That is the form soundness evidence has to take for a TMA. Establish early whether PREVAIL
offers it, whether it can be built alongside, and what a soundness-evidence package would contain:
the signing gate bounds *who* can exploit a soundness bug, and auditability is what reduces the
chance there is one.

**Verified ≠ correct.** A verified, signed program can still **black-hole all traffic** — drop
everything, misroute, degrade — because the proof is about memory-safety and termination, not
intent or correctness. The design needs a **control-plane canary / watchdog that auto-unloads on
a health signal** (traffic-drop, latency, error-rate), on top of the instant kill-switch and
revocation. The safety proof bounds the blast radius from *crashes*; the canary bounds it from
*bad-but-valid* programs.

**This is squarely a TMA item.** The threat model must center on verifier and JIT soundness,
the signing key as the real perimeter (and its protection), and the interpreter-vs-JIT trade for
high-assurance builds — with F5 SIRT sign-off gating implementation, not following it.

## 5. Further TMM-specific concerns

**Read this list with its severity in mind, because thirteen equal-looking bullets overstate the risk.**
Exactly one is both unavoidable and hard — **the safe point**, and an earlier draft of this sentence
overstated it as "needed for any dynamic load into a running TMM whatever the hook kind." It is not.
"Safe point" was one label over three guarantees, and only the first is unconditional: an **ordered
publish** into a slot the hot path already reads, which modifies no text and needs no rendezvous. A
**cross-core rendezvous** is needed only to change live text, which makes it x86-64 work. (It was
nothing at all in the designed-in-call-site form — but that form was removed on 2026-08-13, so the
rendezvous is now unavoidable rather than optional.) **Quiescence** for reclamation is
needed in every form, but has three answers — a poll-loop epoch, per-invocation read-side markers, or a
capped leak. The decomposition and what each form costs is in
`development-scope.md` §1, items 0 · 0b · 0c. Two are not open questions: keeping the verifier out of TMM is a decision
already taken, and the concurrency item records a property that is the reason three other things are
simple. Four are ordinary lifecycle and governance work. One is scope-dependent, biting only on
per-packet hooks. Certification has the best existing answer, since BIG-IP already runs customer TCL and
WASM inline on evaluated appliances, so code outside the validated image is not a new question and only
the JIT is novel. And **four exist only because function-boundary probes are on the table** — the
build-specific probe context, the optimiser deciding the hookable set, the unwind information a
trampoline needs, and the JIT's maturity. An earlier revision offered an escape from those four: take the
narrowest form, designed-in call sites only (outcome 3 of the measurement in
[`design-review-findings.md`](design-review-findings.md) §4), and they go away along with live-text patching
and the rendezvous. **That escape was closed on 2026-08-13, when designed-in call sites were removed** — their
reach is fixed at build time, which is precisely what a CVE defeats. So these four are unconditional. What remains is ordered publish, a
reclamation policy, certification, and the ordinary work.

- **uBPF's own hardening switches, which are per-program and mostly default-off.** `ubpf_create`
  leaves the bounds check and read-only bytecode on, but **constant blinding off** and the
  undefined-behaviour check off (`ubpf/vm/ubpf_vm.c`). Blinding is what stops a bytecode immediate from
  reaching the JIT'd buffer verbatim, i.e. from smuggling native instruction bytes into an executable
  mapping inside TMM — defence in depth behind the signature. Two consequences: the loader must set
  these explicitly rather than inherit them, and **blinding is x86-64 only** — `ubpf.h` says ARM64 is
  *"not yet implemented ... will have no effect"* — so an aarch64 build has no JIT-spray mitigation and
  the interpreter becomes the stronger high-assurance answer there, the same conclusion item 15's fuel
  reaches by a different route.

- **Item zero — the safe point itself, and it is three items.** Every in-TMM item above once assumed
  "a safe point between poll-loop iterations that dequeues and processes a load request." Two things
  were wrong with that. First, **nothing needs to be dequeued in the poll loop**: parse, verify, JIT
  and page population all run on a control thread, and as first sketched `do_load` did them *at* the
  safe point — unbounded work during which the loop is not polling, a latency spike and possibly a
  dropped heartbeat. What reaches the hot path is a single ordered store. Second, the remaining
  guarantees are **separable and separately optional**: a cross-core rendezvous, needed only to modify
  live text (x86-64 only — aarch64's aligned `NOP`↔`B` swap is architecturally safe against concurrent
  execution), obtainable either from a poll-loop checkpoint or from a userspace `text_poke_bp`
  equivalent (`SIGTRAP` handler plus `membarrier(…SYNC_CORE)`); and quiescence, needed to free a
  program's code, obtainable from a poll-loop epoch, from per-invocation read-side markers, or by
  declining to free and capping the leak. **None of the three is a poll-loop check that does not exist
  today and cannot be avoided.** What is true is that the poll loop is the cheapest place to get the
  last two, and that every alternative pays in hot-path cycles, a restart, or leaked memory.
  **One capability does have no substitute, and it is worth stating precisely because everything else
  here is a price:** an **atomic multi-slot change**. TMM is run-to-completion per packet, so a
  checkpoint between iterations is the only point at which several slots can be flipped with no core
  having observed a half-applied set. Without one, a packet already past hook A sees old-A/new-B, and a
  generation counter the trampoline consults does not fix it — it moves cost onto the hot path and still
  cannot rewind that packet. It is **forfeited rather than blocking**, since day one is one program per
  hook with chaining refused (§3.1), so nothing currently needs two slots to change together.
  **It was previously not on the list at all**, and when added it was added as one item.

Sections 1–4 are this register's primary items. These are the next tier — each has a stance and none
changes the day-one posture, and the safe point and certification are the two most likely to shape the
first shippable form.

- **Certification (FIPS — Federal Information Processing Standards — 140-2/3, and Common Criteria).**
  A certified security appliance that can load code into its data plane at runtime is a certification
  problem — evaluators may not accept "it's signed" as sufficient, and it can force a
  **dynamic-load-disabled certified mode** for deployments that require an evaluated configuration.
  A *productization* gate: engage certification early rather than late.
- **Keep the verifier out of TMM.** PREVAIL is heavy C++/Boost; it should verify at **build/sign
  or control-plane time**, so only the small uBPF runtime (+ a signature check) lives in TMM's
  address space. Stating it shrinks the §4 surface, and it is what distinguishes the design from one
  that puts a large dependency in the crown-jewel process.
- **uBPF JIT maturity.** §4 is really "the verifier *and this JIT*." uBPF's arm64/x86-64 JIT is
  far less battle-tested than the kernel's, and here a JIT bug is the RCE. Plan to
  **audit/harden/fork it**, or default to the **interpreter** on high-assurance builds.
- **The optimiser decides the hookable set, not us — and the build system narrows it again.**
  `-fpatchable-function-entry` pads the entries of
  functions the build actually emits out-of-line. **Measured on BNK/x86-64:** it reaches **82–97%
  inside the TMM tree** — the scope the shield targets, where the flag is applied to every
  compilation and the shortfall is the optimiser, not the flag — and **0%** across two dozen
  separately-built F5 components and vendored third-party libraries — some of which (`tmstat`,
  `libbigpacket`, `tcpdump`) arrive as prebuilt RPMs and are never compiled here at all. So the
  *paddable* set is about half the hookable set, and the difference is owned by other teams' builds.
  See [`env/tmm-build-environment.md`](env/tmm-build-environment.md). At `-O2` that is a *subset* of the source: an
  inlined function has no entry of its own — which pushes the usable boundary **outward** to the
  nearest surviving caller, a wider skip radius rather than lost reachability (design §10.1);
  `-fipa-icf` **folds identical function bodies**, so one pad may
  serve two source names and arming "A" also arms "B"; and `ipa-cp`/`ipa-sra` emit **clones**
  (`foo.constprop.0`, `foo.isra.0`) whose symbol name *and argument list* differ from the source, so a
  `ctx` derived from the source signature would be wrong. Three consequences to state before
  anyone promises reach: the hook map must be generated from the **emitted** symbols and must reject
  or disambiguate folded ones (the generator's `DW_AT_low_pc` test silently drops inlined statics —
  see `development-scope.md` item 5); the hookable set is knowable **per build** but is not the
  set of functions an engineer can name from reading the code; and guaranteeing a *specific* function
  stays hookable across releases means marking it `noinline`, which is a **source change** with a
  perf cost — so "no source modification" holds for the mechanism, not for a guarantee about any
  particular target. Day one: publish the hookable set as a build artifact and treat it as the
  contract, rather than implying every named function qualifies.
  **Measured 2026-08-12, on the BNK form factor only** — the containerized TMM from
  `gitswarm.f5net.com/tmm/tmm`, version `10.207.3-main`, built with `make tmm-gdb`: **119,555**
  out-of-line functions (42,215 global, 77,340 local; ~113,604 excluding obvious statically-linked
  third party), with **92 `.constprop`, 76 `.isra` and 126 `.part` clones** — so the folding and
  cloning warned about just above is real and countable rather than hypothetical. This is the first
  hookable-set measurement in this proposal. Appliance and VE are **CBIP** builds, from Perforce via
  `seadev`, and remain unmeasured — the three form factors are separate builds and a count from one
  does not transfer. See [`big-ip-live-surface-design.md`](big-ip-live-surface-design.md) §10.1.
- **Invocation granularity — per-packet bytecode on a partly batched data plane.** eBPF's calling
  convention takes **one `ctx`, once**: it cannot express "here is a vector of 256 packets." A data
  plane whose performance comes from a stage seeing an entire batch at once — so it can loop and
  prefetch across the batch — would therefore be a poor host for bytecode, because a per-packet
  callback inside such a stage forfeits its whole premise. **TMM is the favorable case:**
  run-to-completion and core-pinned, processing per-flow/per-packet through
  a stack rather than as a vector through a graph, so a per-invocation hook fits the existing
  control flow. What remains is per-invocation overhead where TMM *does* batch — burst receive on
  hot paths. The answer there is a **burst-capable invocation form**, with §1's budget pass
  reasoning **per burst** rather than per packet. Note honestly what a burst form does *not* buy:
  it amortizes call overhead while still running one invocation per packet with its own `ctx`; the
  program still cannot reason across the batch. If a future hook ever needs cross-packet reasoning,
  that is a different program model, not a tuning exercise.
- **Patching live text, and safe-return correctness.** The function-boundary mechanism arms by
  atomically overwriting a compiler-reserved nop pad in live text (the ftrace discipline: atomic
  patch + i-cache flush) — proven in kernels, but new inside TMM and per-CPU-architecture work
  that must be exactly right. And a safe-return skips the hooked function's *whole body*, so the
  signed safe-return policy is **two gates in order**: first skippability — locks held, refcounts,
  flow-state advance, input consumed, out-params, allocation — **closed by default, so an unanalysed
  body is observe-only**; and only then the return kind. `void` is the **hardest** case rather than
  the trivial one, because such a function is called entirely for its side effects, and
  `substrate/check_sr_gates.c` asserts that ordering.
- **Multi-tenancy — partitions, route domains, vCMP (virtual CMP).** BIG-IP is deeply multi-tenant,
  and vCMP guests each run their own TMM. A program's **scope** (global vs. per-virtual-server /
  per-partition), its **authorization**, and its **blast radius** must be tenant-aware from day
  one — the governance model cannot be single-tenant.
- **ISSU (in-service software upgrade) / hitless upgrade + failover.** BIG-IP ships zero-downtime
  upgrades, so loaded programs need defined behavior across an in-service upgrade and HA failover —
  **re-verify and reload on the new TMM**, with explicit map-state handling. (Extends §3.)
- **Post-mortem debuggability — and it cuts both ways.** Absent from this register until now. Three
  distinct problems:
  **(1)** a **backtrace through a hooked function** is garbage unless the trampoline carries correct
  CFI (call-frame information) / `.eh_frame`, because the unwinder meets a stub that did not set up a
  frame the way the ABI says. **(2)** a **program counter inside JIT'd code** lands in anonymous
  executable memory with no symbol, so the frame is unresolvable — the loader has to register the JIT
  region the way the perf-map / JIT-dump interfaces do, or every shield-involved crash reads as `??`.
  **(3) a core dump must record which shields were armed**, with their hashes, hooks and modes, and the
  fact that text was patched at all. Without that, an analyst holding a dump cannot tell whether a
  shield was involved, so **every future crash on a box that has ever loaded one becomes ambiguous** —
  a support-organisation cost as well as an engineering one, incurred even by crashes the shield had
  nothing to do with. Patched text also means **the dump no longer matches the shipped binary**, so
  any tooling that checksums or symbolises against the release image needs to know about the pads.
  The other direction: *the same mechanism improves pre-mortem* debuggability, because a flight
  recorder captures the run-up **into** a fault, which a core dump structurally cannot — a dump is the
  state at the moment of death, not the sequence that reached it. The two are complementary rather
  than substitutable: a probe answers a question that was framed in advance, and a dump is the
  artifact available when there was no hypothesis.

- **Jitter-sensitive deployments.** Where a deployment's budget allows no added per-packet jitter at
  all — a 5G UPF (User Plane Function) or a latency-tiered trading path — the mechanism needs a
  **per-hook / per-deployment opt-out**: "dark until lit" is a branch, but a populated hot hook costs
  real cycles.

## 6. Sequencing — day-one vs. deferred

| Concern | Day-one | Deferred / governed |
|---|---|---|
| **Time safety** | admission instruction-budget ceiling; back-edge **fuel** guard (needs the uBPF JIT patch) gating every attacker-reachable hook, with wall-clock as reporting | tuned per-hook budgets from field data |
| **Interface** | read-only `ctx` per hook + program-type descriptor | helper tier (map access, rewrite, lookup) |
| **State** | no maps (base tier); when helpers land: per-CPU maps, failover via TMM's existing mirroring | shared writable cross-TMM maps |
| **Execution** | interpreter or hardened JIT; W^X | — |
| **Trust perimeter** | signing gate + HSM key protection | — |
| **Blast radius** | canary/watchdog auto-unload + kill-switch + revocation | automated health-driven rollback policies |

## 6.1 The honest size of it

An earlier draft of the scope described this as "hundreds of lines, not subsystems." Reviewed against
what each item actually requires, a defensible v1 on two CPU architectures is **subsystem-scale work,
not a feature**, plus the TMA and certification engagement — and no month figure is offered here,
because this is a design proposal rather than a plan and sizing belongs to whoever picks it up. The items that grew most: the safe point (§5, previously unlisted), the
trampoline (a page of assembly, then a long tail of ABI edge cases), arm/disarm (live-text patching,
possibly a memory-manager change), and the hook-map generator — a parameter classifier over DWARF
implementing the platform calling conventions, against an optimised build.

The reframe that matters: **the subsystem being added is not the VM.** It is a code-patching,
live-text, dynamic-code-loading facility inside the crown-jewel process, with its own build-pipeline
toolchain and a permanent per-build ABI.

Which is why this register argues for a **sequencing**, not a commitment. **Three questions come before
the rest of the design**, and none of them requires building the thing: measure the padding flag twice —
the idle cost with nothing armed, then the armed cost at rate (§1.1) — settle a `ctx` model that
verifies against real TMM debug info, and arm one hook end-to-end in a lab TMM with core dumps still
readable. The first of those is specified in `design-review-findings.md` §4, and what its result decides
is **which of two forms the mechanism takes** — pad the image, or pad an allowlisted subset of translation
units — rather than whether to proceed. (A third outcome, designed-in call sites only, was on this list until
2026-08-13 and is no longer available.) The threshold
separating those outcomes belongs to whoever owns the platform's published performance numbers, not to
this document, and should be agreed before the experiment runs.

## 7. The honest one-liner

> The verifier gives you memory-safety and termination — **not** WCET, **not** correctness, and
> **not** immunity from its own bugs. The engine is defensible because the **signing gate** keeps
> attacker input away from the JIT (the verifier never runs on-box), an **admission budget plus a
> back-edge fuel guard** bounds execution time, and a **canary** bounds the blast radius of a
> valid-but-bad program. Verification is one layer
> of several — the floor, not the whole building.

---


[^src]: Sharper still given the source-code exposure — an adversary holding the code can hunt
    verifier/JIT soundness bugs directly. The perimeter is the signing gate, and it holds whether
    or not the source is public.
