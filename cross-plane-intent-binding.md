# Cross-plane intent binding — the proxy witnesses, the kernel enforces

### Agentic AI turns a request into arbitrary execution. Nothing today can say whether what executed was what was authorized. Two eBPF planes in different trust domains can.

**Status:** **DESIGN. Nothing in this document has been built, run, or measured** — in this repo or
anywhere else I can point at. Every mechanism below is a design claim; the numbers that exist are
borrowed from other work and labelled where they are. The three falsifiers in §9 are registered in
[`02-RESEARCH-PARAMETERS.md`](02-RESEARCH-PARAMETERS.md) as P10–P12, and the cheapest one needs no
eBPF program, no build box and no cluster.

**Audience:** F5 product & strategy, TMOS architecture, F5 SIRT, AI security platform leadership.

**Companions:** [`big-ip-live-surface-design.md`](big-ip-live-surface-design.md) §5.1 (*"two
engines, two verifiers, one catalog"* — this document adds the third engine slot),
[`data-plane-intelligence.md`](data-plane-intelligence.md) (the vantage argument, §1–§2),
[`vm-capability-inventory.md`](vm-capability-inventory.md) (what the TMM plane can actually do),
[`idea.md`](idea.md) (a narrower use case for the same substrate, and where this one came from).

---

## 0 · Where this came from, recorded rather than presented as new

This was the **last bullet of a discarded section**. A draft of [`idea.md`](idea.md) proposing
TLS-record-shape observation ended with a "PoC 3 and beyond" list whose final item read:

> *Cross-plane map schema (shared BTF) for TMM ↔ host kernel correlation and
> attestation-by-disagreement.*

The rewrite of that draft (commit `c5ea4de`) deleted the whole section while correcting the
histogram work above it. **The best idea in the document was thrown out as part of fixing its
weakest part** — and it survived only because it was asked for again in the same session.

Worth recording for the same reason `CONTESTED-PREMISES.md` exists: the failure mode is not
*having* a bad idea, it is **editing past a good one** because it sits in the part of the page you
have already decided is filler. "PoC 3 and beyond" was filler. One bullet in it was not.

---

## 1 · The test a killer app has to pass

Given two programmable planes — an embedded verified VM inside TMM, and stock eBPF on the host
kernel of the AI workload — a use case is only worth the platform if it is **impossible with either
plane alone**. Applied honestly, most candidates fail:

| candidate | proxy alone? | host kernel alone? | verdict |
|---|---|---|---|
| Prompt / response DLP, jailbreak detection | **yes** — post-decrypt, in protocol context | no | proxy-only. An AI gateway is the right product, not this |
| Shadow-AI discovery (who is calling which model API) | mostly — as an egress proxy | partly — which process connected where | the join adds process attribution; a CASB approximates it. **On-ramp, not the app** — §10 |
| Model-weight exfiltration | no | **mostly yes** — file reads + egress | host-only. Existing runtime-security products do this |
| GPU tenancy, token cost attribution | partly | partly | commercially attractive, not a security property |
| **Binding a model's authorized intent to what a host actually executed** | **no** | **no** | **requires both.** This document |

One candidate survives, and it survives for a structural reason rather than a feature reason.

---

## 2 · The problem, stated so that it is visibly unsolved

An agent receives a prompt. It retrieves a document. The document carries injected instructions.
The model emits a tool call. The agent runtime executes it — a shell command, an HTTP request, a
database query, a file read. **Something happens on a host.**

Ask the only question that matters — *was that action authorized?* — and no deployed system can
answer it:

1. **The authorization decision, where it exists at all, runs in userspace** — in the same process,
   often the same language runtime, that the injection just influenced. The thing being asked to
   enforce scope is the thing that was manipulated.
2. **The execution happens in the kernel**, which has no concept of a prompt, a session, a tool
   definition, or a tenant.
3. **The join happens in a SIEM**, minutes later, on timestamps and 5-tuples — using logs that a
   compromised host produced about itself.

So nobody can currently say: *this `connect()` to 203.0.113.9 exists because of model output
authorized under session X, tool Y, argument constraint Z.* They correlate by clock and hope.

**Citation status: NOT_RETRIEVED.** Prompt injection as a class, its standing in the OWASP LLM Top
10, and the current state of agent-runtime sandboxing are all **from memory** and carry no row in
[`SOURCES.md`](SOURCES.md). The same applies to the prior art named in §8 (Tetragon, Falco,
Cilium). None of it is asserted here as established; all of it needs retrieval and caching before
this document is shown to anyone.

---

## 3 · The asymmetry, which is the actual product

Two witnesses to the same causal chain, with **complementary blindness and — the part that
matters — different trust domains**:

| | sees | cannot see | can it be tampered with from the compromised host? |
|---|---|---|---|
| **Host kernel** | what **executed** — `execve`, `connect`, `open`, capability use, by cgroup and process | any notion of prompt, session, tool scope, or tenant | it is *in* the blast radius. An attacker with sufficient privilege shapes what it reports |
| **TMM (the proxy)** | what was **requested and authorized** — post-decrypt, in protocol context, with client identity, at line rate | what any process subsequently did | **no. It is off-host.** Different machine, different privilege domain |

Neither plane is sufficient and neither is redundant. The kernel is the only thing that observes
execution; the proxy is the only thing that observes intent *and* cannot be rewritten by whoever
owns the host.

> **The claim this supports, and it is a security property rather than a slogan:** to make an
> unauthorized action look authorized, an attacker must control **both** the workload host **and**
> an off-host proxy in a different trust domain. That is a stated, falsifiable bar — not "we detect
> bad things."

This is also the exact inverse of the constraint `big-ip-live-surface-design.md` §2 establishes.
There, kernel eBPF *cannot* shield TMM — it cannot afford the per-hit trap in a run-to-completion
loop and cannot override a return. Here the workload hosts are **ordinary Linux processes**, which
is the case §5.1 already calls the *"true Cisco analog"* and the case where stock kernel eBPF with
the kernel's own in-tree verifier is exactly the right tool. **Same catalog, third engine slot.**

---

## 4 · The mechanism — three tiers, increasing teeth

Each tier is independently useful and independently shippable. Tier 1 is observation only; nothing
is denied until tier 3.

### Tier 1 · Attribution — build the causal chain

The proxy, having authorized a tool call, mints a **capability**: an identifier naming the session,
the tool, argument constraints, and an expiry. It travels with the request to the agent runtime.

The host program, at the LSM / syscall layer, records every `execve`, `connect`, `open` and
`openat` with cgroup id, process identity, and **the capability that process inherited**.

The output is something nobody can currently produce: a chain from **prompt → model output → tool
call → the syscall that resulted**. That is the audit artifact AI governance regimes ask for, and
it is valuable with zero enforcement attached.

### Tier 2 · Disagreement — detect the unaccounted-for

Two independent counts of the same window, one of which the on-host attacker cannot reach.

> The proxy says: *session X authorized three tool calls, to these three destinations.*
> The kernel says: *five outbound connects from that cgroup in that window.*
> **The delta is the finding.**

Note what is being detected. Not "matches a known-bad pattern" — **"is not accounted for by any
authorization."** That catches the action nobody wrote a rule for, which is the entire difficulty
with agentic attack surface: the dangerous action is usually a legitimate capability invoked for an
illegitimate reason.

### Tier 3 · Capability enforcement — prevent

The host program **denies** the syscall when no live capability covers it. `bpf_lsm` hooks return
a verdict the kernel honours; the deny path is the kernel's, not the application's.

The agent runtime stops being trusted to enforce its own tool scope. An injection that persuades
the model to exfiltrate produces a call for which the proxy **never minted a capability**, so the
`connect()` is refused — not because of a rule about that destination, but because authorization is
absent.

> **Decision point off-host. Enforcement point below the application.** An injected instruction
> cannot talk its way past a program it has no way to address.

**Mandatory: monitor-first.** A denied `connect()` breaks a running application, and unlike a
`SAFE_RETURN` in a poll loop the blast radius is the customer's workload. Tier 2 is the shadow mode
for tier 3, and it is not optional. This is the same discipline `MONITOR` mode already encodes on
the TMM plane.

### The demo

Inject via retrieved content. The agent attempts exfiltration. The kernel blocks it. Then show the
two witnesses side by side and point at the delta. One screen, no narration needed.

---

## 5 · The capability is where this gets designed or lost

The mechanism above is only as good as the capability's binding, and the obvious implementation is
the broken one.

**A bearer token in a header is worthless here.** Anything on the host can read it out of the
process environment, the request, or `/proc`, and replay it for an unrelated action. The threat
model explicitly includes code running on that host.

So the capability must be **verified in-kernel against context the caller does not choose**:

| bound to | checked how | why |
|---|---|---|
| cgroup id / container identity | `bpf_get_current_cgroup_id` | a capability minted for one workload cannot be spent by another |
| process lineage | task-local storage set at request dispatch, inherited on fork | narrows to the subtree the request actually created |
| destination and argument shape | compared in the LSM hook against the map entry | a capability for tool Y cannot authorize an arbitrary destination |
| expiry | monotonic clock at check time | replay window is bounded, not open |

**The honest statement of the residual risk:** a sufficiently privileged on-host attacker who can
write the map or load their own program defeats this. It raises the bar to *kernel-level* privilege
on the workload host **plus** the off-host proxy — it does not eliminate the host from the trust
base. Any wording stronger than that is an overclaim.

---

## 6 · What exists today, per plane

Tiers per `CLAUDE.md` rule 2. The TMM column is measured; the host column is a statement about
stock kernel eBPF, not about anything in this repo.

| capability | TMM plane | host-kernel plane |
|---|---|---|
| Program admission (verify, sign, gate, audit) | **MEASURED** — PREVAIL + Ed25519 + build-ID gate + per-op audit record | the kernel's own in-tree verifier; signing/catalog is ours to add |
| Attach live, no restart | **MEASURED** — arm/disarm on a running TMM, entry bytes restored byte-identical | standard |
| Maps | **MEASURED, and small** — hash only, 4/program, 256 entries, key ≤ 16 B, value ≤ 32 B, per-thread (`ls_map.h:61–64`) | full type set, per-CPU, LRU, pinned, cross-process |
| Egress to userspace | **MEASURED** — per-thread ring, 64 KB × 16 (`ls_tp_ring.h:48`) | ringbuf, perf, sizes of your choosing |
| Clock, pointer chase, program-controlled emit | **BUILT** — helpers 5, 4, 25 (`ls_map_glue.h:672–702`) | standard |
| **Deny an action** | `LS_SAFE_RETURN` only — skip a function body, return a safe value | **`bpf_lsm` returns a verdict the kernel honours** *(from memory; needs `CONFIG_BPF_LSM` and `lsm=bpf` verified on the target kernel)* |
| **Mutate a request** (inject a capability) | **ABSENT.** Verdicts are fallthrough / safe-return. No mutating verdict exists | n/a |
| Scope an attachment to a route or tenant | **ABSENT.** Hooks arm **by symbol, process-wide** | cgroup-scoped by construction |
| Per-invocation cost | **MEASURED** floor ≈ 37 ns whole armed path; 104 ns for a 4-read shield (`GROUND_TRUTH.md:49`) | a syscall-layer hook is not in a poll loop; different budget entirely |

**Read the asymmetry in that table.** The host plane is the *easy* half — mature, well-trodden, and
the kernel ships the verifier. Every hard blocker is on our side.

---

## 7 · What is missing, ranked by which tier it blocks

| # | gap | blocks | size |
|---|---|---|---|
| 1 | **Cross-plane identity.** A shared join key. `UFLOW_COOKIE` is TMM-side only and is a hand-written semantic derivation (`mk_probe.py:30`) | **tier 1** | the design crux |
| 2 | **A comparable clock.** Joining two planes needs the TSC-to-wallclock offset exported so host-side timestamps align. Registered as an open question in the discarded draft, and still open | **tier 2** — the disagreement window is meaningless without it | small mechanism, easy to get subtly wrong |
| 3 | **Capability injection at the proxy.** A mutating verdict does not exist, and the trampoline's safe-value path is already wrong for any return type that does not fit in `rax` (`vm-capability-inventory.md` §5) | **tier 3** | large — and see the shortcut below |
| 4 | **Per-route / per-tenant scoping of an attachment** | tier 1 at production scale | absent from the ranked extension list; may belong on it |
| 5 | **Is the agent host's traffic even in TMM's path?** Egress through BIG-IP Next as an egress gateway is a config-expressibility question — the third term of `exposure = fix absent × compiled in × precondition reachable`, which blocked six CVE candidates (`cve-to-shield-process.md` §4) | **all tiers** | unknown, and unglamorous |
| 6 | Host-side anything. **This repo contains zero host-kernel or GPU-host work** | all tiers | a new workstream, not an extension |

> **The shortcut on #3, stated because it weakens the case for our own substrate and should not be
> hidden.** An iRule can inject a header today. If the capability is minted by policy that an iRule
> can express, **tier 3's proxy side does not need the embedded VM at all** — and the retired HTTP
> tracepoint was rolled back for exactly this reason (*"iRules already saw every field"*).
>
> The substrate earns its place where an iRule cannot go: deriving per-request identity and
> emitting the audit record at line rate under a bound established **before load**, which is the
> distinction `data-plane-intelligence.md` §2 draws and the reason unbounded surfaces are kept off
> cleartext application data. That is a narrower claim than "the substrate enables this," and it is
> the true one.

---

## 8 · Why F5 — position, not physics

Stated plainly, because the inflated version is easy to write and will not survive review.

**What is genuinely structural.** TMM already terminates the traffic: both sides decrypted, in
protocol context, with client identity, at line rate — `data-plane-intelligence.md` §1's table, and
its bounds apply here unchanged (hardware-accelerated flows, FastL4 paths, SSL pass-through, and
per-instance CMP/DAG visibility are all still blind spots). Being **off-host** is not a feature
anyone can add to an on-host agent; it is where the product already sits.

**What is not structural.** Any L7 gateway at the same termination point could mint capabilities. A
host-side runtime-security vendor could add a gateway. The advantage is that F5 is *already* at the
enforcement point with an enforcement mandate and an existing signed-program admission pipeline —
and that `big-ip-live-surface-design.md` §5.1's *"two engines, two verifiers, one catalog"* frame
takes a third engine without redesign. That is a strong commercial position. It is not a moat, and
calling it one invites the correct rebuttal.

**Prior art, all NOT_RETRIEVED and from memory:** Tetragon, Falco and Cilium do the host half —
syscall and LSM observation with policy — and do it well. What no combination of them has is the
off-host witness of *intent*. If one of them ships proxy-side intent capture before this is built,
the differentiation is gone; that belongs in §9 as a commercial falsifier and it is not one an
experiment settles.

---

## 9 · Falsifiers, pre-registered, cheapest first

Registered as **P10–P12** in [`02-RESEARCH-PARAMETERS.md`](02-RESEARCH-PARAMETERS.md).

### P10 · Is a tool call distinguishable at the syscall layer? (the cheap, decisive one)

**Run this before anything else.** Tier 1 assumes one tool call produces an attributable syscall
from an attributable process. If the agent runtime rides a pooled HTTP client, a sidecar, or a
multiplexing language runtime, the kernel sees **one long-lived socket** and per-call attribution
collapses — taking tiers 2 and 3 with it.

> **Falsified if:** instrumenting a real agent stack (a LangGraph-style runtime, or an MCP server)
> with `bpftrace` shows tool calls are not separable at the syscall boundary, and no cheap
> host-side signal recovers the boundary.

Cost: an afternoon. No substrate work, no build box, no cluster. Same shape as the `tcpdump` check
in `idea.md` §3.1 — the cheapest experiment is off-substrate and can kill the whole programme.

### P11 · Can a capability be bound so that on-host code cannot replay it?

> **Falsified if:** a cooperating process on the same host, without kernel privilege, can cause an
> action the proxy did not authorize — by reading and replaying the capability, by inheriting it
> outside its intended subtree, or by racing its expiry.

This is §5's residual risk turned into an experiment, and it is the one that decides whether tier 3
is a security control or a speed bump.

### P12 · Do the two planes share a join key and a comparable clock?

> **Falsified if:** no identity available to TMM at request time can be reconstructed host-side
> without a lookup that the join was supposed to replace; **or** clock skew between the planes
> exceeds the tool-call inter-arrival time, making the tier-2 window unusable.

---

## 10 · Phasing — what ships first, and it is not tier 3

**Phase 0 · Shadow-AI attribution.** Observation only, no capability, no enforcement. Proxy sees
calls to model APIs; host sees which process and container made them. Join gives *"this pod, this
binary, this key, this model."* Weakest moat, shortest path, real product category, and it stands
up the cross-plane identity and clock work (#1 and #2) that everything else needs.

**Phase 1 · Origin attestation.** The host program attests the model server — binary identity,
weights hash, driver version — and the proxy **refuses to route** to an origin whose attested state
changed. Small, sharp, far shorter than tier 3, and it is the trust foundation tier 3 assumes
anyway. It is also the one piece where the proxy acting on host-side evidence is already within
today's verdict vocabulary: refusing to route is a decision, not a mutation.

**Phase 2 · Tier 1 attribution**, gated on P10.

**Phase 3 · Tier 2 disagreement**, gated on P12.

**Phase 4 · Tier 3 enforcement**, gated on P11, a TMA, and a monitor-mode deployment long enough
to establish a false-positive rate on real workloads.

---

## 11 · What this document does not claim

- That any of it works. **Nothing here has been run.**
- That the substrate is required for tier 3's proxy side. §7 says an iRule may suffice, and why.
- That the host is removed from the trust base. §5 states the residual risk; the bar is raised to
  kernel privilege on the host **plus** an off-host proxy.
- That the premise is established. §2's prompt-injection framing and §8's prior art are
  **NOT_RETRIEVED, from memory**, with no rows in `SOURCES.md`.
- That F5's position is a moat. §8 says it is a position.
- Any per-call cost on either plane for any of this. The TMM figures in §6 are floors from other
  programs on other hooks.

## 12 · Open questions

- **What mints the capability, and on what authority?** If the proxy's authorization decision is
  itself derived from model output, an injection that reaches the proxy's input reaches the minting
  decision. The capability's authority has to come from something the injection cannot influence —
  a tool allow-list per session, per identity, established out of band. That is policy design, and
  it is unaddressed here.
- **Who can revoke?** The TMM plane's verifying key is compiled in, so revocation is a rebuild
  (`vm-capability-inventory.md` §7). A capability system needs revocation on a much shorter clock.
- **Does the audit record carry a person?** Peer identity on the loader socket is already recorded
  as PARTIAL — the process is kernel-attested, the *person* is not, and under `kubectl exec`
  everything is uid 0. A provenance product whose audit trail cannot name an operator has a hole in
  exactly the place it is selling.
- **What does tier 2 do about a legitimate disagreement?** Connection reuse, retries, DNS, sidecar
  traffic and health checks all produce syscalls no tool call authorized. The baseline is not zero,
  and the false-positive story is the difference between a finding and noise.
