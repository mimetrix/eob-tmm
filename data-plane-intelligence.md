# Data-Plane Intelligence — the proxy as AI's sensory organ

### **Strategy annex — what the same hooks could later enable. NOT part of the current ask.** The programmable-data-plane substrate is not only a way to *change* TMM; it is also a way to *harvest* what a terminating proxy can see — without moving the data.

**Status:** **Strategy annex** / opportunity framing — deliberately **out of scope for the feasibility phase**
**Audience:** F5 product & strategy, TMOS architecture, F5 SIRT (Security Incident Response Team), data/ML leadership, OSPO (Open Source Program Office)
**Companions:** [`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) (the substrate), [`big-ip-live-shield-design.md`](big-ip-live-shield-design.md) (the security instance), [`data-plane-egress-primitives.md`](data-plane-egress-primitives.md) (how a signal actually leaves the poll loop), [`tmm-usdt-tracepoints.md`](tmm-usdt-tracepoints.md) (the hook + `ctx` catalog whose fields are the feature inputs assumed here)
**Scope:** What a bounded in-process substrate could unlock if it is later pointed not at *behavior* but at *data* — and the flywheel that would connect the two.

> ### Read this as an annex, not as a request
>
> What is being considered is a **feasibility phase**: two questions settled on paper and three proved in a lab — the flag's cost measured, a `ctx` model that verifies against real debug information, and one hook armed end to end on one architecture ([`design-review-findings.md`](design-review-findings.md) §7, §8). **Nothing on this page is being requested, funded, or scheduled by that ask** — no fleet model, no federated training, no data product, no external feed. It is written down for two narrow reasons: so the hook and `ctx` design is not accidentally foreclosed by decisions made for the shield alone, and so the data-governance questions are visible early rather than discovered late.
>
> One consequence worth stating outright, since this page names tooling freely: **almost everything it builds on is proposed and unbuilt** — the `ctx` catalog, the egress ring, and the `tmmtrace` DSL front-end it cites in Tiers 2–3 (a **placeholder name for a proposed utility**; `tmm-usdt-tracepoints.md` §1). Nothing here drains a ring or answers a query.
>
> **One part is no longer proposed, and the distinction matters for how this annex is read.** The *mechanism* — a verified program running in a live TMM at a function the build already emitted, armed and disarmed without a restart — is built and runs. What that buys this annex is narrow but real: the sensor substrate it assumes is no longer hypothetical, so the open questions here are about **what to extract and where to put it**, not about whether a program can run at all. Everything downstream of the hook — the curated `ctx` catalog, aggregation, egress, the collector — remains unbuilt, and the per-call cost that would decide whether any of it is affordable **is still unmeasured**.
>
> **Two pieces here do not depend on the model story at all**, and stand on their own even if nothing else on this page is ever built:
>
> - **§4 Tier 1 and §6 — API discovery, which needs no model.** Deterministic aggregation over structural `ctx`, in observe mode. It is an existing product category and a coherent second use case for the same hooks.
> - **§7 and §7.1 — the OSS and license inventory.** A scoping input for any of this work, including the shield itself.
>
> Everything involving an SLM (small language model), a fleet foundation model, federated training, or any external data offering is a **later, separately-authorized decision** that would need its own data-governance and legal review before it is even a proposal. Read it as a map of what the hooks could reach, not as a plan to reach it.

---

## 1. The vantage, stated honestly

Every observer of enterprise traffic is structurally blind somewhere. **So is the full proxy** — it is simply blind in fewer places. The bounds are documented properties of the platform, so they are stated here rather than left to be found:

| Observer | Structural blindness |
|---|---|
| Endpoint / EDR (endpoint detection & response) | one host; no network context; attacker-disablable |
| NDR (network detection & response) / packet brokers | **ciphertext** — TLS-everywhere ended the wire view |
| SIEM / cloud logs | samples + metadata, after the fact |
| **The full proxy (TMM)** | **real and enumerable:** flows accelerated in **hardware** (ePVA / FPGA / TurboFlex) never enter TMM software at all; **FastL4** paths bypass full-proxy handling; **SSL pass-through** and **client-SSL-only** virtuals are never decrypted end to end; **non-terminated UDP / QUIC** is not in protocol context; and the view is **per box and per TMM instance** — CMP/DAG decides which instance sees a given flow. Where a virtual *does* fully terminate TLS, it sees both sides of that flow, decrypted, in protocol context, at line rate. And note that the **accelerated span is bounded rather than unknown**: the offload decision and its return are TMM software, so how much traffic went to silicon is measurable rather than a blind spot — which is what keeps a zero count interpretable. |

The supportable claim is narrower than "sees everything": **for traffic a virtual actually terminates, this is the least-blind of the four vantages in the table** — the only one of them that is simultaneously post-decrypt, in protocol context, and at line rate. Bounded, and stated as bounded.

Those bounds are not new here. They are the same coverage limits `big-ip-live-shield-design.md` §10 and `tmm-usdt-tracepoints.md` state for enforcement, they are properties of the platform rather than of this proposal, and every counter derived from these hooks has to be read against them — a zero can mean "no attack," "handled in silicon," or "a different TMM instance saw it."

And today even that narrower view **evaporates**: observed once for forwarding, then discarded — *digital exhaust.*

## 2. Why the vantage has gone unused — two constraints, and what the substrate changes

1. **You cannot centralize it.** Exporting decrypted, line-rate application payloads to a central analytics/training system is infeasible (bandwidth) and impermissible (privacy law, data-residency; PII, PHI, PAN — personally identifiable information, protected health information, primary account numbers — and credentials cannot leave the box).
2. **You could not compute on it in place.** Not for want of any inline surface — iRules and WASM both run logic in the data path today (`embedded-ebpf-substrate.md` §1). But neither carries a bound on what it may read that is **established before load**: WASM's memory bounds and its fuel kill are enforced at run time, and TCL's execution time is unbounded in practice. Unbounded-before-load code inline on cleartext application data is the crash-and-leak exposure that keeps those surfaces off bulk analytics.

**The substrate changes the second constraint, and narrows the first.** A bounded in-process program computes on the data *where it lives*, and what leaves the box is the distilled result — a small feature vector, a sketch, an inventory, a scoped report — never the payload.

**Now be precise about what actually holds that line, because it is not a proof.** PREVAIL proves **memory safety over the regions the host declares** (and, only when `--termination` is passed, halting). It proves *nothing* about the **semantics** of what a program returns. A verified program's 64-bit return value can carry eight bytes of a card number, and the verifier has no opinion whatsoever about that. "Data-minimization by proof" is therefore a claim this annex does not make. Three concrete mechanisms do the work instead — defense in depth, not one guarantee:

1. **A declared, minimized `ctx`** — *the host decides what the program can see at all.* For discovery work the default `ctx` is **structural**: method, host, normalized path, header and parameter **names and shapes**, sizes — with values and bodies withheld. Data a program never receives cannot be exfiltrated by it. This is enforced by what the host copies into the per-core `ctx`, not derived by the verifier, and the `ctx` is a per-core scratch copy discarded on fall-through rather than a live window onto TMM state.
2. **A host-owned, schema-checked, one-way sink** — *the program has no egress path of its own.* It returns a value; the **host** writes to the sink (`data-plane-egress-primitives.md` §2). The sink accepts only records matching a declared schema — typed, bounded, fixed fields — and it is one-way and audited. A field absent from the schema has nowhere to go, whatever the program computed.
3. **A signed extractor plus human review** — *the mechanism that addresses semantics.* Which programs may run is decided by **signature and catalog**, not by the verifier: extractors are authored under review, signed, versioned, and auditable, with elevated `ctx` tiers time-boxed and gated by RBAC (role-based access control). A human reading the extractor is what establishes that its output is a shape descriptor and not a smuggled value. No automated check in this design substitutes for that reading.

So the honest form of the claim:

> **The signal leaves the box; the payload does not — because the host chose what the program could see, the host owns the only way out, and only reviewed, signed extractors are admitted.** Held by mechanism and review, not by a theorem about a program's output.

That combination is still a **privacy** story — a data-minimization architecture designed for jurisdictions where centralizing decrypted traffic is not permissible — as well as an **economics** story (kilobytes of signal instead of gigabits of payload) and a **data-quality** story (post-decrypt, in-context, line-rate fidelity, within §1's coverage bounds).

**What it requires:** *both halves* — the vantage (be the proxy) **and** the bounded in-process surface (this substrate). Whether anyone else holds both is a claim about other products' internals that this annex does not make. On the legal side, state only what is established: the verifier and VM carry permissive licenses, so there is **no copyleft in the primary path — subject to the pinned-version SBOM and license scan that `big-ip-live-shield-design.md` §13 (licensing & OSS posture) lists as still to be run**. That is a posture, not a clearance.

## 3. The flywheel — where an F5 model lives

The substrate proposal's framing is that generative AI cannot run at line rate — inference is orders of magnitude too slow for a poll loop, which is exactly why the model is kept out of the data path. The inversion is the opportunity:

> **line-rate truth feeds the models.**

```
 ┌────────────────────┐  features only   ┌────────────────────┐
 │ SENSE              │  (no payload)    │ LEARN              │
 │ bounded probes     │ ───────────────► │ per-box SLM ·      │
 │ distill decrypted  │                  │ fleet foundation   │
 │ line-rate traffic  │                  │ model (federated)  │
 └────────────────────┘                  └─────────┬──────────┘
           ▲                                       │ insight, and
           │ verified bytecode                     │ candidate programs
           │ loads back into the plane             ▼
 ┌─────────┴──────────┐                  ┌────────────────────┐
 │ ADMIT              │ ◄─────────────── │ ACT (proposed)     │
 │ signature · human  │  never straight  │ model drafts a     │
 │ review · verifier  │  to the plane    │ program            │
 └────────────────────┘                  └────────────────────┘
```

**Sense → learn → act**, on one substrate, with the model deliberately kept *out* of the inline trust path: it proposes, a human plus the signature and catalog admit, the verifier bounds memory safety, and the **host** selects the action from its own set — PASS · DROP · RESET · SAFE-RETURN · STEER · SAMPLE (`embedded-ebpf-substrate.md` §2). A program never performs an action; it selects one the host owns. Closing this loop needs both halves of §2, which is what would make it hard to copy.

An **F5 Traffic model** trained federated across the fleet — features and gradients move, payloads stay on the box — would be trained on **post-decrypt, in-protocol-context behavior from the enterprise-application tier**. That description of the training distribution is the bounded version of the claim, and it is the one to make. "The model that has seen more application-layer behavior than anything on earth" is a claim about other operators' data volumes and is not supportable. **All of this is annex material**: federated training over customer traffic is a separate decision with its own governance review — see the note at the top of this page.

### 3.1 The "learn" tier — models & learning paradigms

The learn node isn't one model; it's a tier, and the right technique shifts with **where inference must run** and **what labels you have.**

**By placement — SLM ↔ foundation model ↔ LLM (large language model):**

| Where | Model | Job |
|---|---|---|
| **On-box** (control plane) | **SLM** — compact scorers: distilled small transformers, gradient-boosted trees, streaming anomaly detectors | real-time scoring of the live feature stream; arm / parameterize monitor programs; self-tuning decisions — **no fleet round-trip, data stays local** |
| **Fleet** | **Foundation model** — larger, trained **federated** on aggregated features | learn cross-tenant / per-industry norms and representations; ship distilled task heads + model updates back down to every box |
| **Human-facing** (heavier, likely off-box) | **LLM** — generative | RCA narratives; natural-language → verified probe via the proposed `tmmtrace` front-end; and — via the shield pipeline — drafting candidate verified programs (the *act* arrow), **human-gated and verifier-admitted** |

**By supervision — mostly unsupervised early, by necessity:**

- **Unsupervised / self-supervised — the workhorse.** You start with *no labels.* Self-supervised pretraining (masked / contrastive / next-event objectives over sequences of protocol events) learns representations of *normal*; unsupervised methods (clustering, density estimation, autoencoder reconstruction error, isolation forests) flag drift and novelty. Most early value lives here — zero-day *behavior*, baselining, API drift — none of it needs a labeled corpus.
- **Supervised — where labels exist.** Known-bad from the exploit-replay corpus / CVE PoCs / confirmed incidents; known-good from the legitimate-traffic corpus. Trains classifiers (exploit-behavior, exfil, bot) and the shield **false-positive oracle**.
- **Weak / semi-supervised — cheap labels, not free ones.** The enforce loop manufactures **labelled predicate matches**: a shield block records that a predicate fired, and the combined-play flight recorder captures the exact attempt. A match is not yet a confirmed positive — the false-positive oracle described in this same section exists *precisely because* predicates also fire on legitimate traffic, and treating every block as ground truth would train the classifier on the shield's own errors, then use that classifier to justify them. So the label is genuine weak supervision: it needs the flight-recorder capture plus human or oracle adjudication before it counts as a positive. Cheap and useful at volume — the security and data theses compounding again — but **adjudicated, not assumed**.
- **Bounded feedback — the act step.** Self-tuning is a closed control loop, but note where the program sits in it: **the program emits a scalar recommendation and the host's controller applies it** within sanctioned bounds, observes the resulting feature, and adapts. Knob-setting is not a member of the canonical outcome set, and it must not become one — a program never performs an action, it selects or recommends one the host already owns. Control-flavored, and deliberately **not** open-ended reinforcement learning in the data path.

**The maturity curve (which is also the build order):** deterministic aggregation (the API-discovery MVP — *no model*) → unsupervised anomaly / baselining → supervised heads as labels accumulate → federated self-supervised foundation model → generative authoring (LLM), every output still admitted by the verifier. Each stage ships value on its own; none blocks on the next.

## 4. Use cases, tiered by what to build

**Tier 1 — on-box, no model required.** This is the tier that **stands independently of everything else on this page**: no model, no fleet, no federated training, no data-governance escalation. It is a second use case for the same hooks, and it holds whether or not the rest of this annex is ever pursued.

- **API discovery & schema drift** — live inventory of endpoints, schemas, and sensitive-field exposure, computed in-situ; only the inventory exports. *An existing product category; the MVP (minimum viable product) worked in §6, and the only item here that is a candidate for near-term work.*
- **Behavioral baselining / zero-day-behavior detection** — rolling per-virtual-server feature vectors (protocol-state transitions, timing, entropy, response-size distributions); flag drift (exploit behavior, credential stuffing, bot waves) and **select a pre-signed monitor-mode program from the catalogue** to arm on the suspect hook — under a standing authorization and with an audit record, never by authoring bytecode on the box. The signature, not the model's judgement, stays the perimeter.
- **Encrypted-blind-spot detection** — beaconing periodicity, exfil entropy, malware staging present only in *decrypted server-side* streams, which is to say only inside a terminating proxy.

**Tier 2 — small on-box model (SLM):**
- **RCA copilot** — reads the flight-recorder ring + `tmmtrace` histograms on an incident, writes the root-cause narrative, and *proposes the next probe to load* to confirm it.
- **Self-tuning** — features → predicted optimal knobs (buffer sizing, LB weights, reuse policy) per-tenant per-time-of-day; verified programs **recommend** them as scalars and the host's controller applies them within sanctioned bounds — the program never writes host config.

**Tier 3 — fleet-scale foundation model (the factory):**
- **F5 Traffic Foundation Model** — trained federated on anonymized fleet features; its output is consumed **inside the product** — detection, self-tuning, and pre-trained anomaly heads shipped back down to every box as *signed programs + model updates*.
- **A stronger shield factory** — the AI-shield pipeline's false-positive oracle graduates from synthetic corpora to *real fleet traffic distributions*, so the corpus a machine-authored shield is tested against is the traffic it will meet. (The security and data theses reinforce each other.)
- **`tmmtrace` copilot** — plain English → verified probe, grounded on the signed hook-point map; opens the surface to any engineer who can state the question.
- **Scoped exposure reports** — computed in-situ and surfaced as a *box capability*. Not an attested negative: "no PAN crossed this boundary unencrypted" is a claim the box cannot support, because §1's coverage bounds (offload, FastL4, pass-through, non-terminated UDP) plus any sampling divisor mean it does not see every flow, and a negative over unobserved traffic is not evidence of anything. The supportable form is a **scoped positive**: *"N flows inspected on virtual X between T1 and T2; zero class-Y matches; coverage caveats attached."* Statements *about* observed data rather than the data itself — and explicit about what was never observed.

> **Two places the output could go, and they are not equivalent.** Consumed **inside the product**, the output is fleet intelligence that makes every F5 box detect more and tune itself. Sold as an **external data feed**, it is a regulated-data-broker offering, subject to a legal and commercial review this annex does not attempt and which nothing above depends on. Only the first is described here.

## 5. Recommended build order

Start with **Tier 1 API discovery.** It is an existing market, needs no model, and proves the core mechanic end to end — *compute in-situ, export only the signal, and keep the payload on the box by construction*: a minimized `ctx`, a host-owned schema-checked sink, and a signed, reviewed extractor (§2 — three mechanisms, not a proof). That de-risks everything above it: once "signed extractor plus host-owned one-way sink" is shipping for one use case, the SLM and fleet tiers are additive rather than foundational.

It is also the one piece of the annex that **stands on its own**, independent of whether any model story is ever pursued. Everything after it in this build order is a later, separately-authorized decision.

## 6. Reference architecture — the API-discovery MVP

**Why this one first.** API discovery, schema-drift, and sensitive-data-exposure mapping is an existing security market, needs **no model** (deterministic aggregation plus light classification), runs entirely in **observe mode** (so no program ever selects an outcome), and it exercises the whole *bounded-extractor plus host-owned-sink* mechanic end to end.

**On cost, be precise rather than reassuring.** The hook is **per-request `warm`** in the structural sense — each invocation is amortized against tens of µs of request processing, which is the reason it is affordable at all. But it fires on **every request**, and request rate is something an attacker controls. So it is *not* condition-scoped, and it does not escape the budget question: it carries a **measured per-invocation budget** and a **sampling divisor under load**, and for budgeting purposes an attacker-reachable per-request hook has to be treated at its adversarial rate, not its steady-state one. `tmm-usdt-tracepoints.md`'s class for the same request hook should be read the same way — structure (`warm`) **∧** adversarial reachability. Ship this and the SLM/fleet tiers are additive, not foundational.

```
 ┌────────────────────────── per box (TMM data plane) ──────────────────────────┐
 │  cleartext L7 traffic ─►  [ hooks: request-parse · response-parse ]          │
 │                             │  per-core ctx COPY, discarded on fall-through: │
 │                             │  method · path · header/param NAMES + shapes   │
 │                             │  (values & bodies withheld — ctx minimization) │
 │                             ▼                                                │
 │                   ┌──────────────────────┐                                   │
 │  BOUNDED          │ known / new endpoint │  returns a SCALAR                 │
 │  extractor        │ shape ok / drifted   │  selector + tag —                 │
 │  (observe mode,   │ class flag [tier 2]  │──────┐  NOT a record              │
 │   no helpers,     └──────────────────────┘      ▼                            │
 │   no emit)                         ┌──── host aggregation ─────────┐         │
 │                                    │ the HOST builds the record    │         │
 │                                    │ from declared ctx fields:     │         │
 │                                    │ endpoint sig · name-set/HLL   │         │
 │                                    │ shape schema · counters       │         │
 │                                    │ drift window · class-exp map  │         │
 │                                    └──────────────┬────────────────┘         │
 └───────────────────────────────────────────────────┼──────────────────────────┘
                   ┌──────── control plane ───────┐  │ snapshot
                   │ inventory synthesis + drift  │◄─┘ one-way, schema-checked
                   │ diff → events                │    sink — derived inventory
                   └───────────────┬──────────────┘    ONLY, never raw payload
                                   ▼
      API inventory · schema catalog · drift alerts · sensitive-exposure map
      surfaced on the box (console / iControl REST / SIEM) — a product capability
                                   │  (optional, later — separately authorized)
                                   ▼
      fleet: inventory deltas / schema fingerprints → per-industry API norms
      → sharper drift/anomaly detection shipped back down (payloads stay put)
```

1. **Hooks (sensors).** Designed-in L7 observe hooks at request- and response-parse. The `ctx` is a **per-core scratch copy** of curated fields, built by the host and **discarded on fall-through** — not a live window onto TMM state, because a verified program can write every byte of its `ctx`. The signed hook-point map exposes, in the **base tier**, only **structural** fields: method, host, path, header/param *names* and *shapes* (string/int/array/object), sizes — with values and bodies **withheld**.
2. **Bounded extractor (observe mode, no helpers, no emit) — returns a scalar, not a record.** A small program per hook, a pure function of `ctx`, that returns a **scalar**: a selector plus a small tag (*endpoint unseen*, *shape drifted*, a bucket id). It does **not** return a multi-field record, and it does not emit anything. Under the Phase-1 contract the program signals and the **host** emits (`data-plane-egress-primitives.md` §2, §5.3), which matters here because a program-computed multi-field record is either an **emit helper** or a **program-writable output region** — both explicitly Phase 2 (`data-plane-egress-primitives.md` §7), and the writable-region form is the worse of the two given that `ctx` writes are permitted. So the phase-1 shape of this MVP is: **scalar out of the program, record assembled by the host.** If a later phase wants a true record-emit helper, that is a named Phase-2 decision carrying verifier and ABI cost — not something to assume here.
3. **Sensitive-class detection is a second tier, not the base tier.** The tension is internal to the design and is stated rather than left implicit: value detectors — **Luhn** for a PAN, pattern classes for email or SSN — *need the digits*, and the base-tier `ctx` in step 1 withholds values. The base MVP therefore **cannot** run its own headline detector, and that is a phasing fact rather than a defect. Class detection is a **separately-authorized `ctx` tier**: redact-by-default, RBAC-gated, time-boxed with auto-retirement, its bounded detectors running over explicitly declared value fields and returning only a **class label** ("PAN present"), never the value. Ship the structural base tier first; add the class tier as MVP phase 2, through its own authorization path. The diagram marks it `[tier 2]` for this reason.
4. **Host aggregation (per box).** The host owns compact per-endpoint state — a name-set or HLL (HyperLogLog cardinality sketch) for the schema, shape descriptors, volume and status counters, a rolling window for **drift** (new endpoint, new field, changed shape), and a **class-exposure map** — and it is the *host* that derives the **endpoint signature** (a hash of method plus a path normalized to a template, `/users/{id}`) from declared `ctx` fields. The program's scalar selects and tags; the host records. Host-owned structures are the Phase-1 stand-in for program-reachable maps, which are the deferred helper/map tier.
5. **Inventory synthesis (control plane).** A collector snapshots the aggregates into a normalized **API inventory + schema catalog + exposure report**, diffs against the prior snapshot, and raises **events** — shadow endpoint appeared, schema changed, new sensitive-field exposure.
6. **Egress / surfacing.** The report — and optionally a **scoped emission log** ("across these N snapshots the sink accepted only these declared fields; audit trail attached") — is the *only* thing exported, through the host-owned, schema-checked, one-way audited sink, to the box's own console / iControl REST / SIEM. Never payloads. Be exact about what that log is: it is **the host's record of its own sink**, which is a real and useful audit artifact, and it is *not* a proof about what the extractor computed, nor a statement about traffic the box never saw (§1).
7. **Fleet (optional, later, separately authorized).** Boxes would contribute **inventory deltas / schema fingerprints** (not payloads) to a fleet aggregator that learns cross-tenant and per-industry API norms, and those norms would feed back to sharpen each box's detection. Federated, with raw data confined at the extractor. This step is annex material even within the MVP: nothing above it depends on it, and it needs its own governance review before it is proposed.
8. **Governance.** SIRT-authored, signed, catalogued programs — signature and catalog, not the verifier, decide what may load; RBAC gating any sensitive-value inspection (step 3); `ctx` minimization by default; tamper-evident audit of what was extracted; time-boxed auto-retirement for any elevated-inspection probe.

**What ships:** an F5 **API-discovery & posture** capability *on the box* — inventory, drift, and exposure delivered to the box's own console. Per §4, the output is consumed inside the product rather than sold as a feed.

## 7. Build vs. reuse — the open-source floor

Most of the pipeline (§3.1) assembles from mature, permissively-licensed open source; the net-new work is the bounded in-process surface and the host-owned sink. This section and §7.1 are the part of the annex that is useful **immediately and unconditionally** — they hold regardless of whether the model story above is ever pursued, and the *Sense* row alone is the license inventory for the Tier 1 MVP and for the substrate itself.

| Stage | Reuse (open source) | Build (net-new) |
|---|---|---|
| **Sense** | uBPF + PREVAIL (VM + verifier), clang/LLVM + libbpf/BTF (compile, typed CO-RE), Apache DataSketches / t-digest (HLL, count-min, quantiles), Feast (feature store) | the **verified in-situ extractor** + the `tmmtrace` DSL, the signed TMM hook-point map + `ctx`/BTF, and the **host-owned schema-checked one-way sink** (§2 mechanism 2) |
| **Learn** | PyTorch / JAX (training), PyOD · River · XGBoost (anomaly, SLM), HuggingFace Transformers (sequence SSL), Flower or NVIDIA FLARE (federated) + Opacus (DP), ONNX Runtime · llama.cpp (on-box inference) | the **protocol-event feature schema & self-supervised objective**, federation bound to the host-confined sensor of §2, and the model-registry → signed-program bridge |
| **Act** | PREVAIL (reuse the gate), clang/LLVM, Sigstore/cosign + in-toto + TUF (sign, attest, distribute), Outlines · llguidance (grammar-constrained LLM output) | the **model-output → DSL candidate** synthesis, the **verifier-as-oracle refine loop**, and the **lifecycle engine** (observe-first, catalog, auto-retire, kill-switch) |

The reuse column is a permissive open-source floor — the same posture as the core VM + verifier (`big-ip-live-shield-design.md` §13 (licensing & OSS posture)). The build column is where F5's value lives.

### 7.1 Reference implementations (for OSPO / engineering scoping)

License + repo per candidate. **Run the SBOM/license scan described in `big-ip-live-shield-design.md` §13 (licensing & OSS posture) on pinned versions before shipping** — transitive trees drift.

**Sense**
- **uBPF** — Apache-2.0 — `github.com/iovisor/ubpf`
- **PREVAIL** (`ebpf-verifier`) — MIT — `github.com/vbpf/ebpf-verifier`
- **LLVM/clang** (BPF target) — Apache-2.0 w/ LLVM exception — `github.com/llvm/llvm-project`
- **libbpf** — LGPL-2.1 **OR** BSD-2-Clause (dual) — `github.com/libbpf/libbpf`
- **Apache DataSketches** (C++) — Apache-2.0 — `github.com/apache/datasketches-cpp`
- **t-digest** — Apache-2.0 — `github.com/tdunning/t-digest`
- **Feast** (feature store) — Apache-2.0 — `github.com/feast-dev/feast`
- egress/telemetry: **OpenTelemetry** — Apache-2.0; **Vector** — MPL-2.0 — `github.com/vectordotdev/vector`  · *(avoid Redpanda — BSL, source-available, not OSI; use Kafka/NATS if a broker is needed)*

**Learn**
- **PyTorch** — BSD-3 — `github.com/pytorch/pytorch` · **JAX** — Apache-2.0 — `github.com/google/jax`
- **PyOD** — BSD-2 · **River** — BSD-3 · **XGBoost** — Apache-2.0 · **LightGBM** — MIT
- **HuggingFace Transformers** — Apache-2.0 — `github.com/huggingface/transformers`
- **Flower** — Apache-2.0 — `github.com/adap/flower` · **NVIDIA FLARE** — Apache-2.0 — `github.com/NVIDIA/NVFlare`
- **Opacus** (differential privacy) — Apache-2.0 — `github.com/pytorch/opacus`
- on-box inference: **ONNX Runtime** — MIT — `github.com/microsoft/onnxruntime` · **llama.cpp** — MIT — `github.com/ggml-org/llama.cpp`

**Act**
- **PREVAIL** (reuse the gate) — MIT
- **Sigstore/cosign** — Apache-2.0 — `github.com/sigstore/cosign`
- **in-toto** (supply-chain attestation) — Apache-2.0 — `github.com/in-toto/in-toto`
- **TUF** (`python-tuf`) — MIT/Apache-2.0 — `github.com/theupdateframework/python-tuf`
- grammar-constrained generation: **Outlines** — Apache-2.0 — `github.com/dottxt-ai/outlines` · **llguidance** — MIT/Apache — `github.com/guidance-ai/llguidance`

> **Licensing posture.** Every candidate above is permissive (Apache / BSD / MIT), with two footnotes for counsel: **MPL-2.0** (Vector) is *file-level* copyleft — fine when consumed as a separate binary, not statically linked; **Redpanda is BSL** (source-available, **not** OSI-approved) — excluded here. This mirrors the core substrate's posture; the same SBOM scan (`big-ip-live-shield-design.md` §13 (licensing & OSS posture)) applies, and — as that section says — it has not been run yet.

## 8. Governance as a property of the mechanism

Because the `ctx` is minimized by the host, egress is host-owned and schema-checked, and extractors are signed and reviewed (§2's three mechanisms), the same controls apply however far the data use grows. What the box can be asked to do is bounded, narrowly and checkably:

> **F5 runs a reviewed, signed transform that can only see declared fields, can only emit through a schema-checked one-way sink, and the host keeps an audit log of what that sink accepted.**

Say exactly that and no more. The audit log attests the host's own record of its own sink — not a theorem about what the program computed, and not a claim about traffic the box never saw (§1). Data-minimization, residency, and auditability are properties of the mechanism rather than overlays on it, which is what makes the architecture viable at a TLS boundary in jurisdictions where centralizing the payload is not permissible. Whether any of it is *monetized*, and on what legal basis, is a separate business and legal question this annex deliberately does not answer.

## 9. One-line thesis

**A bounded data plane could make the proxy a sensory organ for AI — turning traffic that only a terminating proxy sees into governed signal that never has to move, and closing the loop by letting models return to the plane as signed, verifier-admitted bytecode.**

**Annex, and out of scope.** This page is a map of what the same hooks could later reach; every stage of it is a separately-authorized decision, and only two pieces stand on their own today — Tier 1 API discovery (§4, §6) and the OSS/license inventory (§7, §7.1).
