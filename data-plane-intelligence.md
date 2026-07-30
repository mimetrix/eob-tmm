# Data-Plane Intelligence — the proxy as AI's sensory organ

### The programmable-data-plane substrate is not only a way to *change* TMM; it is a way to *harvest* what only TMM can see — safely, and without moving the data.

**Status:** Strategy / opportunity framing
**Audience:** F5 product & strategy, TMOS architecture, F5 SIRT, data/ML leadership, OSPO
**Companion:** `embedded-ebpf-substrate.md` (the substrate), `big-ip-live-shield-design.md` (the security instance) · *Detailed method & claims are held in a separate invention disclosure, per IP policy.*
**Scope:** What the verified in-process substrate unlocks when it is pointed not at *behavior* but at *data* — and the flywheel that connects the two.

---

## 1. The vantage, stated as a moat

Every observer of enterprise traffic is structurally blind somewhere — except the full proxy:

| Observer | Structural blindness |
|---|---|
| Endpoint / EDR | one host; no network context; attacker-disablable |
| NDR (network detection & response) / packet brokers | **ciphertext** — TLS-everywhere ended the wire view |
| SIEM / cloud logs | samples + metadata, after the fact |
| **The full proxy (TMM)** | *none* — it **terminates TLS**, so it sees **both sides of every flow, decrypted, in protocol context, at line rate** |

This is the most complete view of enterprise application traffic that exists anywhere. And today it **evaporates**: observed once for forwarding, then discarded — *digital exhaust.*

## 2. Why the vantage has been worthless — a two-part lock only F5 can open

1. **You cannot centralize it.** Exporting decrypted, line-rate application payloads to a central analytics/training system is infeasible (bandwidth) and impermissible (privacy law, data-residency, PII/PHI/PAN/credentials cannot leave the box).
2. **You could not compute on it in place.** TMM has been too opaque and rigid to run analytic code inline — and even if you could, unbounded code inline on decrypted traffic is exactly the crash-and-leak risk no one will accept.

**The verified substrate opens both locks at once.** A verified in-process program computes on the data *where it lives* and exports **only the distilled result** — a small feature vector, a sketch, an inventory, an attestation — not the payload. The verifier proves the program can read only declared fields; the host — not the program — owns the schema-checked, one-way sink it emits through. So:

> **The signal leaves the box; the data never does — and that's provable, not promised.**

That single property is simultaneously a **privacy** story (data-minimization by proof — the only compliant way to do this at a TLS boundary), an **economics** story (kilobytes of signal instead of gigabits of payload), and a **data-quality** story (post-decrypt, in-context, line-rate fidelity nobody else has).

**Why it's defensible:** replicating it requires *both halves* — the vantage (be the proxy) **and** the verified in-process surface (this substrate). No pure-play security or observability vendor has the first; no proxy without this substrate has the second. The OSS licensing of the substrate's verifier and VM is permissive (see `big-ip-live-shield-design.md` §13), so the surface is legally F5's to build and ship.

## 3. The flywheel — where an F5 model lives

The proposal's hero line is that generative AI cannot do line-rate processing. The inversion is the opportunity:

> **line-rate truth feeds the models.**

```
  probes distill decrypted line-rate traffic  ──►  features (payload confined by proof)
        ▲                                                    │
        │                                                    ▼
  verified programs load back into the plane        train F5 models (per-box SLM + fleet foundation model)
  (proven safe — model never in the trust path)             │
        ▲                                                    ▼
        └────────────  models emit insight AND author new verified programs  ◄──┘
```

**Sense → learn → act**, on one substrate, with the "act" step's blast radius bounded by proof and the model deliberately kept *out* of the inline trust path (it proposes; the verifier admits; the host acts). No competitor closes this loop, because closing it needs both halves of §2. An **F5 Traffic model**, trained federated across the fleet (features and gradients move; payloads never leave the box), becomes *the model that has seen more real application-layer behavior than anything on earth* — a data moat, not a feature.

### 3.1 The "learn" tier — models & learning paradigms

The learn node isn't one model; it's a tier, and the right technique shifts with **where inference must run** and **what labels you have.**

**By placement — SLM ↔ foundation model ↔ LLM:**

| Where | Model | Job |
|---|---|---|
| **On-box** (control plane) | **SLM** — compact scorers: distilled small transformers, gradient-boosted trees, streaming anomaly detectors | real-time scoring of the live feature stream; arm / parameterize monitor programs; self-tuning decisions — **no fleet round-trip, data stays local** |
| **Fleet** | **Foundation model** — larger, trained **federated** on aggregated features | learn cross-tenant / per-industry norms and representations; ship distilled task heads + model updates back down to every box |
| **Human-facing** (heavier, likely off-box) | **LLM** — generative | RCA narratives; `tmmtrace` natural-language → verified probe; and — via the shield pipeline — drafting candidate verified programs (the *act* arrow), **human-gated and verifier-admitted** |

**By supervision — mostly unsupervised early, by necessity:**

- **Unsupervised / self-supervised — the workhorse.** You start with *no labels.* Self-supervised pretraining (masked / contrastive / next-event objectives over sequences of protocol events) learns representations of *normal*; unsupervised methods (clustering, density estimation, autoencoder reconstruction error, isolation forests) flag drift and novelty. Most early value lives here — zero-day *behavior*, baselining, API drift — none of it needs a labeled corpus.
- **Supervised — where labels exist.** Known-bad from the exploit-replay corpus / CVE PoCs / confirmed incidents; known-good from the legitimate-traffic corpus. Trains classifiers (exploit-behavior, exfil, bot) and the shield **false-positive oracle**.
- **Weak / semi-supervised — labels for free.** The enforce loop *manufactures* labels: every shield block is a confirmed positive, and the combined-play flight recorder captures the exact attempt. A few confirmed labels propagate across the unlabeled mass — the security and data theses compounding again.
- **Bounded feedback — the act step.** Self-tuning is a closed control loop: adjust a knob within host-sanctioned bounds, observe the resulting feature, adapt. Control-flavored, and deliberately **not** open-ended reinforcement learning in the data path.

**The maturity curve (which is also the build order):** deterministic aggregation (the API-discovery MVP — *no model*) → unsupervised anomaly / baselining → supervised heads as labels accumulate → federated self-supervised foundation model → generative authoring (LLM), every output still admitted by the verifier. Each stage ships value on its own; none blocks on the next.

## 4. Use cases, tiered by what to build

**Tier 1 — on-box, no model required (prove the thesis cheaply):**
- **API discovery & schema drift** — live inventory of endpoints, schemas, and sensitive-field exposure, computed in-situ; only the inventory exports. *An existing product category, fed for free — the recommended MVP.*
- **Behavioral baselining / zero-day-behavior detection** — rolling per-virtual-server feature vectors (protocol-state transitions, timing, entropy, response-size distributions); flag drift (exploit behavior, credential stuffing, bot waves) and auto-arm a monitor-mode program on the suspect hook.
- **Encrypted-blind-spot detection** — beaconing periodicity, exfil entropy, malware staging visible only in *decrypted server-side* streams — signals NDR physically cannot see.

**Tier 2 — small on-box model (SLM):**
- **RCA copilot** — reads the flight-recorder ring + tmmtrace histograms on an incident, writes the root-cause narrative, and *proposes the next probe to load* to confirm it.
- **Self-tuning** — features → predicted optimal knobs (buffer sizing, LB weights, reuse policy) per-tenant per-time-of-day; verified programs nudge them within host-sanctioned bounds.

**Tier 3 — fleet-scale foundation model (the factory):**
- **F5 Traffic Foundation Model** — trained federated on anonymized fleet features; its value is realized **inside the product** — sharper detection, self-tuning, and pre-trained anomaly heads shipped back down to every box as *signed programs + model updates* that competitors cannot source the data to match.
- **A stronger shield factory** — the AI-shield pipeline's false-positive oracle graduates from synthetic corpora to *real fleet traffic distributions*; fleet data makes machine-authored shields measurably safer. (The security and data theses reinforce each other.)
- **tmmtrace copilot** — plain English → verified probe, grounded on the signed hook-point map; democratizes the surface to any SE or support engineer.
- **Compliance attestations** — computed in-situ ("no PAN crossed this boundary unencrypted, evidence attached") and surfaced as a *box capability* — *proofs about* data rather than data.

> **Where the value is captured — the product first.** The compounding advantage is a **better proxy**: fleet intelligence that makes every F5 box detect more, tune itself, and gain capabilities no competitor can source the data to match. **Selling the raw intelligence as an external data feed is a secondary, optional, and fraught path** — it commoditizes the edge, drags F5 into the regulated-data-broker business, and competes with the security vendors and customers F5 sells through. Capture the value in the product; treat any external data offering as a deliberate, later choice, not the plan.

## 5. Recommended build order

Start with **Tier 1 API discovery.** It is an existing market, needs no model, and proves the core mechanic end-to-end — *compute in-situ, export only the signal, prove the payload stayed put*. That de-risks everything above it: once "verified extractor + proof-bounded egress" is shipping for one use case, the SLM and fleet tiers are additive, not foundational.

## 6. Reference architecture — the API-discovery MVP

**Why this one first.** API discovery, schema-drift, and sensitive-data-exposure mapping is the lowest-risk, highest-leverage entry point: it's an existing security market, needs **no model** (deterministic aggregation + light classification), runs entirely in **observe mode** (no enforcement risk; per-request/warm, condition-scoped — no hot-path budget fight), and it exercises the whole *verified-extractor + proof-bounded-egress* mechanic end to end. Ship this and the SLM/fleet tiers are additive, not foundational.

```
 ┌───────────────────────────── per box (TMM data plane) ──────────────────────────────┐
 │  cleartext L7 traffic ─►  [ hooks: request-parse · response-parse ]                   │
 │                             │  typed ctx: method, path, header/param NAMES + shapes   │
 │                             │  (values & bodies withheld by default — ctx minimization)│
 │                             ▼                                                          │
 │                   ┌──────────────────────┐  returns a bounded record                  │
 │  VERIFIED         │ endpoint signature,  │──────────────────────┐                     │
 │  extractor        │ param/field shapes,  │                      ▼                     │
 │  (observe,        │ sensitive-CLASS flags│        ┌──────── host aggregation ───────┐ │
 │   no helpers)     └──────────────────────┘        │ per endpoint: name-set/HLL,      │ │
 │                                                    │ shape schema, counters, rolling  │ │
 │                                                    │ window (drift), class-exposure   │ │
 │                                                    └───────────────┬──────────────────┘ │
 └────────────────────────────────────────────────────────────────────┼──────────────────┘
                       ┌──────── control plane ────────┐               │ snapshot
                       │ inventory synthesis + drift    │◄──── one-way, schema-checked sink
                       │ diff → events                  │      (derived inventory ONLY —
                       └───────────────┬────────────────┘       never raw payload)
                                       ▼
        API inventory · schema catalog · drift alerts · sensitive-exposure map
        surfaced on the box (console / iControl REST / SIEM) — a product capability
                                       │  (optional, later)
                                       ▼
        fleet: inventory deltas / schema fingerprints → per-industry API norms
        → sharper drift/anomaly detection shipped back down (payloads confined)
```

1. **Hooks (sensors).** Designed-in L7 observe hooks at request- and response-parse. The signed hook-point map exposes, by default, only **structural** `ctx` — method, host, path, header/param *names* and *shapes* (string/int/array/object), sizes — with values and bodies **withheld**. Sensitive-value inspection is a separately-authorized, redact-by-default capability that yields only a **class label** ("PAN present"), never the value.
2. **Verified extractor (observe-mode, no helpers).** A small program per hook returns a bounded record: an **endpoint signature** (hash of method + a path normalized to a template, `/users/{id}`), **param/field shape descriptors**, and **sensitive-class flags** (bounded detectors — Luhn for PAN, pattern classes for email/SSN — over declared fields). Pure function of `ctx`; the verifier proves it reads only declared fields and returns only the record, so only structural/derived output can leave.
3. **Host aggregation (per box).** The host owns compact per-endpoint state — a name-set/HLL for the schema, shape descriptors, volume/status counters, a rolling window for **drift** (new endpoint, new field, changed shape), and a **class-exposure map**. (Base tier: program returns records, host owns the maps — no helpers.)
4. **Inventory synthesis (control plane).** A collector snapshots the aggregates into a normalized **API inventory + schema catalog + exposure report**, diffs against the prior snapshot, and raises **events** — shadow endpoint appeared, schema changed, new sensitive-field exposure.
5. **Egress / surfacing.** The report — and optionally a **compliance attestation** ("no raw field of class X emitted") — is the *only* thing exported, through the one-way audited sink, to the box's own console / iControl REST / SIEM. Never payloads.
6. **Fleet (optional, later).** Boxes contribute **inventory deltas / schema fingerprints** (not payloads) to a fleet aggregator that learns cross-tenant/industry API norms; those norms feed back to sharpen each box's detection. Federated; raw confined at the extractor.
7. **Governance.** SIRT-authored signed programs; RBAC gating any sensitive-value inspection; context minimization by default; tamper-evident audit of what was extracted; time-boxed auto-retirement for any elevated-inspection probe.

**What ships:** an F5 **API-discovery & posture** capability *on the box* — inventory, drift, and exposure delivered to the customer's own console, and at fleet scale the baselines that make detection better. Per §5, the value is captured in the product, not sold as a raw feed.

## 7. Build vs. reuse — the open-source floor

Most of the pipeline (§3.1) assembles from mature, permissively-licensed open source; the **net-new work is exactly what the invention disclosures cover.**

| Stage | Reuse (open source) | Build (net-new) |
|---|---|---|
| **Sense** | uBPF + PREVAIL (VM + verifier), clang/LLVM + libbpf/BTF (compile, typed CO-RE), Apache DataSketches / t-digest (HLL, count-min, quantiles), Feast (feature store) | the **verified in-situ extractor** + `tmmtrace` DSL, the signed TMM hook-point map + `ctx`/BTF, and the **host-owned schema-checked one-way sink** (proof-bounded egress) |
| **Learn** | PyTorch / JAX (training), PyOD · River · XGBoost (anomaly, SLM), HuggingFace Transformers (sequence SSL), Flower or NVIDIA FLARE (federated) + Opacus (DP), ONNX Runtime · llama.cpp (on-box inference) | the **protocol-event feature schema & self-supervised objective**, federation bound to the *proof-confined* sensor, and the model-registry → signed-program bridge |
| **Act** | PREVAIL (reuse the gate), clang/LLVM, Sigstore/cosign + in-toto + TUF (sign, attest, distribute), Outlines · llguidance (grammar-constrained LLM output) | the **model-output → DSL candidate** synthesis, the **verifier-as-oracle refine loop**, and the **lifecycle engine** (observe-first, catalog, auto-retire, kill-switch) |

The reuse column is a permissive open-source floor — the same posture as the core VM + verifier (`big-ip-live-shield-design.md` §13). The build column is where F5's value lives.

### 7.1 Reference implementations (for OSPO / engineering scoping)

License + repo per candidate. **Run the `big-ip-live-shield-design.md` §13 SBOM/license scan on pinned versions before shipping** — transitive trees drift.

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

> **Licensing posture.** Every candidate above is permissive (Apache / BSD / MIT), with two footnotes for counsel: **MPL-2.0** (Vector) is *file-level* copyleft — fine when consumed as a separate binary, not statically linked; **Redpanda is BSL** (source-available, **not** OSI-approved) — excluded here. This mirrors the core substrate's posture; the same SBOM scan (`big-ip-live-shield-design.md` §13) applies.

## 8. Governance is the feature, not the friction

Because extraction is verifier-bounded and egress is host-owned and schema-checked, the privacy posture *strengthens* as the data use grows: what could have been "F5 reads your decrypted traffic" becomes "F5 runs a **proven** transform that can only emit **declared** derived signal, and can attest that it did." Data-minimization, residency, and auditability are properties of the mechanism, not overlays on top of it — which is exactly what makes this monetizable at a regulated TLS boundary where centralization is forbidden.

## 9. One-line thesis

**The verified data plane makes the proxy AI's sensory organ — turning traffic only F5 can see into governed signal it never has to move, and closing the loop by letting models return to the plane as verified bytecode.** *Method and claims are held in a separate invention disclosure, per IP policy.*
