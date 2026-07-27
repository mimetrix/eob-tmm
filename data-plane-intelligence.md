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
| NDR / packet brokers | **ciphertext** — TLS-everywhere ended the wire view |
| SIEM / cloud logs | samples + metadata, after the fact |
| **The full proxy (TMM)** | *none* — it **terminates TLS**, so it sees **both sides of every flow, decrypted, in protocol context, at line rate** |

This is the most complete view of enterprise application traffic that exists anywhere. And today it **evaporates**: observed once for forwarding, then discarded — *digital exhaust.*

## 2. Why the vantage has been worthless — a two-part lock only F5 can open

1. **You cannot centralize it.** Exporting decrypted, line-rate application payloads to a central analytics/training system is infeasible (bandwidth) and impermissible (privacy law, data-residency, PII/PHI/PAN/credentials cannot leave the box).
2. **You could not compute on it in place.** TMM has been too opaque and rigid to run analytic code inline — and even if you could, unbounded code inline on decrypted traffic is exactly the crash-and-leak risk no one will accept.

**The verified substrate opens both locks at once.** A verified in-process program computes on the data *where it lives* and exports **only the distilled result** — a small feature vector, a sketch, an inventory, an attestation — not the payload. The verifier proves the program can read only declared fields and emit only through a host-owned, schema-checked, one-way sink. So:

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

## 4. Use cases, tiered by what to build

**Tier 1 — on-box, no model required (prove the thesis cheaply):**
- **API discovery & schema drift** — live inventory of endpoints, schemas, and sensitive-field exposure, computed in-situ; only the inventory exports. *An existing product category, fed for free — the recommended MVP.*
- **Behavioral baselining / zero-day-behavior detection** — rolling per-virtual-server feature vectors (protocol-state transitions, timing, entropy, response-size distributions); flag drift (exploit behavior, credential stuffing, bot waves) and auto-arm a monitor-mode program on the suspect hook.
- **Encrypted-blind-spot detection** — beaconing periodicity, exfil entropy, malware staging visible only in *decrypted server-side* streams — signals NDR physically cannot see.

**Tier 2 — small on-box model (SLM):**
- **RCA copilot** — reads the flight-recorder ring + tmmtrace histograms on an incident, writes the root-cause narrative, and *proposes the next probe to load* to confirm it.
- **Self-tuning** — features → predicted optimal knobs (buffer sizing, LB weights, reuse policy) per-tenant per-time-of-day; verified programs nudge them within host-sanctioned bounds.

**Tier 3 — fleet-scale foundation model (the factory):**
- **F5 Traffic Foundation Model** — trained federated on anonymized fleet features; productized as threat-intel feeds, per-industry baselines, and pre-trained anomaly heads shipped back down as *signed programs + model updates*.
- **A stronger shield factory** — the AI-shield pipeline's false-positive oracle graduates from synthetic corpora to *real fleet traffic distributions*; fleet data makes machine-authored shields measurably safer. (The security and data theses reinforce each other.)
- **tmmtrace copilot** — plain English → verified probe, grounded on the signed hook-point map; democratizes the surface to any SE or support engineer.
- **Compliance as a data product** — attestations computed in-situ ("no PAN crossed this boundary unencrypted, evidence attached") exported as *proofs about* data rather than data.

## 5. Recommended build order

Start with **Tier 1 API discovery.** It is an existing market, needs no model, and proves the core mechanic end-to-end — *compute in-situ, export only the signal, prove the payload stayed put*. That de-risks everything above it: once "verified extractor + proof-bounded egress" is shipping for one use case, the SLM and fleet tiers are additive, not foundational.

## 6. Governance is the feature, not the friction

Because extraction is verifier-bounded and egress is host-owned and schema-checked, the privacy posture *strengthens* as the data use grows: what could have been "F5 reads your decrypted traffic" becomes "F5 runs a **proven** transform that can only emit **declared** derived signal, and can attest that it did." Data-minimization, residency, and auditability are properties of the mechanism, not overlays on top of it — which is exactly what makes this monetizable at a regulated TLS boundary where centralization is forbidden.

## 7. One-line thesis

**The verified data plane makes the proxy AI's sensory organ — turning traffic only F5 can see into governed signal it never has to move, and closing the loop by letting models return to the plane as verified bytecode.** *Method and claims are held in a separate invention disclosure, per IP policy.*
