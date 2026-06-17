# Envoy + eBPF API-Security Tracepoints

### A candidate hook-point catalog for instrumenting F5's Envoy fork to build an API-security data plane

**Status:** Strategy / candidate catalog — early exploration
**Audience:** F5 API-security & data-plane engineering, SIRT, product
**Companion:** `embedded-ebpf-substrate.md` (the verified-eBPF substrate this reuses — observe/enforce duality, telemetry types §3.1, security model §6) · `big-ip-live-shield-design.md` (the embedded-VM + verify + lifecycle spine)
**Scope:** Where, in Envoy's request lifecycle, a designed-in eBPF tracepoint earns its keep for API security — in both observe and enforce modes

---

## 1. Why this is the same play as Live Shield

F5 owning the Envoy fork is the same advantage as owning TMM: you can **instrument by design, not inject** (design §3.1). The substrate ports directly, as a **two-engine model** keyed by what the kernel can see — Envoy is a kernel-visible userspace process:

- **Designed-in USDT probes + kernel eBPF** — the default. Static tracepoints compiled into the Envoy fork; kernel eBPF attaches, near-zero cost when detached, one predictable branch when a hook is empty. This is the control-plane-adapter analog (design §5.1) — *not* brittle uprobes, because F5 owns the source.
- **Embedded eBPF VM in a custom Envoy HTTP filter** — where verified in-process *enforcement* on L7 semantics is needed: a filter that runs signed eBPF and returns a verdict. This is Live Shield ported into the filter chain.

Everything else carries over unchanged: the **observe/enforce duality** (a hook lands as a read-only tracepoint and graduates to an active control once trusted — design §6.1), the **verify-before-load** safety gate, and the **governance around the VM** (signing, authorization tiers, one-way audited sink, auto-retirement — substrate §6).

**Where eBPF beats Envoy's existing knobs** (`ext_authz` / `ext_proc` / WASM / `tap` / access-log): lower per-request cost, **kernel↔stream correlation**, visibility *before the first filter and after the last*, tamper-evidence, and reach into places no filter sits — all without a config push.

## 2. Candidate tracepoints, by request lifecycle

Modes: **obs** = observe-mode tracepoint (telemetry, never changes flow); **enf** = can graduate to an active control. Exact named probes are placed against the Envoy fork and emitted in a per-build hook-point map (the design §5.3 mechanism, applied to Envoy).

### 2.1 Connection & TLS (L4 / transport)

| # | Tracepoint (where) | Mode | API-security signal / control | Why eBPF |
|---|---|---|---|---|
| TP-1 | Listener accept (new connection) | obs/enf | source IP / ASN / geo, conn-rate per source, SYN/flood → tar-pit / early-drop | kernel socket layer, before any Envoy work; cheapest abuse-shedding; anchors correlation |
| TP-2 | TLS handshake / transport socket | obs/enf | SNI, ALPN, **mTLS client identity**, **JA3/JA4 fingerprint**, cipher/version → reject anomalous client | record-layer, pre-HTTP; bot / client attribution for API abuse |

### 2.2 HTTP codec / connection manager

| # | Tracepoint | Mode | Signal / control | Why eBPF |
|---|---|---|---|---|
| TP-3 | Codec frame decode (HTTP/2, HTTP/3) | obs/enf | frame/stream rates, **HTTP/2 Rapid-Reset**, request-smuggling signals, malformed frames → drop | protocol-machine state the filter chain never sees as "requests"; catches protocol-level DoS |
| TP-4 | Request headers decoded (newStream) | obs | `:method` / `:path` / `:authority`, oversized / duplicate headers — raw request identity | earliest point with full request identity; basis for discovery |

### 2.3 L7 decode chain + routing — the core API surface

| # | Tracepoint | Mode | Signal / control | Why eBPF |
|---|---|---|---|---|
| TP-5 | **Route resolved** (route name / cluster / vhost) | obs | **API inventory / discovery**; traffic to default / unmatched routes = **shadow / zombie APIs**; per-route volume | maps raw request → canonical endpoint at ~zero cost; *templating here solves cardinality* |
| TP-6 | `ext_authz` / `jwt_authn` decision | obs | JWT claims (sub / aud / scope / iss), mTLS principal, allow/deny — **consumer identity** | per-consumer identity for baselining & BOLA without a custom filter; reads the decision tamper-evidently |
| TP-7 | **Object/function-authz correlator** | obs/enf | consumer (TP-6) × route × object-id (path param) → **BOLA / BFLA** detection → block | stateful per-consumer scoreboard; the #1 API risk schema/WAF miss |
| TP-8 | Request body decode (`decodeData`) | obs/enf | **schema / OpenAPI conformance**, PII / secret in request, injection, content-type mismatch → block / sanitize | bounded-cost body inspection; verified, can't hang on a crafted body |
| TP-9 | Rate-limit / quota decision | obs/enf | per-consumer velocity, **enumeration / scraping**, credential-stuffing cadence → shape / block | per-consumer scoreboard cheaper than the ratelimit RTT; catches *slow* enumeration |

### 2.4 Upstream / router

| # | Tracepoint | Mode | Signal / control | Why eBPF |
|---|---|---|---|---|
| TP-10 | Router upstream request (cluster / endpoint / retry) | obs/enf | retry storms, unexpected upstream (**SSRF**), which backend serves which API → steer / circuit-break | internal LB / retry state access logs don't cleanly expose |
| TP-11 | Conn-pool / circuit breaker | obs | pool saturation, CB trips, upstream health → backpressure | internal health signals; ties API latency to a backend |

### 2.5 Response / encode path — the under-served half

| # | Tracepoint | Mode | Signal / control | Why eBPF |
|---|---|---|---|---|
| TP-12 | Upstream response headers (`encodeHeaders`) | obs/enf | status per route / consumer (**auth-bypass = 200 where 401/403 expected**), response-size anomaly (**data exfil / successful BOLA**) | response-side visibility WAFs underdo |
| TP-13 | **Response body decode (`encodeData`)** | obs/enf | **sensitive-data exposure** (PII / PCI / secrets leaving), **mass assignment / excessive data exposure** (OWASP API3) → redact / block | highest-value, least-served API control; bounded-cost payload scan |
| TP-14 | Local reply / direct response | obs | attributes Envoy 4xx/5xx (ext_authz 403, rate-limit 429, codec errors) to cause | separates attack-driven errors from app errors |

### 2.6 Stream completion

| # | Tracepoint | Mode | Signal / control | Why eBPF |
|---|---|---|---|---|
| TP-15 | Stream complete / access-log point | obs | the **correlated per-request record** (consumer, route, status, bytes, duration, upstream) — baselining anchor + flight-recorder trigger | one cardinality-bounded record to the controlled sink; lower overhead than the access-log pipeline |

### 2.7 Cross-cutting runtime

| # | Tracepoint | Mode | Signal / control | Why eBPF |
|---|---|---|---|---|
| TP-16 | xDS apply (LDS / RDS / CDS) | obs | **config drift**, new / removed routes (**inventory change**), who changed the data plane | tamper-evident record of data-plane config changes (API supply-chain) |
| TP-17 | Overload manager / worker event loop | obs/enf | loop latency, per-worker CPU / memory under attack → admission control | internal health; L7-DoS detection |
| TP-18 | WASM / `ext_proc` filter boundary | obs/enf | extension cost / latency, misbehavior → circuit-break a degrading extension | guards the extension surface itself |

## 3. Coverage vs. the OWASP API Security Top 10

| OWASP API risk | Covered by |
|---|---|
| API1 **BOLA** | TP-7 (+ TP-6, TP-12 size) |
| API2 Broken authentication | TP-6, TP-2 (mTLS) |
| API3 Object-property level / excessive data exposure / mass assignment | TP-8, **TP-13** |
| API4 Unrestricted resource consumption | TP-9, TP-3, TP-17 |
| API5 **BFLA** | TP-7 |
| API6 Unrestricted access to sensitive business flows | TP-7 + TP-9 (velocity / sequence) |
| API7 SSRF | TP-10 |
| API8 Security misconfiguration | TP-16 |
| API9 **Improper inventory management** | TP-5, TP-16 (shadow / zombie APIs) |
| API10 Unsafe consumption of third-party APIs | TP-10, TP-12 |

## 4. MVP priority (highest value, lowest risk — all observe-first)

**TP-5** (discovery / inventory) → **TP-6 + TP-7** (identity + BOLA) → **TP-13** (response data exposure) → **TP-15** (correlated record).

These four hit BOLA, broken auth, excessive data exposure, and inventory — the core of the API Top 10 — and all start read-only, graduating to enforce once the signal is trusted (the observe→enforce on-ramp, substrate §3 / design §6.1).

## 5. Three design decisions that determine whether this works

1. **Cardinality is the killer.** Key telemetry on the **route name (TP-5), never the raw URI**, and bound consumer cardinality. A metric keyed by an attacker-controlled path or consumer is a cardinality bomb — the same lesson as substrate §3.1 (telemetry types 1–3).
2. **Correlation / stitching is the hard part.** socket 4-tuple (TP-1/2) ↔ HTTP stream (TP-4) ↔ consumer (TP-6) ↔ route (TP-5) ↔ upstream (TP-10) ↔ final record (TP-15). A per-request ID propagated across these hooks is what turns isolated samples into a behavioral profile — this is the substrate §3.1 type-5 (per-flow trace) problem, and where most of the engineering lives.
3. **The combined play ports directly.** Observe to baseline → enforce on the *same* hook → flight-recorder the blocked attempt (substrate §3.1). TP-7 catching a BOLA attempt and capturing the request that tried it is exactly "blocked it *and* kept the forensics."

## 6. Open questions

- **Fork ownership.** This catalog assumes F5 **owns and compiles** the Envoy fork, so designed-in USDT is on the table. On an unmodified upstream Envoy the mechanism shifts toward uprobes + the embedded-VM filter, and the codec / internal-runtime hooks (TP-3, TP-16, TP-17) shrink.
- **Body inspection cost.** TP-8 / TP-13 are the highest-value and the most expensive (payload scanning) — these are the hot-path-budget decisions (design §11); likely sampled, conditionally armed, or scoped to flagged routes/consumers.
- **Consumer-identity source of truth.** TP-6 depends on auth being terminated in Envoy (JWT / mTLS); APIs authenticated downstream of the proxy need a different identity hook.

## 7. One-line thesis

**Envoy gives the L7 API semantics; verified eBPF gives the cheap, tamper-evident, in-process instrumentation and control surface around them. Owning the fork means the hook-point catalog above is designed in, not injected — and the catalog, plus the consumer/route correlation, is the asset.**
