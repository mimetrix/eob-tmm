# AI traffic jig: a repeatable proxy workload

**One activity bytecode artifact:** [ACTIVITY-PROGRAM.md](ACTIVITY-PROGRAM.md)
records the build and live check of both required entry hooks running together.
The [combined-record result](ACTIVITY-COMBINED.md) adds bytecode-generated exchange
keys and an exporter. Ten live exchanges pass, including keep-alive and concurrent
equal IDs. Both hooks were restored and the fixture was removed. Scope is one
worker and non-pipelined HTTP/1; identity remains unknown.

**Export activity metadata:** [AGENT-ACTIVITY.md](AGENT-ACTIVITY.md) documents the
versioned JSON view of the collector stream. Run `activity_export.py --socket
/collector-api/events.sock` where that socket is mounted. Method, target, message
ID and reported response fields are supported. This one-row observation view
keeps correlation and identity unknown. Use `activity_combine.py --socket
/collector-api/events.sock --follow` for checked exchange records.

**MEASURED, 2026-09-24:** 51 synthetic AI exchanges passed through the current TMM, from three
concurrent client workers, including six paced Server-Sent Events (SSE) streams. Request and
response body hashes agree between client and backend. The selected TMM's packet capture and
the backend's observed SNAT address establish the proxy path. Zero TMM restarts.

This is the first baseline for later eBPF-derived metadata and analytics. Protocol-shaped synthetic
peers exercise **HTTP forwarding**, with native `a2a`, `mcp`, `json` and `sse` filters disabled.
The scripts are not reference protocol implementations or conformance tests. They need Python's
standard library only; no model, API key, external AI service or real tool execution.

**Earlier direction, selected 2026-09-25: [agent attribution](ATTRIBUTION.md).** A separate isolated
SSA fixture now passes 23 expected authentication/delegation outcomes, including A/B sharing one
connection, colliding caller IDs, spoofing and replay. Its destination-side trust ledger is the
baseline for the later TMM-internal join.
The [2026-09-28 lifetime gate](LIFETIME.md) adds 71 closed observed parser intervals,
with 204 calls/records and explicit unknown results for late/missed initialization.
The later [bounded correlation test](CORRELATION.md) gives 42 accepted-operation
matches, one authenticated rejection and eight unknowns from 51 completed header
observations. General request identity, native AI-filter visibility and cost remain
unvalidated. The isolated fixture was removed after the evidence was archived.
The [controlled-gap follow-up](GAPS.md) completes 150 requests while testing missed
boundaries, pause/resume, tracking limits and fresh recovery. Reported gaps make
the whole result window unknown; silent-gap detection remains unvalidated.
The preceding [delayed-DLP experiment](INSPECTION.md) now has bounded unarmed allow/deny/timeout
results; retain it as supporting enforcement evidence. Its signed monitor remains unarmed.

## Topology

- [Production entry snapshots](ENTRY-SNAPSHOT.md): native tests and TMM
  build/package pass. Live initialization is refused by the corrected unwind
  gate. The earlier zero-import argument is falsified on both tested binaries.
  The unused fixture is archived and removed.

- [ID and flow side](ID-FLOW.md): 44 exchanges and 88 same-record field observations,
  including keep-alive and concurrent equal IDs. Request association remains open.
- [JSON-context boundary test](JSON-LIFECYCLE.md): 13 exchanges and 306 entry
  records. Unavailable context invalidates the full window; lifecycle remains unknown.
- [Initialization-completion qualification](JSON-INITIALIZATION.md): pinned return
  refusals and compiled-path checks reject the tested candidates. No live probe;
  completed initialization remains unqualified.
- [Void-return completion test](VOID-COMPLETION.md): the native entry-snapshot
  adapter passes both pinned compilers. Production entry capture is the next work.
- [Extracted metadata](EXTRACTED-METADATA.md): actual values from the saved live run.
- [Observed message IDs](MESSAGE-ID.md): exact ID type and raw bytes, including
  large numbers without rounding; a field for later request/reply association.
- [Message scope qualification](MESSAGE-SCOPE.md): pinned flow-side and JSON
  lifecycle candidates; source/compiled checks only, with runtime scope still open.
- [Reported reply fields](REPLY-METADATA.md): result/error presence, signed error
  codes and Boolean tool-error reports, with explicit missing and ambiguous states.
- [Requested tool/resource metadata](OPERATION-TARGET.md): exact tool names and
  resource addresses from bounded JSON-cache reads; a step toward activity profiles.
- [Response metadata](RESPONSE-METADATA.md): measured HTTP status and local transfer
  completion, including paced and interrupted bodies; saved-evidence verifier/export.
- [Session and routing extraction](SESSION-ROUTING.md): saved session-header bytes,
  selected pool/endpoint state and proposed identity-profile/blast-radius uses.
- [Token-cache method extraction](TOKEN-METHOD.md): exact `tools/list` and unfamiliar
  values on the AIMCP/JSON path, delivered through the separate collector.
- [Continuous collector](COLLECTOR.md): measured local journal and HTTP replay.
  Two independent consumers receive the same live method values and status records.
- [Separate collector container](COLLECTOR-CONTAINER.md): measured stop, SIGKILL
  and replacement while TMM forwards traffic. Two API-only test consumer containers
  recover the same values. Resource settings, source checks and security limits are explicit.
- [Production stream](PRODUCTION-STREAM.md): proposed continuous collection,
  replay, multiple consumers and failure behavior; not yet production-validated.

**Current work: [application-metadata probe](METADATA.md).** Establish the hook
locations, readable values, extraction limits and output records before downstream
analytics. [COVERAGE.md](COVERAGE.md) retains the observation-first corrections.
Real activity must establish later representative workload tests.

**Measured now:** a getter-return probe extracts root-object method values in the
native A2A fixture. Live comparisons include unfamiliar and escaped values, empty
strings and explicit truncation. It checks at most four members and copies at most
64 bytes. The AIMCP test input did not call this getter. The later
[token-cache probe](TOKEN-METHOD.md) extracts that method through a JSON-completion
hook: 13 requests, 26 cache records, exact values and explicit exclusions.
It requires the JSON filter and literal root keys. Saved session-header and selected
routing fields now have a [separate bounded result](SESSION-ROUTING.md). Protocol
identity and production coverage remain open. See [the getter result](METADATA.md#7-field-result--measured-on-the-pinned-build)
for the earlier scope and its distinction from the event-only probe.

```text
CLIENT POD                         RUNNING TMM                      BACKEND POD
ai-traffic-client                  ai-traffic virtual server        ai-traffic-backend
11.11.11.114                        11.11.11.99:18090                 22.22.22.114:18090
  three client workers ── HTTP/1 ──→ HTTP proxy ── SNAT .150 ───────→ synthetic origin
  client JSONL records ←─ JSON/SSE ─────────────── JSON/SSE ───────── response + origin JSONL
                            packet witness on tmm-client
```

The VIP is on the lab client network, not a host-exposed public endpoint. `jig.py` creates a
ConfigMap, two dedicated pods, a pool and a virtual server, all in `default` on `kind-vs`.
It checks address/name/port conflicts first and pins the two disposable pods' neighbors to the
selected TMM. This avoids the competing-MAC/SNAT-IP condition recorded during P17. `NET_ADMIN`
is requested only by these fixture pods. The current successful run exercised both neighbor pins.

## Flows

Each worker executes the following **17 HTTP exchanges**, sequentially within its own session;
workers run concurrently. Every exchange has a unique request ID. The retry pair shares an
operation ID but has different request IDs.

| Family / endpoint | Exchanges per worker | Checks |
|---|---:|---|
| MCP-shaped `/mcp` | 8 | `initialize`, initialized notification (202), `tools/list`, echo `tools/call`, `resources/read`, unknown-tool application error, unknown-method JSON-RPC error, invalid session (404) |
| A2A-shaped `/a2a` | 5 | `SendMessage` → `GetTask` → `CancelTask` → `GetTask` confirms canceled state; `SendStreamingMessage` delivers task, artifact and terminal status events |
| Inference-style `/v1/chat/completions` | 4 | JSON answer, streamed deltas + `[DONE]`, deliberate overload (503) followed by a client-driven successful retry |

SSE events are emitted 200 ms apart. The client requires a first-to-last arrival span of at least
150 ms, detecting whole-response buffering in this fixture. MCP tool execution and nonstreaming
inference contain a synthetic 50 ms delay. These are workload settings, **not TMM latency claims**.
Task cancellation changes the mock server's state; it is not proof that real computation stopped.
Usage/token values are fabricated and must not be treated as measured token counts.

## Repeatable procedure

**Starting point:** an existing, working datkube cluster with the recorded TMM image.
The fixture was removed on **2026-09-28**. Follow all steps to recreate it.
The isolated build fixtures were also removed; their evidence was archived first.
See the [cleanup record](CLEANUP-20260928.md). Cluster provisioning and TMM installation
are documented in [the BNK runbook](../bnk-dev-runbook.md) and
[catalog-free deployment](../../catalog-free-deployment.md).

### 1. Prerequisites and files — control machine

Run the control-machine commands from the repository root. Required:

- A checkout/working copy containing this directory, Python 3, SSH and `rsync`.
- Authorized SSH access to `starin@10.145.40.193`, reachable on the private network.
- On datkube: Python 3, `rsync`, `kubectl` access to context `kind-vs`, namespace `default`,
  the F5 ingress controller and the `F5VirtualServer`/`F5BigCnePool` custom resources.
- Multus networks `client-net` and `server-net`, a ready TMM with `tmm-client`/`tmm-server`
  interfaces, and the fixture image available to the node:
  `artifactory.f5net.com/f5-positron-docker/testing-utils:v1.1.2`.
- The recorded lab addresses: client `11.11.11.114`, backend `22.22.22.114`, VIP
  `11.11.11.99:18090`, TMM server self/SNAT IP `22.22.22.150`. `up` checks known Kubernetes
  objects for fixture address/port conflicts. Recheck external address ownership when using a
  different lab; address/interface defaults are currently in `jig.py`.

| File | Role |
|---|---|
| `backend.py` | Threaded synthetic origin; session/task state, JSON/SSE replies and origin ledger |
| `client.py` | Workload generator, semantic assertions, body hashes and client/origin reconciliation |
| `check.py` | Runs the complete client suite against a loopback origin |
| `jig.py` | Generates Kubernetes resources; implements `manifest`, `up`, `run`, `down`; captures evidence |

There is no separate YAML file to maintain: `jig.py manifest` embeds the **current** client and
backend files into the ConfigMap. Upload those files together with `jig.py`.

```bash
# These settings apply on the control machine.
export DK=starin@10.145.40.193
export SSH_KEY=/home/claude/.ssh/id_ed25519
# On another machine, set SSH_KEY to that session's authorized private-key path.
ssh -o BatchMode=yes -o IdentitiesOnly=yes -i "$SSH_KEY" "$DK" 'python3 --version'

python3 env/ai-traffic/check.py
```

The smoke check should end with `PASS loopback fixture only; no TMM/proxy evidence`, after
reporting 51 exchanges and six streams. It verifies the jig, not TMM.

### 2. Upload the fixture — control machine

```bash
rsync -av --exclude='__pycache__/' \
  -e "ssh -o BatchMode=yes -o IdentitiesOnly=yes -i $SSH_KEY" \
  env/ai-traffic/ "$DK":/home/starin/ai-traffic-jig/

sha256sum env/ai-traffic/{backend,client,jig}.py
ssh -o BatchMode=yes -o IdentitiesOnly=yes -i "$SSH_KEY" "$DK" \
  'sha256sum /home/starin/ai-traffic-jig/backend.py /home/starin/ai-traffic-jig/client.py /home/starin/ai-traffic-jig/jig.py'
```

The corresponding hashes should agree. A later `run` also compares installed ConfigMap contents
with the uploaded scripts and records source hashes in its evidence.

### 3. Select and inspect the deployment — datkube

Connect, then run the remaining deployment commands **on datkube**:

```bash
# From the control machine:
# Substitute your authorized identity path when using another machine.
ssh -o IdentitiesOnly=yes -i /home/claude/.ssh/id_ed25519 starin@10.145.40.193

# Now on datkube:
export JIG=/home/starin/ai-traffic-jig/jig.py
export POD=f5-tmm-7597dfff8b-28s9z
kubectl --context=kind-vs -n default get pods -o wide
kubectl --context=kind-vs -n default get network-attachment-definitions client-net server-net
kubectl --context=kind-vs api-resources --api-group=k8s.f5net.com
```

Use one stable, ready TMM pod. The recorded pod is shown above; if it has been replaced, set
`POD` to its replacement explicitly. Both `up` and `run` require the executing ELF to match:

```text
build ID: c3b81927dfdcc31137cd8212b5e23bb85677a06c
SHA-256:  a4b9e777a1daccd8c2b8c7f1aa7eba920b6040253f45f017605ea0a5f0a8afd7
```

For a new binary, verify its authoritative identity and environment before updating `BUILD` and
`RUNTIME_HASH` in `jig.py`. That produces a new validation run, not a replay of this exact binary.

### 4. Create the fixture — datkube, first installation

```bash
# Optional: inspect/save the generated configuration.
python3 "$JIG" manifest > "$HOME/ai-traffic-manifest.json"
python3 "$JIG" up --pod "$POD"
```

`up` creates five resources, waits for the two pods and programmed listener, pins the fixture
neighbors to the selected TMM and checks `/health` through the proxy. It places the fixture pods
on the selected TMM's node; the standalone `manifest` preview uses `vs-worker`. Expected last line:

```text
READY http://11.11.11.99:18090 (HTTP proxy; native AI filters disabled)
```

If it reports `fixture exists; use run, or down then up to update scripts`, use step 5 for the
existing installation, or the update procedure below. `up` refuses to overwrite it. If creation
fails after starting, the driver attempts to remove its fixture resources.

### 5. Generate traffic and collect evidence — datkube

```bash
export OUT="$HOME/ai-traffic-$(date -u +%Y%m%dT%H%M%SZ)"
python3 "$JIG" run --pod "$POD" --workers 3 --rounds 1 --output "$OUT"
python3 -m json.tool "$OUT/result.json"
```

Use a **new output directory for each run**. Success requires both the JSON summary with
`"event": "PASS"` and the final `PASS selected-TMM packet capture; stable identity` line.
For the default run, expect:

| Check | Expected |
|---|---|
| AI HTTP exchanges | 51 = 17 × 3 workers × 1 round |
| Streams | 6 = 2 × 3 workers × 1 round; 21 semantic SSE events total |
| HTTP statuses | 42 × 200, 3 × 202, 3 × 404, 3 × 503; errors are deliberate |
| Backend peer address | `22.22.22.150` |
| Source/body correlation | Installed sources match; request/response hashes and IDs reconcile |
| Runtime | Same pod UID, container, image and restart count before/after |

For a longer observation window, repeat step 5 with `--rounds 10` and a new `OUT` value:
three workers then generate **510 exchanges and 60 streams**. This is the workload formula,
not a separate recorded 510-exchange measurement. Workers are concurrent; requests within each
worker are sequential. Maximums are eight workers and 20 rounds per invocation.

An interactive generator-only run is also available:

```bash
kubectl --context=kind-vs -n default exec ai-traffic-client -- \
  python3 /opt/jig/client.py --workers 3 --rounds 1
```

Use the `jig.py run` wrapper when collecting a result: it adds runtime identity, listener and
packet-capture evidence. The generator alone does not perform those checks.

### 6. Retain the evidence

`run` writes these files under `OUT` on datkube:

| File | Contents |
|---|---|
| `preflight.json` | Run ID, source hashes, runtime identity, installed resources and neighbor entries |
| `client-and-backend.jsonl` | Client observations, the run's origin ledger, and reconciliation summary |
| `backend-stdout.jsonl` | Separate origin stdout copy; may include earlier runs |
| `listener.json` | Actual virtual-server configuration, including native-filter settings |
| `tmm-packets.log` | Twenty packets captured on the selected TMM's client interface |
| `client-stderr.log` | Client diagnostics; normally empty |
| `result.json` | Summary and final runtime identity; written only after all run checks pass |

The first recorded directory is `/home/starin/ai-traffic-evidence-20260924`. To retrieve a new
run, use its printed directory name on the control machine:

```bash
# On the control machine; substitute the directory printed by your run.
export RUN_DIR=ai-traffic-YYYYMMDDTHHMMSSZ
mkdir -p "evidence/runs/$RUN_DIR"
scp -o IdentitiesOnly=yes -i "$SSH_KEY" \
  "$DK:/home/starin/$RUN_DIR/*" "evidence/runs/$RUN_DIR/"
```

For a result cited in repository documents, copy the selected raw receipts to unique names in
`evidence/cache/`, compute their SHA-256s, and register them in `SOURCES.md` and
`evidence/cache/MANIFEST.sha256`. Preserve failed-run receipts too. Repeated runs have different
UUIDs, timestamps and payload hashes; the assertions and counts, rather than byte-identical logs,
are what should repeat.

### 7. Reset, update or clean up — datkube

```bash
# Remove the fixture (also resets its in-memory session/task state).
python3 "$JIG" down

# For another installation, or after uploading updated scripts:
python3 "$JIG" up --pod "$POD"
```

For final cleanup, run only `down`. It checks ownership labels and deletes the fixture ConfigMap,
two pods, pool and virtual server. Evidence directories are retained. To verify removal:

```bash
kubectl --context=kind-vs -n default get \
  configmaps,pods,f5-big-cne-pools,f5-virtualservers \
  -l app.kubernetes.io/managed-by=eob-ai-traffic-jig
```

Protocol state lasts until the backend pod is recreated. Its ledger retains the latest 20,000
events; overlapping large runs that evict a run's entries correctly fail reconciliation.

### Troubleshooting

Before investigating a failure, run `env/scripts/ask '<literal error>'` from the repository root
on the control machine. Record a new symptom if diagnosis takes more than ten minutes.

| Error / symptom | Next check |
|---|---|
| `fixture exists` | Use `run`; for a reset or source update, `down`, then `up`. |
| `installed fixture code differs` | Upload the matching scripts together, then recreate the fixture. |
| `fixture IP in use` / `fixture port in use` | Inspect the existing pods/pools/virtual servers; select unused addresses/port consistently in the manifest and client defaults. |
| `update pinned identity deliberately for a new build` | Verify the selected TMM and its executing binary against the deployment record. |
| Pod not ready / listener never `Programmed` | Inspect `kubectl describe pod ai-traffic-backend`, `describe pod ai-traffic-client`, and `get f5-virtualservers ai-traffic -o yaml`, using `--context=kind-vs -n default`. |
| Timeout despite a ready backend | Inspect the recorded neighbor entries and both sides of the handshake; see the competing-MAC row in `SYMPTOMS.md`. |
| `SSE arrived buffered` | Retain client event-arrival times and origin send records; inspect HTTP/stream-buffering configuration before changing the acceptance threshold. |
| Ledger mismatch / client assertion failure | Start with `client-stderr.log` and matching request IDs in `client-and-backend.jsonl` / `backend-stdout.jsonl`. |
| `no selected-TMM packet witness` | Inspect `tmm-packets.log`, selected pod, `tmm-client` interface and VIP path. A client PASS alone does not establish this witness. |

Raw client stdout/stderr is saved when the client returns an error. Earlier deployment/preflight
failures appear in the invoking terminal; save that output as well when diagnosing them.

## Recorded result and witnesses

Run `ai-4f9fb0add705`, build `c3b81927dfdcc31137cd8212b5e23bb85677a06c`, pod
`f5-tmm-7597dfff8b-28s9z`, UID `42259fbc-3303-492a-95b1-9146b4105583`:

- **51/51** AI exchanges reconciled: 24 MCP-shaped, 15 A2A-shaped, 12 inference-style.
- HTTP statuses: 42 × 200, 3 × 202, 3 × 404 and 3 × 503, all expected.
- **6 SSE streams**, with 21 total events, passed ordered-content and pacing checks.
- All backend requests saw `22.22.22.150`; 20 packets captured on the selected TMM showed the
  client/VIP flow and `lis=default-ai-traffic`.
- Same pod/container before/after, **zero restarts**. Health and ledger-fetch GETs are additional
  control traffic and are excluded from the 51-exchange total.

The client and backend ledgers are **SELF fixture instrumentation**, independent of the eBPF
substrate but authored here. Packet capture, pod state and executable identity are **TOOL/KERNEL**
witnesses. This establishes one cleartext HTTP/1 deployment and these payloads. It does not
validate native AI filters, TLS, HTTP/2, protocol versions generally, provider interoperability,
client-disconnect propagation or production performance. The intentional HTTP/2 CVE revert in
the runtime remains as recorded in [catalog-free deployment](../../catalog-free-deployment.md).

Evidence files are under `evidence/cache/ai-traffic-*20260924*`, with full hashes in
[SOURCES.md](../../SOURCES.md#ai-traffic-fixture-p19-2026-09-24). The loopback receipt is separate
from the datkube result. Acceptance criteria were registered as P19 in
[02-RESEARCH-PARAMETERS.md](../../02-RESEARCH-PARAMETERS.md).

## Next phase: compare internal metadata with this baseline

The concrete existing-hook shortlist, continuous export pipeline and staged **P20** experiment
are in [the AI tracepoint working paper, §8.1](../../ai-gateway-tracepoints.md#81-immediate-next-slice-a-continuous-feed-from-the-existing-http-fixture).
That plan is unrun; the result above establishes the independent traffic baseline.

**IDEA, not implemented by this jig:** start with a small request-lifecycle record from the eBPF
engine and reconcile it against these logs before building analytics. Candidate fields:

| Metadata | Independent fixture reference | Candidate analytics |
|---|---|---|
| Correlation ID, request path, operation/attempt identity | `X-Run-Id`, `X-Request-Id`, `X-Operation-Id`; backend method | Per-operation counts, retry amplification, missing/duplicate observations |
| Request/response bytes, HTTP status, completion/error | Body lengths/hashes and expected status; JSON-RPC errors checked separately | Volume, outcome distribution; distinguish HTTP success from tool failure |
| Start, first semantic output, completion, stream progress | Client monotonic elapsed/arrival times; origin send records | Completion latency, first-output latency, streaming gaps |
| Session/task identity and transitions | MCP session checks and A2A task assertions | Session continuity and task lifecycle |

First determine which fields are available at supported hooks and their valid lifetime. Filter
to this listener/run so unrelated proxy traffic and ledger requests do not inflate counts.
Keep HTTP chunks distinct from semantic SSE events and tokens. Cross-process wall timestamps
are for correlation; do not subtract clocks to claim proxy overhead. Native parser-specific
observations require a separate filter-enabled experiment with their own expected transformations.
