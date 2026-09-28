# Delayed DLP: integration preflight

Updated 2026-09-25. **MEASURED: source/configuration inventory and bounded unarmed gate outcomes.**
The internal-state feed and cost experiment remain **IDEA / unrun** under P20/P16. Streaming data
loss prevention (DLP) enforcement evidence was the first selected experiment. On 2026-09-25 the
owner made [agent attribution](ATTRIBUTION.md) primary; preserve these bounded gate outcomes as
supporting enforcement evidence.

## Registered experiment

A synthetic inference response contains `DLP_CANARY_<run-id>`. The origin produces the same paced
body in each case. An inspector gives a delayed allow, delayed deny, or no answer until timeout.
The host's configured contract is **hold protected response content until inspection allows it**:

| Case | Required independent outcome |
|---|---|
| Delayed allow | No protected body reaches the client before allow; afterward the complete expected body arrives intact. |
| Delayed deny | No protected body reaches the client; the configured denial response is observed. |
| Timeout, fail-closed | No protected body reaches the client; the defined timeout/error path is observed. |

Use an actual TMM inspection/release gate. Delaying output or a verdict in the origin alone cannot
test that gate. A monitor-only eBPF program observes internal execution; the host owns enforcement.
The independent client checks content, not merely HTTP status or an exported verdict. Compare
verdict/release ordering in a validated common clock domain or single packet witness; do not
subtract uncalibrated inspector and client clocks. Handoff to downstream is distinct from receipt.

## Authoritative findings

All external source/runtime claims below cite the [registered preflight receipts](../../SOURCES.md#ai-inspection-integration-preflight-2026-09-24).
The receipts include exact collection scripts, source hashes, excerpt line ranges and command
results. Source tree: `/home/starin/code/tmm`, HEAD
`e2104734a940a099a9190eb84bfbea01fb4b81d4`; inspected module/test files are clean tracked files.

### 1. Response adaptation is a concrete source lead

`src/modules/hudfilter/adapt/adapt.c` describes response-side adaptation through a
`response-adapt` profile and an internal virtual server (IVS). Its source contains:

- An adaptation context with preview/draining buffers and working configuration.
- A timeout callback and `ignore`, `reset`, and `drop` service-down actions.
- State transitions controlling preview retention, bypass draining and backpressure.
- Separate processing of IVS results before and after an iRules event may change the result.

`test/ssa_functional/sslo_tao/tests/icap_service_test.py` constructs ICAP (Internet Content
Adaptation Protocol) service virtual servers and attaches a response-adaptation profile on the
server side. `decl_profile.c` and `decl_tmos_handlers.c` register the corresponding profile
messages. This is a **configuration implementation/test example**, not a test run in this session.

The example uses `pru_ssa_config_server.get_conf_svr()` and `send_create_msgs()`. Its standalone
test deployment configures a NATS `internal-config` transport. That is not evidence of a usable
profile-attachment operation through the current Kubernetes controller.

### 2. The ordinary adaptation verdict is already exposed to iRules

`adapt_tcl.c` registers `ADAPT::result`, `ADAPT::timeout`, `ADAPT::service_down_action`,
`ADAPT::preview_size`, context accessors and other commands. The source raises
`ADAPT_RESPONSE_RESULT`; the iRule can inspect **and change** the result.

Therefore, reporting these values alone does not establish the requested information advantage.
The more specific leads are:

- `IVS_CONTINUE` follows an internal transition without raising the result Tcl event; the source
  also changes timeout handling around this transition.
- Actual preview/draining-buffer lengths and release/backpressure state at a transition.
- Post-iRule execution and the actual drain/error path, compared with the applicable decision.

These are **candidate visibility gaps**, not a completed audit of every iRules/WASM observation.
An `ADAPT::result` accessor even names `continue`; absence of a dedicated event alone does not
prove no other observation can recover the needed fact.

`adapt_context.state`, `result`, `xoff_reason` and several configuration flags are **bitfields**.
The current DSL deliberately refuses bitfields; do not read them as ordinary scalars. A hook's
plain enum argument, such as `new_state`, is a separate candidate. Any bitfield support needs the
existing field-contract and authoritative offset/value checks.

### 3. Packaged hook candidates exist; live coverage is still open

Build-keyed catalogs for `c3b81927dfdcc31137cd8212b5e23bb85677a06c` list padded entries for:

| Function | Indexed patch address | Candidate observation |
|---|---|---|
| `adapt_handle_result_tcl_done` | `0xb9c180` (+0 pad) | Result processing after the Tcl event |
| `adapt_process_error` | `0xb9b0c0` (+0 pad) | Service-down action path and reason |
| `adapt_send_preview_data_to_proxy_if_bypassing` | `0xb9a880` (+0 pad) | Bypass preview drain, not every response release |
| `adapt_set_state` | `0xb9a1c0` (+0 pad) | Requested state transition; entry is before assignment |
| `adapt_timeout_callback` | `0xb9cc44` (+4 pad) | Adaptation timeout; function entry is four bytes earlier |

`adapt_handle_result` and `adapt_ivs_forward_data_from_ivs` appear in the signature catalog but
not in this selected hook-index result. A signature is not an attachable entry. These are discovery
facts only: no new hook was armed, and padding does not establish inline/path coverage, field
lifetime, or request identity. Normal modified-response release still needs an eligible boundary.

### 4. Inference's “EOS hold” is not the required response gate

The inference header labels guardrails as **future**. More decisively,
`hud_inference_egress()` (`inference.c:1517–1558`) passes the original response buffer downward
unmodified. Its response callbacks provide a read-only observation to submodules.
`ext_proc_cs_send_response_chunk()` documents a **lossy mirror** to the analyzer: analyzer
backpressure drops the mirrored chunk rather than stalling customer response traffic.

Thus “hold the analyzer stream until end of stream” does not mean “hold the client's response
until a DLP verdict.” This source path is unsuitable as the assumed response hold/release gate.
It is not a live bypass finding or a claim about every external-processing implementation.

### 5. Current deployment prerequisite and configuration gap

Both receipts identify the same stable `kind-vs/default` pod
`f5-tmm-7597dfff8b-28s9z`, UID `42259fbc-3303-492a-95b1-9146b4105583`, with zero TMM restarts.
`/proc/24/exe` SHA-256 is
`a4b9e777a1daccd8c2b8c7f1aa7eba920b6040253f45f017605ea0a5f0a8afd7`.

- The process has `LS_TP_RING=/dev/shm/ls_tp_ring`; the segment exists (1,049,504 bytes).
  No process named `ls_drain` was found in the container's PID namespace. This does not prove
  there is no differently named or external consumer; ownership/completeness still needs checking.
- The complete installed `F5VirtualServer` schema has no response-adapt/ICAP profile attachment
  field. The collected HTTP-setting and service-policy schemas do not supply one either.
- The served-CRD schema scan returned no inspection-term matches. This is a scoped search result,
  not proof that a lower-level API, opaque policy or another deployment cannot configure it.
- The existing `ai-traffic` listener remains the forwarding-only P19 baseline.

**Integration decision:** after this preflight, the owner selected an **isolated ICAP-capable TMM
fixture**. Use the upstream configuration example as the starting point and establish a separate
baseline. Provisioning and validation are in progress; no DLP outcome is established. This reuses
existing adaptation code through external configuration, with no experiment-specific edits to
TMM function bodies. Do not treat a source profile registration as a working controller interface.

## Remaining gates before the armed experiment

### Isolated SSA fixture progress, 2026-09-25

**MEASURED: forwarding baseline only.** The isolated build-box SSA/Tao fixture now runs the
reused TMM image and acknowledges external configuration over NATS. `baseline-02` delivered the
exact 34-byte HTTP response; the origin saw `10.203.72.10` (TMM's self-IP), with client traffic
addressed to `10.203.72.50:18091`. [Receipts](../../SOURCES.md#isolated-inspection-fixture-2026-09-25)
preserve bootstrap and first-configuration failures alongside the successful baseline.

The first configuration attempt incorrectly enabled `CONFIG_SERVER_DPC_RAISE_ON_ERROR` for
NATS. This transport returns no synchronous DPC reply, so the library's `raise "NULL DPC message"`
became a `TypeError`. Use asynchronous acknowledgements: the fixture watches a separate heartbeat
queue, checks status and the acknowledged generation/sequence, and tests actual forwarding.
Bootstrap's authenticated schema-download 401 was recovered using the exact cached schema archive
(`702364ce…afe99`); no token is required by this fixture's bootstrap.

**Pre-registered unarmed gate trial:** one serial allow, deny and timeout using the same canary body
within a run, three origin writes spaced 200 ms apart, 4,096-byte preview cap, and a complete-preview
(`ieof`) requirement. Delay the verdict 500 ms after complete inspection; configure a 3,000 ms
adaptation timeout with reset on service-down. Allow uses ICAP 204, deny substitutes an HTTP 403
body, and timeout sends no verdict. The client read deadline is 7 seconds and is a test failure,
not evidence of host timeout. Check incremental application reads on the inspector's monotonic
clock; these are not packet timestamps or internal release events. The trial is implemented in
`icap_gate.py` / `icap_suite.py`; this paragraph was registered before the first gate trial.

**Result — `gate-03`, MEASURED, one request per case:** all three checks passed, using the
same 33-byte body. Allow returned it intact; its first client read was 2.12 ms after the inspector's
verdict write. Deny returned exactly the 18-byte denial body with HTTP 403. Silence produced a
connection reset and zero response bytes, about 3.00 seconds after complete inspection. These
are socket/application observations, not per-call cost or proof about arbitrarily long streams.
No eBPF program was attached. Gate-01 failed because fixture objects reused the same ID across
types (IVS not found); gate-02 failed because the inspector incorrectly required `Allow: 204`
despite using a preview. Both failures are retained with the successful receipt in `SOURCES.md`.

**Authoring result, MEASURED off-runtime:** `icap_state.bpf.c` compiled with clang-18, relocated
five field accesses, bound to `fentry/adapt_set_state` at `0xb9a1c0` for packaged build `c3b81927…`,
passed strict PREVAIL/termination with a 256-byte stack and was signed monitor-only. Final object
SHA-256 `f74b62ab74e12d2d348ad0bd5c5a4c39f4a1b0852ddb08d8d0fa8de683c4275a`.
The 64-byte record describes requested new state, preview/draining lengths and lifetime-local
handles, before the host mutates state. **Not loaded or armed; no semantic, publication or cost
result.** Build receipt and artifact hashes are preserved in the
[attribution snapshot](../../SOURCES.md#agent-attribution-fixture-2026-09-25), `result.icap_probe`.

### Armed experiment gates

1. Select/configure the actual gate and inspector; establish precise preview/whole-message coverage,
   allow/deny/error semantics and bounded buffering. In particular, ICAP `100 Continue` is not a
   DLP allow. A timeout contract must identify when its timer is actually armed.
2. Prove the relevant API-access gap and eligible hooks. Define request/content generation,
   decision applicability, field validity, release boundary and an independent receiver witness.
3. Register numeric workload and incremental-cost budgets on the selected deployment. Compare
   unarmed, armed/no-publication, armed/publication and slow/stopped-consumer cases. The budgets
   remain unset; **no armed performance experiment has run**.
4. Validate publication return semantics, single-consumer ownership, record decoding and loss
   accounting on the pinned build. Include initialization separately from steady-state cost.
5. Run the three controlled outcomes, then continuous publication and correlation/pressure checks.
   Preserve uncertain joins and missing records as incomplete evidence, not inferred bypass.

## Repeat the read-only inventory

From the repository root on the control machine, choose a fresh output filename:

```sh
python3 env/ai-traffic/inspection_preflight.py \
  --key /home/claude/.ssh/id_ed25519 \
  --pod f5-tmm-7597dfff8b-28s9z \
  --output /tmp/opencode/ai-inspection-preflight-new.json
```

The driver queries the build box and datkube concurrently, preserves command errors in the
receipt and refuses an existing output file. It does not consume the ring or configure a listener.
Its lab paths, context, PID and candidate source ranges are explicit; update them for another
environment rather than interpreting a mismatched inventory as a failed experiment.

`ask 'inspection hold release DLP guardrail'` and
`ask 'F5VirtualServer response-adapt ICAP configuration'` originally returned **NO RECORD**.
The configuration question is now indexed in `SYMPTOMS.md`.
