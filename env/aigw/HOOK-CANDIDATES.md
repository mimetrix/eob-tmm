# AI gateway hook candidates (MR !21165)

These are function-entry hooks on existing TMM functions, not tracepoints.
No tracepoint call site has been added to TMM.

**2026-10-02 — source and symbol survey.** Since armed: `aigw_host_obs_publish` (record probe) and eight entries for P24 timing, listed in [README.md](README.md#latency-attribution-p24-2026-10-02).
Function names, files and sizes come from the merge request's source at
`74cf09df69` and the plain build's debug symbols. Offsets come from that
build's debug information. Every row is a candidate until a live probe
qualifies it. Items marked INFERRED were read from code paths, not observed.

## How the gateway divides the work

TMM does input and output; the library `libaigw.so` decides. Calls into the
library cannot be hooked: it is a separate shared object without entry pads.
TMM's side can be hooked: the wrappers that call the library and the host
callbacks the library calls back. On the eBPF build, these TMM functions have
the 5-byte entry pad (checked for `hud_aigw_handler`, `aigw_rbac_verdict`,
`aigw_host_upstream` and `aigw_host_obs_publish`).

There is no request-ID argument. The key that joins observations of one request
is the client-side `struct aigw_scb *`, passed directly or as `hc->scb`.

## Candidates, by value

Request steps are those of the design page (1 parse … 17 metering).

| # | TMM function | Step | Reachable at entry | Control at entry |
|---|---|---|---|---|
| 1 | `aigw_host_obs_publish` | 17 | The complete per-request record (or a denial record), up to 8 KiB: model, tokens, cost, status, provider, failover chain, total/gate/first-token times | Observation only. Skipping drops the record |
| 2 | `aigw_rbac_verdict` | 2–4 | The admission verdict and the library's result: status, provider, reason, stage, flags | None; skipping leaves the request hung |
| 3 | `aigw_host_upstream` | 11–12 | The chosen provider row (pool, serverssl) and failover attempt, once per upstream attempt (INFERRED) | **Best narrow dispatch control.** Returning DENY (2) aborts before the credential is written or the provider is dialed |
| 4 | `aigw_host_forward` | 9 | The request and flow; the provider is not chosen yet | DENY gives the library's own 503 and denial record, with no charge (INFERRED) |
| 5 | `aigw_route_raise_pick` | 9, 12 | The provider's pool and serverssl, and the failover attempt | None |
| 6 | `aigw_host_session_event` | 12, 14 | FORWARDED, RETRY_WIRED (with failed status), UPSTREAM_FAILED, REPLAY | None; skipping corrupts billing |
| 7 | `aigw_failover_dispatch` | 14 | The failed provider reply | Returning 0 disables failover for that reply |
| 8 | `aigw_stage_gate_done` | admission time | Gate wall time = `end_us − scb->t_req_us` | None |
| 9 | `aigw_host_reply_parse` | 13 | Reply pass start; side flag | None |
| 10 | `aigw_host_aborted`, `aigw_rbac_scb_reset`, `aigw_vsr_scb_reset`, `aigw_host_detach` | cancellation | Which operations were still in flight (store, router, session) | None |
| 11 | `aigw_host_ivs_done`, `aigw_vsr_call` | 5 | Semantic-router outcome and its round trip | DENY at `ivs_done` gives a 503 (INFERRED) |
| 12 | `aigw_host_store_reply` | 4, 6 | Store round trip: entry time − `hc->t_sent_us` | None |
| 13 | `aigw_rbac_deny_request` | 5, 6, 9 | The refusal reason string | None |
| 14 | `aigw_host_settle_at` | 16 | When settlement happened (response, completion, teardown) | None; billing would be lost |
| 15 | `aigw_host_message` | 13, 15 | Each SSE event's kind and status | None |

## How these answer the paper's questions

| Question | Hooks |
|---|---|
| Why was it allowed, denied, retried or sent here? | 2, 13, 6, 5, 3 |
| Where did the time go: gateway, store, router, provider? | 8, 12, 11, 6 → 9 (provider first byte), 1 (the record's own times) |
| Which attempt consumed time and usage? | 6 and 3 per attempt; 1 carries the failover chain and usage |
| What happened when the client disconnected? | 10 |
| Can we deploy a narrow control live? | 3 (deny dispatch before the key is written), 7 (disable failover) |

Two questions cannot be answered from this build: tool time and inspection time.
The gateway has no tool or guardrail stage yet (the design lists guardrails as
planned).

## Hazards

- **The safe-return value defaults to 0, which is `CONTINUE` in this interface.**
  A default safe return on a verdict wrapper lets the request go on, so it is
  fail-open. A deny control must set the value to 2 (`DENY`).
- **Callbacks run inside library calls.** `respond`, `obs_publish`,
  `provider_facts` and the store callbacks run nested in `session_*`. Changing
  their return changes what the library believes; do not enforce in callbacks.
- **Inlined, so not hookable:** `aigw_rbac_pass`, `aigw_rbac_release`,
  `aigw_scb_reset`, `aigw_vsr_lost`, all `hud_stage_*` helpers, among others.
- **High call rate:** `hud_aigw_handler` runs for every message on the chain.
- **Secrets:** `aigw_host_profile_provider_key` handles provider keys. Never
  probe it.
- The verdict result (`aigw_lib_result`) is a stack local in most callers. An
  exit hook sees only the verdict, not the reason.
