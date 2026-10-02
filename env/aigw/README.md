# AI gateway TMM (MR !21165): isolated build and smoke test

**2026-10-02 — MEASURED: the unmodified merge request builds and serves AI
traffic in an isolated TMM.** This is exploration only. No code was merged, and
no eBPF substrate is in this build yet.
[Sources and build record](../../SOURCES.md#ai-gateway-in-tmm-mr-21165-and-bnk-as-llm-gateway-2026-10-02).

## What the gateway is

The merge request adds an `AIGW` filter to TMM. It is the host for an external
library, `libaigw.so` (version 0.6.0, interface version 4.3). TMM does all the
input and output: connections, HTTP, JSON, SSE, TLS and the Redis client. The
library makes every gateway decision: who the caller is, rate limits and budget,
which provider takes the request, translation between provider formats, the
provider key and the cost record. An `ai_gateway` profile on a virtual server
adds three filters to each chain: `AIGW`, `JSON` and `SSE`. The profile carries
one JSON document, `library_config`, which only the library reads.

## Isolated build

| Item | Value |
|---|---|
| Source | Separate clone `~/code/tmm-aigw`, detached at `74cf09df69`, no edits |
| Toolchain container | `10.204.15_0.1.58-HEAD.cf619836a9` (`tc-tmm:v2.3.1`), separate from ours |
| Library | `aigw-lib-0.6.0-1` from Artifactory |
| Image | `eob-aigw/tmm:mr21165-74cf09df69` |

Before packaging, the shared tags `tmm:local`, `tmm:local_img` and
`tmm_gdb:latest` were saved, and they were restored afterwards. A before/after
check of our existing tree, its uncommitted changes and its toolchain container
is identical.

## Smoke test

Files: [`compose.yaml`](compose.yaml), [`bootstrap.sh`](bootstrap.sh),
[`aigw_smoke_suite.py`](aigw_smoke_suite.py), [`run-suite.sh`](run-suite.sh).
Compose project `eob-aigw-20261002`, its own subnets `10.203.81/82.0/24`. The
test container uses the merge request's branch API schema, because the released
schema has no `ai_gateway` profile. RBAC, budget, rate limit, routing and
translation are off, so no Redis or router is used.

| Check | Result |
|---|---|
| Library loads | TMM log: `aigw lib: loaded /usr/lib64/libaigw.so version 0.6.0` |
| Chat request through the gateway | 200 with the provider's reply. The provider received exactly one `Authorization` header, equal to the configured provider key. The client's own token did not reach the provider. |
| `GET /v1/models` | 200, answered by TMM; the provider was not contacted |
| Unknown model | 404 `model_not_found`; the provider was not contacted; TMM logs `aigw_refusal reason=model_not_found` |
| Empty `library_config` | 503 `AI gateway unavailable`; the provider was not contacted; TMM logs `config refused: library_config is empty` |

The TMM process did not restart. The provider key was generated for this run;
it is absent from the result, the archive and the TMM log. The fixture was
removed; other containers did not change.

Witnesses: SELF for the client, mock provider and assertions; TMM's own log for
the library load and refusals.

## Expected noise

TMM tries to reach the session store (Redis) at `127.0.0.1:6379` and logs
`aigw_dssm ... -> ERR_INIT` repeatedly. That is expected here: no Redis exists,
and no enabled capability needs one.

## Limits

- One TMM worker, HTTP/1, plain-HTTP provider, one provider, non-streaming.
- Not tested: RBAC with virtual keys or JWT, budgets and rate limits (these need
  Redis), failover, translation, prompt cache, semantic routing, streaming, TLS
  to the provider, and performance.
- The design page says the gateway was "IN REVIEW" when retrieved, and the
  merge request uses a temporary branch schema.

## Next

Add the eBPF substrate to this source in a separate branch of the isolated
clone, build it the same way, and repeat this smoke test with and without
probes attached. Then survey the gateway's decision points for tracepoints.
