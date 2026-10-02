# AI gateway TMM (MR !21165): isolated build and smoke test

**2026-10-02 — MEASURED: the unmodified merge request builds and serves AI
traffic in an isolated TMM. With the eBPF substrate added, a signed probe
captures the gateway's per-request records live** ([below](#the-gateway-with-ebpf-added)).
This is exploration only. No code was merged.
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

Done below: the eBPF substrate was added and a probe was attached.

## The gateway with eBPF added

**2026-10-02 — MEASURED: the eBPF substrate builds into the AI gateway TMM, and
a signed probe at the gateway's record-publish callback captures every
per-request record live, with no change to traffic.** Still exploration only.

### Build

The same isolated clone, on a local branch `eob/aigw-ebpf` (never pushed), on
top of the unmodified merge request. The changes are the substrate only:

| Change | Detail |
|---|---|
| Added | 39 files under `src/base/` (the substrate), `Makefile.overrides`, uBPF at `c900ed9f` in `.ubpf/` |
| Modified | `src/compile/filelist` (substrate block), both x86-64 globals whitelists (43 substrate symbols each, additions only) |
| Not applied | The HTTP/2 CVE-fix revert from our main tree. This build keeps the fix. |

uBPF was built in the aigw toolchain container (GCC 11.4.0). The compile passed
with no globals-whitelist failures. The aigw functions now have the 5-byte entry
pad. Packaging, the substrate-content check and the tools bake all passed.
Packaged build `2521bd23…`; image `eob-aigw/tmm-ls:mr21165-ebpf`; runtime
SHA-256 `755f34f0…`. Shared image tags were saved and restored; a before/after
check of our main tree, its changes and its toolchain container is identical.

### Probe

[`aigw_record.bpf.c`](../../substrate/surfaces/aigw_record.bpf.c) attaches at the
entry of `aigw_host_obs_publish`. The library calls that TMM function once per
settled or refused request, with its finished per-request record (JSON). The probe
copies the record in 128-byte chunks, up to 12 chunks, and marks truncation. It
reads only the arguments, never the library's own memory, and it is
monitor-only. It passes pinned PREVAIL (256-byte stack) before and after binding.
[`check_aigw_record.c`](../../substrate/check_aigw_record.c) passes with GCC and
clang, in interpreter and JIT: eight record lengths, truncation, bad arguments,
an unreadable tail and output refusal. It is bound to `0xbcf400` and signed for
build `2521bd23` in monitor mode.

### Live result (attempt 02)

| Phase | Chat | Model list | Unknown model | Empty config |
|---|---|---|---|---|
| Before load | 200, provider called | 200 | 404 | 503 |
| Probe armed | 200, provider called | 200 | 404 | 503 |
| After disarm and revoke | 200, provider called | 200 | 404 | 503 |

While armed, the probe fired twice and produced two complete records (16 frames):
the chat request (`smoke-model`, provider `mock-openai`, 3 input and 1 output
tokens, status 200, total latency 4,135 µs) and the refused request
(`no-such-model`, `error.type` `model_not_found`, status 404). The model list and
the empty-config refusal publish no record, so they produce none. Probe calls
equal records; zero VM errors and zero safe returns. TMM's audit log records
`ARMED LIVE entry=0xbcf400` and `DISARMED LIVE`. After disarm, the kernel shows
the original pad at that address, and the running executable's hash equals the
packaged runtime. The TMM process did not restart.

Attempt 01 failed before arming: the output ring does not exist until TMM's
first probe event, and the test treated its absence as an error. It is retained.

Witnesses: INDEPENDENT (PREVAIL); SELF (clients, mock provider, probe records);
TMM's own audit log; KERNEL (hook bytes, executable hash).

### What this shows, and its limits

The gateway's own per-request record can be observed live, without enabling a
log pipeline and without rebuilding TMM for the probe. The record carries the
model, provider, usage, status, refusal type and latencies. Limits: one worker,
HTTP/1, one plain-HTTP provider, no Redis (so no identity, budget or rate-limit
fields are populated), no streaming. The probe's data-path cost is not measured.
The record format is the library's, not a versioned interface, so a consumer
must not rely on its fields across library versions. The candidate hook list
is in [HOOK-CANDIDATES.md](HOOK-CANDIDATES.md).

## Build-box state and backup (2026-10-02)

**Kept** (the next test runs on these):

- `~/code/tmm-aigw`: the merge request at `74cf09df69`, plus one local commit
  `5e2b79b7` on `eob/aigw-ebpf` with the substrate. The branch has no upstream
  and has never been pushed.
- The aigw toolchain container `10.204.15_0.1.58-HEAD.cf619836a9`.
- Images `eob-aigw/tmm:*`, `eob-aigw/tmm_gdb:*` and `eob-aigw/tmm-ls:mr21165-ebpf`.
  They are not in any registry.
- `~/aigw-build-20261002/`: logs, sources, probe builds, fixture files and records.

**Backup**, in `~/aigw-build-20261002/backup/` with a `SHA256SUMS` file:

| File | SHA-256 | Restores |
|---|---|---|
| `tmm-aigw-ebpf.bundle` | `555bcdea4177fbdfcdc128b8a9ab3378cbb539cc479c083f4d7a9249ee008780` | The local branch: `git fetch <bundle> eob/aigw-ebpf` on a clone that has `74cf09df69` |
| `tmm-ls-mr21165-ebpf.tar.gz` | `852dcb94aa52f2b6265170418bda69d65c0d3d6f59e331c68816fbaf0134e8ce` | The probe-ready image: `gunzip -c … \| docker load` |

These are F5 source and an F5 image, so they stay on the build box. Do not copy
them to this repository or to a public registry.

**Removed** in the scratch cleanup: temporary files under `/tmp` (the PDF tool
environment, the schema extract, the survey's DEB extract, extracted archives
and copied files), the extra `publish.artifactory…/test/tmm-img:v10.204.15-*`
tags on the aigw images, and the `eob-pre-aigw/*` safety tags. A before/after
check shows the main tree, its changes, the shared image tags and the main
toolchain container are unchanged.

## Access control with the session store (2026-10-02)

**MEASURED.** Redis (pinned by digest) runs on the fixture's data network; TMM
reaches it over plain TCP (`SESSIONDB_DISABLE_SSL=true`,
`SESSIONDB_EXTERNAL_SERVICE_ADDR`). The test seeds fixture identities in the
gateway's own key layout. [`aigw_rbac_suite.py`](aigw_rbac_suite.py), attempt 03:

| Case | Result | Provider called |
|---|---|---|
| Valid virtual key | 200 | once, with the provider key only |
| No key | 401 `auth_error` | no |
| Unknown key | 401 `token_not_found_in_db` | no |
| Revoked key (`active` = 0) | 401 | no |
| Key scoped to another model | 403 `model_not_allowed` | no |
| Rate limit 2/hour: requests 1, 2, 3 | 200, 200, 429 `rate_limit_exceeded` | 1, 1, 0 |

Redis counter after the run: 2. The record probe captured all eight decisions,
including `vk_id`, `principal_id`, `team_id` and `identity_state` for keyed
requests. Retained failures: attempt 01 named a second probe that was not built;
attempt 02 found that the gateway treats a **missing** principal, team or org
record as deny-all (a deleted team must not read as unrestricted), so the
fixture must seed them.

## Latency attribution (P24, 2026-10-02)

**MEASURED, with one stage definition falsified and corrected.** One owned eBPF
program, [`aigw_timing.bpf.c`](../../substrate/surfaces/aigw_timing.bpf.c), has
eight entries: admission, the two store requests (`aigw_host_hgetall`,
`aigw_host_eval`), store replies, session events, reply passes, reply completion
and record publish. Events are joined on the request's client-side `aigw_scb`.
A mock provider holds headers for D1 = 200 ms and pauses D2 = 150 ms mid-body.

Result (attempt 03, medians): admission 4.3 ms, of which store round trips
4.1 ms; provider until complete reply 356.4 ms (D1 + D2 = 350 ms); reply
processing in TMM 0.1 ms; delivery 2 µs; total 360.9 ms. The stages sum to the
total within 2 µs. The full table is in
[P24](../../02-RESEARCH-PARAMETERS.md#p24--can-ebpf-probes-attribute-an-ai-gateway-requests-latency-to-its-stages).

**Finding (attempt 02):** for a buffered JSON reply, TMM raises the response
event only after the whole body is parsed. The registered "first byte" stage
therefore measured complete-reply time (about D1 + D2), and so does the gateway's
own `latency_ttft_us` field, which is set on the same event. A true first-byte
time needs a header-level hook and a streamed request.

**Also found (attempt 01):** `aigw_dssm_send`'s callback argument is the host
context only for a key lookup; for a Lua script it is a script-call record. The
probe hooks the two host-table entries instead.

Not yet checked: the probe totals against the gateway record's own latency fields
(needs both probes armed together). Data-path cost of the probes is not measured.
