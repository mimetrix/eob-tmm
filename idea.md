# Streaming-inference shape leakage — framed against the substrate that exists

**Status:** Draft proposal. **Nothing in this document has been measured.** Every claim below is
tiered; the two that would decide whether the idea is worth building are pre-registered falsifiers
in §3, and the cheapest one needs no eBPF program at all.

**Companions:** [`vm-capability-inventory.md`](vm-capability-inventory.md) (the flat capability
list this is written against), [`probe-a-function.md`](probe-a-function.md) (the procedure for
§7), [`data-plane-intelligence.md`](data-plane-intelligence.md) (strategy annex — the nearest
existing framing, and it does **not** cover this), [`GROUND_TRUTH.md`](GROUND_TRUTH.md) (every
MEASURED figure quoted here).

---

## 0 · What this replaces, and why — recorded rather than tidied away

The first draft of this file proposed a **tracepoint ABI v0**: seven designed-in `tmm:*`
tracepoints, three new context structs, a five-helper ABI, per-flow size and gap histograms, and
a one-week path from observation to enforcement. It was written as though the substrate did not
exist. Four things falsified it, and they are kept here because the reasons generalise:

| the draft proposed | why it is wrong |
|---|---|
| seven designed-in `tmm:*` tracepoints | **designed-in call sites are RETIRED** (`vm-capability-inventory.md` §1). Every hook today is a **pad-patched function entry** — no source change, no rebuild. The draft put a build cycle back on the critical path to obtain something the existing mechanism gets without one |
| a `tracepoint` vs `hook` ABI split for observe-safety | duplicates what exists. Observe-only is a **mode** (`MONITOR`), not a class; the verdict vocabulary is already `LS_FALLTHROUGH` / `LS_SAFE_RETURN` |
| five new helpers | **four of the five are built**: map ops (ids 1/2/3), `bpf_probe_read` (4), `bpf_ktime_get_ns` (5), `bpf_perf_event_output` (25) — `substrate/ls_map_glue.h:672–702` |
| per-flow size/gap histograms as the artifact | breaks three hard limits (§5) **and is the wrong statistic** (§6) |

And the framing itself was wrong in a way no limit table would have caught — §2.

> **The pattern worth keeping from this.** The draft's errors were all the same error: proposing
> a capability rather than reading `vm-capability-inventory.md` to find it already shipped, or
> already retired for a stated reason. The inventory exists precisely so this does not cost a
> build cycle to discover.

---

## 1 · The premise, and its citation status

The premise is that a **streaming** inference response (SSE or HTTP/2 `DATA` frames, one flush per
token or small token group) leaks response structure — token count, approximate response length,
and generation cadence — to an observer who cannot decrypt, because each flush becomes its own TLS
record with its own plaintext length and its own arrival time.

**Citation status: NOT_RETRIEVED.** There are no rows in [`SOURCES.md`](SOURCES.md) (130 lines) on
LLM streaming side channels, token-length leakage, or traffic-analysis attacks on inference
endpoints. I believe published work on this exists and am **reasoning from memory, which
`CLAUDE.md` rule 1 does not permit as a basis for a claim**. Before this premise appears in
anything shown to anyone it needs retrieval and caching under the evidence rules.

The **protocol** fact the premise rests on — that a TLS record carries a cleartext 5-byte header
including its length, so record sizes and inter-record gaps are visible without decryption — is
also **from memory, uncited**. It is a well-known property and RFC 8446 is the place to cache it.
It is also load-bearing in the opposite direction from what the first draft assumed, which is §2.

---

## 2 · The reframe: observation is not the moat

**The observable is already public.** Record lengths and timestamps are cleartext on the wire, so
a span port plus fifty lines of Python produces the same size and gap distributions from outside
the box. The first draft's differentiating claim — *"encrypted inference traffic leaks through its
shape, and TMM is the only component positioned to see it"* — is therefore backwards. Shape is the
one signal that needs **no** privileged vantage at all.

Two things TMM does have, and everything of value is one of them:

**1 · Labels.** TMM terminates the TLS, so it holds the *observable* and the *secret* at the same
instant, on real production traffic, at line rate. A passive tap sees shape and must guess the
mapping to token counts. The origin knows the tokens but not what shape reached the client. TMM is
the only place that can emit **paired** `(shape, truth)` rows.

That converts the deliverable from *"shape leaks, per the literature"* into *"on **your** traffic,
client-visible record shape recovers response token count to this measured accuracy."* Nobody else
can produce that number for a customer's real endpoint without owning the model or replaying
synthetic prompts.

**2 · Enforcement.** A tap proves a leak and can do nothing about it. TMM **emits** those records,
so it chooses their sizes and their timing. Measurement and mitigation are one policy object on
one box, and the same instrument verifies the fix.

**What this answers that the retired HTTP tracepoint could not.** That call site was rolled back
because *iRules already saw every field*. iRules operates on HTTP and TCP payload events, not on
the TLS record layer — record granularity is below its floor, and so is the per-record cost.
That is a real answer to *"why not iRules"*. It is **not** an answer to *"why not a span port"*,
which only labels and enforcement answer.

---

## 3 · Falsifier-first — and the cheap disproof needs no eBPF

Two pre-registered kill conditions, in cost order. Neither has been run.

### 3.1 · Does TMM's client-facing framing even carry the leak? (ROADMAP — one afternoon)

**The risk nobody has checked: TMM re-frames.** The records reaching the client are TMM's framing
choice, not the origin's. If TMM coalesces several SSE events or `DATA` frames into one record, or
buffers to a fixed size, the correlation between record size and token length is destroyed *on our
own egress path* — and there is nothing to observe and nothing to fix.

> **Falsifier.** Drive a streaming response through the tls-gateway and capture on the **client**
> side with `tcpdump`. Compare the record-length sequence against the token lengths the origin
> emitted. **If the sequence does not track, the idea is dead** — no substrate work, no build box,
> no program.

This runs against the existing `tls-gateway` (`11.11.11.97`), which is the listener that lit the
whole `ssl_*` surface in [`reachability-survey.md`](reachability-survey.md). It needs a streaming
origin, which is a **config-expressibility question** and therefore the third term of
`exposure = fix absent × compiled in × precondition reachable` — the term that blocked six CVE
candidates (`cve-to-shield-process.md` §4). The CVE demonstration needed a purpose-built h2c
backend **and** a new virtual server before an HTTP/2 path existed at all, and `bnk-core`'s Gateway
path still cannot express server-side HTTP/2. Assume the origin is work.

### 3.2 · Does the span port do it just as well? (ROADMAP)

> **Falsifier.** If the same capture in 3.1 yields the same leak estimate as an in-TMM program
> would, the *observation* half of the value proposition is dead and only §2's labels and
> enforcement survive.

I expect this one to **fire**. It should be run anyway, and stated, because it is the first
question a skeptical reviewer asks and the answer is better volunteered than extracted.

---

## 4 · What the substrate already provides

Nothing in this section is a proposal. It is the inventory this idea must be written against.

| axis | state | source |
|---|---|---|
| Hook type | function entry, **pad-patched**, armed and disarmed live with no restart | `vm-capability-inventory.md` §1 |
| Hook granularity | **by symbol name, process-wide.** There is **no per-virtual-server arming** — §9 | `ls-load.py arm <slot> <fn>` |
| Exit / return probes | **absent** (in progress — see the `fexit` work) | §1 |
| Helpers | map ops (1/2/3), `bpf_probe_read` (4), `bpf_ktime_get_ns` (5), `bpf_perf_event_output` (25) | `ls_map_glue.h:672–702` |
| Maps | hash only · **4 per program** · **256 entries** · key ≤ **16 B** · value ≤ **32 B** · per-thread · **evict-the-incumbent, counted** | `ls_map.h:61–64` |
| Egress | per-thread ring, **64 KB each**, **16 max**, `STREAM` drops-and-counts / `RECORD` overwrites-oldest | `ls_tp_ring.h:48` |
| Verdicts | `LS_FALLTHROUGH`, `LS_SAFE_RETURN` — **no mutating verdict exists** | §5 |
| Modes | `DISABLE` / `MONITOR` / `ENFORCE`, with a signed per-program mode ceiling | §5, §7 |
| Admission | PREVAIL verification · Ed25519 signature · build-ID gate · ctx-ABI check · unique-symbol check | §7 |
| Type information | the shipped binary carries **0 bytes of `.BTF`**; offsets are baked at sign time | `GROUND_TRUTH.md` |
| Counters per slot | `fired`, `safe_returns`, `errors`, `gen` — **cumulative across program swaps** | `probe-a-function.md` §3 |

Three of these have teeth for this idea specifically:

- **`bpf_probe_read` removed the rebuild.** A new hook *shape* used to cost a build cycle because
  the host had to dereference in C. It does not any more — a program chases the pointer itself out
  of the generic five-register context. So everything in §7 is a program, not a build.
- **The generic context is 40 bytes, but PREVAIL verifies 96.** `ls_tramp.c:107` passes
  `uint64_t arg[5]`; bytes 40–95 are verifiable-but-unallocated trampoline stack frame, readable
  by a program that passes every gate we have (commit `7ed7e77`, **not fixed** — a hot-path change
  and the owner's call). Any program here reads `arg[0..4]` and nothing above it.
- **The JIT never consults the bounds callback, and the lab runs the JIT.** So for a JIT'd
  program, PREVAIL's proof is the *only* thing standing behind a computed map or context index.
  §6 is written to avoid computed indices entirely, and that is deliberate.

---

## 5 · The limits the first draft's program broke

Recorded because the numbers are the reason §6 looks the way it does.

| the sketch wanted | the limit | verdict |
|---|---|---|
| `struct shape` ≈ 160 B as a map value | **≤ 32 B** (`ls_map.h:64`) | refused. Two 16-bucket `u32` histograms are 128 B by themselves |
| a per-flow table at BNK concurrency | **256 entries**, per-thread, **evict-the-incumbent** (`ls_map.h:62`) | the nastier one: leak scores computed on silently truncated state **look fine** |
| `BPF_RINGBUF(events, 1 << 20)` | **64 KB** per ring (`ls_tp_ring.h:48`) | 16× over |
| `size_hist[log2_bucket(rec_len)]++` | JIT does not bounds-check | a computed index from attacker-influenced input, with only the verifier behind it |
| a summary computed inside BPF | **no map iteration** | a program can accumulate and never summarise |
| `tmm:flow_close` | **no exit probes** | must be an *entry* hook on a teardown function — §7 |

The three context structs were the one part that fit: all three are under the 96-byte ceiling.

---

## 6 · The artifact: one labeled row per response, not a histogram

**The histogram is the wrong statistic even where it fits.** `leak_score = Shannon entropy of
size_hist` measures that record sizes *vary*, not that they are *informative about tokens*.
Leakage is mutual information between the observed **sequence** and the secret, and the strongest
form of this leak is per-flush record size tracking per-token length — a property of the sequence,
which a histogram discards. The gap histogram discards cadence order the same way. The result
would be a confident-looking 0–100 score that is not measuring the claim.

A histogram is also what you build when you **cannot get labels**. §2 says labels are the entire
advantage, and a marginal distribution cannot be correlated with a truth value.

**So: one row per response, emitted at teardown.**

| field | bytes | where it comes from |
|---|---|---|
| record count (client-facing, app-data) | 2 | incremented at the TX hook |
| total encrypted bytes | 4 | accumulated at the TX hook |
| min / max record size | 2 + 2 | accumulated at the TX hook |
| TTFT (µs) | 4 | first TX minus request start, `bpf_ktime_get_ns` |
| response duration (µs) | 4 | last TX minus first TX |
| **true token or SSE-event count** | 2 | **the label** — post-decrypt, the thing only TMM has |
| flags (streaming, h2 vs h1, padded upstream) | 1 | classification |

**21 bytes.** Fits the 32-byte map value, one map, one key (the flow cookie ≤ 16 B), no histogram,
no computed index, no second map. It is a labeled training row, and it is the artifact nobody else
can make.

Everything that was going to be a histogram becomes an analysis over these rows off-box: regress
recovered token count against the shape fields, report accuracy and its confidence interval. If a
richer per-record sequence is wanted later, the ring carries variable-length payloads
(`ls_ring.h`) and the per-record stream can be emitted directly — but the labeled row answers the
question, and it answers it inside the limits that exist today.

**The label is the hard part, and it is not in §7's hook.** Record count comes from a TLS-layer
hook; the token count comes from the post-decrypt HTTP layer. Two hooks writing one map entry
keyed on the same flow identity — and flow identity is `UFLOW_COOKIE`, a semantic derivation that
`mk_probe.py:30` explicitly says no generator can invent. It is hand-written work, and it is where
the real engineering is.

---

## 7 · Candidate hooks — from the index, with armability as a hint

Read from the local `hook-index.tsv` and `signatures.tsv`. **This is a HINT, not a conclusion:**
the local index is build `499b8c30`, current work is build `1824611c`, and *armability is a
property of the build, not of the function* — `http2_stream_abort` went from `pad_offset=4` to `0`
between builds from identical source. Re-check in the pod (`bnk-explore-hooks.py explain <fn>`)
before believing any row.

| candidate | index | signature | for |
|---|---|---|---|
| `ssl_encsz` | pad 4, unique → ARMABLE | `suite:blob:struct ssl_suite *` \| **`sz:scalar:long unsigned int`** | **the interesting one.** A **scalar** size in a register — readable straight out of the 40-byte generic context, no ctx builder, no `probe_read`, no rebuild |
| `ssl_codec_tx` | pad 4, unique → ARMABLE | `sc:blob:struct ssl_ctx *` \| `codec:blob:struct ssl_codec *` | the TX record path; needs `probe_read` to get a length |
| `ssl_codec_rx` | pad 4, unique → ARMABLE | `sc`, `codec` | the mirror, if the client side is ever wanted |
| `listener_flow_free` / `bigtcp_flow_free` / `bigproto_flow_free` | pad 4, unique → ARMABLE | `cf:blob:struct connflow *` | **flow teardown, for the emit** |
| `__flow_free` | **pad 0 → `ls_arm` REFUSES** | `cf:blob:struct connflow *` | the obvious choice, and it is not available |
| `flow_init` | pad 4, unique → ARMABLE | `cf`, `key:blob:struct flow_key *` | flow open |
| `http_parse_client_headers` | pad 4 — **fires once per request, MEASURED** | — | request start, for TTFT. `GROUND_TRUTH.md`: `fired=20` for exactly 20 requests |

**What is unmeasured and gates everything:** no TX-side `ssl_*` function has **ever** been armed
here. [`reachability-survey.md`](reachability-survey.md) covered 54 candidates and every one was a
`*_parse_*` function. Whether `ssl_encsz` fires once per record, and whether its `sz` argument is
the record length rather than a suite-overhead calculation, is **unknown** — not assumed. That is
the §3.1 experiment's second half and it is one afternoon with `mk_probe.py`, monitor mode, and a
`fired` delta on a clean slot.

---

## 8 · Two PoCs, honestly sized

### PoC A — observe and label (achievable on the built substrate)

Arm the TX-record hook, `http_parse_client_headers`, and a teardown hook; accumulate the §6 row in
one map keyed on the flow cookie; emit at teardown with `bpf_perf_event_output`; analyse off-box.
**Monitor mode throughout**, so the verdict path cannot affect traffic. No new helper, no new
verdict, no rebuild. The work is three ctx derivations, `UFLOW_COOKIE` by hand, and the drain-side
analysis.

### PoC B — reshape (not one week; a different order of magnitude)

The first draft proposed `PAD_TO` and `DELAY_NS` verdict ops "one week apart." Today's verdict
vocabulary is **two values**: run the body, or skip it and return a safe value. `PAD_TO` and
`DELAY_NS` would be the first **mutating** verdicts — bytes changed on the wire, and a send held
inside a run-to-completion poll loop. What that actually needs:

- a safe-value policy path that does not exist: the trampoline moves a hardcoded 0 into `rax`, so
  it is already **wrong for any return type that does not fit in `rax`** (`vm-capability-inventory.md` §5)
- a clamp table for verdict ranges, at admission
- a scheduler interaction for the delay — the one cost this design was built never to pay
- a TMA (Threat Model Analysis) for a program that alters wire bytes, which is a gating prerequisite

**And it may not be needed.** TLS 1.3 has a record-padding mechanism in the protocol itself
(zero padding inside the encrypted record) — *from memory, uncited*. If the mitigation is
expressible as a profile knob plus a `record_size_limit`, the whole of PoC B collapses into
configuration, and the substrate's contribution is the **measurement that proves the knob worked**.
That would be a better outcome and it should be checked before any verdict-op work is scoped.

Also: the draft's *"a verifier-rejected or runtime-faulted hook fails open to `PASS`"* is the right
default but is not a description of what exists — admission **refuses** a program at load
(signature, build gate, ctx-ABI) rather than admitting it in a passthrough state.

---

## 9 · Cost — what is measured, what is not, and the arithmetic

**MEASURED, 2026-09-05** (`GROUND_TRUTH.md:49`), on the real path in a live TMM, Xeon Platinum
8358 @ 2.60 GHz: an armed hook's **whole-path floor** is `cycles_min` 96–98, **≈ 37 ns** —
trampoline register save/restore, call and return, dispatch, and the JIT'd program. The CVE shield
(2 CO-RE reads + 2 `bpf_probe_read`) floors at **270 cycles ≈ 104 ns**. Witnessed **SELF** — the
trampoline times itself with an `rdtsc` pair. The older *"≤ 11 ns"* bench figure is a JIT-path
program-only bound that **excluded** everything the 37 ns figure includes; do not quote it here.

**ESTIMATE, derived from that floor — not a measurement.** A per-record TX hook is much cheaper
for *this* use case than the first draft assumed, and the draft's §1.1 rationale was exactly
inverted. Streaming inference is a **low** event-rate path relative to its duration: at ~30
tokens/s the inter-record gap is ~33 ms, so one 37–104 ns hook per record is single-digit **parts
per million** of the gap. Attaching to a per-record hook to "stress the platform" misreads which
traffic is hot.

**The cost is not borne by the inference flow, though — and this is the real objection.** Hooks arm
**by symbol, process-wide** (§4): there is no per-virtual-server arming, so `ssl_encsz` fires for
every TLS record on every flow through that TMM. Bulk TLS is where the bill lands:

| TLS TX load | records/s (est.) | at 37 ns | at 104 ns |
|---|---|---|---|
| 10 Gbps @ 16 KB records | ~76 k | ~0.3 % of one thread | ~0.8 % |
| 10 Gbps @ 4 KB records | ~305 k | ~1.1 % | ~3.2 % |

Arithmetic from a measured floor, so read it as an **order of magnitude, not a budget** — and a
floor understates: it excludes cache effects under real traffic, which is the whole reason the
per-call data-path cost is still recorded as unmeasured.

**How to measure it properly.** Not the draft's *"loaded vs unloaded at line rate"* — `rdtsc`
deltas are preemption-dominated, which is exactly why the recorded figure is a floor and why
`CLAUDE.md` forbids quoting it as a per-packet cost. The repo's own ranked answer is **PMU
instructions-retired as a helper** (extension #6, open), which is not subject to the preemption
artefact. It is blocked today by `perf_event_paranoid=4`.

---

## 10 · What this does not answer

- **Is there a streaming origin the deployed config can express?** §3.1 depends on it, and the CVE
  demonstration's history says assume not until shown.
- **Does `ssl_encsz`'s `sz` mean what its name suggests, and does it fire per record?** §7.
- **Where does the label come from, exactly?** SSE event boundaries and HTTP/2 `DATA` frames are
  different parsers. The token count may need a third hook, and `http2_*` reachability is
  measured for *parse* functions only.
- **Per-virtual-server arming.** §9 makes this the difference between a demo and a product, and it
  is absent from the ranked extension list — it may belong on it.
- **Two hooks, one map entry, per-thread maps.** A flow is handled by one TMM thread, so the TLS
  and HTTP hooks should share a thread and therefore a map. *Should*. CMP/DAG decides which
  instance sees a flow, and nothing here has verified that both hooks run on the same thread for
  the same flow. If they do not, the label and the shape never meet and §6 does not work.

That last one is the cheapest thing to get wrong and the least visible when it happens — the map
lookup simply misses, the row emits with a zero label, and the analysis regresses shape against
nothing. It wants an assertion in the program and a counter, not a comment.
