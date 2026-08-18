# The reset feed — `rst_why`, end to end

What it is: for every connection TMM resets, a record naming the **exact line of TMM
source** that made the decision, emitted from a running process through a hook that
was armed while traffic flowed, readable by an ordinary process over shared memory.

Verified live on 2026-08-17 against `tmm:maps2` on BNK/datkube. Everything below is
measured output, not a design sketch.

---

## 1. What a record looks like

```json
{"ts_ns":1787066626925893333,"seq":162,"tmm":5,"hook":"reset","fn":"rst_why","schema":3,
 "file":"http_mr_proxy.c","line":993,"err":32,"reason":0,
 "flow":"00003a0c137fafba","cause":"Closing"}
```

Twelve fields, drained from a live pod on 2026-08-18. **This section showed a nine-field
schema-1 record until then**, which is worth flagging rather than quietly replacing: the
record has GAINED fields, and a reader comparing a current record against the old
example would reasonably think three had gone missing.

| added | when | why it matters |
|---|---|---|
| `cause` | Phase 3, when the trampoline began forwarding all six arguments | At `flow_table.c:2618` the cause is `flow_reject_cause[flow_reject_code]` — a runtime lookup into an 18-entry table. No amount of reading the source recovers which entry applied. |
| `flow` | the flow cookie, from `UFLOW_COOKIE(uf)` | Gives CARDINALITY: 3 records across 2 flows is one client hammering, 12 across 12 is systemic. Not identity — the 5-tuple does not fit the remaining ctx budget. |
| `fn` | when each of the four `RST_WHY*` functions got its own slot | `hook` stays `"reset"` for all four so a consumer keyed on it does not break; `fn` names which one fired. |

`schema` went 1 → 3 alongside those, and that is load-bearing: `struct ls_ctx_rst` changed
layout (`file[]` shrank 48 → 32 → 28 to make room), so a consumer built against schema 1
would read `line` out of the middle of a filename. The version is the only thing between
a layout change and silently wrong decoded output.

Read out of the segment by `substrate/drain/ls_drain.c`, which writes JSON lines to
stdout and nothing else — pipe it to a file, `jq`, or a broker publisher.

`seq` is a process-global counter while the rings are per-thread, so **gaps in `seq`
within one ring are normal** and mean another thread emitted in between. A gap is not
a drop; drops are counted separately.

---

## 2. How to trigger a reset

Four triggers, each run five times, with the records they actually produced.

| trigger | sites that fired | per request |
|---|---|---|
| Backend closes abruptly | `http_mr_proxy.c:993` + `:994`, some `tcp.c:4689` | 2 |
| No backend at all (`scale --replicas=0`) | `http_mr_proxy.c:993` + `:994` | 2 |
| Client aborts mid-request (`--max-time 0.001`) | `tcp.c:4999`, `tcp.c:4689` | ~1 |
| Malformed request line | `http_mr_proxy.c:993` + `:994` | 2 |

The commands, from the `client` pod against the Gateway VIP `11.11.11.99`:

```bash
# 1 — the standing trigger. The test backend is `nc -l`, which serves ONE connection
#     and exits, so every request ends with an abrupt upstream close.
kubectl exec client -- sh -c 'for i in 1 2 3 4 5; do
  timeout 2 curl -s -o /dev/null http://11.11.11.99/; done'

# 2 — no backend
kubectl scale deploy http-pool -n spk-app-1 --replicas=0

# 3 — client-side abort. The ONLY trigger here that reaches a different file.
kubectl exec client -- sh -c 'for i in 1 2 3 4 5; do
  curl -s -o /dev/null --max-time 0.001 http://11.11.11.99/; done'

# 4 — malformed request line
kubectl exec client -- sh -c 'for i in 1 2 3 4 5; do
  printf "@@@BADMETHOD / HTTP/9.9\r\n\r\n" | timeout 2 nc 11.11.11.99 80; done'
```

**Two records per request is not a bug and it is worth understanding**, because it
is the clearest evidence the records are real:

```c
/* http_mr_proxy.c, and the line numbers in the feed are these */
if (peer_scb->flow == MRHTTP_FLOW_COMPLETE) {
    RST_WHY(scb->uf,      "Closing");   /* 993 */
    RST_WHY(peer_scb->uf, "Closing");   /* 994 */
```

Two adjacent calls, one per side of the proxy. The feed reports 993 and 994 in equal
numbers because the code calls them in pairs.

The client-abort sites resolve the same way:

```c
/* tcp.c:4999 */  TCP4_NOTIFY(node, tp, HUDEVT_ABORTED,
                      RST_WHY_CF(cf, "TCP RST from remote system"));
/* tcp.c:4689 */  TCP4_NOTIFY(node, tp, HUDEVT_ABORTED,   /* passive-failure path */
                      RST_WHY_CF(cf, "TCP RST from remote system"));
```

### Sites seen so far, ranked, from one live sample

Fifteen requests (twelve normal, three client-aborted) produced:

```
   82  tcp.c:4689           RST_WHY_CF(cf, "TCP RST from remote system")   passive-failure path
   12  http_mr_proxy.c:994  RST_WHY(peer_scb->uf, "Closing")               proxy teardown, peer side
   12  http_mr_proxy.c:993  RST_WHY(scb->uf, "Closing")                    proxy teardown, near side
    8  flow_table.c:2618    RST_WHY_CF(&cf_static, flow_reject_cause[flow_reject_code])
    2  http_mr_proxy.c:973  RST_WHY(scb->uf, "Closing")                    CX_WAIT close
```

Produced with `ls_drain | jq -r '"\(.file):\(.line)"' | sort | uniq -c | sort -rn`.

**`flow_table.c:2618` is the most valuable site found so far and the strongest
argument for Phase 3.** Its cause is not a literal, it is
`flow_reject_cause[flow_reject_code]` --- an *enumerated table* of reject reasons.
That is precisely the field an engineer wants when asking why a flow was rejected,
it already exists in TMM, and it is the sixth argument the trampoline drops. The
feed can currently say "a flow was rejected at flow_table.c:2618" but not which of
the enumerated causes applied.

Note also that ranking is itself information: 82 of 116 records came from one site,
and none of the four triggers was designed to produce it. A counter cannot tell you
that one internal decision dominates your reset volume.

---

## 3. What this gives that TMM does not already have

**CORRECTION FIRST, because earlier drafts of this file overclaimed.** BIG-IP already
puts the reset cause ON THE WIRE. `tcp_common.c` calls, unconditionally, in the
RST-send path immediately before `ip_output`:

```c
rst_cause_append(uflow_fromconnflow(cf), pkt, rst_cause_getinfo(uflow_fromconnflow(cf)));
```

HTTP/2 has `rst_cause_serialize`, QUIC puts it in the reason field. So **a packet
capture does show the reason today.** Any framing that implies "the reason is
invisible without this" is wrong. What is left is narrower and still real:

- **The file identity --- and this bullet used to claim more.** It said "`file:line`,
  which the wire cannot carry". A packet capture DISPROVED that: the RST payload reads
  `BIG-IP: [0x235ef8f:2618] No local listener`, so the LINE NUMBER is on the wire next
  to the cause. What is absent is the file NAME --- the wire carries an opaque
  identifier instead. So this differentiator is far weaker than claimed, and the
  correction is recorded rather than the sentence quietly softened.
- **Decisions that never become a packet --- the real differentiator, and now a
  MEASUREMENT rather than an argument.** In one capture taken while driving known
  traffic, ~32 records were produced and only **5** had a corresponding RST on the
  wire. The 12 `Closing` records are graceful proxy teardowns where no RST is sent at
  all; the 14 `TCP RST from remote system` records are resets TMM RECEIVED rather than
  sent. `rst_cause_append` runs for neither. Five of thirty-two have a wire
  counterpart; the rest exist only in the feed.
- **Always on.** tcpdump cannot run continuously in production at volume. This is a
  bounded-cost stream with counted drops.
- **No customer payload.** 92 bytes of metadata rather than captured traffic.

That is "better instrumentation of something partially visible", not "revealing the
invisible" — and it is worth stating that way before a reviewer does.

### Selective packet capture keyed on a code path — PARKED, and why

An earlier draft of this section pitched it as a clean win: tcpdump filters on wire
attributes and cannot express *"capture the packets around the moment
`flow_table.c:2618` fires with cause Connection limit exceeded"*, so the feed becomes
the trigger for a capture no existing tool can express. That framing survives; the
cost estimate behind it did not. **Parked 2026-08-18.**

**The fact that undercuts it: `rst_why` has no packet.** Its signature is
`(uf, file, lineno, err, reason, cause)` — a flow handle. The reset hook cannot capture
a packet because there is not one in scope. That was not checked before proposing it.

Three tiers, and the value sits entirely in the expensive one:

| tier | cost | value |
|---|---|---|
| Capture the RST packet itself, hooking `rst_cause_append(uf, pkt, ...)` which does have it | days | **near zero** — the RST payload already carries `BIG-IP: [id:line] cause`, so it duplicates the record |
| Capture forward from the trigger | days, no standing cost | misses the traffic that *caused* the reset, which is the whole question |
| **Retrospective — "the packets around the moment"** | **weeks + PERMANENT per-packet cost** | this is the useful one |

Tier 3 needs a per-thread rolling packet buffer **written on every packet, forever,
whether anything triggers or not.** That is a standing data-plane cost, and avoiding
exactly that is why the reset hook currently costs nothing until a reset happens.

**Volume, against the rings we have** (16 x 64KB, 1MB total): records at 92 bytes give
~700 per thread; packets at 1500 bytes give ~43. A 20-packet window for ONE event is
~30KB, half a thread's ring. So it is not a tweak to the existing ring — it needs a
second ring type, sized and retained differently, plus Phase 4 to decouple the record
from the 96-byte program ctx.

**The cheaper thing that answers most of the same question:** capture flow-level
metadata at trigger time rather than packets. The cookie already gives
same-flow-or-not; adding the 5-tuple gives "which client". Bounded, small, no capture
machinery. See the flow-identity note in §3.

### Coverage: how much of "why a RST?" this actually answers

Counted in the tree, not estimated. **1,116 reset-decision call sites across 200
files**, funnelling into three different functions:

| funnels into | sites | armed by this hook |
|---|---|---|
| `rst_why` | **966 (87%)** | **yes** |
| `rst_why_va` (varargs forms) | 131 (12%) | no |
| `rst_why_preserve` | 19 (2%) | no |

**READ THAT AS CODE SITES, NOT RESETS.** It counts places in the source that can
decide a reset, not resets that happen. One hook sees *every* reset flowing through
`rst_why` and *none* flowing through the other two functions.

What fraction of ACTUAL resets that is depends on which of the 1,116 sites execute
under real traffic, and **that is unmeasured**. In the demo it was complete: every
reset produced by the traffic driven came through `rst_why`, and the counts matched
1:1 (15 requests, 15 pairs; 5 closed-port connects, 5 rejects). The 131 varargs sites
format their cause at runtime, which usually marks unusual or diagnostic conditions,
so they may well be rare --- but that is a guess and should not be stated as a finding.

So: **87% of the decision sites, with the runtime fraction unknown and complete in the
one sample taken.** The gap is bounded and named:

- **`rst_why_preserve`** is 19 sites with the same six-argument shape. Arming it is a
  second address and nothing else.
- **`rst_why_va` is the real limit.** 131 sites, and `trampoline_x86_64.S` lists
  varargs as an explicit non-goal: `rax` carries the vector-register count and the
  trampoline does not preserve or forward it. Those sites also format their cause at
  runtime, so the string is not a literal there either.

One file, `tcp_common.c`, sends a RST without calling `RST_WHY` — but that is the
emitter (it holds `rst_cause_append` and the send path), not a decision site. Worth
confirming rather than assuming.

Not reachable from iRules or WASM either way: `RST_WHY` is an internal macro on an
internal path, not an event F5 exposed. Nothing had to be designed in — the hook was
chosen after the binary shipped and armed into a running process with no restart.

Combined with maps (`substrate/shields/rate_watch.bpf.c`), a program at this hook can
answer "is this site firing more than N times for this key" — a per-site rate rather
than a global total. That was measured: 84 firings produced 30 safe-returns, then the
rate settled to one per two, which is a counter crossing its threshold.

---

### What the record does NOT carry: any flow identity

**There is no per-request, per-connection or per-client field.** The record is
`lineno`, `err`, `reason`, `file`, `cause`, plus the ring header's `ts_ns`, `seq`,
`tmm` and `schema`. So a record can be correlated **by time** (nanosecond), **by
thread**, and **by ordering** --- and not to the request that caused it.

This matters because "correlate a reset to the request that caused it" was claimed
several times while building this, including in earlier drafts of this file. What is
true is narrower and still useful: **per-event granularity with an exact site and an
exact cause**, where TMM otherwise offers a total. "We can attribute to a line and a
reason" is supportable. "We can attribute to a request" is not, yet.

**The handle is right there, which is what makes this worth fixing.** `rst_why`'s
FIRST argument is `uf`, the flow. The trampoline forwards it as `a0` and
`ls_ctx_rst_build` ignores it. Adding identity is a host-side dereference of a
pointer we already receive --- the same pattern `ls_ctx_alpn.c` already uses to hand a
program flat bytes derived from `sc`.

The obstacle is the ctx budget, not access. The record is 92 of PREVAIL's 96 bytes,
so a full 5-tuple (12 bytes for IPv4, 36 for IPv6) does not fit. Two ways out:

- **An 8-byte flow hash**, shrinking `cause[]` from 40 to 32. Not an identity, but a
  correlation KEY: equal keys mean the same flow, which is what joining records
  across a session actually requires. Fits today.
- **Decouple the ring record from the program ctx** (`LIMITATIONS.md` 2.3, and the
  ring-output helper in `widening-plan.md` Phase 4). Then egress size stops being
  capped by what the verifier can reason over, and the full tuple fits.

Until one of those lands, describe the feed as per-event with exact attribution to a
code site --- never as request correlation.

---

## 4. Limits, plainly

**`err` and `reason` carry nothing on these paths.** Every record above has
`err=32` (`ERR_UNKNOWN`) and `reason=0`. The discriminating field is `file`:`line`,
not the error code. Do not present `err` as meaningful without checking it on the
path in question.

**The human-readable cause string is the one field not forwarded.** `"Closing"` and
`"TCP RST from remote system"` are `rst_why`'s **sixth** argument. System V puts a
sixth argument in `r9`, and the trampoline forwards only five because `rdi` carries
the slot. So the feed says `http_mr_proxy.c:993` where it could say
`http_mr_proxy.c:993 "Closing"`. Fixing it is Phase 3 of `widening-plan.md` — pass a
pointer to the saved register block instead of individual arguments — and it is the
single highest-value change to this feed.

**Three of four triggers land on the same site.** `http_mr_proxy.c:993/994` is a
generic teardown path, so "no backend", "backend closed" and "malformed request" are
not distinguishable from the reset record alone. Distinguishing them needs either an
additional hook earlier in the path or the cause string above.

**Per-invocation cost is unmeasured.** `cycles` in the slot counters is dominated by
preemption artifacts, and the bench op that would give a clean floor wedges the loader
thread. Quote no per-call number from this.

**The bounds check is not exercised.** `LS_VM_JIT=1` in this deployment, and uBPF's
compiled path does not consult the data bounds callback. Functionality is
demonstrated; the memory-safety property is not.

---

## 5. How it is emitted, and how it is viewed

**TMM emits binary, not JSON.** Per record it writes a fixed-size header plus a
64-byte `struct ls_ctx_rst` into its own per-thread ring: a bounds check, two
`memcpy`s and one release store. No allocation, no syscall, no string formatting,
and no dependence on a reader --- `ls_ring_emit` on a full ring returns 0 and counts
a drop rather than blocking. Formatting JSON on the data path would be exactly the
wrong place to spend the time.

**JSON is produced outside TMM**, by `ls_drain`, a separate process reading the
shared segment. That boundary is the whole design: the agent can be absent, killed
mid-batch or stalled forever and the worst outcome is that rings fill and TMM counts
drops. `substrate/drain/check_drain.c` asserts this rather than assuming it, across
consumer states ABSENT / CRASHED / STALLED / HEALTHY / HOSTILE.

Three ways to view it, all just consuming stdout:

```bash
# raw records
ls_drain --segment /tmp/ls_tp_ring

# which internal decisions are firing, ranked --- the support question
ls_drain --segment /tmp/ls_tp_ring \
  | jq -r 'select(.hook=="reset") | "\(.file):\(.line)"' | sort | uniq -c | sort -rn

# to a broker. No client is linked into the agent, deliberately, so the transport
# is chosen here rather than in the code.
#
# BNK ALREADY RUNS ONE, and it is RabbitMQ, not NATS: the f5-rabbit pod has been up
# since the cluster was built, reachable at amqps://rabbitmq-server.default:5671
# (helm release rabbitmq-0.10.4). Earlier drafts of this doc used `nats pub` as the
# example, which read as a recommendation for something not installed while the bus
# the product actually ships went unmentioned.
ls_drain --segment /tmp/ls_tp_ring | <amqp-publisher> --uri amqps://rabbitmq-server.default:5671
```

**Publishing to that bus is untested here.** It is mTLS (`QK_TLS_CA_BUNDLE`,
`amqps`), so it needs a client cert and a routing key --- and whether data-plane
telemetry belongs on BNK's control-plane bus is a design decision for F5, not an
implementation detail. What is settled is that the agent does not care: stdout is
stdout.

Delivery is **at-least-once**: records are written before `consumer_pos` advances, so
a crash mid-batch re-delivers rather than loses. Dedupe on `seq`.

## Validating it --- against an independent oracle

Everything that went wrong while building this went wrong the same way: a status line
reported success while the underlying property was false. `OK ARMED LIVE` on the wrong
function. Tokens present in a binary with no entry pads. A build that succeeded into an
image carrying a cached older binary. `fired=0` that meant the wrong pod. So validation
must use checks that cannot report success without being true.

**1. Falsifiable counts.** Drive exactly N of a known trigger, expect exactly N records.
15 requests give 15 `:993` AND 15 `:994`, because the code calls `RST_WHY` on adjacent
lines. A wrong hook, a wrong pod or a stale binary each break the arithmetic.

**2. Negative control.** Disarm, drive identical traffic, records must STOP. If they do
not, they were never coming from the hook.

**3. THE INDEPENDENT ORACLE, which is the strongest available.** `rst_cause_append`
puts the cause on the wire, so the same fact exists in two places sharing no code ---
TMM's packet output and this feed:

```bash
kubectl exec client -- sh -c 'timeout 20 tcpdump -i any -s0 -w /tmp/rst.pcap \
    "tcp[tcpflags] & tcp-rst != 0"' &
# ...drive five connects to a closed port...
kubectl exec client -- sh -c 'strings /tmp/rst.pcap | grep -a "BIG-IP:"'
```

Measured 2026-08-17:

```
wire :  5 x  BIG-IP: [0x235ef8f:2618] No local listener
feed :  5 x  "line":2618, "cause":"No local listener"
```

Five driven triggers, five wire RSTs, five records --- same cause, same line number,
from two paths with no common code. This is the check that actually validates the feed,
and it is also the one that disproved the `file:line` claim above.

## 6. Reproducing it

```bash
# ls_drain must be built for the pod's arch on the build box, and STATIC ---
# the f5-tmm container has no toolchain and a thin libc surface.
gcc -O2 -Wall -Wextra -static -I substrate -o ls_drain substrate/drain/ls_drain.c

kubectl cp ls_drain <pod>:/tmp/ls_drain -c f5-tmm

# The segment is the path in LS_TP_RING --- a regular file, NOT /dev/shm.
# Pointing at /dev/shm gives "cannot open ... as a tracepoint segment", which
# reads like a missing feature and is a wrong path.
kubectl exec <pod> -c f5-tmm -- /tmp/ls_drain --segment /tmp/ls_tp_ring
```

Arming, if the slot is not already live — note the address must come from the binary
`/usr/bin/tmm` actually resolves to:

```bash
kubectl exec -i <pod> -c f5-tmm -- python3 /tmp/ls-load.py load 5 /tmp/rate_watch.bpf.o 2 rst_why
kubectl exec -i <pod> -c f5-tmm -- python3 /tmp/ls-load.py arm  5 0x144df00
kubectl exec -i <pod> -c f5-tmm -- python3 /tmp/ls-load.py status 5
```

**Arm every TMM pod, or read the one that served the traffic.** Requests
load-balance across pods; an armed process that happens not to receive the requests
reports `fired=0`, which looks exactly like a hook that does not work.
