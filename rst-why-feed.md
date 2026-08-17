# The reset feed — `rst_why`, end to end

What it is: for every connection TMM resets, a record naming the **exact line of TMM
source** that made the decision, emitted from a running process through a hook that
was armed while traffic flowed, readable by an ordinary process over shared memory.

Verified live on 2026-08-17 against `tmm:maps2` on BNK/datkube. Everything below is
measured output, not a design sketch.

---

## 1. What a record looks like

```json
{"ts_ns":1786983692844260842,"seq":0,"tmm":5,"hook":"reset","schema":1,
 "file":"http_mr_proxy.c","line":993,"err":32,"reason":0}
```

Read out of the segment by `substrate/drain/ls_drain.c`, which writes JSON lines to
stdout and nothing else — pipe it to `nats pub`, a file, or `jq`.

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

---

## 3. What this gives that TMM does not already have

TMM counts resets. It cannot say **which** internal decision produced **this**
connection's reset. The feed can: `http_mr_proxy.c:993` is a normal proxy teardown,
`tcp.c:4999` is the remote system sending a RST. Those are different support answers
and today they are indistinguishable in a counter.

It is also not reachable from iRules or WASM: `RST_WHY` is an internal macro on an
internal path, not an event F5 exposed. Nothing had to be designed in — the hook was
chosen after the binary shipped and armed into a running process with no restart.

Combined with maps (`substrate/shields/rate_watch.bpf.c`), a program at this hook can
answer "is this site firing more than N times for this key" — a per-site rate rather
than a global total. That was measured: 84 firings produced 30 safe-returns, then the
rate settled to one per two, which is a counter crossing its threshold.

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

## 5. Reproducing it

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
