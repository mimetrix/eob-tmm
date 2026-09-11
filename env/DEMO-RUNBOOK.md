# CVE-2025-41414 demo — run it from here

> **Doing it live in terminals? Source the helper in every window:**
> `scp env/scripts/demo-env.sh <datkube>:~/` once, then `. ~/demo-env.sh` in each xterm.
> It gives you `preflight`, `tmm_wait`, `loader`, `normal`, `attack`, `btf_bytes`,
> `tmm_reset` — and it **re-resolves the TMM pod on every call**, which matters because
> the pod name changes when TMM dies halfway through the demo. A window holding a stale
> pod name breaks at exactly the wrong moment. The prose below explains what each step
> proves; the helper is what you type.

**Verified working 2026-09-10** on `tmm:CLEAN-NOBTF`, build `1824611c`, cluster `kind-vs`.
Two commands crash TMM; three prevent it. Everything is already deployed.

## Before you start (30 seconds, and skip it at your peril)

```bash
D=starin@10.145.40.193                       # eob-bnk-datkube-01
ssh $D 'kubectl get pods -n default | grep -E "f5-tmm|client|h2-trailer"'
```

All three must be `Running`. Then **confirm the data path serves** — this is the check
that would have saved the last session:

```bash
ssh $D 'kubectl exec client -n default -- curl -s -o /dev/null -w "%{http_code}\n" \
        --max-time 8 http://11.11.11.99:8081/'
```

- `200` → good.
- `000` on the FIRST request then `200` → normal. There is a ~3-request warm-up window.
- **Connection refused, or `000` repeatedly** → the data path is down. `kubectl delete pod`
  the TMM pod, wait for `2/2`, retest. That is the whole fix; the config plane
  re-programs TMM on start. Do not debug the CNI, ARP, or the VLANs first — all three
  looked guilty and none of them was (`SYMPTOMS.md`).

**And confirm no slot is armed.** A shield left armed in `enforce` makes the crash half
silently *not* crash, which reads as a broken demo:

```bash
ssh $D 'P=$(kubectl get pods -l app=f5-tmm --no-headers | awk "\$3==\"Running\"{print \$1}" | head -1)
S=$(kubectl exec $P -c f5-tmm -- sh -c "ls /tmp/ls_load.sock.* | head -1")
for i in 3 4 6; do kubectl exec $P -c f5-tmm -- env LS_LOAD_SOCKET=$S \
    python3 /usr/bin/ls-load.py status $i; done'
```

Every line must read `armed=0`. If not: `ls-load.py disarm <hook>`.

> **`armed=0` is necessary but not sufficient, and `armed=1` may be a lie.** On 2026-09-11
> `status 3` reported `armed=1 mode=2` while the entry was **not patched** — `disarm` on the
> same hook answered `ERR ... (not armed?)` and a single h2c request then crashed TMM, which
> an armed enforce shield makes impossible. The flag and the patched bytes are separate state
> and can disagree. **If anything looks off, replace the TMM pod** — a fresh pod comes up with
> every slot `armed=0 mode=0 gen=0`, which is the only state worth trusting before a demo.
> Never curl **:8082** as a liveness check: that is the crash path.

## The claim worth making first

The binary about to crash and be defended carries **no internal type information at all**:

```bash
ssh $D 'P=$(kubectl get pods -l app=f5-tmm --no-headers | awk "\$3==\"Running\"{print \$1}" | head -1)
kubectl exec $P -c f5-tmm -- python3 -c "
import struct
b=open(\"/usr/bin/tmm64.no_pgo\",\"rb\").read()
o,=struct.unpack_from(\"<Q\",b,0x28); e,n,x=struct.unpack_from(\"<HHH\",b,0x3A)
sh=lambda i: struct.unpack_from(\"<IIQQQQ\",b,o+i*e)
_,_,_,_,so,sz=sh(x); nm=b[so:so+sz]; t=0
for i in range(n):
    a,_,_,_,_,z=sh(i)
    if nm[a:nm.find(b\"\\0\",a)].decode().startswith(\".BTF\"): t+=z
print(\".BTF bytes:\", t)"'
```

**`.BTF bytes: 0`** — it was 6,711,805, naming 41,710 functions and 16,006 struct layouts
including this CVE's own function and the layout of the struct it dereferences. F5 already
ships this binary `stripped`, so that section was the only layout disclosure in the image,
and it was ours.

## Half 1 — one request kills TMM

Capture the log **first**: when TMM dies the pod is replaced, so `kubectl logs --previous`
returns nothing.

```bash
ssh $D 'P=$(kubectl get pods -l app=f5-tmm --no-headers | awk "\$3==\"Running\"{print \$1}" | head -1)
nohup kubectl logs -f $P -c f5-tmm > /tmp/demo.log 2>&1 &
sleep 3
kubectl exec client -n default -- curl -sk -o /dev/null -w "curl=%{http_code}\n" \
    --http2-prior-knowledge --max-time 10 http://11.11.11.99:8082/
sleep 8
grep -oE "(SIGSEGV|Fault address: [0-9a-fx]+|core dumped)" /tmp/demo.log | sort -u'
```

Expect `curl=000` and:

```
Fault address: 0x13        <- a read of NULL + 0x13
SIGSEGV
core dumped
```

## Half 2 — the shield, armed live, same request

Wait for the replacement pod to reach `2/2`, then:

```bash
ssh $D 'P=$(kubectl get pods -l app=f5-tmm --no-headers | awk "\$3==\"Running\"{print \$1}" | head -1)
S=$(kubectl exec $P -c f5-tmm -- sh -c "ls /tmp/ls_load.sock.* | head -1")
POD=$P python3 ~/gate-scripts/bnk-deliver-program.py ~/nobtf-shields/h2_trailer_guard.bpf.o 3 2
kubectl exec $P -c f5-tmm -- env LS_LOAD_SOCKET=$S python3 /usr/bin/ls-load.py arm 3 http2_http_data_to_frames
kubectl exec client -n default -- sh -c "for i in 1 2 3 4 5; do curl -sk -o /dev/null \
    -w \"%{http_code} \" --http2-prior-knowledge --max-time 10 http://11.11.11.99:8082/; done; echo"
kubectl exec $P -c f5-tmm -- env LS_LOAD_SOCKET=$S python3 /usr/bin/ls-load.py status 3'
```

Expect:

```
OK loaded slot=3 mode=2 signature=verified
OK ARMED LIVE entry=0xcef580 slot=3 kind=fentry (no restart)
200 200 200 200 200
OK armed=1 mode=2 gen=1 fired=15 safe_returns=5 errors=0
```

`fired=15` for 5 requests because the hook runs ~3× per response framing;
**`safe_returns=5`** — exactly one match per request. That is the selectivity, measured.

## Half 3 (optional) — no false positives

```bash
ssh $D 'kubectl exec client -n default -- sh -c "for i in 1 2 3 4 5; do curl -s -o /dev/null \
    -w \"%{http_code} \" --max-time 6 http://11.11.11.99:8081/; done; echo"'
```

Five `200`s, and `safe_returns` does **not** move. Normal traffic is untouched.

## Leave it disarmed

```bash
ssh $D 'P=$(kubectl get pods -l app=f5-tmm --no-headers | awk "\$3==\"Running\"{print \$1}" | head -1)
S=$(kubectl exec $P -c f5-tmm -- sh -c "ls /tmp/ls_load.sock.* | head -1")
kubectl exec $P -c f5-tmm -- env LS_LOAD_SOCKET=$S python3 /usr/bin/ls-load.py disarm http2_http_data_to_frames'
```

Otherwise the next person's crash half will not crash.

## What to say about the limits, if asked

- The predicate is a deliberate **over-approximation**: it matches a bodyless response
  framing, while the true condition is a trailer whose serialised header block is empty —
  a local an entry hook cannot see. **0 false positives is measured, not proven-zero.**
- It needs **HTTP/2 on both sides**, so not every deployment shape is exposed.
- **Per-call cost on the data path is a floor, not a mean:** 96–98 cycles ≈ 37 ns for the
  whole armed path. The mean is contaminated by preemption (`cycles_max` reaches ~145 µs)
  and is recorded as NOT MEASURED.
- The shield is **read-only** and reversible. It is not a patch; it retires when the fix ships.
- This runs on a **CNF-flavoured profile**. `bnk-core`'s Gateway path cannot express
  server-side HTTP/2, so the demo is not reproducible there.

## The pieces, if something needs rebuilding

| what | where |
|---|---|
| the vulnerable image | `tmm:CLEAN-NOBTF` (build `1824611c`), already in both `vs` nodes' containerd |
| the HTTP/2 origin | `env/k8s/h2-trailer-backend.yaml` → `22.22.22.111:8080` |
| the shield source | `substrate/shields/h2_trailer_guard.bpf.c` |
| the signed shield | `~/nobtf-shields/h2_trailer_guard.bpf.{o,sig}` on the datkube host |
| the CVE path | `h2-cve-vs` → `11.11.11.99:8082`, pool `h2-trailer-pool` |
| the plain HTTP path | `http1-vs` → `11.11.11.99:8081` (`ltm-vs-basic` on :80 is fastL4 — never parses HTTP) |
| how it was all built | `docs/pipeline.svg` |
