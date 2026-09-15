# CVE-2025-41414 — the live demo, four terminals, paste-ready

Every block below is **bare commands to paste**. No `ssh` wrappers, no substitutions to
fill in. Do the setup once per window and the rest is literal.

Companion docs: [`DEMO-RUNBOOK.md`](DEMO-RUNBOOK.md) is the same demo with the *why* for
each check; [`../docs/pipeline.svg`](../docs/pipeline.svg) is how the artifacts were built.

---

## Setup — paste in all four windows

```
ssh starin@10.145.40.193
. ~/demo-env.sh
```

| window | role |
|---|---|
| **T1** | TMM's log — the crash evidence |
| **T2** | traffic — where you fire requests |
| **T3** | the loader — load / arm / status / disarm |
| **T4** | pod watch — the audience *sees* TMM die and return |

---

## T3 · pre-flight

```
preflight
```

Must end **`READY`**. If it doesn't:

```
tmm_reset
preflight
```

`tmm_reset` replaces the TMM pod — about two minutes, and it has fixed every problem this
cluster has produced: a refusing data path, a stale `armed` flag, a leftover shield.

---

## T4 · start the watch, then leave it alone

```
kubectl get pods -l app=f5-tmm -w
```

One `Running` pod. Later this line goes `Error`, then a new pod appears. That is the shot
worth having on screen.

---

## T3 · the opening claim

```
btf_bytes
```

> `.BTF section bytes in the running binary: 0`

**Say:** this binary used to carry 6,711,805 bytes of internal type information — 41,710
function names and 16,006 struct layouts, including the function we are about to crash and
the layout of the very struct it dereferences. F5 already ships it stripped of symbols, so
that section was the only map of its internals left, and it was ours. It is gone, and the
mitigation still works. That is the point of the next four minutes.

---

## T1 · start the log tail

```
kubectl logs -f $(tmm_pod) -c f5-tmm | grep --line-buffered -iE "sigsegv|fault address|core dumped|ls_vm:"
```

**Before T2.** When TMM dies its pod is replaced and `kubectl logs --previous` returns
nothing — start this first or the evidence is gone.

---

## T2 · one request

```
attack 1
```

- **T2** prints `000` — no reply, because the process serving it died.
- **T1** prints `Fault address: 0x13` · `** SIGSEGV **` · `core dumped`
- **T4** flips to `Error`, then a new pod appears.

**Say:** one HTTP/2 request. No credentials, no volume, no repetition. The response carried
a trailer with an empty header block, the proxy dereferenced NULL + 0x13, and the data
plane went down.

Pause here.

---

## T3 · wait for the replacement

```
tmm_wait
```

Prints dots, then the new pod name, then `warmed up; ready`. It burns one throwaway
request so the first-request `000` stays off screen.

## T1 · restart the tail — its pod is gone

```
kubectl logs -f $(tmm_pod) -c f5-tmm | grep --line-buffered -iE "sigsegv|fault address|core dumped|ls_vm:"
```

---

## T3 · load and arm, on the running proxy

```
POD=$(tmm_pod) python3 ~/gate-scripts/bnk-deliver-program.py $DEMO_PROG 3 2
```

> `OK loaded slot=3 mode=2 signature=verified`

```
loader arm 3 http2_http_data_to_frames
```

> `OK ARMED LIVE entry=0xcef580 slot=3 kind=fentry (no restart)`

**Say:** that program was mathematically verified before it was allowed near the process,
signed by F5, and pinned to this exact build. It went in over a socket. Five bytes changed
at a function entry. **T4 has not moved** — nothing restarted, nothing reloaded, no
connection dropped.

---

## T2 · the identical request, five times

```
attack 5
```

> `200 200 200 200 200`

## T3 · the counters

```
loader status 3
```

> `fired=15 safe_returns=5 errors=0`

**Say:** fifteen firings for five requests — the hook sits on a function that runs three
times per response. Five safe returns: it matched exactly once per request. It is not
blocking HTTP/2, it is recognising one specific shape.

---

## T2 · no false positives

```
normal 5
```

> `200 200 200 200 200`

Then **T3** again:

```
loader status 3
```

`safe_returns` is still **5**. Normal traffic went through untouched.

> **Check `preflight` said READY before relying on this step.** It exercises a *different*
> backend from the CVE path, and that backend has wedged before — listening on `:80` and
> never replying, which shows as `000` with curl exit 52. If `preflight` flagged the http
> path, skip this step: zeros here look like your shield failing when the cause is a dead
> test backend.

---

## T3 · remove it

```
loader disarm http2_http_data_to_frames
```

> `OK DISARMED LIVE entry=0xcef580`

**Say:** the entry bytes are back to what the compiler emitted. When the real patch ships,
this disappears and leaves nothing behind. It is a bridge across the window between
disclosure and patch, not a fork of the product.

---

## Two things that will happen, so they don't surprise you

**`status` still says `armed=1` after that disarm.** Known, deterministic, recorded in
`GROUND_TRUTH.md`. The entry genuinely *is* unpatched — a second disarm answers
`ERR ... (not armed?)`, which is the trampoline's own view. If someone spots it: a
bookkeeping bug we found and wrote down, and the reason it matters is the direction —
a flag that errs toward *"protected"* is the dangerous way to be wrong.

**Never `curl :8082` to check anything.** That is the crash path. Use `normal` or `:8081`.
A non-HTTP/2 client gets `000` there *without* crashing TMM, which makes it look like a
safe probe and it is not.

---

## Questions you will get

**"Is this a patch?"** No. Read-only, one function, reversible, retired when the fix ships.
It cannot repair state — a bug needing a field initialised can be failed closed, not fixed.

**"What does it cost?"** The floor for the whole armed path is 96–98 cycles, about **37 ns**
— measured on the real path in a live TMM, not a bench. The *mean* is deliberately not
quoted: its tail is dominated by scheduling (`cycles_max` reaches ~145 µs), so it is not a
per-packet cost and `GROUND_TRUTH.md` records it as NOT MEASURED.

**"Will it false-positive?"** The predicate is a deliberate over-approximation — it matches
a bodyless response framing, while the true condition is a trailer whose serialised header
block is empty, a local that an entry hook cannot see. **0 false positives is measured, not
proven-zero.** Say it that way.

**"Does this work everywhere?"** It needs HTTP/2 on both sides, so not every deployment
shape is exposed. And this runs on a CNF-flavoured profile; `bnk-core`'s Gateway path
cannot express server-side HTTP/2, so the demo is not reproducible there yet.

**"How do I know the program is safe?"** It is proven before it loads — memory safety and
bounded termination, by an external verifier. Then signature-checked, then pinned to one
build id: a program signed for a different build is refused, with the reason on the log.

---

## Recovery, any time

```
tmm_reset
preflight
```
