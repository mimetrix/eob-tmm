# What we can demo, after the enablers

Written 2026-08-17, after maps, the ring, live arming and all-six-arguments all
started working. The earlier framing had three candidate demos — shield (CVE),
debug/RCA, and a data-intelligence probe — and it was written when a program could
see five scalars, keep no state, and egress nothing. All three of those are now
false, so the options are worth re-deriving rather than re-scoring.

---

## 1. What is actually proven, today

Each of these was measured on BNK, not designed:

| capability | evidence |
|---|---|
| Arm a function entry in a **running** TMM, no restart | `OK ARMED LIVE entry=0x144df00 slot=5 (no restart)` |
| Disarm, restoring the original bytes | `check_pad_shapes.c`, 14 assertions, round-trip byte-identical |
| Verified programs, every PREVAIL gate on | `make check-shields`, including two that must FAIL and do |
| **State across invocations** | `fired=184 safe_returns=80`, the threshold curve |
| **Egress off the data path** | records read out of shared memory by a separate process |
| Producer never depends on the reader | `check_drain.c`, 17 assertions, ABSENT/CRASHED/STALLED/HOSTILE |
| **All six arguments**, incl. a string | Phase 3; `lea 0x8(%rsp),%rsi` verified in the shipped binary |
| Choose the hook **after** the binary shipped | `rst_why` was never designed as an extension point |

The last two are the ones that change the demo set.

---

## 2. The four original options, re-scored

### Debug / RCA — **ready now, and the strongest**

The reset feed (`rst-why-feed.md`). For every connection TMM resets, a record naming
the exact source line that decided it, live, with the human-readable cause.

Why it lands: "why did BIG-IP reset my connection" is a standing support question. One
live sample showed `82` of `116` records from a single site none of the four triggers
was aimed at — a ranking no counter can produce.

**Scoped honestly, because the first framing overclaimed.** BIG-IP already appends the
reset cause to the RST packet (`rst_cause_append`, unconditional, right before
`ip_output`), so a packet capture DOES show the reason. What the feed adds over a
capture is: `file:line` (the wire carries only the string, and `"Closing"` maps to two
different sites), decisions that never emit a packet at all (40 of that sample were
graceful proxy teardowns), always-on operation where tcpdump cannot run, and metadata
instead of customer traffic.

**Coverage is 87% of CODE SITES — not of resets.** 1,116 places in the source can
decide a reset; 966 funnel into `rst_why` and are caught by this one hook. 131 go to
`rst_why_va` (varargs — an explicit trampoline non-goal, since `rax` carries the
vector-register count) and 19 to `rst_why_preserve` (same 6-arg shape, one more address
away). What fraction of *actual* resets that represents depends on which sites execute
under real traffic and is **unmeasured**; in the demo it was complete, matching the
driven traffic 1:1.

**Selective packet capture keyed on a code path — PARKED (2026-08-18).** An earlier
draft called this the sharper story and it was costed wrong. `rst_why` receives a flow
handle, not a packet, so the reset hook cannot capture one at all. Hooking
`rst_cause_append` instead does give a packet — but the RST payload already carries the
cause, so it duplicates the record for near-zero gain. The version with real value is
retrospective capture, and that needs a rolling per-thread packet buffer written on
EVERY packet forever, which is a standing data-plane cost this design avoids
everywhere else, plus a second ring type (records are 92 bytes, packets 1500, and a
ring is 64KB) plus Phase 4. Weeks, for the worst value-per-cost on the list. See
`rst-why-feed.md` for the tier breakdown.

Not reproducible with iRules or WASM: `RST_WHY` is an internal macro on an internal
path, not an exposed event.

**Status: working. Needs a scripted 5-minute walkthrough, not more engineering.**

### Data-intelligence probe — **ready, but it is the same demo**

This was originally a separate page: HTTP metadata to a downstream analytic. The
honest finding is that the HTTP tracepoint duplicated what iRules already see, which
is why it was rolled back. What survives is the *shape* — binary records into shared
memory, JSON out of a separate process, any consumer — and the reset feed already
demonstrates it end to end.

**Recommendation: fold it into the debug demo as "the same pipe, any hook", rather
than staging a second one that shows the same machinery over less interesting data.**

### CVE mitigation — **still blocked on BNK, and the reason is now precise**

0 of 5 CVEs reachable. Not a capability gap — a *target* gap:

- `prot_transfer_log_profile` has no Kubernetes CRD, so the BNK config surface cannot
  reach the vulnerable state
- OpenSSL is linked in with **1,781 symbols and none padded**, so `EVP_*`, `ASN1_*`,
  `BN_*`, `X509_*` are all unarmable regardless of any CVE in them
- nothing in a CVE description predicts either condition

What Phase 3 *did* change: a shield can now read a six-argument function, including
string arguments, which widens the set of admissible targets. That is necessary, not
sufficient. The gate is reachability.

**Recommendation: stop presenting CVE mitigation as the lead use case.** Present the
*mechanism* — armed, verified, disarmable, on a running process — and be explicit
that a specific CVE demo needs either a reachable target on BNK or the other source
tree. The deliberate ALPN regression (`tmm:vuln-alpn`) demonstrates the mechanism and
must always be labelled as a regressed build.

### "Other" — see below. This is where the enablers actually opened something.

---

## 3. New options, only possible because of the enablers

### 3a. Per-site rate limiting **decided inside the data plane** — small step from here

`rate_watch` already crosses a threshold and changes its verdict from accumulated
state. Today the verdict is `SAFE_RETURN` on a reset path, which is a demo. Point the
same shape at a *decision* function and the program is doing admission control keyed
on state TMM does not itself correlate.

Needs: a hook whose return value is acted on, and a safe-return policy for it
(scope item 7). **Days, not weeks** — the machinery is all present.

### 3b. Correlate a decision to the request that caused it

The gap the whole exercise keeps rediscovering: TMM counts in aggregate and cannot
link a counter to a request. With maps plus the ring, a program can stamp a record
with a key derived from the flow and emit both sides of a decision.

This is the *general* form of what the reset feed does specifically --- and it is NOT
what the reset feed does today. Checked 2026-08-17: `struct ls_ctx_rst` carries no
flow, connection or client field, so records correlate by timestamp and thread only.
"We can attribute to a code site and a reason" is supportable now; "we can attribute
to a request" needs the work below and should not be said before it lands.

`rst_why`'s first argument IS the flow handle, forwarded and currently ignored, so
this is a host-side dereference rather than new plumbing. The constraint is the
96-byte ctx ceiling: at 92 bytes there is room for an 8-byte flow HASH (a correlation
key, not an identity) if `cause[]` shrinks to 32, but not for a 5-tuple. A full tuple
needs the ring record decoupled from the program ctx --- Phase 4.

### 3c. Latency attribution inside TMM — needs exit hooks (Phase 2)

Entry plus exit on an internal function gives per-function time on live traffic,
per flow. Nothing in TMM or iRules offers this. Blocked on return-address hijack,
which carries real re-entrancy risk and is honestly scoped in `widening-plan.md`.

**Not a near-term demo. The most valuable one after that.**

### 3d. Read a function's *outputs* — also Phase 2

"What did this function decide, and why" rather than "what was it asked". The first
tracepoint attempt failed exactly here, reading `header_count` before the parse wrote
it. Same blocker as 3c.

---

## 4. The gating unmeasured thing

**Per-invocation cost.** Every option above is blocked for review, not for
engineering, until there is a defensible number. The slot counters are dominated by
preemption artifacts and the bench op that would give a clean floor wedges the loader
thread.

Also, `LS_VM_JIT=1` in the current deployment and uBPF's compiled path does not
consult the bounds callback — so the memory-safety property is *not* exercised by any
demo above. Functionality is shown; safety is argued from the verifier alone.

Neither is a show-stopper. Both are things a skeptical reviewer will ask in the first
five minutes, and "unmeasured" is a worse answer than a modest number with honest
error bars.

---

## 5. Recommendation

1. **Ship the debug/RCA demo now.** It works, it answers a real question, and it is
   not reproducible by any existing scripting surface. Fold the probe story into it.
2. **Measure per-call cost next.** Unglamorous, and everything else waits on it.
3. **Then Phase 2 (exit hooks)** — the largest remaining jump in what a program can
   express, and the enabler for 3c and 3d.
4. **Re-frame CVE mitigation** as mechanism-proven / target-blocked, with the
   reachability gates named. Do not lead with it.
