# Hook-point catalogue — what is actually worth exposing from inside TMM

Built 2026-08-16 by surveying the source, then checking each candidate against
what TMM already exposes. **The checking is the part that matters**, and it is
what four earlier picks skipped.

---

## The finding that shapes everything else

**TMM's existing telemetry is comprehensive, and nearly every "unique" candidate
turns out to be already covered.** Four in a row:

| candidate | what already covers it |
|---|---|
| HTTP request metadata — method, version, header count | **iRules** read all of it directly |
| waived requests (malformed but forwarded) | **`mcp/stats.h`** exports `passthrough_*` counters |
| TLS client fingerprint | **`ssl_proto_to_ja3_ver`** — JA3 is already in TMM |
| pool member selection | **`pool.c:201`** registers `pool_member_stat_cols[]` in tmstat |

A broad survey found 10,615 branches that change disposition, of which ~9,500
appear "silent". That number is **not a catalogue** — the categories are too
loose (`pressure` matched every `== NULL` check). Mechanical detection narrows;
it cannot judge whether something is worth exposing. Every candidate below was
checked by hand, and most candidates die at that step.

---

## The real gap, stated precisely

It is **not** "TMM hides its internals." It is narrower, and worth getting right
because it is the only honest basis for this work:

> **TMM counts in aggregate. It does not record per event, and it cannot
> correlate a decision back to the request that caused it.**

`tmstat` will tell you there were 412 persistence misses this interval. Nothing
will tell you *this* request, with *this* key, missed and went to member 7
instead — or that the same client did it 40 times in a minute.

And one population has **no coverage at all**:

> **Traffic that never became a request.** Malformed, rejected, or torn down
> before the parse completed. No HTTP event fires, so no iRule and no WASM. It
> never reaches the origin, so no origin log. It is absent from every analytics
> pipeline built on either.

---

## Catalogue

Ranked by *(uniqueness × analytic value) ÷ cost*. "Cost" is high when fields must
be derived rather than read from arguments, or when a source edit is needed.

### 1. Connection teardown attribution — **built, verified**

`rst_why(uf, __FILE__, __LINE__, err, reason, cause)` · ~80 call sites on the HTTP
path.

- **Unique?** Yes, for the pre-parse population. A client sees a bare reset; an
  iRule never runs. TMM keeps a small overwriting ring, uncorrelated to the request.
- **Reachable?** Verified — `fired` 2→13 under mixed traffic.
- **Cost?** Low. Every field is a direct argument; **no F5 source edit** — armed at
  the function entry.
- **Caveat:** the sixth argument (`rst_cause`, the human-written string) is in `r9`
  and the trampoline forwards only five. `file:line` identifies the site instead.

### 2. Per-request outcome correlation — **proposed**

One record per connection at teardown: did it ever become a request; if not, which
`file:line` refused it; bytes, duration, whether a backend was ever selected.

- **Unique?** The "never became a request" rows, yes. The rest is baseline that
  makes them a *rate* rather than a count.
- **Cost?** Medium — needs a teardown-time hook with flow state in scope.

### 3. Persistence lookup outcome, per request — **needs checking**

`base/persist.c` carries a real state machine (`PERSIST_LOOKUPALL_INIT/LOOKUP/
DRAIN/ABORT`). Per-request hit/miss/abort with the key would answer "is
persistence actually working for this client."

- **Unique?** **Unverified.** Aggregate counters very likely exist — check before
  building. This is exactly the step that killed the four above.

### 4. Resource pressure — **needs checking**

Allocation failure, queue depth, buffer exhaustion: TMM straining in ways no
external observer can infer.

- **Unique?** Partly. tmstat almost certainly counts the outcomes; what it will not
  have is *which request was in flight when pressure hit*.
- **Cost?** Low if the failures are at function boundaries.

### Rejected, and why

- **HTTP request metadata** — iRules read all of it. This is what was built first
  and is being rolled back.
- **Waivers** — `passthrough_*` counters exist, and every client-side waiver is
  gated on `proxy_type == TRANSPARENT`, so they cannot fire on a reverse proxy at
  all.
- **TLS fingerprint** — JA3 already in TMM.
- **Pool member selection** — tmstat table already registered.

---

## The rule this catalogue exists to enforce

**Before building any hook point, answer in writing: what already sees this?**

Check `tmstat` tables (`grep TMCOL`), `mcp/stats.h`, iRule commands, and HSL
logging. Four candidates were built or nearly built without that step, and all
four were redundant. The check costs minutes; the build costs a day.
