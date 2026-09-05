# What this mitigation technique can and cannot do

**Status:** capability statement. Every "can" carries its evidence tier (**MEASURED** = observed on a
real TMM; **SHIPPED-UNVALIDATED** = in the binary, not yet exercised); anchors are in
[`GROUND_TRUTH.md`](GROUND_TRUTH.md). Limits are split into **fundamental** (properties of the
approach — they will not change) and **current** (engineering — they will). Companions:
[`cve-shield-capability-matrix.md`](cve-shield-capability-matrix.md) (which *vulnerability classes*
are reachable), [`engine-hard-problems.md`](engine-hard-problems.md) (the hard parts),
[`cve-41414-demonstration.md`](cve-41414-demonstration.md) (the evidence record) and
[`cve-to-shield-process.md`](cve-to-shield-process.md) (the procedure). These replace the milestone
plan that used to be cited here, retired 2026-09-05 once its milestone was reached.

---

## 1. The technique, in one sentence

**A shield is a verified predicate at a function boundary that can substitute the function's return
value.** Everything below follows from that sentence — the power and every limit.

Concretely: a small program is attached at a chosen function's **entry**, sees a **copy** of that
function's arguments, and returns one of two answers — *run the function* (`FALLTHROUGH`) or *don't,
and hand the caller this value instead* (`SAFE_RETURN`). It is proven safe before it loads and can be
armed and removed on a running TMM.

**And that one predicate has two uses, not one.** The hard part of a shield is deciding *whether this
call is the exploit*. Once you can decide that, you can either **act** on it (mitigate) or merely
**count** it (verify). Verification is the same program in monitor mode, so it is strictly cheaper and
strictly safer — nothing is ever skipped, traffic is untouched, and no enforcement decision is taken —
which makes it the **lowest-risk way to deploy any of this**: point it at a CVE's precondition and ask a
live fleet *which instances are actually exposed*, instead of inferring exposure from a version number.

## 2. What it can do

**Attach and detach, live**
- Arm at any **out-of-line** function entry in the TMM data plane — ~62,000 real functions in this
  build (71,309 catalogued, before de-noising) — **while traffic flows, no rebuild, no restart**.
  *MEASURED.*
- **Disarm restores the entry byte-for-byte**, kernel-witnessed in process memory: TMM ends exactly
  as it started. A shield is temporary by construction and retires when the patch ships. *MEASURED.*
- TMM boots with **nothing armed**; the only way a program arrives is signed, over a socket.
  *MEASURED.*

**Read**
- Scalar arguments, and **one-hop struct fields** resolved by CO-RE against the running build's own
  type layout — every read **bounds-checked**, never a raw dereference. *MEASURED.*
- Function **exit** values via `fexit` (return-hijack + shadow stack). *SHIPPED-UNVALIDATED.*

**Decide and act**
- Per invocation: `FALLTHROUGH` (observe and step aside) or `SAFE_RETURN <value>` (skip the body,
  return a chosen value the caller already handles). *MEASURED.*
- **Prevent a crash that otherwise kills TMM.** One variable, opposite outcomes: monitor →
  "performing the unshielded dereference", the process dies; enforce → "shield prevented the
  dereference", `restarts=0`. *MEASURED (2026-08-24) — trigger synthesised.*
- **Block a targeted input on live traffic while sparing normal traffic.** Normal request HTTP 200;
  oversized request blocked (body skipped, `ERR_BUF` returned); `fired +5 / safe_returns +2` — only
  the targeted ones. *MEASURED (2026-09-01).*

**Prove and bound**
- **PREVAIL proves memory safety and bounded termination before the program loads** — a buggy or
  hostile program cannot crash or hang TMM. Refusals are real: a program chasing a raw pointer is
  rejected. *MEASURED.*
- A **budget pass** computes a worst-case cycle ceiling from the verified bytecode (~22 cycles for a
  simple probe, against a budget of 800). The mechanism itself measures **~8.8 ns** per call. A
  kernel uprobe is ~1,000+ ns. *MEASURED (microbenchmark).*
- **F5-signed**; unsigned programs are refused by the in-TMM loader. *MEASURED.*

**Verify — answer "is this running instance actually exposed?"**
- A predicate on a CVE's **precondition**, armed in monitor, **distinguishes a vulnerable build from a
  patched one on live traffic**. Measured 2026-09-01 with one variable — a four-line initialisation —
  and identical traffic: **vulnerable `matched 6/6`, patched `matched 0/6`**, with equal `fired` counts
  proving the probe behaved the same on both. *MEASURED.*
- Why this matters on its own: it replaces *"we believe this version is affected"* with a **measurement
  taken on the instance**, needs **no enforcement decision**, skips nothing, and cannot alter traffic —
  so it can be deployed far more widely and far sooner than a shield can.
- **Same limit as mitigation, for the same reason:** if the precondition is not visible at a boundary
  (§3), it is no more *detectable* than it is *shieldable*. Demonstrated for one bug whose precondition
  is a readable field; it is not a general vulnerability scanner.

**Report**
- Per-slot counters (`fired`, `safe_returns`) and **pushed evidence records** — JSON off the data
  path through a shared-memory ring, rate-limited (first few, then sampled) so a flood cannot turn
  the audit log into a self-inflicted DoS. Records carry mode, verdict, timestamp and the context
  seen — including `"mode":"enforce"`. *MEASURED.*

**Compose**
- Up to 12 slots: independent programs on **different** functions, each with its own mode and
  counters — observe here, enforce there, concurrently. *MEASURED.*

## 3. What it cannot do — fundamental

These follow from §1 and are not roadmap items.

- **It cannot repair state.** Programs are read-only and the `ctx` is a copy, so the only lever is
  substituting a return value. A bug that needs a field *initialised*, a buffer *sanitised*, or a
  value *corrected* can be **failed closed — not fixed**. "Fail closed, don't fall over" is the
  whole offer.
- **It cannot see what isn't at the boundary.** `fentry` runs *before* the body, so it sees inputs,
  not parsed results. If the exploit precondition only exists mid-body or after parsing, an entry
  predicate cannot test it. (`fexit` sees results but is past the damage.)
- **It cannot enforce mid-body.** `SAFE_RETURN` needs a clean function boundary; there is no frame to
  return through from inside a function.
- **It needs a safe return to exist.** If every return value leads the caller somewhere harmful,
  failing closed is not available at that function.
- **It cannot distinguish temporal bugs.** Use-after-free and double-free: no single-entry predicate
  separates a valid pointer from a stale one.
- **It is not a patch.** It is a bridge to one — narrower, reversible, and retired when the fix
  ships. It does not remove the obligation to fix.
- **Data plane only.** Control-plane, management, and companion-microservice CVEs are a separate
  exercise.

## 4. What it cannot do — current (engineering)

These are limits of today's build, each with the work that lifts it.

| limit | why it matters | lift |
|---|---|---|
| **Multi-hop field access.** The DSL resolves scalars and **one** hop. A precondition at `sc->sp->hs->field` needs a hand-written program, which currently trips the CO-RE forward-declaration bug (`rc=-5`). | **The biggest one.** Most real CVE preconditions live in *connection state*, several hops in. This is the gap between "shields simple bugs" and "shields the ones that ship as CVEs." | pointer-target info in the BTF catalog + dotted-path codegen + prefer-defined-struct in the relocator (or resolve at sign time) |
| **Inlined functions have no entry pad**, so they cannot be hooked as-is. | A partially-inlined target yields *false success*: the out-of-line counter climbs while inlined call sites run unshielded. | `noinline` the target for enforce; source-placed probe points for observe |
| **One program per hook** (one pad → one call target). | Two teams cannot shield the same function; replacing means revoke-then-load. | per-hook dispatcher + a declared outcome-composition order |
| **Only `SAFE_RETURN` is wired.** `DROP` / `RESET` / `STEER` / `SAMPLE` are authorable but no host action acts on them. | Algorithmic-DoS classes (Rapid Reset, decompression bombs) are **out of reach today**. | host-side decision-point wiring |
| **No byte capture**, and no live value/histogram egress. | You can filter-and-count on a field; you cannot stream the distribution or a packet window. | per-value egress (`tmmdump` for captures — a separate tool by design) |
| **Per-call cost on the data path is unmeasured.** | The ~8.8 ns is a hot-cache microbenchmark floor, not a per-packet figure under real traffic. | instrumented measurement on the data path |

## 4A. For the classes it cannot mitigate — what would be needed

Most of §3 and §4 converge on **three** enabling capabilities. Naming them this way matters: it turns
a list of limitations into a short, ordered build.

### Unlock A — more outcomes (host acts, not just substitutes a return)
**Unblocks:** algorithmic DoS (Rapid Reset, decompression bombs, "zombie" flow exhaustion — class G),
and any bug at a function where **no safe return exists**.

Today the only lever is `SAFE_RETURN`. For these classes the right action is not "skip this function"
but "**kill this stream / reset this connection / drop this packet**". `DROP` / `RESET` / `STEER` /
`SAMPLE` are already *authorable* — nothing host-side acts on them. Needed:
- host-side **decision-point wiring** so the verdict is applied at a traffic decision point, not just
  as a return value;
- a defined **total order over the outcome set** (most-restrictive-wins), because once more than one
  outcome exists, two programs can disagree (`engine-hard-problems.md` §3.1).

### Unlock B — state across invocations
**Unblocks:** everything whose precondition is a **rate or a count**, not a single input — which is
most of class G. "Too many resets on this connection" is not visible in one invocation's arguments.

Needed:
- **maps that persist between invocations**, keyed per connection / per flow;
- a **time base** in-program (so a rate can be computed);
- and the hard part, stated honestly: shared mutable state is what the current design's
  single-writer-per-core property buys its cheapness with. Adding it re-opens CMP and
  connection-mirroring questions (`engine-hard-problems.md` §3), so this is the costliest unlock, not
  the easiest.

### Unlock C — deeper and finer reads
**Unblocks:** the **majority of real CVEs**, whose precondition lives in connection state several
pointer hops in; plus preconditions only visible **mid-body**.

Needed, in order:
1. **Multi-hop field access** — pointer-target types in the BTF catalog, dotted-path codegen in the
   DSL, and prefer-defined-struct in the CO-RE relocator (or resolve at sign time, which removes the
   on-box parser too). *This is the single highest-leverage item on the board.*
2. **Source-placed probe points** (USDT-style) for arbitrary positions inside a function, with
   DWARF-located arguments — the only way to reach code that is inlined or mid-body.
3. For **enforce** mid-body: there is no clean frame to return through, so the realistic answer is to
   restructure the target with `noinline` helpers and enforce at that boundary. Mid-body stays
   **observe** otherwise.

### The security decision — writes (repair instead of refusal)
**Would unblock:** bugs whose correct fix is to *initialise* or *sanitise* state (the brainpool
uninitialised-field shape), where failing closed is the only option today.

This means giving a program a **write** capability — a narrow, verified "store to this field" helper,
with the verifier proving bounds and ownership, or a host-side "zero field X before the call" action.
It is a genuine step change in risk: it turns a read-only predicate into something that **mutates TMM
memory**, and it would need its own TMA before anyone writes a line of it. **The cheaper alternative
is usually to shield the *consumer* function instead** — fail closed where the bad value is used,
rather than trying to fix it where it is created.

### The genuine dead end — temporal bugs
**Class H (use-after-free, double-free, expired pointer).** Validity is a property of *history*, not
of the arguments at a boundary, so no entry predicate can distinguish a live pointer from a stale one.
Mitigating this would require **object-lifetime tracking** — instrumenting the allocator and
maintaining a liveness map consulted per dereference. That is what ASAN-class instrumentation and the
compiler do, at a cost the poll loop cannot pay. It may be **detectable in a debug build**; it is not
mitigatable in production by this technique, and the matrix says so rather than implying otherwise.

### Out of scope by choice, not by limit
**Control-plane CVEs** need the substrate deployed into the control-plane daemons and companion
microservices — a different process, different constraints, no poll loop. Deferred deliberately.

**Reading the four together:** Unlock C is the one that widens the *addressable* CVE set most (it is
about *seeing* the precondition); Unlock A widens the *class* set (it is about *acting*); Unlock B is
the expensive one and buys the rate-based classes; writes are a security decision, not a feature; and
temporal bugs are honestly out.

## 5. The decision procedure — "is this bug shieldable?"

Five questions. All yes → shieldable today. The first "no" names exactly what is needed.

1. **Is the vulnerable function reachable on the data path, and out-of-line** (does it have an entry
   pad)? → if inlined: `noinline` it, or shield an enclosing boundary.
2. **Is the exploit precondition computable from the arguments at entry** — a scalar, or ≤1 struct
   hop today? → if deeper: needs the multi-hop work.
3. **Is there a return value the caller already handles that is safe?** (`dtls_tx` → `ERR_BUF`;
   `http_parse_client_headers` → `err_t`.) → if not: no fail-closed at this function.
4. **Is skipping the body a clean early-return** — no half-updated state the caller depends on?
5. **Is the class single-input** (memory-safety on one request/connection) rather than temporal or
   algorithmic?

That checklist *is* the honest scope. The plurality of TMM data-plane CVEs — single-input
memory-safety crashes — pass all five; that is why this is worth building, and the classes that fail
question 5 are named in the matrix rather than hand-waved.

## 6. What it is not

- **Not a WAF or IPS.** It does not inspect traffic for signatures at a protocol boundary; it tests a
  predicate on the arguments of one internal C function.
- **Not a general programmability feature for customers.** Programs are **vendor-authored and
  F5-signed**; the appliance refuses anything else.
- **Not iRules.** iRules run at protocol events with a scripting engine; this runs at *internal
  function entries*, verified, with a per-program cycle ceiling.
- **Not "verified means it can't hang the box."** PREVAIL proves *termination*, not a wall-clock
  bound; the cycle ceiling comes from the budget pass and the runtime fuel, and those are the numbers
  that earn a place in the poll loop.
