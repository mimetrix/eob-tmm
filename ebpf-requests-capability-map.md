# Three requests, mapped to what this actually does

Written 2026-08-18 in answer to three asks about using eBPF inside, alongside, or outside
TMM. Each is taken at face value, answered against the code as it exists, and the limits
are stated as plainly as the capabilities.

**The rule this document follows:** anything described as working has been run, and the
evidence is named. Anything unbuilt says so. Where an ask is a poor fit, the answer is "no"
and the reason, not a re-definition of the ask into something we happen to do.

---

## Summary

| # | request | fit | the one-line answer |
|---|---|---|---|
| **a** | Disable unwanted / unused services on a customer instance | **partial** | We can make a *function* a no-op in a running process. That is feature suppression, not surface reduction — the traffic still arrives and the port still listens |
| **b** | Highlight vulnerabilities and active threats immediately | **split** | **Active threats: yes, and uniquely** — a kernel agent structurally cannot see TMM's decisions. **Vulnerabilities: no** — a shield does not change a package version, so the scanner still reports it |
| **c** | Patch where you can / disable the exploit path, customer aware | **strongest** | "Disable the exploit path" is exactly what this does, and MONITOR mode already *is* "make the customer aware first". Blocked on signing and an audit trail, both unbuilt |

**Three cross-cutting gaps block all three from being customer-facing**, and they are listed
in §4 rather than buried: no program signature verification, no audit trail, and no
measured per-invocation cost.

---

## 1. (a) Attack surface reduction — disabling unused services

### What was asked

> Disable unwanted / unused services from running on the customer instance of BIG-IP
> (Microsoft is also asking for the same capability).

### What the mechanism can actually do

Arm a function's entry and have the program always select `LS_SAFE_RETURN`. The host
applies it: the trampoline discards the saved registers, puts the declared safe value in
`rax`, and returns to the *caller*. **The function body never executes.**

That is real and it is running: the ALPN shield works exactly this way, and its logic was
confirmed end to end in a harness — a null input returns the safe value, a live one falls
through, and the JIT matched the interpreter across 40 rounds.

So for a data-plane feature **with no configuration knob**, this switches it off in a
running process, with no restart. That is a genuine capability and no other mechanism in
the product has it.

### What it is not, and this matters for how it is described

- **The port still listens and the connection is still accepted.** The attacker reaches the
  code; we make one function inert. Actual surface reduction means not accepting the
  traffic at all, which is a listener/config concern, not a function-entry one.
- **It is not persistent.** Nothing in TMM's configuration changes, so a restart re-enables
  whatever was suppressed. Persisting it is a control-plane decision that does not exist.
- **It is not "a service".** The unit is a function. A "service" is many functions plus
  config plus listeners, and suppressing one entry point of it may leave the rest running
  in a state its author never intended.

**The honest framing is "suppress a data-plane code path that has no off switch."** That is
narrower than the ask and it is defensible.

### The two hard limits

**1. The safe return value is hardcoded `0`.** In `ls_tramp.c` it is a literal with a
`TODO(f5)` next to it. Per-function safe values belong to the safe-return policy table,
which is unbuilt (scope item 7).

This is the most dangerous item in this document. Returning a *wrong* safe value converts a
crash into **silent misbehaviour**, which is worse than not shielding at all. And the
trampoline moves that value to `rax`, which is only correct for a return type that fits
there — a struct returned by hidden pointer, or anything using `rdx:rax` or the SSE return
registers, needs its own path. The trampoline enforces nothing; admitting a shield on a
hook with a non-trivial return type is an admission-time error nobody currently checks.

**2. Padded functions only.** From the index generated against the shipped binary:

| | count |
|---|---|
| armable today (pad) | **41,143** |
| armable only by displacement (**unbuilt**) | 30,009 |
| total in the index | 71,157 *(per build; count it from the image rather than quoting this)* |

Anything in a linked component — OpenSSL included — is in the second row. The displacement
path is designed and not built.

### What it would take

The safe-return policy table, an admission-time check that a hook's return type is
trivial, and a decision about whether suppression persists across a restart.

---

## 2. (b) Observability — vulnerabilities and active threats

### What was asked

> For vulnerabilities and active threats, highlight to the customer immediately so they can
> act (this is something we get with our Falcon integration).

This is two asks. We are strong on one and absent on the other, so they are answered
separately.

### 2.1 Active threats and internal decisions — yes, and this is the differentiator

**A kernel-based agent cannot see TMM's decisions, structurally.** Falcon and every
kernel-eBPF tool attach to kernel hooks: syscalls, tc, XDP, kprobes, LSM. **TMM has its own
userspace data path and does not traverse them.** So a kernel agent sees the container, the
host, the process, the packets on the wire — and not one decision TMM makes about them.

That is the gap this fills, and it is worth stating as the primary claim:

> `rst_why` and its three siblings decide, at **1,090 call sites**, to tear a connection
> down — with a source line and a human-written reason. None of that crosses the kernel
> boundary a Falcon-style agent watches, and none of it is reachable from iRules. (No claim
> is made about WASM: it is absent from TMM's source tree and from this deployment, so
> there is nothing here to compare against.)

What a record carries today, drained live:

```json
{"ts_ns":1787066626925893333,"seq":162,"slot":5,"hook":"reset","fn":"rst_why","schema":3,
 "file":"http_mr_proxy.c","line":993,"err":32,"reason":0,
 "flow":"00003a0c137fafba","cause":"Closing"}
```

**Validated against an independent oracle**, not just self-reported: `tcpdump` on the wire
showed TMM's own RST payload carrying `BIG-IP: [0x235ef8f:2618] No local listener` — the
same cause *and* the same line number our record reported, from a code path that shares
nothing with ours. Five triggers produced five wire resets and five records that matched.

That same exercise found the honest limit: only **5 of about 32** records had any wire
counterpart at all. The rest are decisions with no external evidence whatsoever — which is
the point, and also why nothing else can report them.

**The screen that decides whether a site is worth hooking.** Four tests, and the second is
the one that is easy to skip:

1. Is it a **decision** — does it carry a reason?
2. **Is it already logged?** If the reason reaches syslog, a tracepoint duplicates it.
3. Does it raise an **iRule event**?
4. Are there **enough call sites** to be a feed rather than a log line?

Applied to real candidates, from the shipped binary rather than from reading source:

| site | logged? | verdict |
|---|---|---|
| `rst_why` (1,090 sites) | **no** — `net/rstcause.c` has zero log macros; the cause goes only into an overwriting in-memory ring | **unique to a hook** |
| `http2_stream_abort` (36 sites) | **no** — its only narration is `TRACES()` inside `#if HTTP2_DEBUG`, undefined in the build. `"initiates ABORT in"` occurs **0 times** in `tmm.no_pgo` | **unique to a hook** |
| `ssl__err` (475 sites) | **yes** — `LOG_WARNING` with function, line, alert and the *interpolated* message. `"Connection error"` occurs **4 times** in the same binary | **duplicates syslog** |

`ssl__err` is included deliberately: it passes test 1 and test 3 and fails test 2, and it
looked like the best candidate available for most of a day. **A site an iRule cannot see is
not automatically a site nothing can see.**

### 2.2 Vulnerability observability — no

A scanner reports **package versions**. A shield does not change a version, so the finding
stays and the audit still fails. That is why CVE work came off the BNK demo entirely.

The survey behind that: BNK tracks **3,068** CVEs, overwhelmingly dependency CVEs in other
containers. 529 (17%) are ordinary C libraries and are *technically* reachable in principle
— displacement exists for exactly that code. It does not matter, because:

> **Dependency-CVE pain is audit pain, and only an upgrade clears an audit.** Upgrading is
> also *cheaper* than shielding — it is a base-image rebuild and it closes the finding
> permanently.

Where shielding a dependency *does* win: when the upgrade is unavailable. No published fix,
an upgrade that breaks compatibility, or a revalidation cycle measured in months. That is a
real subset and it is not most of the 3,068.

### 2.3 What we cannot do on the observability side

- **Attribute a decision to a client.** The record carries a flow **cookie**, which gives
  *cardinality* — 3 records across 2 flows is one client hammering, 12 across 12 is
  systemic — and **not identity**. The 5-tuple does not fit: the record is 92 bytes against
  a measured 96-byte ceiling.
- **Quote a per-invocation cost.** Unmeasured. See §4.

---

## 3. (c) Defense in depth — patch or disable the exploit path

### What was asked

> Patch where you can and/or disable the exploit path (conditioned upon customers being made
> aware of the same).

### The best fit of the three, and one part already exists

**"Disable the exploit path" is the honest verb, and it is what this does.** We do not
patch: no code is modified. A verified program runs at a function's entry, inspects the
arguments, and can refuse the call before the vulnerable body executes.

Worked example, and it is the whole program:

```c
/* restores the bounds check F5's own commit c806f1b2e8 added to ssl_alpn_match */
if (len == 0)              return LS_SAFE_RETURN;   /* RFC 7301: zero-length entry */
if (ix + 1u + len > sz)    return LS_SAFE_RETURN;   /* entry runs past the extension */
```

PREVAIL admits it, the loop is fully unrolled, and the input is a length byte from the
client's TLS ClientHello — attacker-controlled, pre-authentication.

**"Patch where you can" is not us.** Interception is not patching, and describing it as
patching invites a review question we would lose.

### "Conditioned upon customers being made aware" — this is `MONITOR` mode, and it is built

```c
enum ls_mode {
    LS_MODE_DISABLE = 0,
    LS_MODE_MONITOR = 1,  /* evaluate and count; do not apply */
    LS_MODE_ENFORCE = 2,
};
```

In `MONITOR` the program runs, the verdict is counted, and **the host applies nothing**. So
the sequence the ask describes is directly supported:

1. Arm the shield in `MONITOR`.
2. Show the customer the records — what *would* have been refused, at what rate, on which
   flows.
3. Move to `ENFORCE` only once they have seen it.

That progression is a real feature and it has not been part of how this gets described.

### What is missing before it is customer-facing

**Signature verification exists as of 2026-08-20.** Scope item 4. Every load is checked against a
key compiled into TMM, and the loader now states the property that actually holds:

```
ls_vm: LOADER LISTENING on /tmp/ls_load.sock.25 --- programs are signature-checked, the PEER is
       not. Anything that can reach this socket can ask. Lab builds only.
```

The earlier banner read `accepts UNVERIFIED programs`, which was true when written and was still
being printed after it stopped being true --- one of five such strings found in a single sweep and
recorded in `CONTESTED-PREMISES.md` rather than quietly corrected.

**What is now the largest gap** is one level out from where this section used to put it: for a
story that ends "we disabled your exploit path", it is not enough that the program was signed ---
somebody has to be able to say who armed it, when, against which build, and be able to revoke the
key that vouched for it. Neither the audit trail (item 12) nor a key lifecycle exists.

**There is no audit trail.** Scope item 12. Who armed what, when, in which mode, with what
result, is not recorded anywhere durable. "Conditioned upon customers being made aware"
implies a record they can be shown afterwards, and that record does not exist.

---

## 4. The gaps that block all three

Listed together because each one is a review question that will be asked, and each has the
same answer today: not built, or not measured.

| # | gap | state | why it blocks |
|---|---|---|---|
| 1 | **Peer authentication and key lifecycle** | signature verification **built and measured** (2026-08-20); these two are not | The program is now authenticated; the *requester* is not. Anything that can reach the socket may ask, and the verifying key is compiled in with no revocation path |
| 2 | **Audit trail** | unbuilt (item 12) | (c)'s "customer made aware" needs a durable record |
| 3 | **Per-function safe values** | hardcoded `0` | A wrong safe value turns a crash into silent misbehaviour |
| 4 | **Per-invocation cost** | **unmeasured** | `rdtsc` is preemption-polluted, so the mean is meaningless; `perf_event_paranoid=4` on the node blocks hardware counters. Quote no per-call number |
| 5 | **JIT skips the bounds callback** | by design in uBPF | The interpreter and the JIT do not agree on memory safety, and the lab runs the JIT (`LS_VM_JIT=1`) |
| 6 | **Reachability must be measured** | per-site | Five CVE candidates were compiled into the binary and never executed on BNK's path. `fired > 0` under traffic is the only proof |

Item 5 deserves the extra sentence, because it is the least advertised: uBPF's own
`docs/VerifiedPrograms.md` states that PREVAIL *"assumes that r1 points to a valid memory
region"* while uBPF *"doesn't enforce any particular context layout"* and *"memory safety
depends on the program"*. Our defence is a chain of identity checks at admission — section
name, function symbol, ctx ABI version, build ID — **not** a runtime bounds check. That
makes item 1 load-bearing rather than merely desirable.

---

## 5. What to say, and what not to

**Say:**

- A verified program can be loaded into a running TMM and armed at a function entry with no
  restart, and disarmed the same way, with the entry bytes restored byte-identical.
- It reports decisions the data plane makes — by source line and reason — that no kernel
  agent can see, because TMM does not traverse the kernel hooks those agents attach to.
- It can refuse a call before a vulnerable function body runs, and it can do that in
  `MONITOR` first so the customer sees the effect before it takes effect.

**Do not say:**

- "CVE mitigation" for BNK. A shield does not clear a scanner, and the reachable population
  is about two of 3,068.
- "Disable a service." The unit is a function; the port still listens.
- "Patching." Nothing is patched; a call is intercepted.
- Any per-invocation cost figure. It is unmeasured, and saying so is cheaper than being
  corrected.
- "Verified, therefore safe." PREVAIL proves properties of a program against an assumed
  context. It does not prove the host hands it that context, and with the JIT there is no
  runtime backstop.
