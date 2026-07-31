# The reading map — which artifact answers which question

Five pages, and they are meant to be read in a particular order for a particular reason. This page
exists so nobody has to guess.

**Every page is self-contained HTML** — open it in a browser, no server, no build. Each has a
`.teams.md` twin carrying the same content in a form that pastes cleanly into Teams or an email,
because Teams renders HTML badly. The twins are kept in sync deliberately; if they ever disagree,
the HTML is the one that was edited first and the drift is a bug.

---

## Start here, by what you need

| You want… | Read | Time |
|---|---|---|
| The whole proposal on one printable sheet | [`one-pager.html`](one-pager.html) | 3 min |
| To understand the *engine* — what it is, generally | [`programmable-dataplane-engine.html`](programmable-dataplane-engine.html) | 15 min |
| The CVE-mitigation case, in plain language | [`cve-mitigation.html`](cve-mitigation.html) | 8 min |
| To see it done, step by step, on a real bug | [`cve-shield-walkthrough.html`](cve-shield-walkthrough.html) | 20 min |
| To attack it — every hard problem, honestly | [`engine-hard-problems.html`](engine-hard-problems.html) | 20 min |
| To know what it costs to build | [`../development-scope.md`](../development-scope.md) | 10 min |
| Our own review findings, with dispositions | [`../design-review-findings.md`](../design-review-findings.md) | 25 min |

## The intended order, and why

**1 · [`one-pager.html`](one-pager.html)** — the hand-out. Prints to a single sheet. If someone reads
only one thing, this is it, and it is written to survive being forwarded without you in the room.

**2 · [`programmable-dataplane-engine.html`](programmable-dataplane-engine.html)** — the engine, as a
*general* capability. Deliberately not a CVE story: it argues that TMM's own code and behaviour should
be changeable at runtime, provably safely, and that observability is at least as valuable as
mitigation. Read this before the CVE material, or the whole thing looks like a security feature
rather than a programmability surface.

**3 · [`cve-mitigation.html`](cve-mitigation.html)** — the first application, in language that does
not require knowing eBPF. This is the page to send to someone who asks "what problem does this
solve?" It carries the perimeter argument (the signature, not the verifier) and the three honest
coverage limits.

**4 · [`cve-shield-walkthrough.html`](cve-shield-walkthrough.html)** — the proof of work. A real TMM
NULL-deref CVE, from the build steps that must ship once, through the nine runtime steps that mitigate
it, with the actual eBPF program walked line by line and what the verifier would refuse. This is the
page for an engineer who wants to know whether we have actually thought it through.

**5 · [`engine-hard-problems.html`](engine-hard-problems.html)** — the engineering register. Time
safety, the context ABI, shared state, the trust surface, plus nine further concerns and an honest
effort figure. **Hand this to your harshest reviewer first.** Naming the claims we are *retiring*
is what earns the right to the rest.

## What lives outside this directory

- [`../development-scope.md`](../development-scope.md) — what F5 actually builds, item by item, with
  what is reused as-is. The answer to "how much work is this?"
- [`../development-scope-code.md`](../development-scope-code.md) — a candidate code skeleton per item,
  each with a real/stubbed/TODO breakdown.
- [`../design-review-findings.md`](../design-review-findings.md) — three architect reviews and their
  dispositions, including the findings that changed the design. Keep this in reserve rather than
  leading with it: it is the artifact that wins an argument with a skeptic, but forty self-identified
  problems reads as "not ready" if it arrives first.
- [`../engine-hard-problems.md`](../engine-hard-problems.md), [`../embedded-ebpf-substrate.md`](../embedded-ebpf-substrate.md),
  [`../big-ip-live-shield-design.md`](../big-ip-live-shield-design.md) — the long-form design docs the
  explainers are distilled from. References, not narratives: search them, cite them, don't read them
  end to end.
- [`../prototype/`](../prototype/) — a working relay with a synthetic CVE, a designed-in hook, and a
  PREVAIL gate that rejects a deliberately-unsafe program. **Show this before any slide.**

## Two honest notes for whoever circulates this

**The numbers that matter don't exist yet.** Every affordability claim — "free when dark," "tens of
nanoseconds is noise" — is unmeasured. The one-pager and the register both say so, and the ask is a
feasibility phase precisely because of it. Don't let a page get read as a performance claim.

**The canonical facts live in one place each.** The outcome set is defined once, in
[`../embedded-ebpf-substrate.md`](../embedded-ebpf-substrate.md) §2. The hook-map schema is
[`../prototype/substrate/hook_map.schema.json`](../prototype/substrate/hook_map.schema.json). The
loader ABI is [`../prototype/substrate/shield_abi.h`](../prototype/substrate/shield_abi.h), which
compiles and asserts its own wire layout. If an explainer ever contradicts one of those, the
explainer is wrong.
