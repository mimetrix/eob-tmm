**A VERIFIED eBPF ENGINE FOR TMM — one page**
_A design proposal. (Teams-pasteable companion; same content, no HTML.)_

**Give TMM its own verified eBPF engine.**

Everything else at F5 now ships at machine speed. **TMM's own code and behaviour still wait on a release train** — so a new metric, a diagnostic probe, or a mitigation for a live CVE all cost the same thing: a build. Embedding a small userspace eBPF VM at designed-in hook points changes the unit of change from **a release** to **a signed artifact** — and a static verifier is what makes that safe enough to allow on the data-plane path.

---

**WHY TMM IS THE RIGHT HOST — AND WHY THIS ISN'T A GENERAL ANSWER**

- **A proxy, not a forwarder — the budget is there.** A forwarder's unit of work is a packet: single-digit nanoseconds, where bytecode is a meaningful fraction. TMM's unit is a flow, a connection, a request — **microseconds**. A hook costing tens of nanoseconds is noise, and the hooks worth having sit at warm per-request boundaries.
- **Vendor-owned, shipped, closed — the proof is required.** F5 owns the source, so hooks are **designed in** and the hook map comes out of the build. And F5 can't ship a customer a mitigation that *might* crash the data plane — which is why a verifier is the precondition for the artifact existing, not a feature bolted on.

---

**THE MECHANISM, END TO END**

```
author (a few lines of C) -> clang -target bpf -> PREVAIL verify -> budget pass
  -> sign the binding -> load at a named hook -> monitor -> enforce -> auto-retire
```

Two hook kinds cover the **anticipated** and the **unanticipated**: designed-in USDT tracepoints with a curated, versioned context, and **function-boundary probes** at any named function in the build's signed hook map — so a question nobody planned for needs no new build. A program is a pure function of its context: it reads scalars and returns a verdict. **The host owns every outcome** (pass · drop · reset · safe-return · steer · sample) and applies whichever the hook allows; the program cannot invent control flow, inject a value, or reach memory it wasn't handed.

**The security perimeter is the signature, not the verifier.** Only F5-signed bytecode ever reaches the engine, and verification happens earlier — in F5's pipeline, never on anything an attacker supplied. So even a verifier bug is **not remotely triggerable**: exploiting it would also require compromising the HSM-held signing key. That collapses the risk from traffic-borne RCE to supply-chain/insider. What's signed is the whole binding — program hash, the one hook it may attach to, build range, mode ceiling, expiry — so a shield can't be replayed elsewhere or escalated to enforce.

---

**WHAT IT UNLOCKS**

- **Deep observability into a black box** — counters, latency across internal stages, a flight recorder that survives a data-plane crash. *bpftrace* and *tcpdump*, for TMM.
- **Field diagnostics** — ship a customer a signed probe, characterise the issue in situ, pull it. No debug build, no core-dump archaeology.
- **Adaptive control** — steer, sample, gate or shed on an internal signal, decided at the hook.
- **Runtime CVE mitigation** — recognise a bug's precondition and take a safe outcome between patch windows. One application, and the narrowest: it needs the same hooks, verifier and signing gate as everything above it.

---

**WHAT IT IS NOT, STATED PLAINLY**

**Not a hot-patch** — a shield stops a crash; it cannot reproduce the fix's corrected behaviour, so enforcing costs whatever the skipped work did. **Not customer-facing programmability** — the ABI is internal; F5 authors, F5 signs. **Not free** — the engine itself ships in one enabling TMOS release, and coverage follows software: flows handled by hardware offload never enter TMM's software path. **Not measured yet** — the always-on cost of compiling TMM with patchable function entries is the number that decides everything, and nobody has it.

---

**THE ASK**

**A one-quarter feasibility phase, not a build.** Three deliverables: **(1)** measure the dark cost of the compiler flag — kill criterion ~1% pps; **(2)** settle a context model that verifies, against real TMM debug info; **(3)** arm one hook end-to-end in a lab TMM with core dumps still readable. If all three land, the rest is a real 12–18-month programme for 6–8 engineers. If any fails, a quarter was spent instead of two years.

_A design proposal — not a commitment to an implementation. Detailed method & claims are held in a separate invention disclosure._
