# TMM + eBPF: current capabilities and the AI gateway extension

**Status:** Capability summary — demonstrated engine capabilities and proposed AI-specific extensions.

**We have a live-programmable instrumentation and selective-enforcement engine running inside TMM in our BNK/datkube environment.** Signed eBPF programs can be loaded, attached to supported function entries or returns, replaced, and disarmed while traffic continues—without rebuilding or restarting TMM for each program. Demonstrated capabilities include inspecting arguments and internal fields, observing return values, counting matching conditions, and streaming structured records. At suitable function-entry boundaries, an enforce-mode program can also skip the function and return a configured value that its caller can handle.

**The DSL and `tmmtrace` make these capabilities easier to use.** Engineers can author short expressions using named arguments, scalar fields, multi-hop pointer traversal, conditional counts, histogram-oriented values, and shielding predicates. Multi-hop reads and DSL-authored enforcement have been demonstrated on live traffic. Companion tools provide hook discovery, coverage information, counters, context samples, JSON record draining, and refreshing operational views through `tmmtop`. There are still usability gaps: some field-access patterns are unsupported, and the toolbox wrapper needs alignment with the newer build-specific delivery pipeline.

**The build and delivery pipeline provides verified, signed programs tailored to the target TMM binary.** It derives symbols and type information from the packaged build, resolves field offsets before verification and signing, and supports a deployed TMM without embedded type information. Signature checks, build admission, audit records, and live loading have recorded validation. The latest deployed correction makes entry and exit contexts match the full **96-byte region** permitted by PREVAIL; live regression tests exercised both paths with no errors or restarts. Separately, a selective shield has prevented **CVE-2025-41414** on a deliberately vulnerable build: the unprotected request crashed TMM, while the shield prevented the crash in the tested configuration. That demonstrates a real mitigation, with a deliberately approximate predicate and a measured—not universally proven—false-positive rate.

**For the future F5 AI gateway, the proposed next layer is a stable semantic interface for MCP, agent-to-agent, and inference traffic.** The working paper defines candidate tracepoints around admission, tool dispatch and completion, delegation, model routing, streaming progress, content release, and cancellation. Proposed `tmmtrace`/DSL extensions would expose these events through discoverable schemas, typed predicates, correlated records, and explicitly supported actions. The goal is to explain gateway behavior and introduce narrowly scoped controls through the existing live-program lifecycle. These AI-specific interfaces are not implemented yet; protocol-correct rejection, cancellation, and stream termination require additional host integration.

**The remaining engineering work is broader coverage, runtime hardening, and workload-specific performance validation.** Representative packet-path overhead remains unmeasured, including the added context-initialization cost. Armed-status bookkeeping and program-reclamation/concurrency limitations also remain. The engine is operational; extending it into a production AI gateway is the next development stage.

## Sources and evidence tiers

**2026-09-24 update:** catalog-free deployment with authenticated per-program targets is live
([record](catalog-free-deployment.md)). Named embedded-structure traversal now complements pointer
chains: native execution fixtures, real-TMM relocation/admission and scoped HTTP/1 live tests pass
([P17 record](embedded-traversal-validation.md)). These updates extend the context-fix baseline
described above; AI semantic interfaces remain proposed.

Demonstrated engine results are **MEASURED** as scoped in the records below. The AI-specific semantic interfaces and actions are **IDEA**, not implemented capabilities.

- [Capability evidence](GROUND_TRUTH.md)
- [Context validation](ctx-contract-validation.md)
- [CVE demonstration](cve-41414-demonstration.md)
- [AI gateway working paper](ai-gateway-tracepoints.md)
