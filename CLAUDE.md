# Working conventions — eob-tmm

Guidance for Claude Code sessions and contributors working in this repo. This repo holds design
proposals, candidate ABI artifacts, visual explainers, and the **substrate sources that are compiled
into TMM**.

**Status, and the distinction that governs every claim (updated 2026-08-13).** The mechanism runs in
a live TMM on BNK/datkube: a shield is loaded over a socket into an already-running process, armed at
a function entry while traffic flows, and disarmed again — no rebuild, no restart. A hook armed on
`http_parse_client_headers` fired exactly once per request across 16,000 requests through the proxy.
The substrate splices **nothing into TMM's own logic** (startup registers through `INIT_FUNC`), but the
tree does change. In the **substrate-only** tree: 35 files added (33 under `src/base/` — 14 `.c`,
19 `.h` — and 2 whitelist config under `src/compile/`), three build-configuration files edited
(`default_whitelist`, `debug_whitelist`, `filelist`), one compiler flag, ~8,300 lines. Authoritative
count is `git status --porcelain src/` on the build-box TMM tree, re-verified **2026-09-04** — the
added-file counts hold exactly.

**But the modified-file count did not, and the tree is not substrate-only.** The same enumeration
shows a **fourth** modified F5 file that no manifest recorded:
`src/modules/hudfilter/http2/http2.c`, carrying the **CVE-2025-41414 fix (`81d3428d3d`) reverted**
— which is what makes that crash reproducible. So **every binary built from this tree is vulnerable
to CVE-2025-41414**, whatever it was built for, and "substrate-only" describes the *substrate*
delta, not the tree. `ssl.c`, which the manifest named as the fourth modified file, is **not**
modified. Recorded in `CONTESTED-PREMISES.md` §16; the reason it stayed invisible is there too. The larger
"46 files / ~7,800 lines" figure elsewhere counts a **different tree state** — one that also carries
the vulnerable-SSL demo overlay under `src/modules/hudfilter/ssl/` plus the `ssl.c` revert
(`VULNERABLE-BUILD.md`); that overlay is **not** applied in the current tree.

That is not licence to claim more than was shown. Three lines still hold:

- **This repo is not self-contained.** Its sources are built into TMM elsewhere. `make -C substrate
  check` exercises bench harnesses, not a data plane. Reproducing the live results needs the TMM
  build tree and the cluster.
- **Mechanism proven ≠ outcome proven — and the line moved on 2026-09-02, so state it precisely.**
  What *is* demonstrated: **crash-to-no-crash on the real binary** — one variable, opposite outcomes
  (enforce → `SAFE_RETURN`, *"shield prevented the dereference"*, `restarts=0`; monitor →
  `FALLTHROUGH` → `Fault address: 0`, **segfault, core dumped**) — and **enforce on live traffic**,
  blocking a targeted request while normal traffic stayed 200, with exact counters, an
  `"mode":"enforce"` evidence record and a clean disarm. **The limit that replaces the old one:** the
  crash condition WAS **injected** — and as of 2026-09-03 it no longer is. **CVE-2025-41414 is now
  crashed by a single client request and prevented by a selective, PREVAIL-verified shield**
  (`cve-41414-demonstration.md`): `SIGSEGV`/`CR2=0x13` in `http2_http_data_to_frames.cold`
  reproduced twice, then `end_stream==1 && push==0 && status_code!=0` armed enforce → 10/10 on the
  known-positive, **0/10 false positives**, 0 restarts. **The three limits that replace the old
  one:** (a) the predicate is a deliberate *over-approximation* — it matches a bodyless response
  framing, while the true condition is a trailer whose serialised header block is empty, a local
  (`xb.len`) invisible at an entry hook — so `0/10` is measured, not proven-zero; (b) it was
  demonstrated on a **CNF-flavoured profile**, not on `bnk-core`'s Gateway path, which still cannot
  express server-side HTTP/2; (c) per-call cost on the data path remains unmeasured. The older
  wording here read that the crash condition was not carried by a client request, and that
  injection was the same method the dev teams use when a path is hard to reach
  through configuration. Two further claims in this bullet were **also falsified** and are corrected
  rather than dropped: *"no `[EMBARGO]` fix ships a repro"* — two do, and the repro is what supplied
  the trigger vector (`81d3428d3d`, `23f4f689aa`); and the reason a CVE could not be reached was
  attributed to **listener configuration** with Brainpool as the blocked route. The real reason was
  broader and is now stated as a rule: **exposure = fix absent × code compiled/licensed in ×
  precondition reachable in the deployed configuration.** Six candidates were blocked by the third
  term, never by the mechanism — see `cve-to-shield-process.md` §4. Brainpool specifically is
  unreachable because no TLS curve knob exists, not because a listener was mis-declared.
- **Per-call hook cost is unmeasured.** The counter mean is dominated by preemption artifacts and the
  bench op is FIXED as of 2026-08-19 — handed to a TMM thread like a load, and now timing the
  JIT rather than the interpreter it used to measure. So a FLOOR exists: a simple program executes in ≤ 11 ns on the JIT path (min 26–28 cycles at 2.60 GHz, build e8e854ad), bounded by the rdtsc pair that measures it rather than by the program.
  What an armed hook costs ON THE DATA PATH is still unmeasured: the floor excludes the
  trampoline's register save and restore, the call and return, and cache effects under real
  traffic. Quote the floor as a floor, and nothing as a per-packet cost — see
  `load-path-scope.md` §7.

The earlier convention read "there is deliberately no prototype; nothing in this repo executes a
shield." That was true when written and is now superseded. **Replace such claims when they are
falsified rather than letting them stand — and add the new limit in the same edit**, which is why the
three bullets above exist.

**How claims are governed here — five rules, binding.** They exist so the output can be
*argued with*, and so my own errors stay visible rather than being smoothed out of the record.

1. **No cached file, no claim.** Any statement about something external cites a row in
   [`SOURCES.md`](SOURCES.md) naming a file in `evidence/cache/` with a SHA-256. A source that
   cannot be retrieved is recorded `NOT_RETRIEVED` with the reason — never paraphrased.
2. **Claims about our own system carry an evidence tier** — MEASURED, SHIPPED-UNVALIDATED,
   ROADMAP, IDEA, FALSIFIED — anchored in [`GROUND_TRUTH.md`](GROUND_TRUTH.md). **Who witnessed
   it is tracked separately and matters as much:** a counter our own code incremented is weaker
   evidence than something the kernel or an independent tool observed.
3. **Falsifier-first.** Open questions are pre-registered with what would kill them, in
   [`02-RESEARCH-PARAMETERS.md`](02-RESEARCH-PARAMETERS.md). A claim with no stated falsifier is
   not a claim yet.
4. **Being wrong is recorded, not tidied away.** [`CONTESTED-PREMISES.md`](CONTESTED-PREMISES.md)
   keeps attacks on our own premises, including a fix that measurement overturned within the same
   session. Retracting quietly destroys the audit trail that makes the rest worth anything.
5. **The pre-claim gate: reproduce in the authoritative place BEFORE stating a result.** This is
   the rule most often bypassed for speed, and every bypass costs a walk-back. Before saying *X
   passes / fails / works / is measured / is falsified*:
   - **Toolchain- or build-sensitive claims** (PREVAIL, clang, the binary, arming) are verified on
     the **build box with the pinned toolchain**. A workstation, an aarch64 host, or a different
     clang is a **hint, never a conclusion** — `clang-14` passed a PREVAIL program that `clang-18`
     (the pinned build) *refused*: the compiler version alone flipped the verdict.
   - **Claims about our own system**: read the [`GROUND_TRUTH.md`](GROUND_TRUTH.md) /
     [`CONTESTED-PREMISES.md`](CONTESTED-PREMISES.md) / [`env/bnk-dev-runbook.md`](env/bnk-dev-runbook.md)
     row **first**. If a record already states it, trust the record over a fresh convenient check —
     or reproduce in the *recorded* environment before contradicting it. The answer is usually
     already written down; re-deriving it from a faster vantage is how the same thing gets learned
     twice.
   - **Cluster claims**: the pinned image and a **stable** pod, not whichever pod is fastest to
     reach — a churning replica and load-balancer hashing produce false negatives.
   A hint is not a finding until reproduced where it counts. When the fast check and the record
   disagree, the record wins until the authoritative environment says otherwise.

   **And the step that makes this rule actually hold — `ask` first, always.** Rule 5 was written
   before it had a mechanism, and it was bypassed twice on 2026-09-02: `runbook` §12g predicted an
   entire `F5VirtualServer` dead end symptom-for-symptom, and `LS_VM_SELFTEST` — which
   [`GROUND_TRUTH.md`](GROUND_TRUTH.md) records as having *already* cost four days once — sat
   unretrieved while a CVE demonstration was called blocked. The failure is economic, not moral:
   *"read the 1,400-line runbook"* loses to *"run one kubectl command"* every time. So:

   > **Before investigating any build, cluster, loader or measurement symptom, run
   > `env/scripts/ask '<the literal message>'` and state what it returned — including when it
   > returned nothing.**

   It searches [`SYMPTOMS.md`](SYMPTOMS.md) (keyed on literal error text), `GROUND_TRUTH`,
   `CONTESTED-PREMISES`, the runbook and the design docs, in that order, in one command. "I ran
   `ask` and there is no record" is a valid and *required* answer — it licenses free investigation.
   **Then close the loop: add a row to `SYMPTOMS.md` whenever a symptom costs more than ten
   minutes**, keyed on the string you actually had in front of you, not on the topic it belongs to.
   Topic-organised records are what failed; a row is cheap, re-deriving is not.

**Reading order across a repo that spans both eras: see [`DOC-STATUS.md`](DOC-STATUS.md).** It
classifies every document as current, design (pre-build), record, or procedure, and lists the
specific claims the build falsified. Older documents are kept rather than rewritten — the design
reasoning in them is still why the system is shaped as it is — so a reader needs to know which era a
page belongs to before acting on it.

## 1. The git repo is the system of record — publishing to claude.ai needs explicit approval

Deliverables (docs, explainers) live and are versioned **here**. Publishing — or **republishing** —
any file as a **claude.ai Artifact externalizes it to Anthropic-hosted infrastructure**, so it is
**never done without the owner's explicit, per-item approval**, not as a routine step. Default
every deliverable to **repo-only**.

- Artifacts are private-by-default but still hosted off-repo; treat *where they live* as a data
  decision for the account owner / F5 IT, not an implementation detail. The material here is
  sensitive (security-appliance internals), so be deliberate.
- Artifact **deletion is manual** in the claude.ai gallery and cannot be done from tooling —
  removing a repo file does **not** remove any artifact already published from it.
- When an explainer *is* (with approval) published, **redeploy to the same artifact URL** so shared
  links never break — republish the same file path, or pass the existing URL; a rename keeps its
  URL the same way. Repoint every inbound link when retiring/renaming.

## 2. Engineering rigor: precision over polish

The audience is a skeptical engineering + security review; credibility comes from honest scoping.

- Distinguish **proven vs. merely bounded/estimated**, **build/admission-time (amortized, off the
  data path) vs. runtime (per-packet, in the poll loop)**, and **reused OSS vs. net-new work**.
- Name limits, trade-offs, and hard parts plainly, and frame them as **addressable work, not
  show-stoppers**. Security-review-worthy items feed a formal **TMA** (Threat Model Analysis), which
  is a gating prerequisite, not a formality.
- Define terms/acronyms at first use; don't oversimplify a mechanism to its base tier as if that's
  the whole of it; avoid overclaims (e.g. "verified ⇒ can't hang" — termination ≠ WCET).
- For any mechanism whose steps run in different places, prefer a **zoned pipeline diagram**
  (steps · the artifact each emits · where each runs · what touches the hot path) over prose.

## 3. Explainers

The visual explainers in `explainers/` use the `explainer` skill's design system — self-contained,
theme-aware HTML. **One job per page**; keep each single-purpose and cross-linked only when it
helps. Current set: the programmable-data-plane **engine** and the **engine hard-problems**
register, the **live-surface** product one-pager, and — no longer deferred, because the story is
now demonstrated end to end — **`cve-mitigation.html`**, whose worked example is the shield that
actually stopped CVE-2025-41414 (`cve-41414-demonstration.md`). `substrate-as-built.html` stays as
the as-built record. **Retired 2026-09-04:** `presentations/shield-live-demo.html`, which was built
entirely around `dtls_tx` — an internal finding with **no CVE id** — and is superseded by
`presentations/cve-mitigation-demo.html`. Companion design docs live at the repo root
(`engine-hard-problems.md`, `data-plane-egress-primitives.md`, `embedded-ebpf-substrate.md`,
`big-ip-live-surface-design.md`, `tmm-usdt-tracepoints.md`).



## 4. IP / disclosures

Patent and invention-disclosure artifacts stay **out of this repo** (gitignored). Only papers,
design docs, and candidate artifacts belong here. Novel method & claims are referenced as living in a separate
disclosure — never included by path or content.

---

## Git push (SSH)

Only `~/.ssh/id_ed25519_claude` works for GitHub. Remote is often ahead — pull `--rebase` before
push, in one command:

```bash
ssh-agent bash -c 'ssh-add ~/.ssh/id_ed25519_claude && \
  GIT_SSH_COMMAND="ssh -i ~/.ssh/id_ed25519_claude" git pull --rebase origin main && \
  GIT_SSH_COMMAND="ssh -i ~/.ssh/id_ed25519_claude" git push origin main'
```

End commit messages with the `Co-Authored-By` trailer.
