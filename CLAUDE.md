# Working conventions — eob-tmm

Guidance for Claude Code sessions and contributors working in this repo. This repo holds design
proposals, candidate ABI artifacts, visual explainers, and the **substrate sources that are compiled
into TMM**.

**Status, and the distinction that governs every claim (updated 2026-08-13).** The mechanism runs in
a live TMM on BNK/datkube: a shield is loaded over a socket into an already-running process, armed at
a function entry while traffic flows, and disarmed again — no rebuild, no restart. A hook armed on
`http_parse_client_headers` fired exactly once per request across 16,000 requests through the proxy.
The substrate splices **nothing into TMM's own logic** (startup registers through `INIT_FUNC`), but the
tree does change: 46 files and ~7,800 lines added, three build-configuration files edited, and one
compiler flag.

That is not licence to claim more than was shown. Three lines still hold:

- **This repo is not self-contained.** Its sources are built into TMM elsewhere. `make -C substrate
  check` exercises bench harnesses, not a data plane. Reproducing the live results needs the TMM
  build tree and the cluster.
- **Mechanism proven ≠ outcome proven.** No CVE has been mitigated on live traffic. The BNK target
  is not even reachable there (`prot_transfer_log_profile` has no Kubernetes CRD, and the caller
  guards the null), so "it stops the crash" has never been demonstrated end to end.
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

**How claims are governed here — four rules, binding.** They exist so the output can be
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
helps. Current set: the programmable-data-plane **engine**, **CVE mitigation** (the shield), and the
**engine hard-problems** register. Companion design docs live at the repo root
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
