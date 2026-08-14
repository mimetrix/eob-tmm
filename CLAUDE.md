# Working conventions — eob-tmm

Guidance for Claude Code sessions and contributors working in this repo. This repo holds design
proposals, candidate ABI artifacts, visual explainers, and the **substrate sources that are compiled
into TMM**.

**Status, and the distinction that governs every claim (updated 2026-08-13).** The mechanism runs in
a live TMM on BNK/datkube: a shield is loaded over a socket into an already-running process, armed at
a function entry while traffic flows, and disarmed again — no rebuild, no restart. A hook armed on
`http_parse_client_headers` fired exactly once per request across 16,000 requests through the proxy.
The substrate modifies **no F5 source file**; it adds new files, `filelist`/whitelist entries, and one
compiler flag.

That is not licence to claim more than was shown. Three lines still hold:

- **This repo is not self-contained.** Its sources are built into TMM elsewhere. `make -C substrate
  check` exercises bench harnesses, not a data plane. Reproducing the live results needs the TMM
  build tree and the cluster.
- **Mechanism proven ≠ outcome proven.** No CVE has been mitigated on live traffic. The BNK target
  is not even reachable there (`prot_transfer_log_profile` has no Kubernetes CRD, and the caller
  guards the null), so "it stops the crash" has never been demonstrated end to end.
- **Per-call hook cost is unmeasured.** The counter mean is dominated by preemption artifacts and the
  bench op that would give a clean minimum currently wedges the loader thread. Quote no per-call
  number until that is fixed — see `load-path-scope.md` §7.

The earlier convention read "there is deliberately no prototype; nothing in this repo executes a
shield." That was true when written and is now superseded. **Replace such claims when they are
falsified rather than letting them stand — and add the new limit in the same edit**, which is why the
three bullets above exist.

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
`big-ip-live-shield-design.md`, `tmm-usdt-tracepoints.md`).



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
