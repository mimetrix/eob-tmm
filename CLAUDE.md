# Working conventions — eob-tmm

Guidance for Claude Code sessions and contributors working in this repo. This repo holds design
proposals, PoC code, and visual explainers for the embedded-eBPF-in-TMM proposal.

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
design docs, and PoC code belong here. Novel method & claims are referenced as living in a separate
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
