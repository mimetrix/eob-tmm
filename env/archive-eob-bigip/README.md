# Archive — from the retired `eob-bigip` repo

Two files preserved **verbatim** from `eob-bigip/docs` when that repo was
retired on 2026-08-11. Kept for provenance, **not** as current guidance.

"Verbatim" means as-of retirement, not as-of July: `00-project-goals.md`
includes status edits made on 2026-08-11 shortly before the move (a "current
push" bullet and links to the then-`05`/`06`), which is why it references
files that never existed under these names.

| File | Why it's here and not promoted |
|---|---|
| `00-project-goals.md` | The retired repo's own goals/status page. Its roadmap is superseded — this repo's design docs and `env/tmm-build-environment.md` carry the live picture. |
| `01-bigip-form-factors-and-ebpf-surface.md` | Covers BIG-IP form factors (appliance / VE / BNK) and where eBPF fits. That subject matter is **already treated at greater depth** in this repo's root design docs, so promoting it would create two sources of truth. |

## Read these with three caveats

1. **Relative links inside these files are stale by design.** They point at
   the old `NN-` filenames in a directory layout that no longer exists.
   Files were not edited, so the links were not rewritten. The promoted
   equivalents are: `02-environment-notes.md` →
   [`../sandbox-ebpf-limitations.md`](../sandbox-ebpf-limitations.md),
   `03-openstack-cli-reference.md` →
   [`../openstack-cli-reference.md`](../openstack-cli-reference.md),
   `04-bigip-ve-boot-attempt-2026-07-17.md` →
   [`../bigip-ve-boot-2026-07-17.md`](../bigip-ve-boot-2026-07-17.md),
   `05`/`06` → [`../tmm-build-environment.md`](../tmm-build-environment.md)
   and [`../bigip-mcp-server.md`](../bigip-mcp-server.md).
2. **Possible conflict with the root design docs.** `01`'s treatment of form
   factors and the eBPF attach surface was written independently and has
   **not** been reconciled against `big-ip-live-shield-design.md`,
   `data-plane-intelligence.md`, or `design-review-findings.md`. Where they
   disagree, **the root design docs win.** Do not cite `01` as authority.
3. **They describe a repo that no longer exists.** References to the Go
   module, `bpf/xdpcount`, or `bpf/headers/` point at `eob-bigip`'s working
   tree, which was outside the sandbox mount and was never copied here.
