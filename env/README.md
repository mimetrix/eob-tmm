# `env/` — build and test environment

Operational notes for the machines this work runs on: how to reach F5's
internal OpenStack stacks, how to stand up a **TMM build host**, and what
the Claude sandbox can and cannot do. **Infrastructure plumbing, not
proposal content.**

Deliberately separate from the repo-root design docs. Per
[`../CLAUDE.md`](../CLAUDE.md) this repo holds design proposals, candidate
ABI artifacts, and explainers, and **contains no prototype** — nothing here
changes that. These are notes on *provisioning the machines*, and none of
them claim to execute anything.

## Contents

| File | Purpose |
|---|---|
| [`tmm-build-environment.md`](tmm-build-environment.md) | **The active document.** Running log for standing up a TMM build host: stack reachability, SSH paths, Perforce, credential runbook, SJC-vs-SEA comparison, open questions. |
| [`openstack-cli-reference.md`](openstack-cli-reference.md) | How to install and drive `python-openstackclient` against the F5 stacks; image selection, network gotchas, instance launch recipe. |
| [`sandbox-ebpf-limitations.md`](sandbox-ebpf-limitations.md) | What the Claude dev sandbox can do with eBPF (build/codegen only — capabilities are stripped from the bounding set, so nothing loads). |
| [`bigip-ve-boot-2026-07-17.md`](bigip-ve-boot-2026-07-17.md) | The 2026-07-17 BIG-IP VE boot attempt and the kernel-3.10/no-BTF blocker it found. |
| [`bigip-mcp-server.md`](bigip-mcp-server.md) | Backlog: the internal BIG-IP MCP Server page, gated on having a stable TMM. |
| [`scripts/`](scripts/) | `bootstrap-openstack-cli.sh` (rebuild the CLI — needed every session), `merge-clouds-yaml.py` (assemble a multi-cloud `clouds.yaml` from Horizon downloads). |
| [`archive-eob-bigip/`](archive-eob-bigip/) | Two verbatim files from the retired `eob-bigip` repo whose subject matter overlaps this repo's design docs. Archival only — see the README there. |

## Provenance

Everything here moved from `eob-bigip/docs` on **2026-08-11**, when the user
confirmed `eob-tmm` is where this work belongs and that `eob-bigip` can be
deleted. Files were renamed from the old `NN-` numbered scheme to this
repo's descriptive convention, and cross-references were rewritten to match.

The original repo was only ever *partially* visible to the sandbox — the
mount covered `docs/` alone — so its Go module, `bpf/xdpcount` XDP program,
vendored libbpf headers, and git history were **never** captured here and do
not exist in this repo. Where inherited documents reference paths like
`bpf/headers/`, those refer to that retired repo and are historical.

## Two standing cautions

**Durability.** When this repo is a clone inside the Claude sandbox
(`~/eob-tmm`) rather than a host mount, it does **not** survive a sandbox
reset. Commit and push before a session ends.

**Credentials never enter this repo.** OpenStack application-credential
secrets live only in `~/.config/openstack/clouds.yaml` (mode 600), outside
the tree. `.gitignore` carries defensive patterns for credential-shaped
files, but the rule is to keep them out of the working directory entirely,
not to rely on the ignore list.
