# Sources: every external claim, and the file behind it

Rule: **no cached file, no claim.** A statement about anything outside this repository cites a row here, and every row names a file in `evidence/cache/` with a SHA-256 you can check. A source that could not be retrieved is recorded as `NOT_RETRIEVED` with the reason — never paraphrased from memory.

Regenerate the hashes:

```bash
cd evidence/cache && sha256sum * > MANIFEST.sha256
```

## Retrieved

| claim it supports | origin | cached file | SHA-256 | retrieved (UTC) |
|---|---|---|---|---|
| uBPF: PREVAIL assumes r1 points to a valid memory region; uBPF enforces no context layout | vendored ubpf/docs/VerifiedPrograms.md @ c900ed9f | [`ubpf-c900ed9f-VerifiedPrograms.md`](evidence/cache/ubpf-c900ed9f-VerifiedPrograms.md) | `4efc1fd5f1dec514cc305b280c47fd76…` | 2026-08-20T12:37:56Z |
| PREVAIL flag defaults: --termination is "Default: ignore", --allow-division-by-zero is "Default: allow", --strict is off | prevail --help, binary in ebpf-verifier/bin | [`prevail-0.2.5-help.txt`](evidence/cache/prevail-0.2.5-help.txt) | `fe2aa37bc987ed99769ad7a294459a04…` | 2026-08-20T12:37:56Z |
| The PREVAIL binary in use is v0.2.5 | prevail --version | [`prevail-0.2.5-version.txt`](evidence/cache/prevail-0.2.5-version.txt) | `35461307fe187b0161fb7e73804548d3…` | 2026-08-20T12:37:56Z |
| uBPF is iovisor/ubpf @ c900ed9faf1d41358a7ea9217ccd0b64a4ee8d5d, 2026-06-12 | git log in the vendored checkout | [`ubpf-c900ed9f-commit.txt`](evidence/cache/ubpf-c900ed9f-commit.txt) | `01d134ae8be5c1ee8f4f3ee8573cc012…` | 2026-08-20T12:37:56Z |
| PREVAIL is vbpf/ebpf-verifier @ 06769f7b508214e63b97905d275920f7e90182fa, tag v0.2.5 | git log in the vendored checkout | [`prevail-06769f7b-commit.txt`](evidence/cache/prevail-06769f7b-commit.txt) | `bb43c4844dca2bb89331dcf7d6c7e1a3…` | 2026-08-20T12:37:56Z |
| Kernel BTF is produced from DWARF by pahole ("The pahole acts as a dwarf2btf converter") and embedded as ELF sections `.BTF` (type+string data) and `.BTF.ext` (func_info, line_info, CO-RE relocations) | docs.kernel.org/bpf/btf.html | [`kernel-btf.html`](evidence/cache/kernel-btf.html) | `325dfc8ea4e2c615…` | 2026-08-26T14:57:17Z |
| CO-RE relo record is `struct bpf_core_relo {insn_off; type_id; access_str_off; kind}` carried in `.BTF.ext` (not ELF relocs); FIELD_BYTE_OFFSET patches an immediate (ALU/LD) or an instruction offset field (LDX/STX/ST); the access string is colon-separated indices | docs.kernel.org/bpf/llvm_reloc.html | [`kernel-llvm_reloc.html`](evidence/cache/kernel-llvm_reloc.html) | `be288617b83ecdec…` | 2026-08-26T14:57:17Z |
| libbpf CO-RE matches a program's recorded BTF/relocation info to the running kernel's BTF and "updates necessary offsets"; kernel BTF is exposed via sysfs at `/sys/kernel/btf/vmlinux`; `vmlinux.h` = `bpftool btf dump file /sys/kernel/btf/vmlinux format c` | docs.kernel.org/bpf/libbpf/libbpf_overview.html | [`kernel-libbpf_overview.html`](evidence/cache/kernel-libbpf_overview.html) | `269e4b0760ff37cd…` | 2026-08-26T14:57:17Z |

**These five are local-origin, and that is the point of listing them.** They are claims about
*external* software, so the rule applies — but the evidence is the vendored source and the built
binary we actually use, not a web page describing a version we might not have. That is stronger
evidence, not weaker.

## NOT_RETRIEVED

The *workstation* has no outbound network (`https://github.com` -> `HTTP 000`, `https://nvd.nist.gov`
-> `HTTP 403`, verified). The **build box (eob-bnk-build-01) does have egress** --- it is how the
kernel-doc rows above and the bpftime arXiv row below were retrieved and cached. So a remote source
is retrievable *via the build box*; the rows below remain NOT_RETRIEVED because they are internal/
paywalled/suspect, not merely remote.

| source | needed for | status | reason |
|---|---|---|---|
| `CVE-2026-22548` advisory | the worked shield example in the walkthrough | **NOT_RETRIEVED** | no network. **And separately suspect**: `DOC-STATUS.md` already records that this identifier does not correspond to a real published advisory. It must not be presented as one |
| `CVE-2022-4304`, `CVE-2022-0492` | cited in the CVE survey as examples | **NOT_RETRIEVED** | no network. Referenced as identifiers only; no technical claim in this repo rests on their contents |
| F5 commit `c806f1b2e8` | `alpn_guard` reinstates this bounds check | **NOT_RETRIEVED** | internal F5 source control, not reachable from here. The *shield* is in-tree and verifiable; the claim that it matches that commit is not independently checkable in this environment |
| Intel CET / `endbr64` semantics | the four bytes preceding the pad | **NOT_RETRIEVED** | no network. Mitigated: the bytes `f3 0f 1e fa` are read from the live process and cached implicitly in every demo transcript, so the *observation* stands even where the specification reference does not |
| USENIX Security '22 paper (he-yi) | prior art in the substrate design doc | **NOT_RETRIEVED** | no network. Cited as prior art, not as support for any measurement |
| Linux `perf_event_paranoid` documented range | the claim that 4 exceeds what the kernel tree defines | **NOT_RETRIEVED** | no network. **Weakened accordingly**: what is measured is the observed behaviour at the setting present (`EACCES` unprivileged, permitted with `CAP_SYS_ADMIN`), which needs no documentation to be true |

## What this list is missing

Nothing external is currently cited without a row here, but this page was created after most of
the repository was written, so absence of a row is not yet proof that no uncited external claim
survives somewhere. Sweeping for that is unfinished work and is recorded as such rather than
declared complete.
| bpftime latency (arXiv 2311.07923) | https://arxiv.org/abs/2311.07923 | 2026-08-25T16:49:24Z | `evidence/cache/bpftime-arxiv-2311.07923-latency.md` | ae368a303e7455b332e51ca834245edad7c6cdd5f9c41b7843711be3fc408405 | CITED-FROM-ABSTRACT — full PDF not byte-cached |

## F5 CVE advisories (reachability-survey CVE candidates, 2026-08-27) — NOT_RETRIEVED

The my.f5.com advisory pages render via JavaScript and return only a loading shell to automated
fetch; NVD returned its home shell. Marked NOT_RETRIEVED — descriptions in `reachability-survey.md`
are from search-result snippets, not cached full text. Retrieve via authenticated my.f5.com when
matching a specific candidate.

| CVE | advisory URL | status |
|---|---|---|
| CVE-2017-6151 | https://my.f5.com/manage/s/article/K07369970 | NOT_RETRIEVED (JS-gated) |
| CVE-2023-44487 | https://my.f5.com/manage/s/article/K000137106 | NOT_RETRIEVED (JS-gated) |
| CVE-2023-22323 | https://my.f5.com/manage/s/article/K56412001 | NOT_RETRIEVED (JS-gated) |
| CVE-2025-61951 | https://my.f5.com/manage/s/article/K000151309 | NOT_RETRIEVED (JS-gated) |

## F5 Bugzilla — reachable-parser CVE landscape (RETRIEVED via REST API, 2026-08-27)

Retrieved from `https://bugzilla.olympus.f5net.com/rest/bug/<id>` (authenticated, F5-internal — not
publicly retrievable, but reproducible by anyone with F5 Bugzilla access + the BZ id). Fields used:
`cf_cve_number`, `cf_cwe`, `cf_cvss_score`, `cf_conditions`, `cf_affectedversions`, `cf_fixeddate`,
`component`, `status`. Search: `cf_type=Vulnerability` + `cf_affectedversions substring Neptune`.

| BZ | CVE | component | fixed |
|---|---|---|---|
| 1496457 | CVE-2025-41414 | LTM_HTTP2 | 2024-04-24 |
| 1357309 | CVE-2025-36557 | LTM_HTTP/fsm | 2023-10-06 |
| 1783773 | CVE-2025-60016 | TLS/SSL | 2025-03-04 |
| 1552933 | CVE-2024-28889 | LTM_SSL | 2024-03-19 |
| 1361169 | CVE-2023-40534 | LTM_HTTP2 | 2023-10-09 |

Superseded the earlier NOT_RETRIEVED my.f5.com rows for these CVEs: Bugzilla carries the full detail
(CWE, conditions, CVSS, affected versions incl. Neptune) the JS-gated K-articles hid.

## SPK Architecture (internal Confluence) — **NOT_RETRIEVED**, 2026-09-02

`https://docs.f5net.com/spaces/~afreeman/pages/560987062/SPK+Architecture` — F5-internal
Confluence, authentication-gated; the sandbox running these tools has no route to `docs.f5net.com`
and the fetch returned empty content. **Deliberately not paraphrased from memory** (rule 1).

What was needed from it — how SPK/BNK exposes a TLS listener and attaches a client-SSL profile — was
instead answered **from the cluster itself**, which is stronger evidence for this deployment than a
general architecture page: `kubectl api-resources` shows the installed SPK family is
**networking-only** — `F5SPKEgress`, `F5SPKEgressSIP`, `F5SPKSnatpool`, `F5SPKStaticRoute`,
`F5SPKVlan` — with **no SPK ingress CRD** (`F5SPKIngressTCP`/`HTTP2`/… absent). So on this build the
networking half is SPK and the **ingress half is Gateway API**, which is why
`env/bnk-dev-runbook.md` §12g says "BNK uses Gateway API". Anyone with Confluence access should still
read the page and correct this row if it contradicts the cluster.
