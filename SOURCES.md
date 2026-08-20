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

**These five are local-origin, and that is the point of listing them.** They are claims about
*external* software, so the rule applies — but the evidence is the vendored source and the built
binary we actually use, not a web page describing a version we might not have. That is stronger
evidence, not weaker.

## NOT_RETRIEVED

This environment has no outbound network: `https://github.com` returns nothing (`HTTP 000`) and
`https://nvd.nist.gov` returns `HTTP 403`. Verified at the timestamp above, not assumed. So every
genuinely remote source is unretrieved, and none of the following is paraphrased into a claim
anywhere it matters.

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
