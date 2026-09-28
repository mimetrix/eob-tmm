# Catalog-free deployment — implementation and validation record

2026-09-24. **MEASURED: packaged, layer-audited, deployed, and exercised on live HTTP traffic.**
P18 in `02-RESEARCH-PARAMETERS.md` is the pre-registered acceptance/falsification test.

## Contract

| Where | Step | Output |
|---|---|---|
| Build box | Extract the packaged runtime/debug pair; generate discovery/type catalogs | Full-build-keyed catalogs, retained off the gateway |
| Build box | Resolve fields and one unambiguous padded target; check exit return ABI/unwind when applicable | Program with relocated accesses and a 64-byte `.ls.target` record |
| Build box | PREVAIL on the final object, then Ed25519-sign its binding/hash | Verified object + signature; target included in the authenticated hash |
| Gateway, admission | Verify signature/hash, exact full build ID, target executable segment/pad, kind and mode ceiling | One admitted per-slot target, no bulk lookup table |
| Gateway, control path | ARM only the admitted target; refuse retargeting while attached; DISARM only tracked attachments | Existing live patch protocol |
| Gateway, data path | Existing entry/exit trampoline and JIT | No catalog lookup or target-record parsing per call |

The existing 112-byte binding and 192-byte loader header remain unchanged. The record contains
version magic, all 40 hexadecimal characters of the GNU build ID, the function entry address,
entry/exit kind, pad offset and zero reserved bytes. The hook name remains in the signed binding
and must identify the object's sole tracing section. The TSV's `arm_at` is the first NOP;
`bind_target.py` subtracts `pad_offset` to recover the function entry.

Version 1 is deliberately limited to ELF64 little-endian x86-64 **ET_EXEC**, a 20-byte GNU build
ID, and +0/+4 five-NOP entry pads. PIE needs a separate load-bias contract. Return ABI/unwind
eligibility is checked on the build box and vouched for by the signer; it is not reconstructed
from a gateway catalog. Existing reclamation/concurrency limits remain, including in-flight exit
frames during replacement. No new per-call overhead measurement is claimed.

## Why this changes admission as well as packaging

The previous source's ARM branch (`ls_vm_load.c`, HEAD `f08a820`) accepted a separately supplied
address and checked for a loaded slot plus a live pad. It did not compare that address with the
signed LOAD hook. The corresponding build-box source files were byte-identical to HEAD on
2026-09-24 (`ls_vm_load.c` SHA-256 `ece1c836d330fd7216c6425421ca18d29576a2479da75475743c384b68817414`,
`ls_arm.c` `b577781e43a4b1af434654f098b6ab79f85f42cbac623ddc78dac5a2c6467e32`). This is a **source
finding**, not a live adversarial reproduction. The client's catalog/build check was a useful
correctness check, but was not runtime authentication of the attachment address.

`ask 'ERR arm: put the entry address in binding.hook'` returned **NO RECORD**. The new contract
must close that separation rather than replace name lookup with an unchecked address. The mode
ceiling also needs an actual comparison at LOAD/SET_MODE, not merely a signed field.

## Packaging boundary

The image carries loader/drainer tools and a small runtime identity receipt (full build ID +
SHA-256), but no `hook-index.tsv`, `signatures.tsv`, `hook-map.json`, `types.json` or `tmm.btf`.
The layer audit examines every layer in `docker save`, including lower layers and deleted files,
for these catalog filenames and ELF BTF sections. It does not interpret arbitrary nested
application archives or assert that compiled functions/strings cease to disclose information.

## Identity and deployment

- Image: `docker.io/library/tmm:CATALOGFREE-20260924`.
- Image index digest: `sha256:96336e4cd08c72b6180f22ae4f72e179907c4d419fc0af502bc261fd78ae659d`.
- GNU build ID: `c3b81927dfdcc31137cd8212b5e23bb85677a06c`.
- Executing `/proc/24/exe` SHA-256: `a4b9e777a1daccd8c2b8c7f1aa7eba920b6040253f45f017605ea0a5f0a8afd7`.
- Pod `f5-tmm-7597dfff8b-28s9z`, `kind-vs/default`, node `vs-worker`.
- Pod UID `42259fbc-3303-492a-95b1-9146b4105583`; container
  `039aa0fc34f6f0e77542abfa1646858cc328ca9a9b2c6597977c477c03b0be63`.
- Kubernetes image ID: `sha256:a713a9c7c9916b0010a2679674b5abb237bb0c59789cfd398f3773445e2649d1`.

The build receipt is `f08a820-dirty`, not a claim that HEAD alone reproduces the image. Runtime
source hashes in `catalog-tree-20260924.log` match the staged files. That enumeration reports
37 added files (35 base files: 14 C, 21 headers, 8,948 lines) and four modified F5 files. The
fourth is the deliberate `http2.c` CVE-2025-41414 revert; **this remains a vulnerable demo image**.
Both the preceding `CTX96-20260923` and `CLEAN-NOBTF` images remain available on both kind nodes.

## Results and witnesses

| Check | Result | Witness / limit |
|---|---|---|
| Pinned build-box fixtures | 16 target/parser cases under ASan/UBSan; final entry/exit objects pass PREVAIL; 5 layer-audit fixtures; 16 signature assertions + keyless refusal; 40 client assertions | Compiler/verifier/sanitizer tools; not live coverage |
| Package and final probe build | Package command exits 0; bound entry/exit probes pass pinned clang-18/PREVAIL before signing | Build-box logs; runtime identity separately witnessed below |
| Every distributable image layer | **16 layers, 7,504 regular files, 1,318 ELF files**, no named bulk catalogs or ELF BTF | Saved-image audit, including lower layers/deleted content; defined filename/ELF scope |
| Build-side discovery | `tmmtrace list http_parse_client_headers` resolves the name | 71,310 indexed entries is not measured hook coverage; `inline_status` is absent |
| Signed wrong full build, same prefix; wrong kind; address outside executable text | LOAD refused; slot state and pad unchanged | Runtime replies/counters plus independent pad readback |
| Unsigned modification to target record | LOAD refused; log identifies program-hash mismatch | Signature implementation's log, not independent cryptographic proof |
| Monitor ceiling | LOAD in enforce refused; SET_MODE to enforce refused | Runtime reply and subsequent monitor state |
| Different name/address supplied to ARM; untracked DISARM | Refused with attachment/pad preserved | Runtime reply plus `/proc/24/mem` |
| Attached entry↔exit replacement | Refused before publication | State unchanged; current attachment remains intact |
| Attached replacement with a validly signed different hook | A final repeat adds `fentry/device_poll`; refused for both current hook kinds | Correctly bound/verified/signed different-target artifact, never armed; slot state unchanged |
| Same-target reload while patched | Accepted for entry and exit; generation increments and patch stays intact | Runtime state, pad readback and subsequent traffic |
| Live context probes | **32 entry + 32 exit requests**, each `fired +32`, test verdict `+32`, errors `+0`, HTTP **200** | SELF counters/samples; curl responses and kernel/pod identity independently observed |
| Disarm | Five bytes restored to `9090909090`; **8 HTTP 200 requests after each disarm with zero fires** | `/proc` readback and counter deltas |
| DSL authoring path | `fentry` and `fexit` `/arg0 != 0/ { count() }`, each relocated, bound, verified, signed on builder; **16/16 hook hits and matches** live | Separate build and datkube logs; both disarmed/disabled afterward |
| Process stability | Same UID/container, **zero restarts** | Kubernetes plus executing ELF identity |

The first complete context run ends at slot 0 `gen=3`, `fired=64`, `mode=0`; the DSL run
ends at slot 2 `gen=2`, `fired=32`, `mode=0`. `armed=1` still describes VM bookkeeping rather
than an installed patch (`CONTESTED-PREMISES.md` §17). The independent final read is NOPs.
The complete repeat adding the valid different-hook replacement case also passes: another
32 entry + 32 exit requests, both eight-request post-disarm controls, zero errors/restarts,
same pod/container. Slot 0 then ends at **`gen=7`, `fired=128`, `mode=0`**, with independent
NOP readback (`catalog-final-retarget-20260924.log`).
The temporary HTTP/1 fixture at `11.11.11.99:18081` was deleted after validation. Shared
`:8081` still has the documented HTTP/1-to-HTTP/2 backend mismatch; these results use the fixture.

**Scope:** one function, one stable pod, sequential HTTP/1 traffic with signature enforcement
enabled. `safe_returns` here counts a successful test verdict in **monitor** mode, not blocked
requests. This does not measure data-path cost, establish concurrency/quiescence safety, validate
new return conventions, or conceal compiled code/strings. Exit eligibility and field semantics
are vouched for by the build-side signer. The image audit is for the TMM image, not arbitrary
other containers/toolbox images. The existing toolbox authoring path is not this deployment path.

## Reproduction

After stage → sync → `bnk-package.sh`, on the build box:

```sh
sh ~/eob-tmm-staged/env/scripts/bnk-bake-tools.sh --btf-only
CLANG=clang-18 TMM_BTF=~/lstools/tmm.btf sh ~/eob-tmm-staged/env/scripts/bnk-build-programs.sh
OUT=~/catalog-probes sh ~/eob-tmm-staged/env/scripts/bnk-build-ctx-test.sh
sh ~/eob-tmm-staged/env/scripts/bnk-bake-tools.sh tmm:local tmm:CATALOGFREE-20260924
sh ~/eob-tmm-staged/env/scripts/bnk-ship-image.sh verify tmm:CATALOGFREE-20260924 \
  'ls_vm: LOAD REFUSED --- signed target/build/mode contract'
```

Import the image on every node of the active kind cluster, deploy, then restart the ingress
controller after TMM is Ready. Transfer signed probes and `bnk-test-ctx-contract.py` plus
`bnk-deliver-program.py` to datkube. Apply `env/k8s/ctx-contract-test.yaml`, wait for Ready and
Programmed, and run the driver with one stable pod, probe directory and full build ID. It requires
JIT/samples/verbose logging and disabled slot 0. Delete the fixture afterward. Reusing these
addresses requires checking the lab for conflicts first.

## Cached record

SHA-256 values are in `evidence/cache/MANIFEST.sha256`; source registration is in `SOURCES.md`.
All files below have prefix `evidence/cache/catalog-` and suffix `-20260924.log`:
`before`, `checks`, `package`, `bake`, `ship`, `deploy`, `discovery`, `probes-final`,
`live`, `live-retarget`, `dsl-live`, `final`, `final-retarget`, `tree`.

The bake log retains the old `mk_hook_map.py` console text claiming +0 pads are unsupported;
source inspection and pinned fixtures disproved that wording. The console wording is corrected
without rewriting the log. Indexed pad eligibility is not a live coverage measurement.
