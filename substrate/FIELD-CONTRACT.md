# The field contract

Two environments, one boundary, and everything that crosses it is an artifact.

**Build side.** Any tool is available — a compiler, `gdb`, `pahole`, `readelf`, the source tree,
the debug info. A build runs and emits artifacts. **Those artifacts are the entire contract.**

**Field side.** All that exists is the running software. No source, no debug info, no compiler, no
DWARF reader. **Nothing can be derived there.** Every fact must already be inside what shipped.

Verified in the running TMM container, 2026-08-25: `gdb` — absent. `readelf` — absent. So this is
not a policy we intend to keep; it is the environment we are already in.

The artifacts for any deployed build remain retrievable, so a stale derived number has no excuse
to survive a rebuild. Regenerating is always possible; guessing is never necessary.

---

## What the build must emit

| artifact | derived from | consumed by | what breaks without it |
|---|---|---|---|
| `hook-index.tsv` | the shipped package pair, both build ids checked equal | `ls_arm`, by symbol name | arming falls back to a guessed address — refused instead |
| `signatures.tsv` | one DWARF walk of the matching debuginfo | argument shapes per hook | a builder reads the wrong register |
| `ls_ctx_parse_offsets.h` | `mk_ctx_parse.py` over the build's debug info | compiled **into** TMM | build fails; there are deliberately no fallback offsets |
| the `.bpf.o` programs | `clang -O2 -target bpf`, verified, then signed | the loader | nothing can be loaded |
| the Ed25519 public key | the signing key, baked into the binary at link | in-TMM signature check | unsigned programs would be accepted |
| `-fpatchable-function-entry=5,0` | a compiler flag, not a file | `ls_arm` | no pad exists; arming is refused |

Every number about TMM's layout is derived. Field **names** are specification — which of TMM's
fields a program may see is a design choice — but no offset, width, shift, mask, size or bound is
typed by a human. `ls_ctx_parse.h` used to carry seven hand-written offsets under a banner reading
`GENERATED for build 1778975c`; by 2026-08-25 the debug tree was `e35ed0ed` and the cluster ran
`499b8c30`. All seven were still correct, which is luck, and luck is not shippable.

**Two readers, not one.** `mk_ctx_parse.py --cross-check` runs every DWARF reader present and
fails unless they produce identical output. It has already earned this twice: one reader died on
`DW_AT_const_value : 1 byte block: 0` — a form that appears in real TMM DWARF and not in a
fixture — and the two disagreed on a bitfield's byte until the comparison was moved from the raw
`offsetof` primitive to the derived result. Confirmed on TMM's own debug info: `readelf` and `gdb`
agree on all 13 derived values.

---

## What the running system must provide

Anything here is a deployment requirement, not an implementation detail.

| requirement | why | status in the shipped image |
|---|---|---|
| TMM built with the entry pad | there is nothing to patch otherwise | build-time flag, costs 0.182% of binary size |
| the eight `LS_*` environment variables | a fresh deployment carries **zero**; the substrate is compiled in and completely dormant, and a dormant one looks identical to a working one | set by `bnk-enable-substrate.sh`, which verifies from TMM's own log |
| a writable `/tmp` | the loader socket (`/tmp/ls_load.sock.<instance>`) and the record ring live there | present |
| `python3` in the container | **only** because `ls-load.py` is the development client — a product loader would not need it | present in the stock image; not something we add |
| `/usr/share/ls/` | the index, signatures and programs are read from disk at arm time | baked into the image layer |
| `ls_drain` | reads the record ring; static, no runtime dependencies | baked in |

Nothing else. No network egress, no sidecar, no host mount, no privileged capability beyond what
TMM already holds, and no tool that reads debug information — because none is present and none is
needed.

**Declared gap: nothing yet asserts the stamped build id matches the target.**
`ls_ctx_parse_offsets.h` records the build id it was derived from, and the header is regenerated
per build, so a stale file cannot survive a clean build. But an incremental build could in
principle compile a header derived from a *different* artifact, and no check currently compares
that stamp against the binary being produced. The hook index already has this guarantee — its
build id is compared against `/proc/<pid>/exe` and arming is refused on a mismatch — and the
offsets header does not. Until it does, the protection here is procedural, not enforced.

**The one that has bitten us.** A freshly installed deployment has the substrate compiled in and
every `LS_*` variable absent. The pods report healthy, and the absence shows up only as an absence:
no loader socket, so nothing can be loaded; no ring, so programs emit into nothing. Every test
suite here needs `LS_LOAD_SOCKET` and reports a connection failure rather than a missing
configuration. Check the variables before believing anything else.
