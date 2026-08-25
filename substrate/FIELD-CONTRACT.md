# The field contract

Two environments, one boundary, and everything that crosses it is an artifact.

**Build side.** Any tool is available — a compiler, `gdb`, `pahole`, `readelf`, the source tree,
the debug info. A build runs and emits artifacts. **Those artifacts are the entire contract.**

**Field side.** All that exists is the running software.

**Corrected 2026-08-25 — the first version of this page was wrong about what that includes.** It
said "no debug info", which was an assumption, not a measurement. Measured inside the running TMM
container:

| | |
|---|---|
| `/usr/lib/debug` | **233 MB**, shipped with the TMM package |
| `.build-id/49/9b8c300bcc…debug` | symlink to `tmm64.no_pgo.debug` — **the build id the cluster is running** |
| `tmm64.no_pgo.debug` | **146 MB**, carries `.debug_info`, and contains `http_parse_ctx`, `http_parse_info` and `parse_state` |
| any DWARF reader | **absent** — no `readelf`, `objdump`, `gdb`, `nm`, `eu-readelf` in either container |
| the `debug` sidecar | `f5-debug-sidecar:v10.146.1`, Debian-based with `apt`/`dpkg`; `binutils` and `elfutils` are **not** installed |

So the field is missing a **tool**, not the **information**. Full DWARF for the running binary is
right there. That is a materially different constraint from the one this page first asserted, and
worth stating precisely because it changes what is possible rather than merely what is convenient.

**It does not change where derivation belongs.** Work that can be done once at build time should
not be repeated on every pod at every start — 146 MB of DWARF is not free to walk, and the build
already knows the answer. Build-time derivation stays the design.

**It does change what can be PROVEN in the field**, which is the more valuable half. See the gap
below.

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

Nothing else. No network egress, no host mount, and no privileged capability beyond what TMM
already holds. No tool that reads debug information is present, and none is required by the load
path — adding `binutils` to the debug sidecar is optional, and buys the field-side verification
described below.

**The staleness gap, and why no field tooling is needed to close it.**
`ls_ctx_parse_offsets.h` records the build id it was derived from. Nothing yet compares that stamp
to anything, so a generated header reused across trees could in principle be compiled in.

The fix is a transitive chain built entirely from artifacts the build already produces:

| link | where | status |
|---|---|---|
| offsets header build id **=** hook index build id | bake | **the missing one** |
| signature index build id **=** hook index build id | bake | enforced — a mismatch is fatal |
| hook index build id **=** the binary inside the image | bake, step 5 | enforced |
| hook index build id **=** `/proc/<pid>/exe` of the running TMM | run time, `ls-load.py` | enforced, and tested (`check_ls_load.py`: a mismatched build id must refuse to arm) |

Close the first row and the offsets are verified against the **running** binary, transitively,
through a gate that already exists and already refuses. One comparison in the bake, no new
mechanism, and nothing added to any container.

**So the field-side option is recorded and NOT recommended.** The running container does hold the
DWARF (see above), so re-deriving the offsets in the field is possible — but it would mean
installing a reader into the debug sidecar, and the rule here is that nothing gets installed unless
the build artifacts cannot answer the question. They can. This is a technique still being worked
out, so the possibility is worth keeping on the page; it is not worth taking while a build artifact
settles it. If a future question genuinely cannot be answered from the build, that is when adding
`binutils` earns its argument — and it should arrive with the reason written down.

**The one that has bitten us.** A freshly installed deployment has the substrate compiled in and
every `LS_*` variable absent. The pods report healthy, and the absence shows up only as an absence:
no loader socket, so nothing can be loaded; no ring, so programs emit into nothing. Every test
suite here needs `LS_LOAD_SOCKET` and reports a connection failure rather than a missing
configuration. Check the variables before believing anything else.
