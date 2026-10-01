# Build TMM and its eBPF bytecode from source

**Status, 2026-09-30: procedure assembled from source inspection. This sequence
has not been run from a fresh host.** A TMM source-tree path is necessary, but it
is not sufficient. Some steps below still need a build-specific integration
recipe. They are marked **GAP**; later commands do not remove those gaps.

The existing [TMM guide](TMM-BUILD.md) and [bytecode guide](BYTECODE-BUILD.md)
describe the prepared lab. This page gives the order, required inputs, outputs
and unresolved dependencies without assuming that lab exists.

The last recorded activity build uses one ELF file with two legacy loaded
instances. See [its build and live record](../env/ai-traffic/ACTIVITY-PROGRAM.md).
The new [program-ownership contract](../substrate/PROGRAMS.md) is a separate
integration target. Its native/socket tests, incremental TMM build, package and
isolated live ownership test now pass. The live scope is two owners and two
entry hooks on one worker. Multiple workers and sustained cost remain open.
The earlier activity traffic does not qualify this new ownership model.

## Build order

```text
BUILD HOST                       TMM TOOLCHAIN CONTAINER
Inventory sources/tools ───────► Build matching uBPF library
Prepare signing public key       Integrate substrate + build configuration
                                 Build TMM → package runtime and debug ELF
                                            │
BUILD HOST                                  ▼
                         Check runtime/debug identity
                         Derive hook index and type data
                         Compile bytecode → resolve fields → bind targets
                         Verify each entry → sign final ELF
                                            │
OUTPUT                                      ▼
                 TMM package + matching bytecode/signature + build record
```

ELF means Executable and Linkable Format. The debug ELF supplies symbols and
type information. PREVAIL checks bytecode before signing. These build steps do
not run on the traffic-processing path. Loading and live testing are later steps.

## 1. Supply and record the inputs

Set these paths on the build host. Each value must be supplied by the operator;
the strings below are placeholders.

```bash
set -euo pipefail
export REPO=/absolute/path/to/eob-tmm
export TMM=/absolute/path/to/tmm
export OUT=/absolute/path/to/new-build-output
export SIGN_KEY=/absolute/path/outside/repos/shield_sk.pem
```

`REPO` must contain the selected substrate and bytecode sources. A TMM checkout
alone does not contain them. `OUT` must be a new directory with an existing,
writable parent. Keep source snapshots separate from build outputs and keys.

```bash
test -d "$REPO/substrate"
test -f "$TMM/Makefile"
test -f "$TMM/input-manifest.yml"
test -d "$TMM/src/base"
test ! -e "$OUT"
mkdir "$OUT"
export RECEIPT="$OUT/pipeline-receipt"
git -C "$REPO" rev-parse HEAD
git -C "$REPO" status --short
git -C "$TMM" rev-parse HEAD
git -C "$TMM" status --short
```

Run the blocks in the same Bash session, which stops on error. Save the output.
`RECEIPT` gives packaging and metadata generation the same explicit record path.
Read each tree's build instructions, including
`AGENTS.md` when present. Save the actual source inputs and their SHA-256 hashes;
a commit ID alone does not identify uncommitted or untracked files.

The recorded TMM base is `e2104734a940a099a9190eb84bfbea01fb4b81d4`.
A different revision requires an integration and field-layout review. Preserve
existing changes. The lab manifest includes a deliberate HTTP/2 CVE-fix revert;
that revert is not a prerequisite for embedding eBPF. See
[the tree record](../substrate/TMM-TREE-DELTA.md).

## 2. Prepare the host and its access

Check these requirements before starting a build:

| Requirement | Check or source |
| --- | --- |
| Linux x86-64 for the recorded native qualification | `uname -sm`; another architecture needs separate qualification |
| Git, Bash, Make, Python 3, C/C++ compiler, CMake | Required by bootstrap and native tools |
| Docker daemon access and `script` | Required by the TMM container build and its terminal handling |
| TMM dependencies and registry access | Use this tree's `input-manifest.yml` and build instructions |
| Go implementation of `yq` | Check `yq --version`; the Python wrapper is not interchangeable |
| clang 18.1.3 with BPF target; LLVM objcopy | Recorded activity compiler; check version and BPF support |
| GCC 13.3.0 and GDB for activity checks | Host qualification tools; not a substitute for TMM's compiler |
| OpenSSL with Ed25519 support | Public-header generation and signing |
| `readelf`, `nm`, `objdump`, `dpkg-deb` | ELF and package inspection |
| Boost and yaml-cpp development files | PREVAIL build dependencies |
| pkg-config; libdw, libelf and zlib development files | Detached type-data tool build dependencies |

Also check Python module requirements in the selected scripts; type/debug tools
can require `pyelftools`. Read the patched pahole builder's prerequisites before
using it. The table is a tool inventory, not a complete OS package lockfile.

Obtain installation commands for the actual host OS. Record tool versions and
the resolved toolchain image digest. Obtain the credentials required by that
TMM revision through its documented setup. A successful image pull does not
prove access to all build dependencies. Keep credentials out of build records.
The [lab runbook, sections 7–8](../env/bnk-dev-runbook.md#7--credentials-on-the-box)
records the `.env` dependency and terminal requirement for the recorded base.

## 3. Fetch and build the authoring dependencies

```bash
bash "$REPO/bootstrap.sh"
bash "$REPO/bootstrap.sh" --check
bash "$REPO/substrate/check_vendor_pin.sh" "$REPO"
test -s "$REPO/ubpf/build/lib/libubpf.a"
test -x "$REPO/ebpf-verifier/bin/prevail"
"$REPO/ebpf-verifier/bin/prevail" --version
```

For a host without upstream access, bootstrap accepts `--from=/path/to/mirrors`.
The required revisions are in [vendor.pins](../substrate/vendor.pins).
Bootstrap can report a failed optional build and continue. Check the artifacts
and verifier explicitly; a skipped verifier is not a successful verification.
This step prepares host tools and native tests. It does not build TMM.

## 4. Prepare the signing key before compiling TMM

The public key compiled into TMM must match the private key used in step 12.
Use an existing selected key, or create a key for a new build environment:

```bash
REPO="$REPO" SIGN_KEY="$SIGN_KEY" KEYDIR="$(dirname "$SIGN_KEY")" \
  HDR="$TMM/src/base/ls_sig_pubkey.h" \
  sh "$REPO/env/scripts/bnk-init-signing-key.sh"
```

This command writes the public header. Review an existing tree's key before
using it. Keep the private key outside the source snapshot. Subsequent source
copies must preserve this generated header.

## 5. Start this tree's TMM toolchain

For the recorded base, run the top-level container setup with a terminal:

```bash
script -qec "make -C \"$TMM\" start" "$OUT/tmm-start.log"
```

Require successful completion, including dependency installation. Identify the
container created for this tree from its name and mounts. Record its ID, image
digest and compiler version. Do not select the first running container.
For another TMM revision, first check that its build exposes this target.

## 6. Build the uBPF library that TMM will link

Use the pinned uBPF source in a separate TMM build copy, conventionally
`$TMM/.ubpf`. Build it inside the container from step 5, with that container's
compiler and a fresh build directory. Do not copy the host-built library from
step 3 into TMM.

The recorded CMake options are:

```text
-DCMAKE_BUILD_TYPE=Release
-DUBPF_ENABLE_TESTS=OFF
-DUBPF_SKIP_EXTERNAL=ON
-DCMAKE_POSITION_INDEPENDENT_CODE=ON
```

Required outputs are `build/vm/ubpf_config.h` and `build/lib/libubpf.a`.
Save the source revision, applied patches, compiler identity and library hash.

**GAP:** the repository records a
[uBPF JIT scratch patch](../substrate/ubpf-patches/0001-jit-scratch-rightsize.patch),
but bootstrap builds the unpatched host copy. A fresh TMM recipe must explicitly
select and apply its patch set in the separate build copy, then record it.
Neither the source revision alone nor a pre-existing `.ubpf/build` establishes
which library was linked. The old runbook container command is an example,
not a container selector or complete patch recipe.

## 7. Integrate the selected substrate

Use an explicit source manifest. Copy its C files and headers into the required
TMM include environment. Generate and check the assembly wrapper first:

```bash
make -C "$REPO/substrate" tramp-asm
make -C "$REPO/substrate" check-tramp-mirror
```

Review the existing tree before copying. Preserve its generated public key.
Apply the corresponding changes to `src/compile/filelist`, both x86-64 globals
whitelists and `Makefile.overrides`. The build must:

- Link the library from step 6.
- Provide the uBPF API, generated-header and `src/base` include paths.
- Compile `ls_prep.c` in TMM's include environment, without `STDINC`.
- Add `-fpatchable-function-entry=5,0` to the selected TMM build variant.
- Compile the generated `ls_tramp_asm.c` wrapper.

**Incremental ownership integration is now measured.** The current manifest
includes `ls_program.h` and `ls_program_impl.h`.
[`program-globals.patch`](../substrate/program-globals.patch) adds `g_programs`
and removes the now-thread-local `g_prog_stack` in both x86-64 whitelists.
The explicit-input
[`build-programs-integration.py`](../env/scripts/build-programs-integration.py)
copies the selected sources, checks the native receipt, invalidates old objects,
runs `make tmm` and inspects the linked binary. It covers steps 7–8 for the
recorded existing tree. [Result and limits](../substrate/PROGRAMS.md).

**GAP:** [TMM-TREE-DELTA.md](../substrate/TMM-TREE-DELTA.md) also retains historical
filelist and global lists, including retired context-builder files. The new driver
requires the existing activity-host integration; it does not configure a fresh
TMM tree. Do not paste an old list and call a fresh-tree integration complete.

`bnk-sync-substrate.sh` copies sources and invalidates objects; it does not create
all fresh-tree build configuration. `entry_snapshot_integrate.py` is pinned to
one lab tree and previous receipts. Its `--activity` mode copies only three
files. It is not an installer for the new program-ownership model.

## 8. Compile TMM and inspect the linked result

On an existing build, invalidate the affected substrate objects and `harness.o`.
Regenerate `filelist.mk` after filelist changes. If the compiler flag from step 7
is new, rebuild all affected TMM objects, not only substrate objects. Use this
tree's clean procedure. Confirm that obsolete outputs are gone.

```bash
script -qec "make -C \"$TMM\" tmm" "$OUT/tmm-build.log"
```

The recorded base produces `src/compile/obj_x86_64.no_pgo/tmm.no_pgo`.
Check the actual output path for the selected variant. Require a fresh artifact,
save its full GNU build ID and SHA-256, and inspect its substrate symbols and
target entry pads. Resolve globals-whitelist differences against this build's
actual globals. Do not disable that check.

## 9. Package the runtime and matching debug ELF

After reviewing its cleanup scope, the existing packaging entry point is:

```bash
TMM="$TMM" SRC="$REPO/substrate" \
  sh "$REPO/env/scripts/bnk-package.sh"
```

It clears version-stamped package outputs, invokes `make container`, checks
substrate symbols and records the package identity. Require both the runtime
and matching debug package. If the selected tree needs explicit debug-package
flags, take them from its Makefile before packaging.

Packaging can relink TMM. Select the packaged runtime as the bytecode target;
do not bind against the intermediate binary from step 8. Inspect the package
contents and retain the exact pair. The bake script selects the first matching
package, so its input directory must contain only the selected pair.

## 10. Derive this package's build-side metadata

Set `DEBS` to the directory containing that pair and `CTX` to a new metadata
directory. Both are absolute paths supplied by the operator.

```bash
export DEBS=/absolute/path/to/selected-package-directory
export CTX="$OUT/metadata"
export LS_PAHOLE_DIR="$OUT/pahole"
TMM="$TMM" REPO="$REPO" DEBS="$DEBS" CTX="$CTX" LS_EMBED_BTF=0 \
  sh "$REPO/env/scripts/bnk-bake-tools.sh" --btf-only
```

This consumes the package receipt and produces `tmm64.no_pgo`, `tmm.btf`,
`hook-index.tsv` and `hook-map.json`. BTF is the detached type data used for
field resolution. The explicit pahole directory avoids reusing an unrecorded
host cache. Save its fetched revision, patch hash and tool version.
Retain the matching debug ELF separately; this script's debug
extraction directory is temporary. Check full build IDs and hashes. Keep type
data and indexes on the build host.

## 11. Compile, resolve, bind and verify the bytecode

Choose the bytecode source explicitly. The TMM source path does not select an
eBPF program. For the two-entry activity program, the compile command is:

```bash
clang-18 -target bpf -O2 -g -Wall -Wextra -Werror \
  -ffunction-sections -mllvm -disable-block-placement \
  -c "$REPO/substrate/surfaces/agent_activity.bpf.c" \
  -o "$OUT/agent_activity.bpf.o"
```

Before making this object deployable, check its field offsets, enum values and
hook signatures against the selected TMM debug ELF. Compilation alone cannot
check them. Programs with named-field relocation records must first resolve
those records against this package's BTF, as described in
[BYTECODE-BUILD.md](BYTECODE-BUILD.md#3--resolve-bind-then-verify-pinned-toolchain).

**GAP:** `activity_program_build.py --sign` compares layouts to an earlier debug
ELF at a fixed lab path. It also requires an earlier parser header and a package
receipt. A source path alone cannot satisfy these inputs. Its source capture
expects a source-only directory; passing a whole checkout with binaries and
caches is not equivalent. A portable activity build needs an explicit layout
check and explicit paths for these dependencies.

After field qualification, select the LLVM 18 objcopy path as `OBJCOPY` and the
pinned verifier path as `PREVAIL`. For this activity object:

```bash
export OBJCOPY=/absolute/path/to/llvm-18/bin/llvm-objcopy
export PREVAIL="$REPO/ebpf-verifier/bin/prevail"
"$OBJCOPY" --strip-debug --remove-section=.BTF \
  --remove-section=.BTF.ext --remove-section=.rel.BTF.ext \
  "$OUT/agent_activity.bpf.o"
python3 "$REPO/substrate/bind_targets.py" \
  --prog "$OUT/agent_activity.bpf.o" --binary "$CTX/tmm64.no_pgo" \
  --index "$CTX/hook-index.tsv" --objcopy "$OBJCOPY"
for entry in json_filter_handle_json_complete hud_aimcp_handler; do
  "$PREVAIL" "$OUT/agent_activity.bpf.o" "fentry/$entry" \
    --termination --strict --no-division-by-zero --stack-size 256
```

Require `PASS:` for both entries. Check that stripping preserved executable
sections and that the final object is at most 256 KiB. Run its native interpreter
and JIT checks against the selected uBPF library. A single-entry object uses
`bind_target.py`; `bind_targets.py` requires two through twelve entry sections.

## 12. Sign the final bytes and retain the build record

Derive the prefix from the packaged runtime:

```bash
BUILD_ID=$(python3 "$REPO/substrate/ls_buildid.py" "$CTX/tmm64.no_pgo")
BUILD_PREFIX="0x${BUILD_ID:0:8}"
```

For a qualified host using the new program-ownership API, the signing form is:

```bash
python3 "$REPO/substrate/sign_shield.py" --key "$SIGN_KEY" \
  --prog "$OUT/agent_activity.bpf.o" --hook @program-v1 \
  --mode-ceiling monitor --build-min "$BUILD_PREFIX" \
  --build-max "$BUILD_PREFIX" -o "$OUT/agent_activity.sig"
```

This form requires the new loader. It does not make an older loader compatible.
The recorded legacy activity build instead signs the same ELF once per hook;
see [ACTIVITY-PROGRAM.md](../env/ai-traffic/ACTIVITY-PROGRAM.md).
The signer does not run PREVAIL. Require step 11 first, and do not modify the
object after signing. The target set also binds the full build ID.

Retain source hashes, toolchain identity, library recipe/hash, build logs,
runtime/debug package hashes, target metadata hashes, verifier output, native
test results, final bytecode hash and signature hash. Keep the private key
separate. These outputs establish a build record, not a live traffic result.

## What is needed to call this reproducible

A fresh-host run must complete all twelve steps without reading unlisted lab
files. It must produce the selected TMM package and its matching verified,
signed bytecode. Missing inputs must be reported before source publication.

The remaining work is a complete integration manifest, an explicit TMM-linked
uBPF recipe, path-configurable qualification drivers, and a fresh-host test.
For the new ownership model, add a TMM build and an isolated live test with two
programs sharing hooks and independent removal. Until those steps have receipts,
this page is a build sequence with explicit gaps, not a proven clean-host recipe.
