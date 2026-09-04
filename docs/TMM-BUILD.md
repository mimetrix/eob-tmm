# TMM build — the image and its build artifacts

How the TMM image is built, what our adjustments are, and how the type information the
runtime needs (`.BTF`) becomes an artifact **embedded in the binary**. Everything here is
**build-time**: it produces the image a pod runs. Compiling the bytecode that gets loaded
into that running TMM is a **separate, independent process** — see
[`BYTECODE-BUILD.md`](BYTECODE-BUILD.md). The two never touch.

> **What this delivers:** a TMM image whose binary carries the eBPF VM, the entry pads that
> make live arming possible, and its own type information as a `.BTF` ELF section — so
> portable bytecode can be relocated against it and loaded at runtime with no rebuild.
> Validated end to end (live arm on build `ee2056234fd0`, 2026-08-26 — see `co-re-plan.md`).

## Boxes

| box | address | role |
|---|---|---|
| build box (`eob-bnk-build-01`) | `10.145.37.36` | TMM source, toolchain container, `make`, bake, pahole |
| datkube (`eob-bnk-datkube-01`) | `10.145.40.193` | the `kind` cluster the image runs on |

`10.145.42.119` is **retired** (SSH refused 2026-08-26); the scripts default to `.37.36`.
Key for the build box: `~/.ssh/id_ed25519`. Build box → datkube push: `~/.ssh/id_datpush`.

## The two repo copies on the build box

Getting this wrong costs a cycle and the symptom points elsewhere, so it is first:

| copy | refreshed by | read by |
|---|---|---|
| `~/code/tmm/src/{base,modules/…}` | `bnk-stage.sh` **then** `bnk-sync-substrate.sh` | the compiler — these *become* TMM |
| `~/eob-tmm-staged/` | `bnk-stage.sh` | `bnk-package.sh` and `bnk-bake-tools.sh` (the tools/scripts baked/run for the image) |

**Always start a cycle with `bnk-stage.sh`** — it copies the working tree (not `HEAD`), verifies
the far end by content, and removes stale files (this is what clears retired substrate).

## The pipeline

```
bnk-stage.sh ──▶ bnk-sync-substrate.sh ──▶ make tmm-gdb ──▶ receipt ──▶ bnk-bake-tools.sh ──▶ ship ──▶ deploy
   stage repo      sync substrate→tree     build TMM+VM     package    derive+embed .BTF,     ctr      roll pods,
   (both copies)   (src/base)              (our adjustments) provenance  bake artifacts-only    import   verify
```

### 1 · Stage + sync
```bash
env/scripts/bnk-stage.sh            # both repo copies start here; verifies by content
env/scripts/bnk-sync-substrate.sh   # copies substrate/*.c,*.h into ~/code/tmm/src/base
```
`bnk-check-tree-sync.sh` compares the synced tree to `substrate/.tree-expected-delta` (a both-ways
manifest) and refuses on any divergence. `ls_sig_pubkey.h` is **generated per box** and must not
travel.

### 2 · Build TMM with our adjustments
```bash
sudo rm -f ~/code/tmm/src/compile/obj_x86_64.*/ls_*.o   # no .d files here; invalidate by hand
rm -f ~/code/tmm/src/compile/filelist.mk                # generated; delete to regenerate
script -qec "make tmm-gdb" /dev/null                    # the standard debug build
```
`make tmm-gdb` is the **standard** TMM build. Our adjustments to it, and nothing else in F5 source:

- **Substrate sources in `src/compile/filelist`** — the 12 general-mechanism files compiled into TMM
  (`ls_vm{,_config,_load}.c`, `ls_tramp{,_asm}.c`/`ls_swap`/`ls_arm`, `ls_prep`, `ls_sig`, `ls_audit`,
  `ls_tp_emit`, and the CO-RE relocator `ls_core_relo.c`), each `STDINC`/`STDINC UBPF`.
- **Globals whitelist** (`src/compile/{default,debug}_whitelist_x86_64`) — TMM's exact manifest of
  mutable global state; the link fails on any difference *in either direction*. Our entries:
  `g_ls_audit`, `g_ls_names`/`g_ls_nshapes`/`g_ls_shapes`, and `g_ls_btf` (the parsed target BTF).
- **`-fpatchable-function-entry=5,0`** — the 5-byte entry pad on every function, so any function can
  be armed at runtime (a `JMP rel32` overwrites the pad). This is what makes "attach to a running
  TMM" possible; see [The 5-byte pad](#the-5-byte-pad-is-required) below.
- **uBPF** built by the same toolchain (`.ubpf/build/lib/libubpf.a`, via `Makefile.overrides`).

No existing F5 function body is edited (startup registers through `INIT_FUNC`). The build produces
the stripped runtime binary (`/usr/bin/tmm64.no_pgo`) and the `tmm-debuginfo` package (its DWARF).

### 3 · Provenance receipt
```bash
env/scripts/bnk-receipt.sh write package build_id=<id> commit=<sha> source=make-tmm-gdb
```
The bake refuses a DEB pair with no packaging receipt (this is what catches a stale DEB reaching an
image). `bnk-package.sh` is the full verified packaging run that records this itself; a plain
`make tmm-gdb` build records the receipt with `source=make-tmm-gdb`, disclosing what it was.

### 4 · Derive + embed the BTF (the type artifact)
The kernel embeds its BTF as a `.BTF` section in `vmlinux` (pahole at build) and re-exposes it via
`/sys/kernel/btf/vmlinux` only because userspace can't read kernel memory (cached kernel docs in
`SOURCES.md`). TMM is a userspace process, so its equivalent is to carry `.BTF` in its own binary and
read it back from `/proc/self/exe`. `bnk-bake-tools.sh` step **1b** does this:
```bash
PAHOLE=$(substrate/toolchain/build-pahole.sh)          # patched pahole, idempotent build
"$PAHOLE" --lang_exclude=c++ --btf_encode_detached=tmm.btf <tmm64.no_pgo.debug>
objcopy --add-section .BTF=tmm.btf --set-section-flags .BTF=readonly,data \
        tmm64.no_pgo tmm64.no_pgo.embedded
```
- **`build-pahole.sh`** builds pahole (dwarves v1.29) with a one-line patch mapping the `_Atomic`
  qualifier → `BTF_KIND_VOLATILE` (BTF has no atomic kind; layout-identical and CO-RE-transparent).
  Patch: `substrate/toolchain/pahole-atomic-qualifier.patch`.
- **`--lang_exclude=c++`** skips the Tcl/STL C++ compilation units BTF can't represent (TMM embeds
  Tcl for iRules). The surface structs are all C and are kept.
- **`objcopy --add-section` preserves the GNU build-id** (verified), so embedding is invisible to the
  arming build-id gate. The BTF travels *inside* the exact binary that runs — it cannot drift. That
  non-drift property is real, and it is what `LS_EMBED_BTF=0` gives up in exchange for the section
  not being there at all.
- **The binary ships with no type information — this is the default since 2026-09-04.** It keeps
  6,711,805 bytes naming 41,710 functions and 16,006 struct layouts out of an image whose binaries
  F5 already ships `stripped`. It requires every program to have been relocated at sign time (step
  4b); a program still carrying `.BTF.ext` is **refused at load with the cause named on the log**,
  which is what makes the default safe rather than merely desirable. `LS_EMBED_BTF=1` restores the
  old behaviour. Measured: `bnk-test-btfless.sh` 6/6 — a shield loads, arms and runs
  (`fired 145,850 → 211,836 in 3 s`) on a binary with 0 bytes of `.BTF`.

### 4b · Build the programs — **and this now has to come AFTER packaging**

```bash
# on the BUILD BOX: clang 18, PREVAIL, the signing key and tmm.btf are all there
TMM_BTF=$HOME/lstools/tmm.btf env/scripts/bnk-build-programs.sh
```

**Why the order became load-bearing (2026-09-04).** It never used to matter: programs were
build-independent, carrying field *names* and being relocated on-box at load. Sign-time relocation
(`02-RESEARCH-PARAMETERS.md` P9) changes that — the stage now reads the **packaged** binary to bake
field offsets and to pin `build_min`/`build_max`, so running it before `bnk-package.sh` produces
artifacts pinned to the *previous* build. They will then be refused at load by the build gate, which
is the gate working correctly and an annoying way to discover a pipeline-order mistake.

So: **`bnk-package.sh` → `bnk-build-programs.sh` → `bnk-bake-tools.sh`.** Packaging re-links the
binary and the build id differs from `make tmm`'s, which is exactly why the programs must be signed
against the packaged one.

> **The circular dependency this creates, and how to get out of it.** `tmm.btf` is derived *inside*
> `bnk-bake-tools.sh` (step 1b, pahole on the debuginfo DEB) — but step 4b now *needs* it, and it
> must be the BTF of the build just packaged, not the previous one. So on a fresh build the order is
> **bake once to produce `tmm.btf`, then build the programs, then bake again**, which pays for a bake
> twice for no reason.
>
> The derivation is not really part of imaging: it is a per-build artifact two other stages consume
> (`gen_type_catalog.py` needs it for `tmmtrace` as well). **It belongs in its own step before the
> program build** — `bnk-bake-tools.sh --btf-only` stops after step 1b for exactly this. Using the
> *previous* build's BTF here is the failure mode to avoid: the offsets would be baked from the wrong
> layout and every gate downstream would pass, because the signature and the proof would both cover
> the wrong-but-consistent bytes. The build gate catches the mismatch only because the range is
> pinned separately.

The run reports which target it read, and refuses to sign a relocated program that has no build
range to bind it to — baked offsets vouched for on every build are a silent wrong-offset load.

### 5 · Bake the image — build artifacts only
```bash
env/scripts/bnk-bake-tools.sh                          # BASE=tmm:local → OUT=tmm:ls
```
`Dockerfile.ls-tools` layers on the base image and installs **only build artifacts**:
- the `.BTF`-embedded binary (over `/usr/bin/tmm64.no_pgo`),
- `hook-index.tsv` (name → entry address + build id; `ls-load.py` arms by name against it),
- `signatures.tsv` (every function's parameter types; from the debuginfo),
- `ls-load.py` (loader client) and `ls_drain` (ring reader).

**No bytecode is baked.** The bake verifies index build-id == binary build-id (arming works) and that
the binary trusts the signing key (loaded programs will be accepted). Bytecode is compiled/verified/
signed independently and arrives over the socket — see `BYTECODE-BUILD.md`.

### 6 · Ship + deploy
```bash
# build box: save + push (id_datpush)
docker save tmm:ls -o /tmp/tmm-ls.tar
scp -i ~/.ssh/id_datpush /tmp/tmm-ls.tar starin@10.145.40.193:/tmp/
# datkube: kind load fails ("failed to detect containerd snapshotter") — import per node
for n in datkube-control-plane datkube-worker; do
  docker exec -i $n ctr --namespace=k8s.io images import - < /tmp/tmm-ls.tar
done
kubectl delete pods -l app=f5-tmm            # roll onto the new image (imagePullPolicy: Never)
```
Verify the new pods run the new binary and carry `.BTF`:
```bash
POD=$(kubectl get pods -l app=f5-tmm -o name | head -1)
kubectl exec $POD -c f5-tmm -- python3 /usr/share/ls/ls_buildid.py "$(readlink -f /usr/bin/tmm)"
# build-id must equal the baked image's; .BTF section present in /usr/bin/tmm64.no_pgo
```

## Tools

| tool | step | what it does |
|---|---|---|
| `bnk-stage.sh` | 1 | tar the working tree → `~/eob-tmm-staged` (verified by content) |
| `bnk-sync-substrate.sh` | 1 | copy `substrate/*.{c,h}` into the TMM tree `src/base`; invalidate objects |
| `bnk-check-tree-sync.sh` | 1 | both-ways manifest check vs `.tree-expected-delta` |
| `make tmm-gdb` | 2 | the standard TMM debug build + our filelist/whitelist/pad adjustments |
| `bnk-receipt.sh` / `bnk-package.sh` | 3 | packaging provenance the bake requires |
| `substrate/toolchain/build-pahole.sh` | 4 | build the patched pahole (dwarves v1.29 + atomic patch) |
| `bnk-bake-tools.sh` | 4–5 | derive+embed `.BTF`, generate hook-index/signatures, bake artifacts-only image |
| `ctr … images import` per node | 6 | load the image into `kind` (the `kind load` workaround) |

## The 5-byte pad is required

`-fpatchable-function-entry=5,0` is **how we attach**, and it is orthogonal to CO-RE (which is how
the loaded bytecode reads fields). The pad leaves a 5-byte nop sled at every function entry so the
trampoline can overwrite it with a `JMP rel32` (5 bytes) at runtime — that is what makes "arm any
function on a running TMM, no restart" possible. Dropping it would mean a different, worse attach
mechanism (breakpoint/trap, or inline rewriting). It stays.

**Caution:** the pad, the embedded `.BTF`, and arming must all land on the **same binary variant**.
TMM ships several (`tmm64.no_pgo`, `tmm64.debug`, PGO); the debug binary has **no pads** (a "no pad"
arming failure has shipped repeatedly). The Dockerfile repoints `/usr/bin/tmm` at the padded
`tmm.default` → `tmm64.no_pgo`, and that is the binary the `.BTF` is embedded in.

## Build assumptions (factored in)

- **The build must emit DWARF** (`tmm-debuginfo`, via `make tmm-gdb`). A stripped release build → no
  BTF → no CO-RE.
- **BTF generation is pinned-toolchain-sensitive** — pahole choked on `_Atomic` and C++ references; a
  clang/toolchain bump can surface new DWARF forms. Re-validate on any toolchain change (rule 5).
- **Embed on the build box, not in the image** — `objcopy`/binutils are on the build box; a
  data-plane container may not have them.
- **Struct layout is ABI-stable** across PGO/`-O` variants (relocator offsets match the `pahole -C`
  oracle). *Risk not yet triggered:* LTO could drop/merge types — revisit if a build enables it.
