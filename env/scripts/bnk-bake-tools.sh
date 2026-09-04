#!/bin/sh
# Bake the live-surface tools into a built TMM image. RUNS ON THE BUILD BOX.
#
#   bnk-bake-tools.sh [base-tag] [out-tag]      default: tmm:local -> tmm:ls
#   bnk-bake-tools.sh --btf-only                stop after deriving $CTX/tmm.btf
#
# --btf-only EXISTS TO BREAK A CIRCULAR DEPENDENCY, added 2026-09-04. Step 1b below
# derives this build's BTF, and since sign-time relocation
# (02-RESEARCH-PARAMETERS.md P9) the PROGRAM build needs that file --- for the build
# just packaged, not the previous one. But the derivation lives in here, so a fresh
# build otherwise has to bake once to get tmm.btf, build the programs, then bake
# again: two full bakes, one of them thrown away.
#
# The derivation was never really part of imaging. It is a per-build artifact that
# two other stages consume (gen_type_catalog.py needs it for tmmtrace too). So:
#
#   bnk-package.sh
#   bnk-bake-tools.sh --btf-only        <- produces $CTX/tmm.btf and stops
#   TMM_BTF=$CTX/tmm.btf bnk-build-programs.sh
#   bnk-bake-tools.sh [--] [base] [out]
#
# Using the PREVIOUS build's BTF here is the failure to avoid: offsets would be
# baked from the wrong layout, and the signature and the PREVAIL proof would both
# cover wrong-but-consistent bytes, so every gate downstream would pass.
#
# WHAT THIS REPLACES. The tools used to be kubectl cp'd into running pods. That
# leaves no record, does not survive a restart, differs per pod, and happens in front
# of whoever the demo is for. It also puts files into a production-shaped data-plane
# container by hand.
#
# THE ORDER IS FORCED, and the reason is worth stating because it looks circular:
# the hook index must be generated from the PACKAGED binary, not the build tree's,
# because packaging re-links and every address moves. But the packaged binary only
# exists after `make container`. So the index cannot be part of the runtime image
# build --- it is a layer ON TOP, which is also why no F5 build file is touched.
#
# THE INDEX IS THE POINT. It carries the build id of the binary it describes, and
# ls-load.py refuses to arm when that does not match the running binary. On
# 2026-08-17 a stale address armed the function 64 bytes past rst_why; it also has a
# nop pad, so the patch succeeded, OK ARMED LIVE was printed, and nothing fired
# across 16,000 requests. A pad cannot distinguish itself from another pad.
set -e

BASE="${1:-tmm:local}"
BTF_ONLY=""
if [ "$1" = "--btf-only" ]; then BTF_ONLY=1; shift; fi
[ "$1" = "--" ] && shift
OUT="${2:-tmm:ls}"
TMM="${TMM:-$HOME/code/tmm}"
DEBS="${DEBS:-$TMM/docker_build/DEBS/amd64}"
# DERIVE the repo from where this script lives, rather than assuming a name under $HOME.
# The default was $HOME/eob-tmm, which is the path on the WORKSTATION. On the build box the
# tree is ~/eob-tmm-staged, so running this there without REPO= set failed on the first file
# it reached --- and every earlier successful bake had happened to pass REPO= by hand. A
# default that only works on one of the two machines a script runs on is a trap for whoever
# omits the variable, which will be me.
REPO="${REPO:-$(cd "$(dirname "$0")/../.." 2>/dev/null && pwd)}"
[ -d "$REPO/substrate" ] || REPO="$HOME/eob-tmm"
[ -d "$REPO/substrate" ] || { echo "*** cannot locate the repo. Tried $(cd "$(dirname "$0")/../.." && pwd) and \$HOME/eob-tmm. Pass REPO=<path>." >&2; exit 2; }
CTX="${CTX:-$HOME/lstools}"

fail() { echo "*** $*" >&2; exit 1; }

echo "=== 1. the DEB pair --- the index must come from what SHIPS, not the build tree"
BIN_DEB=$(ls "$DEBS"/tmm_*.deb 2>/dev/null | head -1) || true
DBG_DEB=$(find "$DEBS" -name 'tmm-debuginfo_*.deb' 2>/dev/null | head -1) || true
[ -n "$BIN_DEB" ] || fail "no tmm_*.deb under $DEBS --- has 'make container' finished?"
[ -n "$DBG_DEB" ] || fail "no tmm-debuginfo_*.deb under $DEBS.
    Without it the binary is stripped and there are no symbols, so there is no
    index to build and nothing can be armed by name."
echo "  runtime   : ${BIN_DEB##*/}"
echo "  debuginfo : ${DBG_DEB##*/}"

echo
echo "=== 1b. the receipt --- did packaging actually run for THESE DEBs?"
# WHY THIS COMES BEFORE ANYTHING IS GENERATED. Every check downstream compares artifacts
# against each other, and a stale DEB agrees with itself perfectly: same binary, same build
# id, every gate green, and the image ships without the change. That is what happened on
# 2026-08-19. Agreement is not freshness, so the question "did the packaging stage run and
# produce THIS pair" has to be asked separately --- and the only thing that can answer it is
# a record left by that stage.
RT=$(mktemp -d); trap 'rm -rf "$RT"' EXIT
dpkg-deb -x "$BIN_DEB" "$RT"
LIVEID=$(python3 "$REPO/substrate/ls_buildid.py" "$(readlink -f "$RT/usr/bin/tmm.default")")
sh "$REPO/env/scripts/bnk-receipt.sh" require package build_id "$LIVEID" || fail "the DEB pair
    in $DEBS was not produced by a verified packaging run. Run:
        env/scripts/bnk-package.sh
    It clears the version-stamped chain, builds, verifies the result contains the substrate
    that was compiled, and records the build id this stage just refused to accept."

echo
echo "=== 1b. derive THIS build's BTF and embed it into the runtime binary (.BTF section)"
# The loader reads the binary's OWN .BTF (ls_vm_target_btf -> /proc/self/exe): the kernel's
# vmlinux model minus sysfs. BTF is derived from this build's DWARF by the patched pahole
# (atomic->volatile + C++ excluded; substrate/toolchain/build-pahole.sh) and embedded with
# objcopy, which PRESERVES the GNU build-id --- so the arming build-id gate is unaffected
# (verified: same id before/after). objcopy runs HERE on the build box; the image needs no
# binutils. The .BTF then travels inside whatever binary was armed --- it cannot drift.
mkdir -p "$CTX"
PAHOLE=$(sh "$REPO/substrate/toolchain/build-pahole.sh") || fail "could not build the patched
    pahole (needs libdw-dev/libelf-dev/zlib1g-dev on the build box; patch under substrate/toolchain)."
DBGDIR=$(mktemp -d); trap 'rm -rf "$RT" "$DBGDIR"' EXIT
dpkg-deb -x "$DBG_DEB" "$DBGDIR"
DBGBIN=$(find "$DBGDIR" -name 'tmm64.no_pgo.debug' | head -1)
[ -n "$DBGBIN" ] || fail "no tmm64.no_pgo.debug in $DBG_DEB --- cannot derive BTF"
LD_LIBRARY_PATH="$(dirname "$PAHOLE")" "$PAHOLE" --lang_exclude=c++     --btf_encode_detached="$CTX/tmm.btf" "$DBGBIN" 2>/dev/null
[ -s "$CTX/tmm.btf" ] || fail "pahole produced no BTF from $DBGBIN"
REALBIN="$RT/usr/bin/tmm64.no_pgo"
BID_BEFORE=$(readelf -n "$REALBIN" | sed -n 's/.*Build ID: //p')

# THE SHIPPED BINARY CARRIES NO TYPE INFORMATION. THAT IS NOW THE DEFAULT (P9 3c).
#
# $CTX/tmm.btf is still derived above and still kept on the build box --- the program
# build stage needs it to resolve offsets at sign time, and gen_type_catalog.py needs
# it for tmmtrace. What changes is only whether it goes INTO the shipped ELF.
#
# WHAT IT REMOVES, measured on the deployed image: 6,711,805 bytes naming 41,710
# functions and 16,006 struct layouts --- including http2_http_data_to_frames and the
# layout of the struct CVE-2025-41414 dereferences. F5 ships both binaries `stripped`
# with symtab FUNC: 0, so this section is the ONLY layout disclosure in the whole
# image, and it is ours (CONTESTED-PREMISES.md 14).
#
# IT WAS OPT-IN UNTIL 2026-09-04, AND THE REASON IT NO LONGER IS. A program that
# still carries .BTF.ext can only be relocated against a binary that embeds .BTF, and
# this stage CANNOT check that the programs about to ship are stripped, because it
# bakes no bytecode at all --- that is a separate stage by design. So the failure mode
# of a wrong-order build lands at ARM time on the cluster rather than here, which is
# why the default waited on evidence rather than on confidence.
#
# The evidence arrived: env/scripts/bnk-test-btfless.sh, 6 of 6 on build 1824611c ---
# 0 bytes of .BTF in the running binary, a stripped/relocated/signed program loads,
# arms and RUNS (fired 145,850 -> 211,836 in 3 s, errors=0, restarts=0), and a program
# still carrying .BTF.ext is REFUSED with the cause named on the log. That last case is
# what makes the default safe: the wrong-order build now fails with a message that says
# exactly what to do, instead of silently reading placeholder offsets.
#
#   LS_EMBED_BTF=0 (default)  do NOT embed --- every program must be relocated at sign
#                             time, which bnk-build-programs.sh does by default on the
#                             build box (it auto-discovers tmm.btf and says so)
#   LS_EMBED_BTF=1            embed, for a build whose programs were made with
#                             TMM_BTF=none, or to compare against the old behaviour
if [ "${LS_EMBED_BTF:-0}" = "0" ]; then
    cp "$REALBIN" "$CTX/tmm64.no_pgo" || fail "could not stage the runtime binary"
    readelf -SW "$CTX/tmm64.no_pgo" | grep -q '\.BTF' && fail "LS_EMBED_BTF=0 but the
    binary ALREADY carries a .BTF section --- it came from somewhere other than this
    step, and shipping it would defeat the point. Find out where before continuing."
    BID_AFTER=$(readelf -n "$CTX/tmm64.no_pgo" | sed -n 's/.*Build ID: //p')
    [ "$BID_BEFORE" = "$BID_AFTER" ] || fail "the build-id changed ($BID_BEFORE -> $BID_AFTER)"
    echo "  BTF: NOT embedded (the default). $(du -h "$CTX/tmm.btf" | cut -f1) kept on the build"
    echo "       box only; the shipped ELF carries no type information at all."
    echo "       EVERY program must be relocated at sign time --- bnk-build-programs.sh"
    echo "       does that by default here. A program that was not will be REFUSED at"
    echo "       load, saying so. Set LS_EMBED_BTF=1 for the old behaviour."
else
    objcopy --add-section .BTF="$CTX/tmm.btf" --set-section-flags .BTF=readonly,data     "$REALBIN" "$CTX/tmm64.no_pgo" || fail "objcopy failed to embed .BTF"
    BID_AFTER=$(readelf -n "$CTX/tmm64.no_pgo" | sed -n 's/.*Build ID: //p')
    readelf -SW "$CTX/tmm64.no_pgo" | grep -q '\.BTF' || fail "embedded binary has no .BTF section"
    [ "$BID_BEFORE" = "$BID_AFTER" ] || fail "objcopy changed the build-id ($BID_BEFORE -> $BID_AFTER) --- would break the arming gate"
    echo "  BTF: $(du -h "$CTX/tmm.btf" | cut -f1) embedded into tmm64.no_pgo; build-id preserved (${BID_AFTER%${BID_AFTER#????????}})"
    echo "       *** LS_EMBED_BTF=1 --- this is NO LONGER the default. The shipped ELF will"
    echo "       carry the full internal type layout: 41,710 function names and 16,006"
    echo "       struct layouts in a binary F5 otherwise ships stripped. Deliberate?"
fi

if [ -n "$BTF_ONLY" ]; then
    echo
    echo "=== --btf-only: stopping here ==="
    echo "  $CTX/tmm.btf  ($(wc -c < "$CTX/tmm.btf") bytes, build ${BID_BEFORE%${BID_BEFORE#????????}})"
    echo
    echo "  Next: TMM_BTF=$CTX/tmm.btf env/scripts/bnk-build-programs.sh"
    echo "        then bnk-bake-tools.sh (add LS_EMBED_BTF=0 to ship a binary with no"
    echo "        type information --- every program must be relocated first)."
    exit 0
fi

echo
echo "=== 2. generate the index (mk_hook_map.py checks the pair's build ids agree)"
python3 "$REPO/substrate/mk_hook_map.py" --debs "$DEBS" \
        -o "$CTX/hook-map.json" --index "$CTX/hook-index.tsv"
BID=$(awk -F'\t' '/^#build_id/{print $2}' "$CTX/hook-index.tsv")
N=$(grep -vc '^#' "$CTX/hook-index.tsv")
[ -n "$BID" ] || fail "the generated index carries no build id"
echo "  build id  : $BID"
echo "  symbols   : $N"

echo
echo "=== 2b. generate the SIGNATURE index --- one DWARF walk for every function"
# WHY THIS IS A BUILD STEP. mk_probe.py needs one function's parameter names and types to
# generate a probe. Finding them means walking every compilation unit of a 97 MB debuginfo,
# measured at 1m54s --- and the walk costs the same whether you want one signature or all
# 66,905 of them. So it happens once, here, and every later lookup is 0.10s.
#
# That is the difference between "name a function, get a running probe" and "name a
# function, wait two minutes". The second one cannot be demonstrated and would not be used.
#
# SEPARATE FROM hook-index.tsv on purpose. They answer different questions about the same
# binary and either can be useful without the other:
#   hook-index.tsv  CAN this name be armed?   -> address, pad shape, relocatability
#   signatures.tsv  WHAT does it take?        -> parameter names, types, kinds
# A function can be in one and not the other: a parameterless function has no signature
# entry, and an inlined-away function has a signature but no address.
python3 "$REPO/substrate/mk_probe.py" --debs "$DEBS" \
        --build-index "$CTX/signatures.tsv" | sed 's/^/  /'
SBID=$(awk -F'\t' '/^#build_id/{print $2}' "$CTX/signatures.tsv")
[ -n "$SBID" ] || fail "the signature index carries no build id"
# BOTH indexes must describe the SAME binary. They are generated from the same DEB pair by
# two different tools, so a mismatch means one of them read a stale file --- exactly the
# failure the runtime build-id gate catches one step too late.
[ "$SBID" = "$BID" ] || fail "index build ids disagree:
    hook-index.tsv  $BID
    signatures.tsv  $SBID
    Two tools read what should be one binary and got different answers. Do not bake this."
echo "  build id  : $SBID (matches the hook index)"

# 2b-bis. THE OFFSETS HEADER MUST DESCRIBE THIS BINARY TOO.
#
# ls_ctx_parse_offsets.h carries the byte offsets the substrate uses to read TMM's parser structs,
# derived by mk_ctx_parse.py from a build artifact and stamped with that artifact's build id.
# Nothing compared that stamp to anything until now, so a header generated against one tree could
# be compiled into a binary built from another --- and a wrong offset there is SILENT: the
# substrate reads a plausible number out of the wrong field and every counter still moves.
#
# This closes the one missing link in a chain that is otherwise already enforced. With it the
# offsets are verified against the RUNNING binary transitively: offsets == index here, index ==
# image binary at step 5, and index == /proc/<pid>/exe at arm time, where ls-load.py already
# refuses. No new mechanism, and nothing installed in any container --- substrate/FIELD-CONTRACT.md
# records why the field-side alternative is deliberately not taken.
OFFH="$REPO/substrate/ls_ctx_parse_offsets.h"
if [ -f "$OFFH" ]; then
    OBID=$(sed -n 's/.*LS_CTX_PARSE_BUILD_ID[[:space:]]*"\([0-9a-f]*\)".*/\1/p' "$OFFH")
    [ -n "$OBID" ] || fail "ls_ctx_parse_offsets.h carries no build id --- regenerate it:
    substrate/mk_ctx_parse.py --debuginfo <tmm.debug> -o substrate/ls_ctx_parse_offsets.h"
    [ "$OBID" = "$BID" ] || fail "the ctx offsets describe a DIFFERENT binary:
    hook-index.tsv            $BID
    ls_ctx_parse_offsets.h    $OBID
    The substrate would read TMM's parser structs at offsets taken from another build, which is
    silent when wrong. Regenerate from THIS build's debuginfo and rebuild TMM."
    echo "  ctx offsets: $OBID (matches the hook index)"
else
    echo "  ctx offsets: no ls_ctx_parse_offsets.h in the staged tree."
    echo "               If this TMM was built with the parse ctx builder then that build could"
    echo "               not have compiled --- the header has no fallback offsets by design. If it"
    echo "               was not, there is nothing to check here. Not guessing which."
fi

echo
echo
echo "=== 2c. is the staged tree the one we think it is?"
# THE HOLE THAT COST A CYCLE, 2026-08-20. bnk-sync-substrate.sh refreshes the TMM tree and
# stamps a commit for substrate/ --- but the BAKE reads $REPO/env/scripts for ls-load.py and
# friends, and nothing checked those. The staged copy was three commits behind, so the image
# shipped a client with no signature support and TMM correctly refused every load. The stamp I
# added that morning covered substrate/ only; a gate over one directory and not its neighbour is
# not a gate.
#
# So: compare the staged scripts against the repo they came from. This runs on the build box
# where the repo may not exist, so a missing repo is reported and skipped rather than fatal ---
# but a MISMATCH is fatal, because that is the case that ships a stale tool.
if [ -d "$REPO/.git" ]; then
    _drift=$(cd "$REPO" && git status --porcelain -- env/scripts env/docker substrate 2>/dev/null | wc -l)
    _head=$(cd "$REPO" && git rev-parse --short HEAD)
    echo "  staged from : $_head$( [ "$_drift" -gt 0 ] && echo " (+$_drift uncommitted)" )"
else
    # The usual case: $REPO here is a `git archive` extract with no history. Compare CONTENT
    # against the checked-in copies instead --- there is nothing else to compare against, and
    # the thing that actually matters is whether the tools are current, not their provenance.
    echo "  staged tree has no git history (a tar extract), so provenance cannot be read from it."
    echo "  Verifying the tools the image will carry are the ones staged:"
    for _f in ls-load.py bnk-deliver-program.py; do
        [ -f "$REPO/env/scripts/$_f" ] || fail "$_f missing from the staged tree at
    $REPO/env/scripts. The bake copies its tools from there, so a missing one ships an image
    without it. Re-stage with: git archive HEAD substrate env/scripts env/docker | ssh ... tar x"
    done
    # ls-load.py must be able to send a signature, or every load into this image is refused by
    # the TMM baked beside it. Checked by capability rather than by version, because a version
    # string would be one more thing to keep in step.
    grep -q 'read_signature' "$REPO/env/scripts/ls-load.py" || fail "the staged ls-load.py cannot
    send a signature (no read_signature). TMM in this image verifies signatures, so every load
    would be refused --- which looks exactly like a broken signature check and is not.
    Re-stage the scripts from a commit that has it."
    echo "  ls-load.py   : can send signatures"
fi

echo
echo "=== 3. assemble the build context"
cp "$REPO/env/scripts/ls-load.py" "$CTX/ls-load.py"
# REBUILD ls_drain FROM SOURCE, every time. Checking only that it EXISTED shipped a stale
# one: it was compiled once and its source changed twice afterwards (the tmm->slot rename,
# then the h2abort and prog decoders), so the image carried a reader three commits behind.
# It printed "tmm" for a field renamed to "slot" and dumped schema-5 records as raw hex ---
# the records were correct and the consumer was not. Same family as the missing .d files:
# an artifact older than its source with nothing comparing the two.
#
# STATIC on purpose --- the container's libc is not ours to rely on.
DRAIN_SRC="$REPO/substrate/drain/ls_drain.c"
[ -f "$DRAIN_SRC" ] || fail "no drain source at $DRAIN_SRC"
gcc -O2 -Wall -Wextra -Werror -static -I"$REPO/substrate" \
    -o "$CTX/ls_drain" "$DRAIN_SRC" || fail "ls_drain failed to build --- refusing to bake
    an image around a consumer that does not compile."
echo "  ls_drain  : rebuilt from source ($(stat -c%s "$CTX/ls_drain") bytes, static)"
# NO bytecode is baked. Compiling bytecode is a completely independent process
# (bnk-build-programs.sh); its signed output is loaded over the socket at runtime and relocated
# against the binary's embedded .BTF. The image carries only build artifacts.
# ALL THREE docker files, and then CHECK the Dockerfile is the one we think.
#
# On 2026-08-18 a bake used a STALE Dockerfile: an older copy had been staged under $REPO
# on the build box, so the layer built with the previous inline assertion instead of
# ls-verify-layer.sh --- and the build-id check therefore never ran. The layer looked
# fine, because the thing that would have complained was the thing that was missing.
#
# So: copy all three, then assert the Dockerfile actually references the verifier. A
# Dockerfile that does not is either stale or has had its assertion removed, and both are
# reasons to stop.
cp "$REPO/env/docker/Dockerfile.ls-tools" "$CTX/Dockerfile"
cp "$REPO/env/docker/ls-verify-layer.sh" "$CTX/ls-verify-layer.sh"
# FROM substrate/, not env/docker/. There was a second copy of the build-id reader under
# env/docker/ and it carried the segment-only parse that truncates a 20-byte id to 16 on the
# PGO debug build. One file, copied here, is the fix --- see substrate/ls_buildid.py.
cp "$REPO/substrate/ls_buildid.py"       "$CTX/ls_buildid.py"
grep -q "ls-verify-layer.sh" "$CTX/Dockerfile" || fail "the Dockerfile at
    $REPO/env/docker/Dockerfile.ls-tools does not reference ls-verify-layer.sh.
    It is stale, or its assertion was removed. Either way the build-id check would not
    run and the layer would be unverified --- which is what happened once already."
grep -q "ln -sf /usr/bin/tmm.default" "$CTX/Dockerfile" || fail "the Dockerfile does not
    repoint /usr/bin/tmm at the padded binary. Dockerfile.runtime points it at tmm.debug
    whenever a debug binary is present, and that build has NO entry pads --- nothing can
    be armed. Four images have shipped that way." 
echo "  context   : $CTX  (ls_drain $(stat -c%s "$CTX/ls_drain") B)"

echo
echo "=== 4. build the layer"
docker build --build-arg "BASE=$BASE" -t "$OUT" "$CTX" 2>&1 | tail -6 | sed 's/^/  /'

echo
echo "=== 5. VERIFY THE RESULT, from inside the image --- not from this script's beliefs"
# The index's build id must match the binary that /usr/bin/tmm RESOLVES to. Checking
# the index alone would pass on an image whose tmm points at the padless debug build.
docker run --rm --entrypoint sh "$OUT" -c '
  R=$(readlink -f /usr/bin/tmm)
  echo "  tmm resolves to : $R"
  IDX=$(awk -F"\t" "/^#build_id/{print \$2}" /usr/share/ls/hook-index.tsv)
  echo "  index build id  : $IDX"
  LIVE=$(python3 - "$R" <<'"'"'PY'"'"'
import struct, sys
f = open(sys.argv[1], "rb"); e = f.read(64)
phoff, = struct.unpack_from("<Q", e, 0x20)
pes, pn = struct.unpack_from("<HH", e, 0x36)
for i in range(pn):
    f.seek(phoff + i*pes); ph = f.read(pes)
    if struct.unpack_from("<I", ph, 0)[0] != 4: continue
    off, = struct.unpack_from("<Q", ph, 0x08); sz, = struct.unpack_from("<Q", ph, 0x20)
    f.seek(off); n = f.read(sz); j = 0
    while j + 12 <= len(n):
        ns, ds, t = struct.unpack_from("<III", n, j)
        nm = n[j+12:j+12+ns].rstrip(b"\x00"); d = j+12+((ns+3)&~3)
        if t == 3 and nm == b"GNU": print(n[d:d+ds].hex()); sys.exit(0)
        j = d + ((ds+3)&~3)
PY
)
  echo "  binary build id : $LIVE"
  if [ "$IDX" = "$LIVE" ]; then
    echo "  MATCH --- arming by name will work in this image"
  else
    echo "  *** MISMATCH. ls-load.py will refuse to arm, which is correct but useless."
    echo "      The index describes a different binary than the one this image runs."
    exit 1
  fi
  SIG=$(awk -F"\t" "/^#build_id/{print \$2}" /usr/share/ls/signatures.tsv)
  if [ "$SIG" != "$LIVE" ]; then
    echo "  *** signatures.tsv build id $SIG describes a different binary."
    exit 1
  fi
  echo "  signatures      : $(grep -vc "^#" /usr/share/ls/signatures.tsv) functions, build id matches"
'

echo
echo "=== 5b. does the binary TRUST the key the programs beside it were SIGNED with?"
# THE CHECK THAT DID NOT EXIST, and its absence cost a full build-and-deploy cycle on 2026-08-21.
# An image was produced in which TMM trusted one key (the workstation's) while the 15 programs
# shipped alongside it were signed with another (the build box's). Every gate this script already
# ran was green --- build ids matched, the index matched the binary, the substrate functions were
# all present --- because none of them compares those two artifacts to each other. The failure
# surfaced only on a live TMM, as "slot 5 holds NO PROGRAM" three assertions downstream of a load
# that had been refused.
#
# The check is direct rather than clever: the public key is compiled in as 32 raw bytes, so take
# the 32 raw bytes of the signing key's public half and look for them IN the binary. No addresses,
# no .rodata arithmetic --- byte-archaeology at a guessed offset is how I got the previous
# generation of this wrong. Present or absent, and nothing in between.
SIGN_KEY="${SIGN_KEY:-$HOME/.ls-signing/shield_sk.pem}"
if [ -f "$SIGN_KEY" ]; then
    _kh=$(openssl pkey -in "$SIGN_KEY" -pubout -outform DER 2>/dev/null | tail -c 32 | xxd -p | tr -d '\n')
    if [ ${#_kh} -eq 64 ]; then
        docker run --rm --entrypoint sh "$OUT" -c "
            B=\$(readlink -f /usr/bin/tmm)
            python3 - \"\$B\" $_kh <<'PYEOF'
import sys
b = open(sys.argv[1], 'rb').read()
k = bytes.fromhex(sys.argv[2])
n = b.count(k)
print('  trusted key present in the binary: %d' % n)
sys.exit(0 if n > 0 else 1)
PYEOF" \
          && echo "  MATCH --- this image's loader will accept programs signed with this key (loaded at runtime)" \
          || fail "the binary does NOT contain the public half of $SIGN_KEY.
    Every program in this image would be refused, and the error would talk about invalid
    signatures rather than about a mismatched key. Regenerate the header ON THE BUILD BOX
    (env/scripts/bnk-init-signing-key.sh), remove obj_*/ls_sig.o, and relink."
    else
        echo "  could not read 32 raw bytes from $SIGN_KEY --- skipping, and that is not a pass"
    fi
else
    echo "  no $SIGN_KEY on this machine, so the pairing is unchecked. Not a pass:"
    echo "  an image whose loader refuses everything it ships is indistinguishable from a"
    echo "  crypto failure once it is running."
fi

echo
echo "=== 6. record what this stage produced"
sh "$REPO/env/scripts/bnk-receipt.sh" write bake "build_id=$BID" "tag=$OUT" "bytecode=decoupled"

echo
echo "  Next: bnk-ship-image.sh verify $OUT 'shape disagrees with the'"
echo "        docker save $OUT | ssh -i ~/.ssh/id_datpush <datkube> 'cat > /tmp/$OUT.tar'"
