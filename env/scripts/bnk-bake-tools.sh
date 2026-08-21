#!/bin/sh
# Bake the live-surface tools into a built TMM image. RUNS ON THE BUILD BOX.
#
#   bnk-bake-tools.sh [base-tag] [out-tag]      default: tmm:local -> tmm:ls
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
echo "=== 2. generate the index (mk_hook_map.py checks the pair's build ids agree)"
mkdir -p "$CTX/shields"
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
# EVERY BAKED PROGRAM MUST HAVE ITS SIGNATURE. A program without one is refused at load, so
# baking it produces an image whose own programs do not work --- which looks like a broken
# signature check rather than a missing file.
_no_sig=0
for _o in "$CTX"/shields/*.bpf.o; do
    [ -f "$_o" ] || continue
    [ -f "${_o%.o}.sig" ] || { echo "  *** ${_o##*/} has no signature"; _no_sig=$((_no_sig + 1)); }
done
[ "$_no_sig" -eq 0 ] || fail "$_no_sig baked program(s) have no signature. Every load is
    signature-verified now, so an unsigned program in the image is refused by the TMM that
    ships with it. Re-run bnk-build-programs.sh with SIGN_KEY set."
echo "  programs  : $(ls "$CTX"/shields/*.bpf.o | wc -l) objects, $(ls "$CTX"/shields/*.bpf.sig 2>/dev/null | wc -l) signatures"

ls "$CTX"/shields/*.bpf.o >/dev/null 2>&1 || fail "no verified programs in $CTX/shields.
    Compile with clang -O2 -target bpf and run PREVAIL over each before baking one in."
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
echo "  context   : $CTX  ($(ls "$CTX"/shields/*.bpf.o | wc -l) programs, ls_drain $(stat -c%s "$CTX/ls_drain") B)"

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
  echo "  programs        : $(ls /usr/share/ls/*.bpf.o 2>/dev/null | wc -l)"
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
          && echo "  MATCH --- this image's loader will accept the programs this image ships" \
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
sh "$REPO/env/scripts/bnk-receipt.sh" write bake "build_id=$BID" "tag=$OUT" \
                                      "programs=$(ls "$CTX"/shields/*.bpf.o | wc -l)"

echo
echo "  Next: bnk-ship-image.sh verify $OUT 'shape disagrees with the'"
echo "        docker save $OUT | ssh -i ~/.ssh/id_datpush <datkube> 'cat > /tmp/$OUT.tar'"
