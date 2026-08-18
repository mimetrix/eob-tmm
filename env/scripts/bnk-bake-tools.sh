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
REPO="${REPO:-$HOME/eob-tmm}"
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
echo "=== 3. assemble the build context"
cp "$REPO/env/scripts/ls-load.py" "$CTX/ls-load.py"
[ -x "$CTX/ls_drain" ] || fail "no ls_drain in $CTX.
    Build it: gcc -O2 -Wall -Wextra -Werror -static -o $CTX/ls_drain drain/ls_drain.c
    STATIC on purpose --- the container's libc is not ours to rely on."
ls "$CTX"/shields/*.bpf.o >/dev/null 2>&1 || fail "no verified programs in $CTX/shields.
    Compile with clang -O2 -target bpf and run PREVAIL over each before baking one in."
cp "$REPO/env/docker/Dockerfile.ls-tools" "$CTX/Dockerfile"
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
  echo "  programs        : $(ls /usr/share/ls/*.bpf.o 2>/dev/null | wc -l)"
'

echo
echo "  Next: bnk-ship-image.sh verify $OUT 'shape disagrees with the'"
echo "        docker save $OUT | ssh -i ~/.ssh/id_datpush <datkube> 'cat > /tmp/$OUT.tar'"
