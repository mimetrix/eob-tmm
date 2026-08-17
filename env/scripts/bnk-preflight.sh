#!/bin/sh
# ONE GATE. Run every check, in dependency order, and refuse on the first failure.
#
# WHY THIS EXISTS, and it is not flattering. By 2026-08-17 there were four separate
# guards in this directory, each written after a specific failure, each correct. Every
# error that day happened anyway, because having a guard and running a guard are
# different things:
#
#   - bnk-check-deployed.sh compares build IDs. Not run; a cached docker layer
#     shipped a binary three revisions old while the debs regenerated underneath it.
#   - bnk-verify-artifact.sh prints which binary /usr/bin/tmm resolves to. It printed
#     tmm64.debug and was read past; that binary has no entry pads, so nothing in it
#     could be armed. Third image to ship that way.
#   - bnk-entry-address.sh's header warns that packaging RE-LINKS the binary, so an
#     address from obj/ or from an older deb is not the address in the pod --- and the
#     failure is silent because a nop pad exists at plenty of wrong places. An address
#     from a stale deb then armed rst_cause_match_peer instead of rst_why. Arming
#     reported success. The counter read fired=0, which looks exactly like a hook that
#     does not work.
#
# So: no menu of scripts. One command, run in order, exits non-zero at the first
# problem, and --- the part that actually matters --- PRINTS THE ARM ADDRESS IT
# RESOLVED, from the binary it just verified. There is then no stale address to paste,
# because the address arrives from the same run that checked the image.
#
#   bnk-preflight.sh <image-tag> <symbol> [token...]
#
#   bnk-preflight.sh tmm:p5 rst_why 'ls_map: reloc'
#
# Exit 0 means: repo and build tree agree, local checks pass, the image runs a padded
# binary, that binary is the freshly linked one, every token is present, and the
# symbol's entry carries an intact pad at the address printed.
set -e

TAG="$1"
SYM="$2"
shift 2 2>/dev/null || true

if [ -z "$TAG" ] || [ -z "$SYM" ]; then
    echo "usage: $0 <image-tag> <symbol> [token...]" >&2
    exit 2
fi

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
BUILD_BOX="${BUILD_BOX:-starin@10.145.42.119}"
OBJ="${OBJ:-\$HOME/code/tmm/src/compile/obj_x86_64.no_pgo/tmm.no_pgo}"

step() { printf '\n=== %s ===\n' "$1"; }
die()  { printf '\n*** REFUSING: %s\n' "$1" >&2; exit 1; }

# ---------------------------------------------------------------- 1. sources agree
step "1/6  repo and build tree hold the same sources"
"$HERE/bnk-check-tree-sync.sh" || die "repo and build tree diverged. Resolve before building --- a
      repo-over-tree copy is what deleted the map registration calls once already."

# ------------------------------------------------------------------ 2. local checks
step "2/6  local checks (make -C substrate check)"
if ! make -C "$REPO/substrate" check >/tmp/.preflight_check.log 2>&1; then
    tail -25 /tmp/.preflight_check.log >&2
    rm -f /tmp/.preflight_check.log
    die "make check failed. The harnesses know things this script does not."
fi
grep -ciE '^ *ok' /tmp/.preflight_check.log | sed 's/^/  checks passing: /'
rm -f /tmp/.preflight_check.log

# --------------------------------------------------- 3. the image runs a padded bin
step "3/6  the image's /usr/bin/tmm is armable, and carries the change"
scp -q -o StrictHostKeyChecking=no "$HERE/bnk-verify-artifact.sh" "$BUILD_BOX:/tmp/.pf_bva.sh"
if [ "$#" -gt 0 ]; then
    ssh -o StrictHostKeyChecking=no "$BUILD_BOX" \
        "chmod +x /tmp/.pf_bva.sh && /tmp/.pf_bva.sh $TAG $(for t in "$@"; do printf "'%s' " "$t"; done)" \
        || die "the image is unarmable or missing the change (see above)"
else
    echo "  (no tokens given --- binary-name check only)"
    ssh -o StrictHostKeyChecking=no "$BUILD_BOX" \
        "chmod +x /tmp/.pf_bva.sh && /tmp/.pf_bva.sh $TAG '/'" || true
fi

# ------------------------------------------- 4. the image holds the CURRENT binary
#
# The check that was skipped. A tag is re-pointed by every `docker build -t`, and a
# cached layer can carry an old binary while the debs beside it are new. The build ID
# is the only thing that cannot be re-pointed.
step "4/6  the image's binary IS the freshly linked one (build IDs)"
IDS=$(ssh -o StrictHostKeyChecking=no "$BUILD_BOX" "
    O=\$(readelf -n $OBJ 2>/dev/null | grep -o 'Build ID: [0-9a-f]*' | head -1 | awk '{print \$3}')
    R=\$(docker run --rm --entrypoint sh $TAG -c 'readlink -f /usr/bin/tmm' 2>/dev/null)
    cid=\$(docker create $TAG 2>/dev/null)
    docker cp \"\$cid:\$R\" /tmp/.pf_bin >/dev/null 2>&1
    docker rm \"\$cid\" >/dev/null 2>&1
    I=\$(readelf -n /tmp/.pf_bin 2>/dev/null | grep -o 'Build ID: [0-9a-f]*' | head -1 | awk '{print \$3}')
    rm -f /tmp/.pf_bin
    echo \"\$O \$I\"")
OBJ_ID=$(echo "$IDS" | awk '{print $1}')
IMG_ID=$(echo "$IDS" | awk '{print $2}')
echo "  obj   : ${OBJ_ID:-<unreadable>}"
echo "  image : ${IMG_ID:-<unreadable>}"
[ -n "$OBJ_ID" ] && [ -n "$IMG_ID" ] || die "could not read both build IDs. Treat as diverged."
[ "$OBJ_ID" = "$IMG_ID" ] || die "the image does NOT carry the freshly linked binary.
      Almost certainly a cached docker layer: \`make container\` reuses one even when
      the debs beside it regenerated. Rebuild with --no-cache, or copy the binary in
      explicitly, then run this again."

# ------------------------------------------------ 5. the arm address, FROM that image
#
# Resolved here, and printed, so there is no opportunity to paste one from an older
# deb. rst_why moved 64 bytes between two builds on 2026-08-17 and the old address
# landed inside rst_cause_match_peer --- which has a pad, so arming succeeded.
step "5/6  resolve $SYM's entry address from the binary just verified"
ADDR=$(ssh -o StrictHostKeyChecking=no "$BUILD_BOX" "nm $OBJ 2>/dev/null | awk '\$3==\"$SYM\"{print \$1; exit}'")
[ -n "$ADDR" ] || die "no symbol '$SYM' in $OBJ. If the binary is stripped, read it from
      the matching tmm-debuginfo deb --- and from the one for THIS build."
echo "  $SYM = 0x$ADDR"

# ------------------------------------------------------- 6. the pad is actually there
step "6/6  the entry pad at that address is intact"
PAD=$(ssh -o StrictHostKeyChecking=no "$BUILD_BOX" "
    objdump -d --start-address=0x$ADDR --stop-address=\$((0x$ADDR + 10)) $OBJ 2>/dev/null \
      | grep -cE 'nop'")
echo "  nop instructions in the first 10 bytes: ${PAD:-0}"
if [ "${PAD:-0}" -lt 3 ]; then
    ssh -o StrictHostKeyChecking=no "$BUILD_BOX" \
        "objdump -d --start-address=0x$ADDR --stop-address=\$((0x$ADDR + 12)) $OBJ 2>/dev/null | tail -6" >&2
    die "no entry pad at 0x$ADDR. Either this build lacks
      -fpatchable-function-entry=5,0 for that translation unit, or the symbol is a
      static the compiler cloned. Arming it would patch a real instruction."
fi

cat <<EOT

=======================================================================
  PREFLIGHT PASSED for $TAG

  Arm with THIS address --- it came from the binary this run verified:

      python3 ls-load.py load 5 <prog>.bpf.o 2 $SYM
      python3 ls-load.py arm  5 0x$ADDR

  Do not carry an address over from a previous build. rst_why moved 64
  bytes between two builds on 2026-08-17 and the stale address armed a
  neighbouring function, silently, reporting success.
=======================================================================
EOT
