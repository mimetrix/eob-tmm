#!/bin/sh
# Strip the debug binary out of a built TMM image. RUNS ON THE BUILD BOX.
#
#   bnk-strip-debug.sh <src-tag> [dst-tag]        default dst = <src-tag>-stripped
#
# WHY. CORRECTED 2026-09-04 --- the original reason given here was WRONG and is kept visible
# rather than reworded. It said "76 MB of symbols". Measured against the PRISTINE F5 image
# (tmm-img:v10.207.3-HEAD.b13f8f034e), both binaries are ELF executables, `stripped`, with
# symtab FUNC: 0, no .debug_* sections and no .BTF:
#
#     tmm64.debug   76,019,416  stripped  build id 1f7b70d0...
#     tmm64.no_pgo  57,107,456  stripped  build id 269b5d25...   <-- the one TMM runs
#
# tmm64.debug is a SECOND STRIPPED EXECUTABLE from a different build configuration (unoptimised,
# hence 76 MB vs 57 MB), named for its build config, not for debug info it does not carry.
# F5 ships NO symbols and NO DWARF. So there is no symbol disclosure to remove.
#
# The real reason to remove it: it is a duplicate copy of every function --- 117,852 unwind
# records vs the running binary's 72,142 --- compiled differently, at different addresses, and
# WITHOUT our entry pads. That is ROP-gadget surface and a cross-build diffing aid. Lesser than
# symbols would have been, still worth deleting, and 76 MB of executable nothing references has
# no business in an appliance image. Nothing on the data path needs it.
#
# WHY AN OVERLAY RATHER THAN A PACKAGING CHANGE. The debug binary is installed by F5's
# docker_build/Dockerfile.runtime. Editing that file would make it a FOURTH modified F5 file,
# and this repo claims exactly three (filelist + the two globals whitelists) in several places.
# So this removes the file in a layer of our own instead. Be honest about the difference:
#
#   * the file becomes UNREADABLE in the running container --- the disclosure goal is met;
#   * the bytes remain in the lower layer --- image and registry SIZE do not shrink.
#
# The production fix is one line in Dockerfile.runtime (recorded in 4.1). This is the lab
# answer that costs nothing else.
#
# WHY IT CHECKS BEFORE DELETING. Dockerfile.runtime line ~54 does
#     if test -f /usr/bin/tmm.debug; then ln -sf /usr/bin/tmm.debug /usr/bin/tmm; fi
# so on an image built WITH a debug binary present, /usr/bin/tmm can point AT it. Removing it
# there would leave the entrypoint dangling --- a bricked image that looks fine until it runs.
# So resolve /usr/bin/tmm first and refuse if it lands on a debug binary.
set -e

SRC="${1:?usage: bnk-strip-debug.sh <src-tag> [dst-tag]}"
DST="${2:-${SRC}-stripped}"

echo "== 1. what does /usr/bin/tmm actually resolve to in $SRC? =="
RESOLVED=$(docker run --rm --entrypoint sh "$SRC" -c 'readlink -f /usr/bin/tmm 2>/dev/null' || true)
echo "  /usr/bin/tmm -> ${RESOLVED:-<unresolvable>}"
case "$RESOLVED" in
  *debug*)
    echo "  *** REFUSING: the entrypoint resolves to a DEBUG binary."
    echo "      Removing it would brick the image. Rebuild so tmm resolves to tmm64.no_pgo first."
    exit 1 ;;
  "")
    echo "  *** REFUSING: cannot resolve /usr/bin/tmm --- not deleting anything on a guess."
    exit 1 ;;
esac

echo "== 2. what is there to remove? =="
docker run --rm --entrypoint sh "$SRC" -c \
  'ls -la /usr/bin/*debug* 2>/dev/null | awk "{printf \"  %12d  %s\n\", \$5, \$9}"' || true

echo "== 3. build the stripped layer =="
printf 'FROM %s\nRUN rm -f /usr/bin/tmm64.debug /usr/bin/tmm.debug /usr/bin/tmm64.debug.SHA256SUM\n' \
    "$SRC" | docker build -q -t "$DST" - >/dev/null
echo "  built $DST"

echo "== 4. VERIFY --- symbols gone, entrypoint intact =="
docker run --rm --entrypoint sh "$DST" -c '
  n=$(ls /usr/bin/*debug* 2>/dev/null | wc -l)
  echo "  debug artifacts remaining : $n   (want 0)"
  r=$(readlink -f /usr/bin/tmm 2>/dev/null)
  echo "  /usr/bin/tmm -> ${r:-<BROKEN>}"
  test -x "$r" && echo "  entrypoint is present and executable  (ok)" \
               || { echo "  *** ENTRYPOINT BROKEN --- do not ship $DST"; exit 1; }
  nm "$r" >/dev/null 2>&1 && echo "  note: the running binary still has its own symbol table" \
                          || echo "  running binary is stripped of symbols too"
'
echo
echo "== ready: $DST =="
echo "  the 76 MB debug binary is no longer readable in the container (disclosure goal met);"
echo "  image size is unchanged because the bytes remain in the lower layer. For the size win"
echo "  too, remove it in docker_build/Dockerfile.runtime --- see engine-hard-problems.md 4.1."
