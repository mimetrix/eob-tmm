#!/bin/sh
# Resolve a TMM function's entry address for arming --- from the DEB pair, not the build tree.
#
# THIS IS THE TRAP THIS SCRIPT EXISTS FOR. Packaging RE-LINKS the binary, so the
# address of a function in ~/code/tmm/src/compile/obj_*/tmm.no_pgo is NOT the
# address in the tmm64.no_pgo that ends up in the pod. Arming the build tree's
# address patches whatever happens to live there instead --- and the failure is
# silent, because a nop pad exists at plenty of wrong places too.
#
# So: extract BOTH debs, assert the build IDs match, take the address from the
# debuginfo, and read the bytes back out of the runtime binary. If the build IDs
# disagree, the pair is mismatched and every address below is wrong; the script
# stops rather than printing a plausible number.
#
# Until the hook-map generator exists (scope item 5), this is how a hook's
# address is obtained, and it changes on EVERY rebuild.
#
# usage:  bnk-entry-address.sh [symbol]           (default: the worked-example hook)
#         run on the BUILD BOX, after `make tmm-gdb` and packaging.
set -e

SYM="${1:-http_psm_profile_name_lookup}"
DEBS="${DEBS:-$HOME/code/tmm/docker_build/DEBS/amd64}"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

[ -d "$DEBS" ] || { echo "no DEBS dir at $DEBS (set DEBS=)"; exit 1; }

mkdir -p "$W/bin" "$W/dbg"
(cd "$W/bin" && dpkg-deb -x "$(ls "$DEBS"/tmm_*.deb | head -1)" .)
(cd "$W/dbg" && dpkg-deb -x "$(ls "$DEBS"/tmm-debuginfo_*.deb | head -1)" .)

B="$W/bin/usr/bin/tmm64.no_pgo"
D="$W/dbg/usr/lib/debug/usr/bin/tmm64.no_pgo.debug"
[ -f "$B" ] && [ -f "$D" ] || { echo "expected binaries not in the debs"; exit 1; }

bid() { readelf -n "$1" 2>/dev/null | grep -A1 "Build ID" | tail -1 | tr -d ' \n'; }
if [ "$(bid "$B")" != "$(bid "$D")" ]; then
    echo "*** BUILD IDs DIFFER --- the deb pair is mismatched."
    echo "    binary:    $(bid "$B")"
    echo "    debuginfo: $(bid "$D")"
    echo "    Any address from this pair would be wrong. Rebuild and repackage together."
    exit 1
fi
echo "  build-ids match: $(bid "$B")"

A=$(nm --defined-only "$D" | awk -v s="$SYM" '$3==s {print $1}' | head -1)
[ -n "$A" ] || { echo "*** symbol not found in debuginfo: $SYM"; exit 1; }
echo "  $SYM  entry = 0x$A"
echo
echo "  first 24 bytes as they will be in the pod:"
objdump -d --start-address="0x$A" --stop-address="$((0x$A + 24))" "$B" | tail -6 | sed 's/^/    /'
echo
echo "  Expect 'f3 0f 1e fa' (endbr64) then five 0x90 nops --- that pad is what arming"
echo "  overwrites with 'e8 <rel32>', a call to ls_trampoline_entry. If you see"
echo "  anything else in those five bytes, the function is already armed or the"
echo "  build was made without -fpatchable-function-entry=5,0."
