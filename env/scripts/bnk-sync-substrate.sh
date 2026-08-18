#!/bin/sh
# Copy substrate sources into the TMM build tree, and make sure make NOTICES.
#
# THE BUG THIS EXISTS FOR, observed 2026-08-18. The map-identity fix was a change
# to ls_map_glue.h alone. It was copied to the tree, `bnk-check-tree-sync.sh`
# reported IN SYNC, and `make tmm` ran to completion with zero errors --- and the
# resulting binary did not contain the change. `nm` showed the old set of globals
# and the new one, g_ls_names, was simply absent.
#
# The reason is that TMM's compile directory has NO .d files. Make therefore has no
# dependency edge from an object to the headers it includes, so a header-only change
# leaves every object newer than the header it now contradicts, and nothing is
# recompiled. The build is not wrong; it is answering a question about timestamps
# that has nothing to do with what changed.
#
# This is the same FAMILY of failure as the lost map registrations and the four
# images that shipped without the code being tested: the build succeeds, the
# artifact is stale, and every downstream measurement is taken against the wrong
# binary. It is not detectable from the build log, which is why it needs a step
# rather than a warning.
#
# So: after copying, DELETE the substrate objects. There are a dozen of them and
# they rebuild in under a minute, which is cheap next to a wrong conclusion. Do not
# try to be clever about which headers affect which TUs -- that computation is
# exactly what the missing .d files would have done, and getting it subtly wrong
# reproduces the bug while looking careful.
#
#   bnk-sync-substrate.sh            copy, invalidate objects, verify
#   bnk-sync-substrate.sh --dry-run  say what would be copied and removed
set -e

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
BUILD_BOX="${BUILD_BOX:-starin@10.145.42.119}"
TREE="${TREE:-code/tmm/src}"
DRY=""
[ "$1" = "--dry-run" ] && DRY=1

SRC="$REPO/substrate"
[ -d "$SRC" ] || { echo "*** no substrate/ under $REPO" >&2; exit 2; }

echo "=== 1. check sync FIRST --- after the copy the evidence is gone"
# The check is what stands between a routine copy and deleting a change that only
# exists in the tree. Run it, show it, and stop unless it is clean.
if ! sh "$(dirname "$0")/bnk-check-tree-sync.sh" > /tmp/.syncout 2>&1; then
    if grep -q "ONLY IN TREE" /tmp/.syncout; then
        sed -n '/ONLY IN TREE/,$p' /tmp/.syncout | head -20
        echo
        echo "*** REFUSING TO COPY. Files exist only in the tree; copying would delete"
        echo "    them with no trace, which is how the map registrations were lost."
        exit 1
    fi
fi
grep -E "DIFFERS|ACKNOWLEDGED|VERDICT|delta" /tmp/.syncout | sed 's/^/  /' || true
rm -f /tmp/.syncout

echo
echo "=== 2. copy the substrate sources into their include worlds"
# base/ takes the STDINC files; the ssl module takes its own ctx builder. Which
# world a file belongs to is decided by src/compile/filelist, not by this script.
if [ -n "$DRY" ]; then
    echo "  (dry run) would copy $(ls "$SRC"/ls_*.c "$SRC"/ls_*.h 2>/dev/null | wc -l) ls_* files"
else
    tar -C "$SRC" -cf - $(cd "$SRC" && ls ls_*.c ls_*.h harness.c 2>/dev/null) \
      | ssh "$BUILD_BOX" "cd $TREE/base && tar -xf -"
    scp -q "$SRC/ls_ctx_alpn.c" "$SRC/ls_ctx_alpn.h" \
        "$BUILD_BOX:$TREE/modules/hudfilter/ssl/" 2>/dev/null || true
    echo "  copied"
fi

echo
echo "=== 3. INVALIDATE the objects --- the step whose absence caused the bug"
if [ -n "$DRY" ]; then
    ssh "$BUILD_BOX" "ls $TREE/compile/obj_x86_64.*/ls_*.o 2>/dev/null | sed 's|.*/|  would remove |'" || true
else
    # sudo, AND count afterwards instead of announcing. The objects are created by
    # the build running as root INSIDE the toolchain container, so a plain rm gets
    # "Permission denied" -- and `rm -f` keeps going, so a script that prints its
    # own success message reports 24 files removed while removing none. That is
    # exactly what happened on 2026-08-18, and it cost a whole 40-minute build:
    # make ran clean, the binary was stale, and only `nm` on the result showed it.
    # Never report an outcome you have not measured.
    ssh "$BUILD_BOX" "
        cd $TREE/compile || exit 1
        n=\$(ls obj_x86_64.*/ls_*.o 2>/dev/null | wc -l)
        sudo rm -f obj_x86_64.*/ls_*.o
        m=\$(ls obj_x86_64.*/ls_*.o 2>/dev/null | wc -l)
        if [ \"\$m\" -ne 0 ]; then
            echo \"  *** \$m of \$n objects SURVIVED the delete --- refusing to go on.\"
            echo \"      They are root-owned (built inside the container); sudo is required.\"
            exit 1
        fi
        echo \"  removed \$n substrate objects across all build variants (verified: 0 remain)\"
        echo \"  (no .d files exist here, so make cannot see header changes itself)\"
    "
fi

echo
echo "  Next: on the build box,  cd ~/code/tmm && script -qec 'make tmm' /dev/null"
echo "  Then VERIFY THE BINARY, never the build log:"
echo "      nm src/compile/obj_x86_64.no_pgo/tmm.no_pgo | grep ' [bBdD] g_ls_'"
echo "      env/scripts/bnk-verify-artifact.sh <tag> '<a string unique to your change>'"
