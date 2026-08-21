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

# SSH OPTIONS ARE A VARIABLE, because a REPLAY talks to a box that has never been seen before.
# Found 2026-08-21 rebuilding the build box from nothing: this script died at "Host key
# verification failed" on the first byte it tried to send. On a long-lived box the key is already
# trusted and the plain `ssh` here works forever; on a fresh one it does not, and the failure comes
# after the provenance banner has already printed, which reads like a transfer problem rather than
# a trust problem. Worse on a workstation whose ~/.ssh is read-only: `accept-new` cannot record the
# key either, so it warns and proceeds, and only a caller can decide whether that is acceptable.
#
#   SSH_OPTS="-o StrictHostKeyChecking=accept-new"                 # first contact, key recorded
#   SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"   # read-only ~/.ssh
SSH_OPTS="${SSH_OPTS:--o StrictHostKeyChecking=accept-new}"
SSH="ssh $SSH_OPTS"
SCP="scp $SSH_OPTS"

SRC="$REPO/substrate"
[ -d "$SRC" ] || { echo "*** no substrate/ under $REPO" >&2; exit 2; }

echo "=== 1. check sync FIRST --- after the copy the evidence is gone"
# The check is what stands between a routine copy and deleting a change that only
# exists in the tree. Run it, show it, and stop unless it is clean.
sh "$(dirname "$0")/bnk-check-tree-sync.sh" > /tmp/.syncout 2>&1 || true

# READ THE COUNT, NOT THE PROSE. This grepped for the string "ONLY IN TREE" and matched
# the check's own ADVICE ("do not copy while anything reads DIFFERS or ONLY IN TREE"),
# which that script prints on every diverged run. So the guard fired on its own help text
# and refused every legitimate copy. A guard that cries wolf gets deleted, which is worse
# than not having one.
#
# The verdict line ends "(N only-in-tree, M only-in-repo)". N is a number and cannot be
# confused with commentary.
ONLY_TREE=$(sed -n 's/.*(\([0-9]*\) only-in-tree.*/\1/p' /tmp/.syncout | head -1)
if [ -z "$ONLY_TREE" ]; then
    echo "*** could not read the only-in-tree count from the sync check --- refusing"
    echo "    rather than copying on an unparsed verdict."
    exit 1
fi
if [ "$ONLY_TREE" -ne 0 ]; then
    grep -E "^  ONLY IN TREE" /tmp/.syncout | head -20
    echo
    echo "*** REFUSING TO COPY. $ONLY_TREE file(s) exist only in the tree; copying would"
    echo "    delete them with no trace, which is how the map registrations were lost."
    exit 1
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
    # NOT JUST ls_* --- the tree needs two headers whose names do not match that glob, and this
    # script never copied them. Found 2026-08-21 by rebuilding the build box from nothing: the
    # compile stopped at `shield_abi.h: No such file or directory`. On the previous box both files
    # had been placed by hand once, months of syncs never touched them, and nothing noticed because
    # they were already there --- a file that is present for a reason nobody records is a file that
    # only exists on one machine. substrate/.tree-expected-delta lists them; the glob did not.
    #
    # Derived from the manifest rather than restated, so adding a header there is enough.
    EXTRA=$(grep -E '^\?\? src/base/' "$SRC/.tree-expected-delta" 2>/dev/null \
              | awk '{print $2}' | sed 's|.*/||' \
              | grep -vE '^ls_|^harness' | tr '\n' ' ')
    for f in $EXTRA; do
        [ -f "$SRC/$f" ] || { echo "  *** the manifest lists $f but substrate/$f does not exist"; exit 1; }
    done
    echo "  extra (non-ls_*) headers from the manifest: ${EXTRA:-none}"
    tar -C "$SRC" -cf - $(cd "$SRC" && ls ls_*.c ls_*.h harness.c 2>/dev/null) $EXTRA \
      | $SSH "$BUILD_BOX" "cd $TREE/base && tar -xf -"
    # SSL-MODULE FILES, listed explicitly. These are the .c files that must compile in
    # the ssl module's include world because they touch struct ssl_ctx --- a copy in
    # base/ would need every -I that module has, which is the build-config guessing the
    # STDINC split exists to avoid. Their HEADERS stay in base/ and are reached as
    # <local/base/...>, so only the .c moves.
    for f in ls_ctx_alpn.c ls_ctx_alpn.h ls_ssl_cookie.c; do
        [ -f "$SRC/$f" ] || { echo "  *** $SRC/$f missing"; exit 1; }
        $SCP -q "$SRC/$f" "$BUILD_BOX:$TREE/modules/hudfilter/ssl/$f"
    done
    echo "  copied (base/ + 3 ssl-module files)"
    # STAMP THE COMMIT THE STAGED COPY CAME FROM. The staged tree is a tar extract with no
    # .git, so packaging cannot work this out for itself --- it recorded "unknown" on its
    # first real run. Writing it here, from the machine that actually has the repo, is the
    # only place the answer exists.
    # -dirty WHEN THE TREE IS NOT CLEAN, which is the usual case here: the substrate is
    # normally synced and built BEFORE the change is committed, so a bare HEAD sha names a
    # commit that does not contain what was just copied. Recording it without the suffix
    # would put a precise and wrong provenance string into the pipeline receipt --- worse
    # than "unstamped", because it looks authoritative.
    C=$(cd "$REPO" && git rev-parse --short HEAD 2>/dev/null || echo unstamped)
    if [ -n "$(cd "$REPO" && git status --porcelain -- substrate 2>/dev/null)" ]; then
        C="$C-dirty"
    fi
    echo "$C" | $SSH "$BUILD_BOX" "cat > $TREE/../.substrate-commit" 2>/dev/null || true
    echo "  stamped commit $C"
fi

echo
echo "=== 3. INVALIDATE the objects --- the step whose absence caused the bug"
if [ -n "$DRY" ]; then
    $SSH "$BUILD_BOX" "ls $TREE/compile/obj_x86_64.*/ls_*.o 2>/dev/null | sed 's|.*/|  would remove |'" || true
else
    # sudo, AND count afterwards instead of announcing. The objects are created by
    # the build running as root INSIDE the toolchain container, so a plain rm gets
    # "Permission denied" -- and `rm -f` keeps going, so a script that prints its
    # own success message reports 24 files removed while removing none. That is
    # exactly what happened on 2026-08-18, and it cost a whole 40-minute build:
    # make ran clean, the binary was stale, and only `nm` on the result showed it.
    # Never report an outcome you have not measured.
    $SSH "$BUILD_BOX" "
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
