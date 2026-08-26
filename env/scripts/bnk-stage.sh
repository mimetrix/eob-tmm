#!/bin/sh
# Refresh the STAGED tree on the build box --- the copy the packaging and bake steps read.
#
# THE BUG THIS EXISTS FOR, 2026-08-20. Signature verification was working in TMM and every
# load was refused. The cause was not cryptographic: the image carried an ls-load.py from
# before signatures existed, so the client sent no signature and TMM correctly refused. The
# staged tree was three commits behind and nothing in the pipeline looked at it.
#
# There were two synchronisation steps and they covered different things:
#
#   bnk-sync-substrate.sh   repo/substrate  ->  build box code/tmm/src/{base,modules}
#                           the sources COMPILED INTO TMM. Stamps .substrate-commit.
#   (nothing)               repo            ->  build box ~/eob-tmm-staged
#                           the tree that bnk-package.sh and bnk-bake-tools.sh READ, for
#                           substrate freshness checks and for the TOOLS baked into the image.
#
# The second was a `git archive HEAD | ssh ... tar x` typed by hand when someone remembered.
# It shipped a stale client, and the -dirty stamp added that same morning covered substrate/
# only --- a gate over one directory and not its neighbour is not a gate.
#
# So this is a step. It copies from the WORKING TREE, not from HEAD: the substrate is normally
# synced and built before the change is committed, and `git archive HEAD` would silently stage
# the previous version of exactly the file being tested.
#
#   bnk-stage.sh              refresh, stamp, verify
#   bnk-stage.sh --dry-run    list what would be sent
set -e

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
BUILD_BOX="${BUILD_BOX:-starin@10.145.37.36}"   # eob-bnk-build-01; .42.119 retired (SSH refused 2026-08-26)
DEST="${DEST:-eob-tmm-staged}"
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

# WHAT THE STAGED TREE IS FOR, and therefore what belongs in it. Not the whole repo: the docs
# are large, change constantly, and nothing downstream reads them, so staging them would make
# every provenance stamp look dirty for reasons that cannot affect a binary.
DIRS="substrate env/scripts env/docker"
# bootstrap.sh TRAVELS TOO, and its absence was a hole. The build box needs the vendored
# dependencies --- uBPF to compile against, PREVAIL to verify shield programs before they are
# signed --- and both are gitignored, so the only way onto a fresh box is bootstrap.sh, which was
# staged nowhere. Found 2026-08-21: bnk-build-programs.sh on a rebuilt box would have refused for
# want of a verifier, correctly, with no way provided to supply one. It reads its pins from
# substrate/vendor.pins, which is already in DIRS.
FILES="bootstrap.sh"

for d in $DIRS; do
    [ -d "$REPO/$d" ] || { echo "*** $REPO/$d does not exist --- refusing to stage a partial tree" >&2; exit 2; }
done

echo "=== 1. provenance of what is about to be staged"
C=$(cd "$REPO" && git rev-parse --short HEAD 2>/dev/null || echo unstamped)
DIRTY=$(cd "$REPO" && git status --porcelain -- $DIRS 2>/dev/null | wc -l | tr -d ' ')
STAMP="$C"
[ "$DIRTY" -gt 0 ] && STAMP="$C-dirty"
echo "  HEAD      : $C"
echo "  uncommitted in $DIRS: $DIRTY file(s)"
if [ "$DIRTY" -gt 0 ]; then
    (cd "$REPO" && git status --porcelain -- $DIRS | sed 's/^/    /')
    # Not an error. Staging uncommitted work is the NORMAL case --- the alternative is testing
    # a build that does not contain the change. It is stamped -dirty so that no downstream
    # receipt claims a precise commit it cannot support.
    echo "  -> staging the WORKING TREE, stamped $STAMP"
fi

echo
echo "=== 2. send"
if [ -n "$DRY" ]; then
    (cd "$REPO" && tar -cf - $DIRS | tar -tf - | sed 's/^/  /' | head -40)
    echo "  ... $(cd "$REPO" && tar -cf - $DIRS | tar -tf - | wc -l | tr -d ' ') paths total (dry run, nothing sent)"
    exit 0
fi
# --delete semantics, deliberately: a file removed from the repo must disappear from the
# staged tree, or a renamed tool leaves its predecessor behind to be found by a grep and
# believed. tar cannot express that, so remove the staged directories first. Safe because
# this tree is a copy with no unique content --- and if that ever stops being true, the
# freshness check in step 3 is what will notice.
$SSH "$BUILD_BOX" "cd ~/$DEST 2>/dev/null && rm -rf $DIRS; mkdir -p ~/$DEST" 
# ls_sig_pubkey.h is EXCLUDED for the same reason it is excluded from the tree sync: it is
# generated from the signing key of whichever machine built it, and shipping one machine's copy to
# another silently repoints the trust. See the long note in bnk-sync-substrate.sh.
(cd "$REPO" && tar -cf - --exclude='substrate/ls_sig_pubkey.h' $DIRS $FILES) \
  | $SSH "$BUILD_BOX" "cd ~/$DEST && tar -xf -"
echo "$STAMP" | $SSH "$BUILD_BOX" "cat > ~/$DEST/.staged-commit"
echo "  staged $DIRS -> $BUILD_BOX:~/$DEST"
echo "  stamped $STAMP"

echo
echo "=== 3. VERIFY the copy, from the far end --- not from this script's belief that scp worked"
# Compare CONTENT, per file, both ways. The failure being guarded against is a file that
# exists on both sides with different bytes, which every "did the transfer succeed" check
# and every timestamp comparison reports as fine.
LOCAL_SUM=$(cd "$REPO" && find $DIRS $FILES -type f ! -name '*.pyc' ! -name 'ls_sig_pubkey.h' | sort | xargs sha256sum | sha256sum | cut -c1-16)
REMOTE_SUM=$($SSH "$BUILD_BOX" "cd ~/$DEST && find $DIRS $FILES -type f ! -name '*.pyc' ! -name 'ls_sig_pubkey.h' | sort | xargs sha256sum | sha256sum | cut -c1-16")
echo "  local  : $LOCAL_SUM"
echo "  staged : $REMOTE_SUM"
if [ "$LOCAL_SUM" != "$REMOTE_SUM" ]; then
    echo
    echo "*** THE STAGED TREE DOES NOT MATCH THE REPO. Do not build on it. Files differing:"
    $SSH "$BUILD_BOX" "cd ~/$DEST && find $DIRS -type f ! -name '*.pyc' | sort | xargs sha256sum" > /tmp/.stage-remote
    (cd "$REPO" && find $DIRS $FILES -type f ! -name '*.pyc' ! -name 'ls_sig_pubkey.h' | sort | xargs sha256sum) > /tmp/.stage-local
    diff /tmp/.stage-local /tmp/.stage-remote | sed 's/^/    /' | head -30
    rm -f /tmp/.stage-local /tmp/.stage-remote
    exit 1
fi
echo "  MATCH --- every staged file has the bytes the repo has"

echo
echo "=== 4. the specific capability whose absence cost a cycle"
# Checked by capability, not by version string: a version would be one more thing to keep in
# step, and the question that matters is whether the client can do the thing TMM requires.
$SSH "$BUILD_BOX" "
    f=~/$DEST/env/scripts/ls-load.py
    grep -q read_signature \$f && echo '  ls-load.py : can send a signature' \
      || { echo '  *** ls-load.py CANNOT send a signature. TMM verifies them, so every load'; \
           echo '      into an image baked from this tree is refused --- which looks exactly'; \
           echo '      like a broken signature check and is not.'; exit 1; }
    grep -q SHIELD_CTX_ABI_VERSION ~/$DEST/substrate/sign_shield.py && echo '  sign_shield.py : reads the context ABI from the header, not hardcoded' \
      || echo '  *** sign_shield.py hardcodes the context ABI version --- signed artifacts will be refused'
"
echo
echo "  Next: bnk-sync-substrate.sh  (the OTHER copy --- the sources compiled into TMM)"
