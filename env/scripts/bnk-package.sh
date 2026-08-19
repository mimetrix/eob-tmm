#!/bin/sh
# Package TMM into DEBs, with the stale-artifact removal built in. RUNS ON THE BUILD BOX.
#
#   bnk-package.sh              clear the stale chain, make container, verify the result
#   bnk-package.sh --check      verify only --- do not build
#
# WHY THIS EXISTS RATHER THAN A LINE IN THE RUNBOOK. The runbook already said it:
#
#     Before any `make container`, delete stale artifacts or your changes are silently
#     absent from the new image --- it builds, deploys and runs the old code:
#         sudo rm -rf RPMS SRPMS docker_build/DEBS BUILD_* docker_build/tmm-runtime.*
#
# On 2026-08-19 that line was not read, and two `make container` runs were wasted: the first
# exited 0 and packaged a binary BYTE-IDENTICAL to the one already deployed, the second died
# with `gcc: fatal error: no input files` on an unrelated object from a stale BUILD_x86_64.
# Both are the same sentence in the runbook. Documentation that has to be remembered at the
# right moment is not a control; a script is.
#
# WHY THE CHAIN GOES STALE. Its targets are version-stamped ---
# docker_build/tmm-runtime.$(VERSION).$(ARCH_VARIANT).tgz, and RPMS/$(ARCH)/tmm-$(RELEASE)-...
# --- and VERSION comes from TMM's git revision. The substrate's files are UNTRACKED, so
# changing them cannot change VERSION, so make sees every packaging target as current and
# repackages the previous binary. `make tmm` is unaffected; it is only packaging that lies.
#
# WHY THE BUILD-ID GATE CANNOT SEE IT. That gate proves the index and the binary AGREE. A
# stale DEB agrees with itself perfectly --- same binary, same id, everything matches, and the
# image ships without the change. Agreement is not freshness. So this script ends by checking
# freshness directly, against the sources, via bnk-check-deb-contains-substrate.sh.
set -e

TMM="${TMM:-$HOME/code/tmm}"
SRC="${SRC:-$HOME/eob-tmm-staged/substrate}"
HERE=$(cd "$(dirname "$0")" && pwd)
CHECK_ONLY=""
[ "$1" = "--check" ] && CHECK_ONLY=1

fail() { echo "*** $*" >&2; exit 1; }
[ -d "$TMM" ] || fail "no TMM tree at $TMM"
cd "$TMM"

if [ -z "$CHECK_ONLY" ]; then
    echo "=== 1. clear the version-stamped packaging chain"
    # COUNT BEFORE AND AFTER instead of trusting rm. These files are created by the build
    # running as root inside the toolchain container, so a plain rm gets Permission denied ---
    # and rm -f keeps going, so a script that prints its own success message reports files
    # removed while removing none. That has happened here, and it cost a 40-minute build.
    BEFORE=$(ls -d RPMS SRPMS docker_build/DEBS BUILD_* docker_build/tmm-runtime.*.tgz \
             2>/dev/null | wc -l)
    sudo rm -rf RPMS SRPMS docker_build/DEBS BUILD_* docker_build/tmm-runtime.*.tgz
    AFTER=$(ls -d RPMS SRPMS docker_build/DEBS BUILD_* docker_build/tmm-runtime.*.tgz \
            2>/dev/null | wc -l)
    echo "  stale artifacts: $BEFORE -> $AFTER"
    [ "$AFTER" -eq 0 ] || fail "$AFTER stale artifact(s) survived removal. They are root-owned;
    rm -f reports success after Permission denied. Nothing below would be trustworthy."

    echo
    echo "=== 2. make container"
    LOG=/tmp/bnk-package.$$.log
    script -qec "make container" "$LOG" >/dev/null 2>&1 || true
    RC=$(sed -n 's/.*COMMAND_EXIT_CODE="\([0-9]*\)".*/\1/p' "$LOG" | tail -1)
    echo "  exit: ${RC:-unknown}   log: $LOG"
    if [ "${RC:-1}" != "0" ]; then
        grep -nE "error:|Error [0-9]" "$LOG" | head -8 | cut -c1-160 | sed 's/^/  /'
        fail "make container failed. The log is at $LOG.
    'gcc: fatal error: no input files' on an unrelated object means a stale BUILD_* survived
    --- which step 1 exists to prevent, so read its output above before anything else."
    fi
fi

echo
echo "=== 3. VERIFY FRESHNESS --- does the packaged binary contain what was just built?"
# The check that the build-id gate cannot make. Reads the substrate sources for every
# non-static function and requires each in the packaged debuginfo's symbol table.
sh "$HERE/bnk-check-deb-contains-substrate.sh" "$TMM/docker_build/DEBS/amd64" "$SRC"

echo
echo "=== 4. record what this stage produced"
# THE RECEIPT. The next stage refuses unless the DEBs it reads carry this build id, so
# skipping this stage --- or baking from a different one --- is a hard error rather than an
# omission nobody mentions. bnk-preflight.sh's header is the reason this exists: four correct
# guards sat beside the path on 2026-08-17 and every error happened anyway.
RDEB=$(ls "$TMM"/docker_build/DEBS/amd64/tmm_*.deb 2>/dev/null | head -1)
RT=$(mktemp -d); trap 'rm -rf "$RT"' EXIT
dpkg-deb -x "$RDEB" "$RT"
PKGID=$(python3 "$SRC/ls_buildid.py" "$(readlink -f "$RT/usr/bin/tmm.default")")
# The repo commit, so a bake from a different commit than the package is visible. It recorded
# "unknown" on the first real run: $SRC is the STAGED copy on the build box, which is a tar
# extract and not a git repo. The commit therefore has to be passed in by whoever staged it ---
# and a field that silently reads "unknown" is worse than no field, so say which it is.
COMMIT="${REPO_COMMIT:-}"
if [ -z "$COMMIT" ]; then
    COMMIT=$(cd "$SRC/.." 2>/dev/null && git rev-parse --short HEAD 2>/dev/null || true)
fi
if [ -z "$COMMIT" ]; then
    COMMIT="unstamped"
    echo "  note: no repo commit recorded. \$SRC is a staged extract, not a git checkout, so"
    echo "        pass REPO_COMMIT=\$(git rev-parse --short HEAD) from the machine that staged"
    echo "        it if you want the bake tied to a commit as well as a build id."
fi
sh "$HERE/bnk-receipt.sh" write package "build_id=$PKGID" "commit=$COMMIT" \
                                       "deb=$(basename "$RDEB")"

echo
echo "  Next: bnk-bake-tools.sh   (it regenerates both indexes from these DEBs)"
