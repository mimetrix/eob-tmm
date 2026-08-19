#!/bin/sh
# Assert the PACKAGED binary actually contains the substrate that was just built.
#
#   bnk-check-deb-contains-substrate.sh [debs-dir] [substrate-dir]
#
# THE FAILURE THIS CATCHES, observed 2026-08-19. `make tmm` succeeded, the linked binary
# contained the new code, `make container` succeeded, the DEBs were freshly written --- and the
# binary inside them was BYTE-IDENTICAL to the one already deployed. The packaging chain keys
# on version-stamped filenames (docker_build/tmm-runtime.$(VERSION).$(ARCH).tgz, and the RPM
# under RPMS/), and VERSION comes from TMM's git revision. The substrate's sources are
# untracked, so changing them does not change VERSION, so make saw its targets as current and
# repackaged yesterday's binary. Nothing in either build log said so.
#
# WHY THE BUILD-ID GATE DID NOT CATCH IT. That gate proves the index and the binary AGREE. A
# stale DEB agrees with itself perfectly: same binary, same id, everything matches, and the
# image ships without the change. Agreement is not freshness. This is the third distinct
# member of that family in this repo --- missing .d files, the stale Dockerfile, and now the
# version-stamped packaging chain: the build succeeds, the artifact is stale, and every
# downstream measurement is taken against the wrong binary.
#
# HOW IT CHECKS, without naming a single symbol. Every non-static function defined in the
# substrate's .c files must appear in the packaged DEBUGINFO binary's symbol table. The list
# comes from reading the sources, so adding a file needs no edit here; a file that was added
# and never packaged fails, and so does a whole packaging chain that did not run.
#
# The debuginfo package is what carries symbols --- the runtime binary is stripped, which is
# why `nm` on it returns nothing and why an earlier attempt to check this with `strings` inside
# the container was worthless (strings is absent there and silently returns nothing).
set -e

DEBS="${1:-$HOME/code/tmm/docker_build/DEBS/amd64}"
SRC="${2:-$HOME/eob-tmm-staged/substrate}"

fail() { echo "*** $*" >&2; exit 1; }

DBG=$(find "$DEBS" -name 'tmm-debuginfo_*.deb' 2>/dev/null | head -1)
[ -n "$DBG" ] || fail "no tmm-debuginfo_*.deb under $DEBS"
[ -d "$SRC" ] || fail "no substrate sources at $SRC"

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
dpkg-deb -x "$DBG" "$TMP"

# The debug binary matching the shipped one, selected by build id rather than by name --- the
# package carries two, and picking by size got the wrong one once already.
RDEB=$(ls "$DEBS"/tmm_*.deb 2>/dev/null | head -1)
[ -n "$RDEB" ] || fail "no tmm_*.deb under $DEBS --- cannot tell which debug binary ships"
RT=$(mktemp -d); trap 'rm -rf "$TMP" "$RT"' EXIT
dpkg-deb -x "$RDEB" "$RT"
WANT=$(python3 "$SRC/ls_buildid.py" "$(readlink -f "$RT/usr/bin/tmm.default")")

DB=""
for f in $(find "$TMP" -type f -size +10M 2>/dev/null); do
    b=$(python3 "$SRC/ls_buildid.py" "$f" 2>/dev/null) || continue
    [ "$b" = "$WANT" ] && { DB="$f"; break; }
done
[ -n "$DB" ] || fail "no debug binary in the debuginfo package matches the shipped build id $WANT"
echo "  debuginfo : $(basename "$DB")  (build $WANT)"

# Non-static function definitions in the substrate's .c files: a line starting at column 1
# with an identifier followed by '(' , where the PREVIOUS line is the return type on its own
# line. That is this codebase's house style throughout, which is why it can be relied on.
# check_* files are test harnesses and are not compiled into TMM.
EXPECT="$TMP/expect"
: > "$EXPECT"
for f in "$SRC"/ls_*.c; do
    [ -f "$f" ] || continue
    awk '
      /^static/ { prev=""; next }
      /^[A-Za-z_][A-Za-z0-9_]*\(/ {
          if (prev != "" && prev !~ /^static/ && prev !~ /[;,)]$/ && prev !~ /^\// && prev !~ /^ /) {
              name = $0; sub(/\(.*/, "", name); print name
          }
      }
      { prev = $0 }
    ' "$f" >> "$EXPECT"
done
sort -u "$EXPECT" -o "$EXPECT"
NEXP=$(grep -c . "$EXPECT" || true)
[ "$NEXP" -gt 0 ] || fail "found no non-static functions in $SRC/ls_*.c --- the extractor is
    broken, and a check that expects nothing passes against anything."

nm "$DB" 2>/dev/null | awk '$2 ~ /^[TtWw]$/ {print $3}' | sort -u > "$TMP/have"
MISSING="$TMP/missing"
comm -23 "$EXPECT" "$TMP/have" > "$MISSING"
NMISS=$(grep -c . "$MISSING" || true)

echo "  expected  : $NEXP non-static substrate function(s), read from the sources"
echo "  present   : $((NEXP - NMISS))"
if [ "$NMISS" -ne 0 ]; then
    echo "  MISSING   : $NMISS"
    sed 's/^/      /' "$MISSING" | head -20
    fail "the packaged binary does not contain the substrate that was built.

    This is the version-stamped packaging chain going stale. Clear it and repackage:

        cd ~/code/tmm
        sudo rm -f RPMS/x86_64/tmm-10*.rpm RPMS/x86_64/tmm-debug*-10*.rpm \\
                   RPMS/noarch/tmm-headers-10*.rpm docker_build/tmm-runtime.*.tgz \\
                   docker_build/DEBS/amd64/tmm_10*.deb docker_build/DEBS/amd64/tmm-debug*_10*.deb
        make container

    Verify the removal by COUNTING what remains --- those files are root-owned and a plain
    rm keeps going after Permission denied, so a script can report success having removed
    nothing. That has happened here before."
fi
echo "  MATCH --- the packaged binary contains every non-static substrate function"
