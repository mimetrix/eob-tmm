#!/bin/sh
# Assert this image can actually arm by name. RUNS AT IMAGE BUILD TIME, inside the
# image, so a broken layer fails at build rather than during a demo.
#
# THE CHECK THAT MATTERS is the build-id comparison. Dockerfile.runtime points
# /usr/bin/tmm at tmm.debug whenever a debug binary is present, and the debug build
# overrides CFLAGS_OPTIMIZE --- which is where -fpatchable-function-entry lives. So
# tmm64.debug has no entry pads and NOTHING in it can be armed; arming fails with "no
# pad", which reads like a stale address and is not. That has shipped four times, three
# of them reaching the cluster.
#
# Comparing the index's build id against the binary tmm RESOLVES to catches both that
# and a stale index, which are different faults with identical symptoms.
set -e

IDX_FILE=/usr/share/ls/hook-index.tsv

test -s "$IDX_FILE"       || { echo "*** $IDX_FILE missing or empty"; exit 1; }
grep -q '^#build_id' "$IDX_FILE" || { echo "*** index carries no #build_id header"; exit 1; }
test -x /usr/bin/ls_drain || { echo "*** /usr/bin/ls_drain missing or not executable"; exit 1; }
test -f /usr/bin/ls-load.py || { echo "*** /usr/bin/ls-load.py missing"; exit 1; }
ls /usr/share/ls/*.bpf.o >/dev/null 2>&1 || { echo "*** no verified programs baked in"; exit 1; }

R=$(readlink -f /usr/bin/tmm)
case "$R" in
  *debug*) echo "*** /usr/bin/tmm resolves to $R --- the debug build has NO entry pads,"
           echo "    so nothing can ever be armed. Repoint it at tmm.default."
           exit 1 ;;
esac

IDX=$(awk -F'\t' '/^#build_id/{print $2}' "$IDX_FILE")
LIVE=$(python3 /usr/share/ls/ls_buildid.py "$R")

echo "  tmm resolves to : $R"
echo "  index build id  : $IDX"
echo "  binary build id : $LIVE"

if [ "$IDX" != "$LIVE" ]; then
    echo "*** BUILD ID MISMATCH. The index describes a different binary than this"
    echo "    image runs, so every address in it is wrong. ls-load.py would refuse"
    echo "    to arm --- correct, but useless. Regenerate the index from the DEB pair"
    echo "    this image was built from."
    exit 1
fi

echo "  ls-tools OK: $(grep -vc '^#' "$IDX_FILE") symbols, $(ls /usr/share/ls/*.bpf.o | wc -l) programs"
