#!/bin/sh
# The pipeline's chain of custody. Each stage records what it produced; the next refuses
# unless what it is about to consume matches.
#
#   bnk-receipt.sh write <stage> <key=value>...     record a stage's output
#   bnk-receipt.sh require <stage> <key> <value>    refuse unless the recorded value matches
#   bnk-receipt.sh show                             print the receipt
#
# WHY A RECEIPT AND NOT MORE CHECKS. There were already four correct guards in this directory
# by 2026-08-17, and every error that day happened anyway. bnk-preflight.sh's own header says
# why: "having a guard and running a guard are different things." Adding a fifth guard beside
# the path does nothing. What was missing is that a stage could not tell whether its
# PREDECESSOR had run --- so a bake happily read a DEB pair nobody had verified, and a deploy
# happily rolled an image nobody had baked from those DEBs.
#
# A receipt makes that answerable. Packaging records the build id it produced; the bake refuses
# unless the DEBs it is reading carry that id; the ship refuses unless the image carries it.
# Skipping a stage is then a hard error with a specific message, instead of a step nobody
# remembers to mention.
#
# It also records the repo commit, because a bake from a different commit than the package is a
# real and invisible mismatch: the substrate in the binary and the tools in the image would
# come from two different trees.
#
# THIS IS NOT SECURITY. Anyone can edit the file. It is a memory aid with teeth --- it catches
# a forgotten step, not a determined one. Signature verification is scope item 4 and unbuilt.
set -e

RECEIPT="${RECEIPT:-$HOME/lstools/pipeline-receipt}"
CMD="${1:-show}"

case "$CMD" in
write)
    STAGE="$2"; shift 2
    [ -n "$STAGE" ] || { echo "*** write needs a stage name" >&2; exit 2; }
    mkdir -p "$(dirname "$RECEIPT")"
    # Rewrite this stage's lines, keep every other stage's. A stage re-running must replace
    # its own record rather than appending a second one --- two records for one stage is
    # exactly the ambiguity a receipt is supposed to remove.
    TMP="$RECEIPT.$$"
    [ -f "$RECEIPT" ] && grep -v "^$STAGE " "$RECEIPT" > "$TMP" 2>/dev/null || : > "$TMP"
    for kv in "$@"; do
        echo "$STAGE ${kv%%=*} ${kv#*=}" >> "$TMP"
    done
    echo "$STAGE recorded_at $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$TMP"
    mv "$TMP" "$RECEIPT"
    echo "  receipt: $STAGE recorded ($# field(s)) in $RECEIPT"
    ;;
require)
    STAGE="$2"; KEY="$3"; WANT="$4"
    [ -n "$WANT" ] || { echo "*** require needs <stage> <key> <value>" >&2; exit 2; }
    if [ ! -f "$RECEIPT" ]; then
        echo "*** NO PIPELINE RECEIPT at $RECEIPT." >&2
        echo "    The '$STAGE' stage has not run, or ran somewhere else. This stage will not" >&2
        echo "    guess: run the pipeline in order (bnk-package.sh, then bnk-bake-tools.sh," >&2
        echo "    then bnk-ship-image.sh) so each stage records what it produced." >&2
        exit 1
    fi
    GOT=$(awk -v s="$STAGE" -v k="$KEY" '$1==s && $2==k {print $3}' "$RECEIPT" | tail -1)
    if [ -z "$GOT" ]; then
        echo "*** the receipt has no '$KEY' for stage '$STAGE'." >&2
        echo "    Recorded stages:" >&2
        awk '{print "      " $1 " " $2 " " $3}' "$RECEIPT" >&2
        exit 1
    fi
    if [ "$GOT" != "$WANT" ]; then
        echo "*** RECEIPT MISMATCH on $STAGE/$KEY." >&2
        echo "      recorded  $GOT" >&2
        echo "      found now $WANT" >&2
        echo "    The artifact in front of this stage is not the one the previous stage" >&2
        echo "    produced. Re-run the pipeline from '$STAGE' rather than continuing --- this" >&2
        echo "    is how a stale DEB reached an image with every other check passing." >&2
        exit 1
    fi
    echo "  receipt: $STAGE/$KEY matches ($GOT)"
    ;;
show)
    [ -f "$RECEIPT" ] || { echo "  no receipt at $RECEIPT"; exit 0; }
    sed 's/^/  /' "$RECEIPT"
    ;;
*)
    echo "usage: $0 write <stage> <k=v>... | require <stage> <key> <value> | show" >&2
    exit 2
    ;;
esac
