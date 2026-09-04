#!/bin/sh
# Does PREVAIL still accept a program AFTER its offsets are baked?
#
#   check_prevail_after_relo.sh <tmm.btf>
#
# THE FALSIFIER THIS ANSWERS is falsifier 3 of 02-RESEARCH-PARAMETERS.md P9, and it
# is the one most likely to kill the sign-time-relocation plan. Today the order is
#
#     compile -> PREVAIL -> sign -> ship -> RELOCATE ON-BOX -> uBPF -> JIT
#
# so PREVAIL proves a program whose field offsets are still the local stub's --- 0, 1,
# 2 for a three-byte placeholder struct --- and the immediates are rewritten afterwards,
# inside TMM, to this build's real offsets. Taking BTF out of the binary means the
# order becomes
#
#     compile -> RELOCATE -> PREVAIL -> sign -> ship -> uBPF -> JIT
#
# which is strictly better in two ways (the proof and the signed hash both cover the
# bytes that actually run) and carries one risk: PREVAIL now sees REAL offsets. A real
# offset is larger and can sit outside whatever bound the verifier inferred from the
# placeholder, so a program that verifies today can be REFUSED after relocation. If
# that happens the plan needs rework, and it needs to be known before the embedded
# .BTF is deleted rather than after.
#
# WHAT A DIFFERENCE MEANS, in either direction:
#   PASS -> REJECT   the proof was relying on the placeholder layout. Real finding.
#   REJECT -> PASS   worse: a negative test (reject_*) that starts verifying means
#                    relocation moved the program out of the shape it was written to
#                    trip, so the test no longer tests anything.
#
# WHERE THIS RUNS. Here, on the machine that has PREVAIL and clang --- which is the
# same machine bnk-build-programs.sh runs on, so this IS the pipeline's verification
# stage and not a workstation approximation. The clang here is 14 and the build box
# is 18; that difference has flipped a PREVAIL verdict before (CLAUDE.md rule 5), so
# a clean result here is authoritative for THIS stage and not for the build box's.
set -e

BTF="${1:?usage: check_prevail_after_relo.sh <tmm.btf>}"
[ -s "$BTF" ] || { echo "*** no BTF at $BTF"; exit 2; }

HERE=$(cd "$(dirname "$0")" && pwd)
PREVAIL="${PREVAIL:-$HERE/../ebpf-verifier/bin/prevail}"
CLANG="${CLANG:-clang}"
READELF="${READELF:-readelf}"
[ -x "$PREVAIL" ] || { echo "*** no PREVAIL at $PREVAIL"; exit 2; }

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
cc -O2 -w -DLS_CORE_RELO_TEST "$HERE/ls_core_relo.c" -o "$T/relo"

echo "prevail : $PREVAIL"
echo "clang   : $($CLANG --version | head -1)"
echo "btf     : $BTF ($(wc -c < "$BTF") bytes)"
echo

SAME=0; CHANGED=0; SKIP=0
printf "  %-24s %-8s %-8s %-8s %s\n" program relos before after verdict
for f in "$HERE"/shields/*.bpf.c "$HERE"/surfaces/*.bpf.c; do
    [ -e "$f" ] || continue
    b=$(basename "$f" .bpf.c)
    o="$T/$b.o"
    $CLANG -O2 -g -target bpf -I "$HERE" -c "$f" -o "$o" 2>/dev/null || {
        printf "  %-24s %-8s %-8s %-8s %s\n" "$b" - - - "does not compile"
        SKIP=$((SKIP+1)); continue; }
    sec=$($READELF -SW "$o" 2>/dev/null | grep -oE 'f(entry|exit)/[^ ]*' | head -1)
    [ -n "$sec" ] || { printf "  %-24s %-8s %-8s %-8s %s\n" "$b" - - - "no fentry/fexit section"
                       SKIP=$((SKIP+1)); continue; }

    if "$PREVAIL" "$o" "$sec" --termination --strict --no-division-by-zero \
                  --stack-size 256 >/dev/null 2>&1; then BEFORE=PASS; else BEFORE=REJECT; fi

    # relocate into a copy; a refusal here is not a PREVAIL result and is reported as such
    if "$T/relo" "$o" "$BTF" "$T/$b.reloc.o" >"$T/rl" 2>&1; then
        N=$(grep -oE '[0-9]+ relo' "$T/rl" | grep -oE '[0-9]+' | head -1)
        if "$PREVAIL" "$T/$b.reloc.o" "$sec" --termination --strict --no-division-by-zero \
                      --stack-size 256 >/dev/null 2>&1; then AFTER=PASS; else AFTER=REJECT; fi
    else
        N=0; AFTER="norelo"
    fi

    if [ "$AFTER" = norelo ]; then
        # zero-relocation objects are refused by the relocator (rc=-3, a known symptom);
        # nothing was rewritten, so PREVAIL cannot have changed its mind.
        printf "  %-24s %-8s %-8s %-8s %s\n" "$b" 0 "$BEFORE" "$BEFORE" "no relocations --- unchanged"
        SAME=$((SAME+1))
    elif [ "$BEFORE" = "$AFTER" ]; then
        printf "  %-24s %-8s %-8s %-8s %s\n" "$b" "${N:-0}" "$BEFORE" "$AFTER" "same"
        SAME=$((SAME+1))
    else
        printf "  %-24s %-8s %-8s %-8s %s\n" "$b" "${N:-0}" "$BEFORE" "$AFTER" "*** CHANGED"
        CHANGED=$((CHANGED+1))
    fi
done

echo
echo "  unchanged : $SAME"
echo "  CHANGED   : $CHANGED"
echo "  skipped   : $SKIP"
if [ "$CHANGED" -ne 0 ]; then
    echo
    echo "  *** P9 falsifier 3 FIRES. Relocating before verification changes what PREVAIL"
    echo "      decides, so sign-time relocation is not a drop-in reordering. Do NOT remove"
    echo "      the embedded .BTF on this result."
    exit 1
fi
echo
echo "  PREVAIL's verdict is unchanged by relocation on every program that has any."
# SAY WHICH TOOLCHAIN THIS WAS, and do not assert anything about the other one.
# The first version of this line ended "The build box runs a different clang" ---
# which is false when the script is run ON the build box, and it was. CLAUDE.md
# rule 5 makes the distinction load-bearing: clang-14 once passed a program that
# clang-18, the pinned build, REFUSED. So the host and compiler are reported and
# the reader is told what that buys, rather than being handed a claim about a
# machine this run never touched.
_cv=$($CLANG --version | head -1 | grep -oE '[0-9]+' | head -1)
echo "  Toolchain: clang $_cv on $(uname -n) ($(uname -m))."
if [ "$_cv" = "18" ]; then
    echo "  That is the PINNED build compiler, so this is a conclusion and not a hint"
    echo "  (CLAUDE.md rule 5)."
else
    echo "  The pinned build compiler is clang 18. This is a HINT, not a conclusion ---"
    echo "  re-run on the build box before relying on it (CLAUDE.md rule 5)."
fi
