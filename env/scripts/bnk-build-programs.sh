#!/bin/sh
# Compile and VERIFY every bytecode program, and emit only the ones that verify.
#
#   bnk-build-programs.sh [outdir]           default: $HOME/lstools/shields
#
# WHY THIS EXISTS. This stage used to be a paragraph in the runbook and a clang line typed by
# hand. bnk-bake-tools.sh refuses to build an image unless $CTX/shields holds .bpf.o files, so
# the one stage that decides WHICH bytecode ships was the one stage with no script --- and a
# hand-typed clang invocation is where the wrong -I, the wrong target, or a skipped
# verification goes unnoticed. The whole point of the substrate is that nothing unverified
# loads; a manual step in front of it is the weakest link by construction.
#
# THE EXPECTATION RUNS BOTH WAYS, which is the part worth reading. Programs named reject_* are
# NEGATIVE tests: they exist to be refused, and a build where reject_termination.bpf.c passes
# verification is a worse failure than one where rst_watch.bpf.c does not. So this script
# asserts the direction it expects for each program and fails on a surprise in either
# direction. Compiling everything and baking whatever came out would bake a rejected program
# on one path and, on the other, quietly lose the evidence that the verifier still works.
#
# WHERE THIS RUNS. clang and PREVAIL both, which today means the dev sandbox (PREVAIL built
# from source, clang 14) rather than the build box (clang 18, no PREVAIL). That split is not
# an accident of these two machines --- it is the shape the production pipeline is meant to
# have: compile in dev/CI, verify and sign at F5, load on the target and nowhere else. The
# script states which half it can do and refuses rather than skipping the other.
#
# PREVAIL's defaults are permissive. --termination is "Default: ignore",
# --allow-division-by-zero is "Default: allow", --strict is off. They are passed explicitly
# because "verified" without them means materially less than it sounds.
set -e

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
OUT="${1:-$HOME/lstools/shields}"
PREVAIL="${PREVAIL:-$REPO/ebpf-verifier/bin/prevail}"
# The signing key, outside the repo by default. SIGN_CEILING is the MOST a signed program may be
# run at --- monitor unless asked otherwise, because enforce should be requested rather than
# defaulted into.
SIGN_KEY="${SIGN_KEY:-$HOME/.ls-signing/shield_sk.pem}"
CLANG="${CLANG:-clang}"

fail() { echo "*** $*" >&2; exit 1; }

command -v "$CLANG" >/dev/null 2>&1 || fail "no clang. Set CLANG= or install it."
[ -x "$PREVAIL" ] || fail "no PREVAIL at $PREVAIL.
    Compiling without verifying is not this stage. Build it (env/bnk-dev-runbook.md) or set
    PREVAIL=, and do not work around this by baking unverified objects."
SRC="$REPO/substrate/shields"
[ -d "$SRC" ] || fail "no $SRC"

mkdir -p "$OUT"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

echo "  clang    : $($CLANG --version | head -1)"
echo "  prevail  : $PREVAIL"
echo "  out      : $OUT"
echo

npass=0; nreject=0; nbad=0
for f in "$SRC"/*.bpf.c; do
    b=$(basename "$f" .bpf.c)
    o="$TMP/$b.bpf.o"

    # NEGATIVE TESTS ARE NAMED. reject_* must be refused; everything else must verify.
    case "$b" in reject_*) want=REJECT ;; *) want=PASS ;; esac

    if ! $CLANG -O2 -g -target bpf -I "$REPO/substrate" -c "$f" -o "$o" 2>"$TMP/cerr"; then
        echo "  *** $b: does not COMPILE"
        sed 's/^/        /' "$TMP/cerr" | head -4
        nbad=$((nbad + 1)); continue
    fi

    # The section name IS the hook, read from the object rather than from a table beside it.
    # bnk-deliver-program.py derives the hook the same way, so a program cannot be loaded
    # against a different function than the one it was compiled for.
    sec=$(llvm-readelf --sections "$o" 2>/dev/null | grep -o 'fentry/[^ ]*' | head -1)
    [ -n "$sec" ] || { echo "  *** $b: no fentry/<hook> section --- nothing says what it attaches to"
                       nbad=$((nbad + 1)); continue; }

    if "$PREVAIL" "$o" "$sec" --termination --strict --no-division-by-zero \
                  --stack-size 256 >"$TMP/v" 2>&1; then got=PASS; else got=REJECT; fi

    if [ "$got" != "$want" ]; then
        if [ "$want" = REJECT ]; then
            echo "  *** $b: expected REFUSAL, got PASS. A negative test that verifies means"
            echo "      the verifier no longer catches what this program was written to trip."
        else
            echo "  *** $b: expected PASS, got REFUSAL:"
            tail -3 "$TMP/v" | sed 's/^/        /'
        fi
        nbad=$((nbad + 1)); continue
    fi

    if [ "$want" = REJECT ]; then
        echo "  refused  $b  ($sec)  --- as intended"
        nreject=$((nreject + 1)); continue
    fi

    # The cycle budget, on the SAME object that verified. Advisory today: it reports an
    # estimate and this script does not gate on it, because the per-call cost that would
    # calibrate the estimate is still unmeasured (load-path-scope.md 7). Stating the number
    # is worth doing; enforcing a threshold nobody has validated is not.
    est=$(python3 "$REPO/substrate/budget_pass.py" --section "$sec" "$o" 2>/dev/null \
          | grep -oE '[0-9]+ (cycles|insns)' | head -1)
    cp "$o" "$OUT/$b.bpf.o"

    # SIGN IT HERE, in the same step that verified it.
    #
    # This is the natural place and not a convenience: the signature asserts "this key vouches
    # for this exact program at this exact hook", and the only moment both facts are established
    # is immediately after PREVAIL accepted the object and its fentry/ section was read from it.
    # Signing earlier would vouch for something unverified; signing later would need the hook
    # rediscovered, and a rediscovered hook is a second answer to a question already answered.
    #
    # The private key stays OUTSIDE the repository --- $SIGN_KEY, default ~/.ls-signing. A build
    # with no key produces unsigned programs and says so per program, rather than failing: a tree
    # someone has just cloned should still compile and verify, and only fail at the point where
    # the missing key actually matters, which is load.
    if [ -n "$SIGN_KEY" ] && [ -f "$SIGN_KEY" ]; then
        if python3 "$REPO/substrate/sign_shield.py" --key "$SIGN_KEY" --prog "$o" \
               --hook "${sec#fentry/}" --mode-ceiling "${SIGN_CEILING:-monitor}" \
               -o "$OUT/$b.bpf.sig" >/dev/null 2>&1; then
            echo "  verified $b  ($sec)${est:+  budget ~$est}  SIGNED"
        else
            rm -f "$OUT/$b.bpf.sig"
            echo "  *** $b verified but COULD NOT BE SIGNED --- it will be refused at load"
            nbad=$((nbad + 1)); continue
        fi
    else
        echo "  verified $b  ($sec)${est:+  budget ~$est}  UNSIGNED (no \$SIGN_KEY)"
    fi
    npass=$((npass + 1))
done

echo
echo "  $npass verified and emitted, $nreject correctly refused, $nbad unexpected"
[ "$nbad" -eq 0 ] || fail "$nbad program(s) did not behave as expected. Nothing was emitted for
    them, but do not bake this set --- a surprise here is either a broken program or a
    verifier that changed behaviour, and both need looking at before an image ships."
[ "$npass" -gt 0 ] || fail "nothing verified --- there is nothing to bake."
[ "$nreject" -gt 0 ] || fail "no program was refused. There are reject_* negative tests in
    $SRC; if none of them tripped the verifier, the verification step is not doing anything."
echo "  Next: bnk-bake-tools.sh (it reads \$CTX/shields, default \$HOME/lstools/shields)"
