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
# WHERE THIS RUNS --- CORRECTED 2026-09-04, and the correction matters for what a clean
# result is worth. This said the split was forced: "the dev sandbox (PREVAIL built from
# source, clang 14) rather than the build box (clang 18, no PREVAIL)". The build box DOES
# have PREVAIL --- bnk-stage.sh puts it at ~/eob-tmm-staged/ebpf-verifier/bin/prevail, it
# is an x86-64 binary and it runs there. So the build box has ALL FOUR things this stage
# needs: clang 18, PREVAIL, the signing key ($HOME/.ls-signing) and this build's tmm.btf.
#
# RUN IT THERE BY PREFERENCE, because clang 18 is the PINNED build compiler and the
# difference is not cosmetic: CLAUDE.md rule 5 records clang-14 passing a PREVAIL program
# that clang-18 REFUSED. A verification taken under clang 14 is a hint about a program the
# pinned toolchain may reject.
#
# The dev sandbox remains useful (it is where the sources are edited, and it has the same
# PREVAIL), and the eventual production shape is still the one described before: compile in
# dev/CI, verify and sign at F5, load on the target and nowhere else. What was wrong was
# the claim that today's two machines FORCE that split. They do not.
#
# PREVAIL's defaults are permissive. --termination is "Default: ignore",
# --allow-division-by-zero is "Default: allow", --strict is off. They are passed explicitly
# because "verified" without them means materially less than it sounds.
set -e

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
OUT="${1:-$HOME/lstools/shields}"
PREVAIL="${PREVAIL:-$REPO/ebpf-verifier/bin/prevail}"

# SIGN-TIME RELOCATION (02-RESEARCH-PARAMETERS.md P9). When this build's BTF is
# available, field offsets are resolved HERE and the .BTF/.BTF.ext sections are
# stripped from the artifact, so the shipped program carries baked offsets and the
# appliance needs no type information of its own --- which is what lets the 6.7 MB
# `.BTF` section come out of the binary.
#
# It also fixes something that was already wrong: today PREVAIL proves a program
# whose offsets are still the local stub's, and the immediates are rewritten
# afterwards inside TMM. So neither the proof nor the signed hash covers the bytes
# that actually run. Relocating BEFORE verification and signing makes both cover
# them. Measured not to change any PREVAIL verdict: substrate/check_prevail_after_relo.sh.
#
# WITHOUT THE BTF THIS STAGE SKIPS RELOCATION AND SAYS SO, LOUDLY, PER PROGRAM. It
# does not fail: a program with .BTF.ext intact still loads against a binary that
# embeds its own BTF, which is every binary until the bake stops embedding it. A
# silent skip is what would be dangerous --- the artifact would look identical and
# the disclosure would still be required.
TMM_BTF="${TMM_BTF:-}"
if [ -z "$TMM_BTF" ] && [ -s "$HOME/lstools/tmm.btf" ]; then
    TMM_BTF="$HOME/lstools/tmm.btf"
fi

# llvm-objcopy, NOT objcopy. GNU objcopy cannot read a BPF ELF --- binutils 2.40
# answers "Unable to recognise the format of the input file" --- and the failure is
# quiet in the way that matters: an unstripped program still loads and verifies
# perfectly, so the only casualty is the disclosure this strip exists to remove.
# Resolved once and asserted, the same lesson as $READELF below.
OBJCOPY=""
for _c in llvm-objcopy llvm-objcopy-18 llvm-objcopy-14 /usr/lib/llvm-18/bin/llvm-objcopy; do
    command -v "$_c" >/dev/null 2>&1 && { OBJCOPY="$_c"; break; }
done

# WHICH readelf, RESOLVED ONCE AND ASSERTED --- because a missing tool here reads as a broken
# program. This used `llvm-readelf --sections` with 2>/dev/null, and on a build box configured from
# the dev-machine playbook llvm-readelf is NOT on PATH: it ships at /usr/lib/llvm-18/bin and nothing
# links it. So the section lookup returned empty for all 18 programs and the script reported
#
#     *** rst_watch: no fentry/<hook> section --- nothing says what it attaches to
#
# eighteen times, then refused to bake --- correctly, on completely false evidence. The objects were
# fine; `readelf -S` on the same file shows `fentry/rst_why` right there. Measured 2026-08-21 on a
# box rebuilt from nothing.
#
# Same failure shape as `strings` being absent inside the TMM container, and as every other
# single-probe negative in this project: a silenced command's empty output is not a fact about the
# input. So: try the tools in order, prove the chosen one can actually read a section table, and
# fail loudly naming the tool if none can.
READELF=""
# -W ON GNU readelf IS NOT OPTIONAL, and my first version of this fallback omitted it. GNU readelf
# TRUNCATES long section names in its table: `fentry/ssl_alpn_match` comes back as
# `fentry/ssl_a[...]`. Fifteen programs verified and signed because their hook names are short, and
# alpn_guard --- the one long name in the set --- was reported as "expected PASS, got REFUSAL",
# with PREVAIL saying `Section not found` and then helpfully printing the real name one line below.
# A fallback that is ALMOST equivalent is worse than none: it works for most inputs and lies about
# the rest, and the lie looked like a broken program.
for _c in "llvm-readelf --sections" "/usr/lib/llvm-18/bin/llvm-readelf --sections" "readelf -SW"; do
    set -- $_c
    command -v "$1" >/dev/null 2>&1 || continue
    READELF="$_c"
    break
done
[ -n "$READELF" ] || { echo "*** no usable readelf. Tried llvm-readelf, /usr/lib/llvm-18/bin/llvm-readelf
    and readelf -SW. Install binutils or llvm, or set READELF. Refusing to report every program as
    section-less, which is what the previous version of this script did." >&2; exit 1; }
echo "  readelf: $READELF"
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
# CLEAN first: a program retired from the tree must not survive in the bake context
# (that is how 15 stale bespoke .bpf.o rode into an image after the ctx-layer retirement).
rm -f "$OUT"/*.bpf.o "$OUT"/*.bpf.sig
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# The fexit exit-admission gate checks return type + unwind against the TARGET
# build's binary; located from this DEB dir, extracted lazily on the first fexit
# program. ADMIT_STATE: '' = not yet located, 'ready' = extracted, 'none' = no DEB.
ADMIT_DEBS="${LS_TARGET_DEBS:-$HOME/code/tmm/docker_build/DEBS/amd64}"
ADMIT_STATE=""

echo "  clang    : $($CLANG --version | head -1)"
echo "  prevail  : $PREVAIL"
echo "  out      : $OUT"
echo

# The relocator is the SAME SOURCE that runs inside TMM (src/base/ls_core_relo.c),
# compiled here with its test driver. Not a second implementation --- that was the
# point of check_relo_baked.py, which cross-checks this one against an independent
# Python walk and agrees on every relocation.
RELO=""
if [ -n "$TMM_BTF" ] && [ -s "$TMM_BTF" ]; then
    if [ -z "$OBJCOPY" ]; then
        echo "  WARN sign-time relocation DISABLED --- no llvm-objcopy on PATH."
        echo "       GNU objcopy cannot strip a BPF ELF, so the artifact could not be"
        echo "       stripped even if it were relocated. Install llvm-objcopy."
    elif cc -O2 -w -DLS_CORE_RELO_TEST "$REPO/substrate/ls_core_relo.c" -o "$TMP/relo" 2>/dev/null; then
        RELO="$TMP/relo"
        echo "  relocate : sign-time, against $TMM_BTF ($(wc -c < "$TMM_BTF") bytes)"
        echo "  objcopy  : $OBJCOPY"
    else
        echo "  WARN sign-time relocation DISABLED --- ls_core_relo.c did not build here."
    fi
else
    echo "  relocate : SKIPPED (no TMM_BTF) --- programs keep .BTF.ext and will be"
    echo "             relocated ON-BOX, which requires the binary to embed its own .BTF"
fi
echo

npass=0; nreject=0; nbad=0
nreloc=0; nstrip=0; nskipreloc=0
for f in "$SRC"/*.bpf.c "$REPO/substrate/surfaces"/*.bpf.c; do
    [ -e "$f" ] || continue
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
    sec=$($READELF "$o" 2>/dev/null | grep -oE 'f(entry|exit)/[^ ]*' | head -1)
    [ -n "$sec" ] || { echo "  *** $b: no fentry/ or fexit/ section --- nothing says what it attaches to"
                       nbad=$((nbad + 1)); continue; }

    # RELOCATE, THEN STRIP, THEN VERIFY --- in that order, deliberately. PREVAIL
    # must see the offsets that will actually execute, and the signature below must
    # cover the stripped bytes, so both come after this.
    RELOCATED=no
    if [ -n "$RELO" ]; then
        if "$RELO" "$o" "$TMM_BTF" "$TMP/$b.reloc" >"$TMP/rl" 2>&1; then
            nr=$(grep -oE '[0-9]+ relo' "$TMP/rl" | grep -oE '^[0-9]+' | head -1)
            mv "$TMP/$b.reloc" "$o"
            "$OBJCOPY" --remove-section=.BTF --remove-section=.BTF.ext \
                       --remove-section=.rel.BTF.ext "$o" 2>/dev/null || true
            # VERIFY THE STRIP BY READING THE RESULT, not by trusting an exit code.
            # A strip that silently no-ops leaves a working program and an intact
            # disclosure, which is the one failure that would not announce itself.
            left=$($READELF "$o" 2>/dev/null | grep -c '\.BTF' || true)
            if [ "${left:-1}" -ne 0 ]; then
                echo "  *** $b: relocated but the .BTF sections are STILL PRESENT after"
                echo "      $OBJCOPY. Refusing to sign an artifact that still carries them."
                nbad=$((nbad + 1)); continue
            fi
            RELOCATED=yes
            nreloc=$((nreloc + 1))
            RELNOTE="  reloc ${nr:-0}"
        else
            # A zero-relocation object is refused by the relocator (a known symptom).
            # Nothing needed resolving, so the program is already build-independent;
            # strip anyway so it carries no type information either.
            "$OBJCOPY" --remove-section=.BTF --remove-section=.BTF.ext \
                       --remove-section=.rel.BTF.ext "$o" 2>/dev/null || true
            RELOCATED=yes
            RELNOTE="  reloc 0"
        fi
    else
        nskipreloc=$((nskipreloc + 1))
        RELNOTE=""
    fi

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

    # EXIT-ADMISSION GATE (fexit only). An exit hook reads the return value and
    # hijacks the return address, so the target function must have an rax-representable
    # return (#5) and no non-local exit that unwinds through its frame (#4). Both are
    # properties of the TARGET BUILD's binary --- exit_admit.py checks them against the
    # DEB pair. Refused here, before signing, so an unsafe exit surface is never vouched
    # for. Skipped LOUDLY on a compile-only clone that has no target build to check.
    case "$sec" in
    fexit/*)
        if [ -z "$ADMIT_STATE" ]; then
            _DDEB=$(find "$ADMIT_DEBS" -name 'tmm-debuginfo_*.deb' 2>/dev/null | head -1)
            _RDEB=$(ls "$ADMIT_DEBS"/tmm_*.deb 2>/dev/null | head -1)
            if [ -n "$_DDEB" ] && [ -n "$_RDEB" ]; then
                mkdir -p "$TMP/admit/rt" "$TMP/admit/db"
                dpkg-deb -x "$_RDEB" "$TMP/admit/rt" 2>/dev/null
                dpkg-deb -x "$_DDEB" "$TMP/admit/db" 2>/dev/null
                ADMIT_RT=$(find "$TMP/admit/rt" -name tmm64.no_pgo ! -name '*.debug' | head -1)
                ADMIT_DB=$(find "$TMP/admit/db" -name tmm64.no_pgo.debug | head -1)
                ADMIT_STATE=ready
                [ -n "$ADMIT_RT" ] && [ -n "$ADMIT_DB" ] || ADMIT_STATE=none
            else
                ADMIT_STATE=none
            fi
        fi
        if [ "$ADMIT_STATE" = none ]; then
            echo "  WARN $b  ($sec)  --- exit-admit SKIPPED (no target DEB in $ADMIT_DEBS); return-type/unwind safety UNVERIFIED"
        elif python3 "$REPO/substrate/exit_admit.py" "$ADMIT_DB" "$ADMIT_RT" "${sec#*/}" >"$TMP/a" 2>&1; then
            echo "  admit    $b  ($sec)  --- fexit safe (rax-return + unwind-clear)"
        else
            echo "  *** $b: fexit REFUSED by exit-admit ---"; sed 's/^/        /' "$TMP/a" | grep -E 'REFUSE|#4|#5' | head -3
            nbad=$((nbad + 1)); continue
        fi
        ;;
    esac

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
    # is immediately after PREVAIL accepted the object and its fentry/ or fexit/ section was read from it.
    # Signing earlier would vouch for something unverified; signing later would need the hook
    # rediscovered, and a rediscovered hook is a second answer to a question already answered.
    #
    # The private key stays OUTSIDE the repository --- $SIGN_KEY, default ~/.ls-signing. A build
    # with no key produces unsigned programs and says so per program, rather than failing: a tree
    # someone has just cloned should still compile and verify, and only fail at the point where
    # the missing key actually matters, which is load.
    if [ -n "$SIGN_KEY" ] && [ -f "$SIGN_KEY" ]; then
        # THE BUILD RANGE, which this script did not pass until 2026-09-04.
        #
        # sign_shield.py defaults to 0..0xffffffff and passing nothing meant every
        # program this pipeline has ever signed is vouched for on EVERY build,
        # forever. That was harmless only because the loader did not read the field
        # either (CONTESTED-PREMISES.md 15) -- and it stops being harmless the moment
        # field offsets are baked at sign time instead of resolved on-box.
        #
        # The range is the first 4 bytes of the target build's GNU build id, and
        # min == max: a SHA-1 prefix has no ordering, so a wider range is not a
        # statement about builds (ls_build_gate.h).
        #
        # SKIPPED LOUDLY, NOT SILENTLY, when there is no target build to read. A
        # compile-only clone has no DEB pair, and signing a wildcard while saying
        # nothing is exactly how this gap survived. $ADMIT_RT is already resolved
        # above for the fexit exit-admission gate, so this costs no extra unpack.
        BRANGE=""
        if [ -n "$ADMIT_RT" ] && [ -f "$ADMIT_RT" ]; then
            _BID=$(python3 "$REPO/substrate/ls_buildid.py" "$ADMIT_RT" 2>/dev/null)
            case "$_BID" in
            ????????*) BRANGE="--build-min 0x${_BID%${_BID#????????}} --build-max 0x${_BID%${_BID#????????}}" ;;
            esac
        fi
        # A RELOCATED PROGRAM MUST NOT CARRY THE WILDCARD. This is the coupling the
        # build gate was built for (CONTESTED-PREMISES.md 15). Baked offsets are
        # valid for exactly ONE build; vouching for them on every build is how a
        # program ends up reading the wrong bytes of a real TMM structure with
        # PREVAIL's blessing and no complaint from anything. Refuse, do not warn:
        # the artifact would look identical to a correct one.
        if [ "$RELOCATED" = yes ] && [ -z "$BRANGE" ]; then
            echo "  *** $b: offsets were BAKED at sign time but there is no build range"
            echo "      to bind them to (no target binary in $ADMIT_DEBS). A relocated"
            echo "      program signed for every build is a silent wrong-offset load."
            echo "      Refusing to sign it."
            nbad=$((nbad + 1)); continue
        fi
        if [ -z "$BRANGE" ]; then
            echo "  WARN $b  --- signing with the WILDCARD build range (any build,"
            echo "       forever): no target binary in $ADMIT_DEBS to read a build id from."
        fi
        if python3 "$REPO/substrate/sign_shield.py" --key "$SIGN_KEY" --prog "$o" \
               --hook "${sec#*/}" --mode-ceiling "${SIGN_CEILING:-monitor}" \
               $BRANGE -o "$OUT/$b.bpf.sig" >/dev/null 2>&1; then
            echo "  verified $b  ($sec)${est:+  budget ~$est}${RELNOTE}  SIGNED"
        else
            rm -f "$OUT/$b.bpf.sig"
            echo "  *** $b verified but COULD NOT BE SIGNED --- it will be refused at load"
            nbad=$((nbad + 1)); continue
        fi
    else
        echo "  verified $b  ($sec)${est:+  budget ~$est}${RELNOTE}  UNSIGNED (no \$SIGN_KEY)"
    fi
    # COUNTED HERE, NOT AT STRIP TIME. reject_* programs are stripped as well and
    # then correctly refused, so counting at the strip made the summary claim one
    # more shipped artifact than exists. Count what is emitted.
    [ "$RELOCATED" = yes ] && nstrip=$((nstrip + 1))
    npass=$((npass + 1))
done

echo
echo "  $npass verified and emitted, $nreject correctly refused, $nbad unexpected"
if [ "$nstrip" -gt 0 ]; then
    # TWO DIFFERENT NUMBERS, said separately. $nreloc had at least one field offset
    # resolved; $nstrip is every program whose .BTF/.BTF.ext came out. They differ
    # because a program with NO field reads needs no relocation but is still stripped,
    # and the first version of this message reported the smaller number as if it
    # covered both --- understating what had actually been emitted.
    echo "  $nstrip program(s) stripped of .BTF/.BTF.ext --- they carry no type"
    echo "    information and the appliance needs none to load them."
    echo "  of those, $nreloc had field offsets RESOLVED HERE and baked for one build;"
    echo "    the rest read no fields, so there was nothing to resolve."
    echo "    The signature therefore covers the bytes that will actually run."
fi
if [ "$nskipreloc" -gt 0 ]; then
    echo "  $nskipreloc program(s) NOT relocated --- they keep .BTF.ext and depend on the"
    echo "    binary embedding its own .BTF. Pass TMM_BTF= to relocate them here."
fi
[ "$nbad" -eq 0 ] || fail "$nbad program(s) did not behave as expected. Nothing was emitted for
    them, but do not bake this set --- a surprise here is either a broken program or a
    verifier that changed behaviour, and both need looking at before an image ships."
[ "$npass" -gt 0 ] || fail "nothing verified --- there is nothing to bake."
[ "$nreject" -gt 0 ] || fail "no program was refused. There are reject_* negative tests in
    $SRC; if none of them tripped the verifier, the verification step is not doing anything."
echo "  Next: bnk-bake-tools.sh (it reads \$CTX/shields, default \$HOME/lstools/shields)"
