#!/bin/sh
# Turn a fresh clone of this repository into one whose checks run. THIS IS STEP ONE.
#
#   ./bootstrap.sh              fetch and build the vendored dependencies, then verify
#   ./bootstrap.sh --check      say what is missing and stop --- change nothing
#   ./bootstrap.sh --no-prevail skip PREVAIL (heavy: needs cmake, boost, yaml-cpp)
#
# WHY THIS EXISTS, measured 2026-08-20. A fresh clone of this repository does NOT pass its own
# checks. `make -C substrate check` fails four targets --- check-skeletons, check-vm, check-map,
# check-glue --- every one on `fatal error: ubpf.h: No such file or directory`, three screens down
# in the output of a target that had already printed forty "ok" lines. REPRODUCING.md said the
# checks run "on any Linux host with a C compiler, Python 3 and clang". That was false, and it was
# false in the document whose entire job is telling someone how to reproduce this.
#
# The cause is not an oversight so much as a blind spot: uBPF and PREVAIL are vendored and
# gitignored, so they are present on every machine this work was done on and absent from every
# machine it would be reproduced on. Nothing in the repository could notice, because everything
# that would notice was running where they existed.
#
# WHAT IS AND IS NOT FETCHED HERE. Source only, at pinned revisions, from the upstream origins ---
# never a prebuilt artifact. Both libraries are built from that source on this machine. A binary
# of unknown provenance inside a security appliance is not a shortcut, it is the thing the
# signature work exists to prevent.
#
# WHAT THIS CANNOT DO, so that nobody reads a clean run as more than it is: it prepares the
# BENCH HARNESSES. It does not build TMM, and it cannot --- that needs F5's TMM source tree, the
# toolchain container and credentials none of which live here. See REPRODUCING.md for the boundary
# and env/bnk-dev-runbook.md for the far side of it.
set -e

ROOT=$(cd "$(dirname "$0")" && pwd)
PINS="$ROOT/substrate/vendor.pins"
MODE=""
WANT_PREVAIL=1
for a in "$@"; do
    case "$a" in
        --check)      MODE=check ;;
        --no-prevail) WANT_PREVAIL=0 ;;
        -h|--help)    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)            echo "*** unknown option $a" >&2; exit 2 ;;
    esac
done

[ -f "$PINS" ] || { echo "*** no $PINS --- is this the repository root?" >&2; exit 2; }
. "$PINS"

say()  { printf '\n%s\n' "$*"; }
info() { printf '  %s\n' "$*"; }
fail() { printf '*** %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------------------------
say "=== 1. host tools"
# CHECKED BY CAPABILITY, and clang's BPF target is checked by USE rather than by version. A clang
# built without the BPF backend is installed, on PATH, and answers --version perfectly while
# being unable to compile a single one of the programs here.
MISSING=""
for t in git cc python3 make; do
    have "$t" && info "$(printf '%-11s %s' "$t" "$(command -v $t)")" || MISSING="$MISSING $t"
done
if have clang; then
    if echo 'int f(void){return 0;}' | clang -target bpf -c -x c - -o /dev/null 2>/dev/null; then
        info "clang       $(command -v clang)  (BPF target works)"
    else
        info "clang       present, but its BPF target does NOT work --- the shield programs"
        info "            cannot be compiled. check-shields will skip loudly."
    fi
else
    info "clang       ABSENT --- check-shields and the shield programs will skip"
fi
[ -z "$MISSING" ] || fail "missing host tools:$MISSING"
have cmake || info "cmake       ABSENT --- needed to configure uBPF (ubpf_config.h is generated)"

# ---------------------------------------------------------------------------------------------
say "=== 2. what the checks need, and whether it is here"
NEED=0
report() {
    if [ -e "$ROOT/$2" ]; then info "have    $1"
    else                        info "MISSING $1   ($2)"; NEED=1; fi
}
report "uBPF source (ubpf.h)"                "$UBPF_DIR/vm/inc/ubpf.h"
report "uBPF configured (ubpf_config.h)"     "$UBPF_DIR/build/vm/ubpf_config.h"
report "PREVAIL source"                      "$PREVAIL_DIR/CMakeLists.txt"
report "PREVAIL built (bin/prevail)"         "$PREVAIL_DIR/bin/prevail"
if [ "$NEED" -eq 0 ]; then
    info "nothing to fetch."
fi
if [ "$MODE" = check ]; then
    say "=== --check given, so nothing was changed."
    [ "$NEED" -eq 0 ] && exit 0 || exit 1
fi

# ---------------------------------------------------------------------------------------------
say "=== 3. fetch, at the pinned revisions"
# CLONE THEN CHECKOUT, not --depth 1 --branch, because a pin is a REVISION and a shallow clone of
# a branch may not contain it. Bandwidth is not the scarce resource here; being able to state
# exactly what was built is.
fetch() {
    _dir="$1"; _origin="$2"; _pin="$3"; _name="$4"
    if [ -d "$ROOT/$_dir/.git" ]; then
        _head=$(git -C "$ROOT/$_dir" rev-parse HEAD)
        if [ "$_head" = "$_pin" ]; then info "$_name already at $_pin"; return 0; fi
        info "$_name is at $_head, pin is $_pin --- fetching the pin"
        git -C "$ROOT/$_dir" fetch -q origin "$_pin" 2>/dev/null \
          || git -C "$ROOT/$_dir" fetch -q origin
        git -C "$ROOT/$_dir" checkout -q "$_pin"
    else
        [ -e "$ROOT/$_dir" ] && fail "$ROOT/$_dir exists and is not a git checkout. Move it aside;
    this script will not delete anything it did not create."
        info "cloning $_name from $_origin"
        git clone -q "$_origin" "$ROOT/$_dir"
        git -C "$ROOT/$_dir" checkout -q "$_pin"
    fi
    _got=$(git -C "$ROOT/$_dir" rev-parse HEAD)
    [ "$_got" = "$_pin" ] || fail "$_name checked out $_got, wanted $_pin"
    info "$_name at $_got"
}
fetch "$UBPF_DIR" "$UBPF_ORIGIN" "$UBPF_PIN" uBPF
[ "$WANT_PREVAIL" -eq 1 ] && fetch "$PREVAIL_DIR" "$PREVAIL_ORIGIN" "$PREVAIL_PIN" PREVAIL \
                          || info "PREVAIL skipped (--no-prevail)"

# ---------------------------------------------------------------------------------------------
say "=== 4. configure uBPF --- ubpf_config.h is GENERATED and four checks include it"
# The header the failing targets could not find is ubpf.h, which exists in the source tree. The
# one that only exists after cmake runs is ubpf_config.h, and it is the reason "just clone it" is
# not enough. Two include paths, and both are needed: vm/inc for the API, build/vm for the
# generated configuration.
if [ -f "$ROOT/$UBPF_DIR/build/vm/ubpf_config.h" ]; then
    info "already configured"
else
    have cmake || fail "cmake is needed to generate ubpf_config.h, and four checks include it.
    Install cmake, or run with the include path pointed at an existing configured tree."
    ( cd "$ROOT/$UBPF_DIR" && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
        -DUBPF_ENABLE_TESTS=OFF -DUBPF_SKIP_EXTERNAL=ON \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON >/dev/null 2>&1 ) \
      || fail "cmake configure failed in $UBPF_DIR --- rerun it by hand to see why:
    cd $UBPF_DIR && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DUBPF_ENABLE_TESTS=OFF"
    [ -f "$ROOT/$UBPF_DIR/build/vm/ubpf_config.h" ] || fail "cmake ran but did not produce
    build/vm/ubpf_config.h. The layout may have moved between revisions; find it and point the
    Makefile's include path at it rather than assuming."
    info "generated build/vm/ubpf_config.h"
fi
# The library itself, for anything that links rather than only includes. Cheap next to a wrong
# conclusion, and the failure is reported rather than ignored.
if [ ! -f "$ROOT/$UBPF_DIR/build/lib/libubpf.a" ]; then
    ( cd "$ROOT/$UBPF_DIR" && cmake --build build -j"$(nproc 2>/dev/null || echo 2)" >/dev/null 2>&1 ) \
      && info "built libubpf.a" \
      || info "libubpf.a did NOT build --- header-only checks still work; anything that links will not"
fi

# ---------------------------------------------------------------------------------------------
say "=== 5. PREVAIL"
if [ "$WANT_PREVAIL" -eq 0 ]; then
    info "skipped. check-shields will skip loudly, which is not the same as passing."
elif [ -x "$ROOT/$PREVAIL_DIR/bin/prevail" ]; then
    info "already built: $("$ROOT/$PREVAIL_DIR/bin/prevail" --version 2>&1 | head -1)"
else
    info "building --- this is the slow part (a few minutes, and it needs boost and yaml-cpp)"
    if ( cd "$ROOT/$PREVAIL_DIR" && cmake -B build -DCMAKE_BUILD_TYPE=Release >/dev/null 2>&1 \
         && cmake --build build -j"$(nproc 2>/dev/null || echo 2)" >/dev/null 2>&1 ); then
        info "built: $("$ROOT/$PREVAIL_DIR/bin/prevail" --version 2>&1 | head -1)"
    else
        info "PREVAIL did NOT build. Everything else still works; check-shields will skip."
        info "Most often this is a missing dependency --- on Debian/Ubuntu:"
        info "    sudo apt-get install libboost-dev libyaml-cpp-dev"
        info "Rerun by hand to see the real error:"
        info "    cd $PREVAIL_DIR && cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build"
    fi
fi

# ---------------------------------------------------------------------------------------------
say "=== 6. verify the revisions are what the repository claims"
sh "$ROOT/substrate/check_vendor_pin.sh" "$ROOT" | sed 's/^/  /'

say "=== 7. now run the checks"
info "make -C substrate check"
info ""
info "If a target still fails on a missing header, that is a real gap in this script rather"
info "than something to work around --- say so, because the whole point is that a clean clone"
info "reaches a clean check."
