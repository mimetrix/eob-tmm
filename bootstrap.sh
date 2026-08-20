#!/bin/sh
# Turn a fresh clone of this repository into one whose checks run. THIS IS STEP ONE.
#
#   ./bootstrap.sh              fetch and build the vendored dependencies, then verify
#   ./bootstrap.sh --check      say what is missing and stop --- change nothing
#   ./bootstrap.sh --no-prevail skip PREVAIL (heavy: needs cmake, boost, yaml-cpp)
#   ./bootstrap.sh --from=DIR   clone from a local mirror --- for a host with no internet route
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
MIRROR=""
for a in "$@"; do
    case "$a" in
        --check)      MODE=check ;;
        --no-prevail) WANT_PREVAIL=0 ;;
        --from=*)     MIRROR=${a#--from=} ;;
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
# TRANSPORT DOES NOT MATTER; THE REVISION DOES. Observed on the first real run of this script:
# `git clone https://github.com/...` failed with "server certificate verification failed. CAfile:
# none" --- the host had no CA bundle, while ssh to the same host worked. A reproduction
# environment is exactly where that is normal: no CA store, an egress proxy, or no internet at all.
#
# So each origin is tried over HTTPS, then over ssh, then from a local mirror given as
# --from=<dir>. That is not a weakening of provenance, and it is worth being precise about why:
# the identity of what you get is established by comparing HEAD to the pinned SHA-1 afterwards,
# and check_vendor_pin.sh then re-checks it independently. A transport chooses who you talk to; the
# hash decides whether you got the right bytes.
ssh_form() {
    # https://github.com/o/r.git -> git@github.com:o/r.git
    printf '%s' "$1" | sed -e 's|^https://\([^/]*\)/|git@\1:|'
}

try_clone() {
    _origin="$1"; _dest="$2"; _name="$3"
    if [ -n "$MIRROR" ] && [ -d "$MIRROR/$(basename "$_dest")" ]; then
        info "cloning $_name from the mirror $MIRROR/$(basename "$_dest")"
        if git clone -q "$MIRROR/$(basename "$_dest")" "$_dest"; then
            # POINT ORIGIN BACK AT THE CANONICAL URL. check_vendor_pin.sh asserts the origin, not
            # just the revision, and it is right to: "we have these bytes" and "these bytes came
            # from upstream" are different claims, and a tree whose origin is a path on somebody's
            # laptop cannot support the second. The first run of this script left origin pointing
            # at the mirror and the pin check failed --- correctly. Recording the canonical origin
            # keeps that check strict while letting an offline host bootstrap at all.
            git -C "$_dest" remote set-url origin "$_origin"
            info "  origin recorded as $_origin (cloned via the mirror; the pin is checked next)"
            return 0
        fi
    fi
    info "cloning $_name from $_origin"
    git clone -q "$_origin" "$_dest" 2>/tmp/.bs_err && return 0
    _e=$(tail -1 /tmp/.bs_err 2>/dev/null)
    info "  https failed: $_e"
    _ssh=$(ssh_form "$_origin")
    if [ "$_ssh" != "$_origin" ]; then
        info "  retrying over ssh: $_ssh"
        rm -rf "$_dest"
        git clone -q "$_ssh" "$_dest" 2>/tmp/.bs_err && return 0
        info "  ssh failed: $(tail -1 /tmp/.bs_err 2>/dev/null)"
    fi
    rm -rf "$_dest"
    return 1
}

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
        try_clone "$_origin" "$ROOT/$_dir" "$_name" || fail "could not clone $_name.
    Tried $_origin over https and over ssh. If this host has no route to the internet, mirror the
    two repositories somewhere reachable and pass:
        ./bootstrap.sh --from=/path/containing/$_dir
    The pin is verified against the SHA-1 either way, so where the bytes came from does not change
    whether they are the right ones."
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
# EXIT CODE, NOT JUST OUTPUT. The first version piped this through sed, which swallowed the
# failure --- the script printed "*** uBPF origin is ..." and carried on to report success. A
# verification step whose result is discarded is decoration.
[ "$WANT_PREVAIL" -eq 0 ] && export PIN_SKIP_PREVAIL=1
if sh "$ROOT/substrate/check_vendor_pin.sh" "$ROOT" > /tmp/.bs_pin 2>&1; then
    sed 's/^/  /' /tmp/.bs_pin
else
    sed 's/^/  /' /tmp/.bs_pin
    rm -f /tmp/.bs_pin
    fail "the vendored trees are NOT the revisions this repository pins. Do not build on them ---
    the whole point of the pin is that what runs here is what the documents describe."
fi
rm -f /tmp/.bs_pin

say "=== 7. now run the checks"
info "make -C substrate check"
info ""
info "If a target still fails on a missing header, that is a real gap in this script rather"
info "than something to work around --- say so, because the whole point is that a clean clone"
info "reaches a clean check."
