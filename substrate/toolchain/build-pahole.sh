#!/bin/bash
# Build the patched pahole this project's BTF generation needs, to a stable path.
#
# WHY PATCHED. TMM's DWARF contains _Atomic-qualified types (our ls_ring/ls_tp_seg)
# that stock pahole (through v1.29) refuses ("Unsupported DW_TAG_atomic_type"),
# aborting the encode and dropping those structs. The one-line patch in
# pahole-atomic-qualifier.patch maps the atomic qualifier to BTF_KIND_VOLATILE
# --- layout-identical and skipped by CO-RE modifier resolution. Combined with
# --lang_exclude=c++ (TMM embeds Tcl/STL C++ that BTF cannot represent) this yields
# a clean, complete BTF of the C surfaces. See co-re-plan.md Phase 2.
#
# Idempotent: if $OUT/pahole already runs, does nothing. Prints the pahole path on
# stdout (last line) so callers can `PAHOLE=$(build-pahole.sh)`.
set -eu
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${LS_PAHOLE_DIR:-$HOME/.cache/ls-pahole}"
PATCH="$REPO/substrate/toolchain/pahole-atomic-qualifier.patch"
TAG="v1.29"

if [ -x "$OUT/build/pahole" ] && LD_LIBRARY_PATH="$OUT/build" "$OUT/build/pahole" --version >/dev/null 2>&1; then
    echo "$OUT/build/pahole"; exit 0
fi
command -v cmake git gcc >/dev/null || { echo "*** need cmake/git/gcc to build pahole" >&2; exit 1; }
pkg-config --exists libdw libelf 2>/dev/null || {
    echo "*** need libdw-dev + libelf-dev (sudo apt-get install -y libdw-dev libelf-dev zlib1g-dev)" >&2; exit 1; }
[ -f "$PATCH" ] || { echo "*** missing $PATCH" >&2; exit 1; }

rm -rf "$OUT"; mkdir -p "$OUT"
git clone --quiet --recurse-submodules --depth 1 --branch "$TAG" \
    https://github.com/acmel/dwarves.git "$OUT" >&2
git -C "$OUT" apply "$PATCH" >&2 || { echo "*** patch did not apply to dwarves $TAG" >&2; exit 1; }
mkdir -p "$OUT/build"
( cd "$OUT/build" && cmake -D__LIB=lib -DCMAKE_BUILD_TYPE=Release .. >/dev/null 2>&1 && make -j"$(nproc)" >/dev/null 2>&1 ) \
    || { echo "*** pahole build failed" >&2; exit 1; }
[ -x "$OUT/build/pahole" ] || { echo "*** pahole did not build" >&2; exit 1; }
echo "$OUT/build/pahole"
