#!/bin/sh
# Assert the vendored dependencies are the revisions we say they are.
#
#   check_vendor_pin.sh [repo-root]
#
# WHY THIS EXISTS. Four documents recorded the borrowed-code provenance and they disagreed with
# each other and with the tree. REPRODUCING.md and DOC-STATUS.md said the uBPF revision "cannot
# be stated" because the vendored copy has no version-control history; the architect brief and
# DOC-STATUS said the PREVAIL binary "reports v0.2.6". Checked 2026-08-20: the vendored copies in
# this repo DO carry git history, the uBPF revision is exactly the c900ed9 the docs also cite, and
# the PREVAIL binary reports v0.2.5 --- matching its own checkout. The "cannot be stated" claim
# was about a DIFFERENT copy, the build box's ~/code/tmm/.ubpf, which is a git-less extract.
#
# A prose pin drifts because nothing compares it to anything. This does.
#
# WHAT IS PINNED, and the distinction matters for a Threat Model review:
#
#   uBPF     iovisor/ubpf @ c900ed9f, PLUS substrate/ubpf-patches/0001-jit-scratch-rightsize.patch.
#            The vendored source tree is UNPATCHED --- the patch is applied when the library TMM
#            links is built, so the tree and the artifact are deliberately not the same thing.
#   PREVAIL  vbpf/ebpf-verifier @ 06769f7b (tag v0.2.5), UNMODIFIED. No patch, no fork.
#
# The patch applying cleanly to the pinned revision is the load-bearing check: it is what makes
# "base plus this diff" a reproducible statement rather than an assertion about a binary nobody
# can rebuild.
set -e

ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"

# THE PINS COME FROM ONE FILE, which bootstrap.sh also reads. They used to be constants here, and
# bootstrap.sh would have needed the same four values to CREATE the tree this script verifies ---
# two copies of a pin is exactly how the original disagreement between four documents started.
PINS="$ROOT/substrate/vendor.pins"
[ -f "$PINS" ] || { echo "*** no $PINS --- the pins have no single definition" >&2; exit 1; }
. "$PINS"
PATCHES="$ROOT/substrate/ubpf-patches"
for v in UBPF_PIN UBPF_ORIGIN PREVAIL_PIN PREVAIL_TAG PREVAIL_ORIGIN; do
    eval "_val=\$$v"
    [ -n "$_val" ] || { echo "*** $PINS does not define $v" >&2; exit 1; }
done

fail() { echo "*** $*" >&2; exit 1; }
n=0

check_repo() {
    _dir="$1"; _pin="$2"; _origin="$3"; _name="$4"
    [ -d "$ROOT/$_dir" ] || fail "$_name: no $ROOT/$_dir"
    [ -d "$ROOT/$_dir/.git" ] || fail "$_name: $_dir has no git history, so its revision cannot be
    established from the tree. That is the exact hole this check exists to close --- do not
    replace it with a comment."
    _head=$(git -C "$ROOT/$_dir" rev-parse HEAD)
    [ "$_head" = "$_pin" ] || fail "$_name revision drift:
    pinned  $_pin
    tree    $_head
    Either the checkout moved or the pin in this script is stale. Decide which, and change the
    other --- a mismatch here means every reproduction instruction in the repo is wrong."
    _url=$(git -C "$ROOT/$_dir" config --get remote.origin.url || echo "")
    [ "$_url" = "$_origin" ] || fail "$_name origin is $_url, pinned as $_origin"
    echo "  ok    $_name  $_pin  (from $_origin)"
}

check_repo ubpf          "$UBPF_PIN"    "$UBPF_ORIGIN"    "uBPF   "; n=$((n+1))

# PREVAIL CAN BE DELIBERATELY ABSENT, and that must not read the same as drift. bootstrap.sh
# --no-prevail exists because PREVAIL needs boost and yaml-cpp and takes minutes, and a host
# without them can still run every other check. So: absent-and-declared is a SKIP that says so,
# absent-and-undeclared is a failure. What is never allowed is absent-and-silent.
#
# PIN_SKIP_PREVAIL=1 is the declaration. It is a word from the caller, not an inference from the
# filesystem: inferring it would turn a genuinely missing dependency into a clean run.
if [ "${PIN_SKIP_PREVAIL:-0}" = "1" ] && [ ! -d "$ROOT/ebpf-verifier" ]; then
    echo "  SKIP  PREVAIL --- not present, and PIN_SKIP_PREVAIL=1 says that is intended."
    echo "        check-shields will skip too. A skipped verifier is not a passing verifier."
else
    check_repo ebpf-verifier "$PREVAIL_PIN" "$PREVAIL_ORIGIN" "PREVAIL"; n=$((n+1))

    # PREVAIL's tag, because a revision is precise and a tag is what a human quotes.
    _tag=$(git -C "$ROOT/ebpf-verifier" describe --tags --exact-match HEAD 2>/dev/null || echo "")
    [ "$_tag" = "$PREVAIL_TAG" ] || fail "PREVAIL is at revision $PREVAIL_PIN but describes as
    '${_tag:-<no exact tag>}', pinned as $PREVAIL_TAG."
    echo "  ok    PREVAIL tag $PREVAIL_TAG matches the pinned revision"; n=$((n+1))
fi

# PREVAIL MUST BE UNMODIFIED. The whole verification argument rests on it being the upstream
# verifier; a local change would have to be disclosed in a TMA, so it is checked rather than
# promised.
if [ "${PIN_SKIP_PREVAIL:-0}" = "1" ] && [ ! -d "$ROOT/ebpf-verifier" ]; then
    _dirty=0
else
_dirty=$(git -C "$ROOT/ebpf-verifier" status --porcelain --untracked-files=no | wc -l)
[ "$_dirty" -eq 0 ] || fail "PREVAIL has $_dirty modified tracked file(s). It is documented as
    unmodified, and 'we use the upstream verifier' is a claim a security review will test."
echo "  ok    PREVAIL is unmodified (no tracked file differs)"; n=$((n+1))
fi

# uBPF: the tree is expected UNPATCHED, and the patch is expected to apply to it.
_udirty=$(git -C "$ROOT/ubpf" status --porcelain --untracked-files=no | wc -l)
[ "$_udirty" -eq 0 ] || fail "the vendored uBPF tree has $_udirty modified tracked file(s).
    It is documented as a clean checkout with the patch applied at BUILD time; a modified tree
    means the source and the recorded patch no longer describe the artifact together."
echo "  ok    uBPF tree is a clean checkout of the pinned revision"; n=$((n+1))

[ -d "$PATCHES" ] || fail "no $PATCHES"
_np=0
for p in "$PATCHES"/*.patch; do
    [ -f "$p" ] || continue
    _np=$((_np + 1))
done
[ "$_np" -gt 0 ] || fail "no patches in $PATCHES, but uBPF is documented as carrying one.
    If the patch was upstreamed, remove the claim as well as the file."

# THE LOAD-BEARING CHECK. Export the pinned revision, apply every recorded patch to it, and
# require a clean apply. That is what makes "c900ed9 plus these diffs" reproducible.
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
git -C "$ROOT/ubpf" archive HEAD | tar x -C "$TMP"
for p in "$PATCHES"/*.patch; do
    [ -f "$p" ] || continue
    ( cd "$TMP" && patch -p0 -s --dry-run < "$p" ) 2>&1 || fail "$(basename "$p") does not apply
    cleanly to $UBPF_PIN. The pin and the patch disagree, so nobody can rebuild the library TMM
    links from what this repo records."
    ( cd "$TMP" && patch -p0 -s < "$p" )
    echo "  ok    $(basename "$p") applies cleanly to the pinned revision"; n=$((n+1))
done

echo "  ok    check_vendor_pin: $n assertions"
