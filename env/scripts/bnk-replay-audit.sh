#!/bin/sh
# Can this repository rebuild the environment? Answered by checking, not by reading.
#
#   bnk-replay-audit.sh          audit every claim the runbook makes that can be checked here
#
# WHAT THIS IS FOR. env/bnk-dev-runbook.md stands the environment up "from nothing", and has
# never been replayed from nothing --- both boxes were built incrementally over ten days. A full
# replay is blocked by two things this script cannot resolve (see §0 below), so this checks the
# half that IS checkable: does every file, script, symbol and command the runbook depends on
# actually exist, and could the TMM tree be reassembled from this repository if the build box
# vanished. That question is the reason substrate/.tree-expected-delta exists, and on 2026-08-21
# that file was 18 entries stale --- which is the kind of thing only a check finds.
#
# It deliberately changes NOTHING and provisions NOTHING.
set -e

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
BUILD_BOX="${BUILD_BOX:-starin@10.145.42.119}"
RUNBOOK="$REPO/env/bnk-dev-runbook.md"
MANIFEST="$REPO/substrate/.tree-expected-delta"
PASS=0; FAIL=0; BLOCK=0
ok()    { PASS=$((PASS+1));  printf "  ok     %s\n" "$1"; }
bad()   { FAIL=$((FAIL+1));  printf "  FAIL   %s\n" "$1"; [ -n "$2" ] && printf "         %s\n" "$2"; return 0; }
block() { BLOCK=$((BLOCK+1)); printf "  BLOCK  %s\n" "$1"; [ -n "$2" ] && printf "         %s\n" "$2"; return 0; }

echo "=== 0. what a full replay needs that is not obtainable from here"
# Stated first so a clean run below is not mistaken for "the replay works".
command -v openstack >/dev/null 2>&1 \
  && ok "openstack CLI present" \
  || block "openstack CLI absent --- §1 installs it, and §1 also needs credentials that do not exist here"
[ -f "$HOME/.config/openstack/clouds.yaml" ] \
  && ok "clouds.yaml present" \
  || block "no ~/.config/openstack/clouds.yaml" \
           "§1 builds it from clouds-sea.yaml, DOWNLOADED FROM THE HORIZON WEB UI by a person. Not scriptable."
block "quota" "§0: SEA allows 40 cores / 80 GB. The two live boxes are 32/64. A third
         datkube-dev-large (16/32) does NOT fit, so provisioning fresh boxes means DELETING the
         live ones --- the TMM tree, the toolchain image and the running cluster."

echo
echo "=== 1. every script the runbook tells you to run"
for f in $(grep -oE 'env/scripts/[a-zA-Z0-9._-]+' "$RUNBOOK" | sort -u); do
    [ -e "$REPO/$f" ] && ok "$f" || bad "$f is referenced by the runbook and does not exist"
done

echo
echo "=== 2. could the TMM tree be reassembled from this repo alone?"
# THE QUESTION THE MANIFEST EXISTS FOR. Every '??' entry is a file the substrate ADDS to a clean
# TMM tree, so every one must exist in substrate/ --- or be a documented generated artifact. A
# manifest entry with no source behind it is a file that would be lost.
missing=""; gen=""
while read -r st path; do
    [ "$st" = "??" ] || continue
    base=$(basename "$path")
    case "$base" in
        ls_shield_blob.h|ls_sig_pubkey.h)
            # Generated, and by what is named here so the claim is checkable rather than asserted.
            gen="$gen $base" ;;
        *_whitelist_x86_64.pre-ubpf)
            # Backups of F5 build config taken before the substrate touched it. They exist on the
            # tree side by design and have no source here.
            gen="$gen $base" ;;
        *)
            if [ -f "$REPO/substrate/$base" ]; then :; else missing="$missing $base"; fi ;;
    esac
done < "$MANIFEST"
if [ -z "$missing" ]; then
    ok "every added file in the manifest has its source in substrate/"
else
    bad "manifest entries with NO source in this repo:$missing" \
        "these would be lost if the build box died --- which is the exact question this file answers"
fi
ok "generated / tree-side-only, by design:$gen"

# And the other direction: a source in substrate/ that the tree should have but the manifest omits.
tree_c=$(grep -c '^?? src/base/ls_' "$MANIFEST" || true)
repo_c=$(ls "$REPO"/substrate/ls_*.c "$REPO"/substrate/ls_*.h 2>/dev/null | wc -l | tr -d ' ')
printf "  note   manifest lists %s added base/ls_* files; substrate/ holds %s ls_*.{c,h}\n" "$tree_c" "$repo_c"
printf "         (not equal by design --- some headers are consumed only by the checks here)\n"

echo
echo "=== 3. the three F5 files the substrate modifies, and whether their content is recoverable"
# The manifest records NAMES not diffs, on purpose: this repo pushes to GitHub and those files are
# F5 build configuration. So recoverability depends on the SUBSTANCE being written down elsewhere.
for claim in \
  "filelist:base/ls_audit.c:substrate/TMM-TREE-DELTA.md" \
  "whitelist:g_ls_audit:substrate/TMM-TREE-DELTA.md" \
  "compiler flag:fpatchable-function-entry:substrate/TMM-TREE-DELTA.md" ; do
    what=$(echo "$claim" | cut -d: -f1); needle=$(echo "$claim" | cut -d: -f2); doc=$(echo "$claim" | cut -d: -f3)
    grep -q -- "$needle" "$REPO/$doc" 2>/dev/null \
      && ok "$what: '$needle' is recorded in $doc" \
      || bad "$what: '$needle' appears NOWHERE in $doc --- the modification is not recoverable"
done

echo
echo "=== 4. does the live tree still match the manifest, both ways"
if sh "$REPO/env/scripts/bnk-check-tree-sync.sh" >/tmp/.ra 2>&1; then
    ok "$(grep VERDICT /tmp/.ra | sed 's/^ *//')"
else
    bad "tree and manifest disagree" "$(grep -E 'VERDICT|ONLY IN|DELTA:' /tmp/.ra | head -3)"
fi
rm -f /tmp/.ra

echo
echo "=== 5. the vendored dependencies, and the bootstrap that creates them"
[ -x "$REPO/bootstrap.sh" ] && ok "bootstrap.sh present and executable" \
                           || bad "bootstrap.sh missing --- a fresh clone cannot reach a clean check"
sh "$REPO/substrate/check_vendor_pin.sh" "$REPO" >/dev/null 2>&1 \
  && ok "vendored revisions match substrate/vendor.pins" \
  || bad "vendored revisions do NOT match the pins"

echo
echo "=== 6. the signing key, without which nothing can be signed"
[ -x "$REPO/env/scripts/bnk-init-signing-key.sh" ] \
  && ok "bnk-init-signing-key.sh present --- the key has a documented origin" \
  || bad "no documented way to create the signing key"

echo
echo "=== summary"
printf "  %d checked ok, %d failed, %d blocked on things not obtainable here\n" "$PASS" "$FAIL" "$BLOCK"
echo
echo "  BLOCKED is not PASSED. A full replay needs browser-issued credentials and enough quota"
echo "  to run a third box, and there is quota for neither. What this audit establishes is that"
echo "  the REPOSITORY half is complete --- not that the runbook has been replayed."
[ "$FAIL" -eq 0 ] || exit 1
