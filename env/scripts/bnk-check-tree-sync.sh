#!/bin/sh
# Do the repo and the TMM build tree hold the same substrate sources?
#
# WHY THIS EXISTS. On 2026-08-17 the five uBPF registration calls that make eBPF
# maps work existed ONLY in the build box's copy of ls_vm.c. They had been written
# there directly and never carried back. Copying the repo's substrate/ over that
# tree -- the routine step before every build -- deleted them.
#
# Nothing failed. Programs loaded, PREVAIL verified them, they ran, and every map
# lookup returned NULL, which is indistinguishable from a program whose predicate
# never matches. The live "maps work in TMM" result had come from an earlier image
# that still had the calls; the tree that replaced it looked identical.
#
# The other two guards cannot see this one. bnk-verify-artifact.sh asks whether the
# BINARY contains the change -- and it did, at the time. bnk-check-deployed.sh asks
# whether the cluster runs the last local build -- and it did. Both compare
# downstream of the tree. This compares the tree itself, and it is the only one of
# the three that catches a source file that is about to be overwritten.
#
#   bnk-check-tree-sync.sh              compare, report, exit 1 on any difference
#   bnk-check-tree-sync.sh -v           also print the diffs
#
# SEARCHES THE WHOLE TREE, BY FILENAME. The first version of this script looked
# only in src/base and reported ls_ctx_alpn.c as "never copied to the tree" when it
# was in fact compiled from src/modules/hudfilter/ssl -- substrate files land in
# whichever include world their hook lives in. A guard that reports a false absence
# gets ignored, which is worse than not having it.
#
# RUN IT BEFORE COPYING, NOT AFTER. After the copy the evidence is gone: the tree
# matches the repo because the repo just overwrote it.
#
# A difference is not automatically wrong -- a deliberate experiment in the tree is
# a legitimate reason for one. What is never right is not knowing. Resolve each
# difference in a direction you chose: carry it back to the repo, or discard it.
set -e

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
BUILD_BOX="${BUILD_BOX:-starin@10.145.37.36}"   # eob-bnk-build-01; .42.119 retired (SSH refused 2026-08-26)
TREE="${TREE:-\$HOME/code/tmm/src}"
VERBOSE=""
[ "$1" = "-v" ] && VERBOSE=1

SRC="$REPO/substrate"
[ -d "$SRC" ] || { echo "*** no substrate/ under $REPO" >&2; exit 2; }

TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT

echo "  repo : $SRC"
echo "  tree : $BUILD_BOX:$TREE"
echo

mkdir -p "$TMPD/tree"

# Locate every substrate-shaped file anywhere under the tree and tar it up with a
# flat name, in ONE round trip. Object directories are excluded: a copy of a header
# under obj_x86_64.* is build output, not a source of truth, and matching it would
# report in-sync against the very thing that gets rebuilt.
#
# Flattening to basenames means a file copied into TWO include worlds collapses to
# one entry and only the first is compared. That is reported below rather than
# hidden, because two copies of one header in a build is itself a defect.
# Two things this deliberately does NOT do: write to a fixed filename under the
# build box's /tmp, and leave anything behind. An earlier version used
# /tmp/.tsync_paths, which both littered a shared box and raced a second
# concurrent run. mktemp plus a trap on the remote side, so a guard about stale
# artifacts stops creating them.
ssh -o StrictHostKeyChecking=no "$BUILD_BOX" "
    cd $TREE 2>/dev/null || exit 1
    L=\$(mktemp) || exit 1
    trap 'rm -f \"\$L\"' EXIT INT TERM
    find . \( -name 'obj_*' -o -name 'BUILD_*' \) -prune -o \
         -type f \( -name 'ls_*.c' -o -name 'ls_*.h' -o -name 'vm_stack_policy.h' \) -print \
      2>/dev/null > \"\$L\"
    tar cf - --transform 's|.*/||' -T \"\$L\" 2>/dev/null
    { echo '--PATHS--'; cat \"\$L\"; } >&2
" > "$TMPD/tree.tar" 2>"$TMPD/stderr" || true

if [ ! -s "$TMPD/tree.tar" ]; then
    echo "  VERDICT : CANNOT COMPARE --- nothing readable under $TREE. Treat as diverged."
    exit 1
fi
tar xf "$TMPD/tree.tar" -C "$TMPD/tree" 2>/dev/null || true

# Where each file actually lives, so a difference can be resolved without hunting.
# Carried back on stderr in the SAME round trip as the tar --- one ssh instead of
# two, and no remote file to leave behind.
sed -n '/^--PATHS--$/,$p' "$TMPD/stderr" 2>/dev/null | tail -n +2 > "$TMPD/paths" || : > "$TMPD/paths"

# -F because a basename is a literal, not a pattern: "ls_vm.c" as a regex also
# matches ls_vmXc. Anchored by prefixing the separator and comparing the tail.
# The i > 0 test is load-bearing. index() returns 0 when the basename is not in
# the line, and when the basename is LONGER than the line
# length($0) - length(b) + 1 is also <= 0 --- so 0 == 0 matched, and this reported
# base/ls_tp.h as the home of ls_tramp_asm.c. Caught by deleting a file from a
# throwaway copy of the repo and reading the output, which is the only reason it
# was caught at all.
where() {
    awk -v b="/$1" '{ i = index($0, b)
                      if (i > 0 && i == length($0) - length(b) + 1) {
                          sub(/^\.\//, ""); print; exit
                      } }' "$TMPD/paths" 2>/dev/null
}

# How many tree paths share a basename --- see the flattening note above.
dupes() {
    awk -F/ '{ print $NF }' "$TMPD/paths" 2>/dev/null | sort | uniq -d
}

differ=0
only_tree=0
only_repo=0
acked=0

# Differences that are known and chosen. Reported, never silent, but not a
# failure --- see substrate/.tree-sync-known for why that distinction matters.
KNOWN="$SRC/.tree-sync-known"
is_known() { [ -f "$KNOWN" ] && awk -v b="$1" '$1 == b { found = 1 } END { exit !found }' "$KNOWN"; }
known_why() { awk -v b="$1" '$1 == b { $1 = ""; sub(/^ +/, ""); print; exit }' "$KNOWN" 2>/dev/null; }

for f in "$TMPD"/tree/*; do
    [ -f "$f" ] || continue
    b=$(basename "$f")
    if [ ! -f "$SRC/$b" ]; then
        printf '  ONLY IN TREE   %-24s <-- on the build box, NOT in git: %s\n' "$b" "$(where "$b")"
        only_tree=$((only_tree + 1))
        differ=1
        continue
    fi
    if ! cmp -s "$f" "$SRC/$b"; then
        # A GENERATED file differs because it was generated from different input.
        # Say so, because "hand-carry the tree's version back" is the wrong repair
        # for one -- but do NOT excuse it: ls_shield_blob.h is what TMM arms at
        # startup, so a stale one in the tree means a stale shield in the binary.
        if is_known "$b"; then
            printf '  ACKNOWLEDGED   %-24s %s\n' "$b" "$(known_why "$b" | cut -c1-70)"
            acked=$((acked + 1))
            continue
        fi
        if head -3 "$SRC/$b" | grep -qi 'GENERATED'; then
            printf '  DIFFERS (gen)  %-24s %s\n' "$b" "regenerate, do not hand-merge"
            differ=1
            continue
        fi
        # Which side has more lines is a hint, not a verdict -- say which, and
        # let the person reading decide. Silence here is what cost the calls.
        rl=$(wc -l < "$SRC/$b")
        tl=$(wc -l < "$f")
        printf '  DIFFERS        %-24s repo=%-5s tree=%-5s  %s\n' "$b" "$rl" "$tl" "$(where "$b")"
        [ -n "$VERBOSE" ] && diff -u "$SRC/$b" "$f" | sed 's/^/        /' | head -60
        differ=1
    fi
done

# The reverse direction matters too: a repo file with no counterpart in the tree
# has never been compiled, so anything claimed about it is untested.
for f in "$SRC"/ls_*.c "$SRC"/ls_*.h; do
    [ -f "$f" ] || continue
    b=$(basename "$f")
    case "$b" in
        ls_ctx_*_bpf.h) continue ;;   # program-side headers, never in the tree
        ls_json.h)                    # JSON escaping for the drain agent's output.
            continue ;;               # Host-side only --- included by ls_drain.c and
                                      # check_json.c, never by anything TMM compiles.
                                      # TMM emits binary; nothing in it formats JSON.
        ls_tp_http.h)                 # HTTP record schema: read by the drain agent,
            continue ;;               # check_tp.c and the .bpf.c programs. The
                                      # tracepoint that emitted those records was
                                      # rolled back out of the tree, so absent there
                                      # is correct. Named, not pattern-matched.
    esac
    if [ ! -f "$TMPD/tree/$b" ]; then
        printf '  ONLY IN REPO   %-24s <-- never copied to the tree, so never built\n' "$b"
        only_repo=$((only_repo + 1))
        differ=1
    fi
done

# ---- the tree DELTA, not just the substrate file contents -------------------
#
# Everything above compares files we own. It cannot see the other half of the
# integration: the four F5 files we MODIFY, and any file we add that does not match
# the ls_* naming pattern. harness.c hid in exactly that gap --- it existed only on
# the build box and no check looked for it.
#
# So compare the tree's own change list against a manifest, both ways. Names and
# status only; the diffs of F5 files are deliberately not stored (see the manifest).
EXPECT="$SRC/.tree-expected-delta"
if [ -f "$EXPECT" ]; then
    ssh -o StrictHostKeyChecking=no "$BUILD_BOX" \
        "cd $TREE/.. 2>/dev/null && git status --porcelain src/ 2>/dev/null" \
        | sed 's/^ *//' | sort > "$TMPD/actual_delta" 2>/dev/null || : > "$TMPD/actual_delta"
    grep -v '^#' "$EXPECT" | grep -v '^$' | sed 's/^ *//' | sort > "$TMPD/want_delta"

    if [ ! -s "$TMPD/actual_delta" ]; then
        echo "  DELTA          could not read the tree's change list --- treat as diverged"
        differ=1
    else
        newd=$(comm -13 "$TMPD/want_delta" "$TMPD/actual_delta")
        gone=$(comm -23 "$TMPD/want_delta" "$TMPD/actual_delta")
        if [ -n "$newd" ]; then
            echo "  DELTA: IN TREE, NOT IN THE MANIFEST (would be lost if the VM died):"
            echo "$newd" | sed 's/^/    /'
            differ=1
        fi
        if [ -n "$gone" ]; then
            echo "  DELTA: IN THE MANIFEST, NOT IN THE TREE (stale manifest, or a change reverted):"
            echo "$gone" | sed 's/^/    /'
            differ=1
        fi
        [ -z "$newd$gone" ] && echo "  delta          $(wc -l < "$TMPD/want_delta") tree changes, all accounted for"
    fi
else
    echo "  DELTA          no $EXPECT --- the F5-file and non-ls_* additions are unchecked"
    differ=1
fi

d=$(dupes)
if [ -n "$d" ]; then
    echo
    # THREE OF THESE ARE THE DESIGN, NOT A PROBLEM, and treating them as divergence made this
    # check print DIVERGED on every run with (0 only-in-tree, 0 only-in-repo) --- a verdict that
    # contradicted its own counts. bnk-sync-substrate.sh deliberately copies ls_ctx_alpn.c,
    # ls_ctx_alpn.h and ls_ssl_cookie.c into modules/hudfilter/ssl, because they touch struct
    # ssl_ctx and must compile in that module's include world; their headers stay in base/ and are
    # reached as <local/base/...>. So the same name legitimately exists twice.
    #
    # This is the failure this script was written to prevent, committed by the script itself: a
    # guard that is always red is a guard nobody reads, and the line that matters --- ONLY IN TREE
    # --- was sitting underneath a permanent false alarm. Expected duplicates are now listed as
    # BY DESIGN; an unexpected one still fails.
    #
    # The expected set is READ FROM the sync script rather than restated here, so the two cannot
    # drift. If that grep ever finds nothing, every duplicate is unexpected and the check fails
    # loudly --- which is the right direction to be wrong in.
    SSL_COPIES=$(sed -n 's/^ *for f in \(.*\); do$/\1/p' \
                   "$(dirname "$0")/bnk-sync-substrate.sh" 2>/dev/null | head -1)
    unexpected=""
    for b in $d; do
        _paths=$(grep "$b" "$TMPD/paths" | tr '\n' ' ')
        case " $SSL_COPIES " in
            *" $b "*) printf '    %-24s %s  <- BY DESIGN (ssl module include world)\n' "$b" "$_paths" ;;
            *)        printf '    %-24s %s  <- UNEXPECTED\n' "$b" "$_paths"; unexpected=1 ;;
        esac
    done
    if [ -n "$unexpected" ]; then
        echo "  SAME NAME IN TWO PLACES, and at least one is not accounted for:"
        differ=1
    else
        echo "  (all $(echo $d | wc -w) accounted for by bnk-sync-substrate.sh's ssl-module list)"
    fi
fi

echo
if [ "$differ" -eq 0 ]; then
    if [ "$acked" -gt 0 ]; then
        echo "  VERDICT : IN SYNC --- apart from $acked acknowledged difference(s) above"
    else
        echo "  VERDICT : IN SYNC --- the tree holds exactly what git holds"
    fi
    exit 0
fi

cat <<EOT
  VERDICT : DIVERGED.  differs/only-in-tree/only-in-repo above
            ($only_tree only-in-tree, $only_repo only-in-repo)

      Resolve every line before building. In particular, DO NOT copy the repo
      over the tree while anything reads DIFFERS or ONLY IN TREE -- that copy is
      exactly what deleted the map registration calls, and it left no trace.

      To see what would be lost:   $0 -v
      To carry a tree-side change back:
          scp $BUILD_BOX:$TREE/<file> $SRC/<file>
EOT
exit 1
