#!/bin/sh
# Does the built binary actually CONTAIN the change? Refuse to ship if not.
#
# WHY THIS EXISTS. On 2026-08-17 four consecutive builds were reported successful
# and shipped, and none of them contained the code being tested. Conclusions were
# then drawn on the cluster for hours from a binary compiled before the fixes:
# "maps do not work" was measured against a binary with no map code in it.
#
# Root cause: obj_x86_64.*/*.o are written by the build container and owned by
# ROOT. `rm` on them fails with "Permission denied", make cannot overwrite them,
# and every subsequent build silently RELINKS THE STALE OBJECT. Nothing in the
# build output says so --- make reports success, the image builds, the pods roll.
#
# The check is one grep. It would have caught this on the first build.
#
#   bnk-verify-artifact.sh <image-or-binary> <token> [token...]
#
# A token is any string unique to the change --- a new log line, an error message,
# a function name that will survive as a symbol. Every token must be present or
# this exits non-zero.
#
# EXAMPLES
#   bnk-verify-artifact.sh tmm:demo 'ls_map: reloc'
#   bnk-verify-artifact.sh /tmp/tmm64.no_pgo 'ls_tp: ring' 'ls_vm: init'
#
# WHAT A TOKEN MUST NOT BE. Anything the compiler may fold away. A string literal
# inside a function that is reachable is safe; a `static inline` never called is
# not, and neither is an integer constant. If the token is absent, check whether
# the code is dead before concluding the build is stale --- both are real, and
# they look identical here.
set -e

TARGET="$1"
shift || true

if [ -z "$TARGET" ] || [ -z "$1" ]; then
    echo "usage: $0 <image-or-binary> <token> [token...]" >&2
    echo "  refuses (exit 1) unless every token appears in the binary" >&2
    exit 2
fi

BIN=""
CLEANUP=""

if [ -f "$TARGET" ]; then
    BIN="$TARGET"
elif docker image inspect "$TARGET" >/dev/null 2>&1; then
    # Check the binary /usr/bin/tmm RESOLVES to, not one that merely exists in the
    # image. Dockerfile.runtime repoints tmm at tmm.debug when a debug build is
    # present, so an image can carry a correct no_pgo binary and run something
    # else --- which is how tmm:0b and tmm:cve1 shipped unarmable.
    R=$(docker run --rm --entrypoint sh "$TARGET" -c 'readlink -f /usr/bin/tmm' 2>/dev/null)
    [ -z "$R" ] && R=/usr/bin/tmm64.no_pgo
    cid=$(docker create "$TARGET")
    BIN=$(mktemp)
    docker cp "$cid:$R" "$BIN" >/dev/null 2>&1
    docker rm "$cid" >/dev/null 2>&1
    CLEANUP="$BIN"
    echo "  image  : $TARGET"
    echo "  binary : $R (what /usr/bin/tmm resolves to)"
else
    echo "*** not a file and not a local docker image: $TARGET" >&2
    exit 2
fi

# ---- IS THIS THE BINARY THAT CAN BE ARMED? ---------------------------------
#
# -fpatchable-function-entry=5,0 is in CFLAGS_OPTIMIZE, which the DEBUG build does
# not use, so functions in tmm64.debug have no entry pad --- rst_why there is
# endbr64 followed straight by push %rbp. Dockerfile.runtime points /usr/bin/tmm at
# tmm.debug whenever a debug build is present, so an image can carry a perfectly
# good no_pgo binary and run one nothing can be armed in. Three images shipped that
# way with every token present: tmm:0b, tmm:cve1, tmm:maps1.
#
# THE GATE IS THE BINARY NAME, NOT A PAD COUNT. Two attempts at counting pads both
# gave healthy-looking numbers for the debug binary (11,025 by disassembly window,
# 2,093 by exact byte pattern) because some translation units do carry the flag and
# alignment nops look similar. A metric that passes the exact artifact it exists to
# reject is worse than none. Which binary is running is unambiguous.
case "$R" in
    *debug*)
        cat >&2 <<EOT

  *** REFUSING. /usr/bin/tmm resolves to $R --- a DEBUG binary.

      -fpatchable-function-entry is in CFLAGS_OPTIMIZE, which the debug build does
      not use, so its functions have no entry pad and NOTHING can be armed. Token
      checks pass anyway, which is how tmm:0b, tmm:cve1 and tmm:maps1 shipped
      unarmable.

      Fix, no rebuild needed --- tmm.default is the no_pgo binary:
          printf 'FROM <image>\\nRUN ln -sfn /usr/bin/tmm.default /usr/bin/tmm\\n' \\
            | docker build -t <image>-armable -
EOT
        [ -n "$CLEANUP" ] && rm -f "$CLEANUP"
        exit 1
        ;;
esac

# Per-FUNCTION armability is a different question and this cannot answer it: a pad
# at the entry of the function you intend to arm. bnk-entry-address.sh checks that,
# against the binary resolved above.

rc=0
for tok in "$@"; do
    n=$(strings "$BIN" 2>/dev/null | grep -c -- "$tok" || true)
    if [ "$n" -gt 0 ]; then
        printf '  ok      %-40s (%s)\n' "$tok" "$n"
    else
        printf '  ABSENT  %-40s <-- the build does NOT contain this\n' "$tok"
        rc=1
    fi
done

[ -n "$CLEANUP" ] && rm -f "$CLEANUP"

if [ "$rc" -ne 0 ]; then
    cat >&2 <<'EOT'

  *** REFUSING. At least one token is missing, so this binary does not contain
      the change. Do not ship it and do not draw conclusions from it.

      Most likely causes, in order of how often they have actually happened:

      1. Root-owned stale objects. The build container writes
         obj_x86_64.*/*.o as root; `rm` fails with Permission denied and make
         relinks the old object while reporting success.
         `touch` THE SOURCE INSTEAD --- no sudo needed. The build container runs
         as root and CAN overwrite the object; the problem is only that make
         never decides to, because it compares mtimes. Touching the .c (and any
         header whose layout changed) makes it decide to:
             touch ~/code/tmm/src/base/<file>.c
         Confirmed 2026-08-17: ls_tp_emit.o sat three hours stale through a
         successful build, `rm` was refused, and a touch rebuilt it.
             sudo rm -f ~/code/tmm/src/compile/obj_x86_64.*/<file>.o   # also works

      1b. AND THIS CHECK CANNOT SEE THAT CASE. Tokens are strings. A struct
         layout change --- ls_ctx_rst going 64 to 92 bytes --- has no string to
         grep for, so every token passed while the binary emitted the old record.
         What caught it was the CONSUMER: ls_drain's length check refused to
         decode a 64-byte record as a 92-byte one and printed it as raw hex.
         For a layout change, verify the consumer decodes it, not that a token
         is present.
      2. The source edit landed AFTER the build started. Copying a file while a
         build runs races it -- the TU may already have compiled. Copy, verify
         mtimes, then build.
      3. Stale BUILD_x86_64/ -- gives "gcc: fatal error: no input files" on an
         unrelated object. Clear RPMS SRPMS docker_build/DEBS BUILD_* (sudo).
      4. The token is genuinely dead code and was optimised out. Check that
         before blaming the build.
EOT
    exit 1
fi

echo "  VERDICT : every token present --- safe to ship"
