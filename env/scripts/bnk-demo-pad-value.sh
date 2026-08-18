#!/bin/sh
# Part 2 of the demo: WHAT THE FIVE-BYTE PAD ACTUALLY BUYS. Run on the DATKUBE host.
#
#   bnk-demo-pad-value.sh [symbol]        default: rst_why
#
# THE CLAIM THIS PROVES, in one screen: a live data plane is armed and disarmed with
# NOTHING DISPLACED, and the entry bytes come back byte-identical.
#
# Why that is the whole argument. Every other inline-hooking mechanism --- Frida's
# included --- rewrites the instructions AT the target and relocates the ones it
# overwrote. That needs an instruction decoder in the process, it needs somewhere to
# put the displaced bytes, and it opens a window in which another thread's program
# counter can be inside the bytes being rewritten. We overwrite five nops the compiler
# RESERVED, so no instruction is displaced, nothing needs relocating, and disarm is a
# byte-for-byte restore. That is why arming a running data plane under traffic is
# arguable at all rather than reckless.
#
# It reads /proc/<pid>/mem, so it shows the bytes IN THE RUNNING PROCESS at each step.
# Reading the file on disk would show the static bytes and prove nothing --- a file has
# no armed state.
#
# The contrast at the end matters as much as the arm: an UNPADDED function is REFUSED,
# which is the honest boundary of this mechanism and the reason the displacement path
# exists as separate work.
set -e

SYM="${1:-rst_why}"
SLOT="${SLOT:-5}"
PROG="${PROG:-/usr/share/ls/rst_watch.bpf.o}"

say() { printf '\n\033[1m%s\033[0m\n' "$1"; }
ctl() { kubectl exec -i "$1" -c f5-tmm -- python3 /usr/bin/ls-load.py "$2" "$3" "$4" "$5" "$6" 2>&1; }

POD=$(kubectl get pods -l app=f5-tmm --no-headers | grep Running | awk '{print $1}' | head -1)
[ -n "$POD" ] || { echo "*** no Running f5-tmm pod" >&2; exit 1; }

# The reader. Kept as a heredoc rather than a baked-in tool because it is a
# demonstration aid, not part of the mechanism --- and because printing the decode
# next to the bytes is what makes the point land.
# -i IS LOAD-BEARING. Without it kubectl attaches no stdin, `python3 -` reads an empty
# program, and this function prints NOTHING while returning 0 --- so the script narrated
# "read the third line" over blank output on its first run. Combined with 2>/dev/null
# that was a demo step that silently did not happen. Errors now surface, and the caller
# checks for empty output.
read_entry() {
    OUT=$(kubectl exec -i "$POD" -c f5-tmm -- python3 - "$1" <<'PY'
import os, sys
addr = int(sys.argv[1], 16)
pid = None
for d in os.listdir("/proc"):
    if not d.isdigit():
        continue
    try:
        exe = os.readlink("/proc/%s/exe" % d)
    except OSError:
        continue
    if os.path.basename(exe).startswith("tmm"):
        pid = d
        break
if pid is None:
    sys.exit("no tmm process")
with open("/proc/%s/mem" % pid, "rb") as m:
    m.seek(addr)
    b = m.read(14)
hexs = " ".join("%02x" % x for x in b)
# Decode only what matters: the 4-byte endbr64, then the five bytes we own, then
# proof that what follows is untouched.
head, patch, rest = b[:4], b[4:9], b[9:14]
def dec(p):
    if p == b"\x90" * 5:
        return "5 x nop        <- the compiler's reserved pad, DISARMED"
    if p[0] == 0xe8:
        off = int.from_bytes(p[1:5], "little", signed=True)
        return "call rel32 %-+d  <- ARMED: the pad now calls the trampoline" % off
    return "?? not a pad and not a call"
print("      raw      : %s" % hexs)
print("      endbr64  : %s" % " ".join("%02x" % x for x in head))
print("      pad[5]   : %s   %s" % (" ".join("%02x" % x for x in patch), dec(patch)))
print("      after    : %s   <- the function's REAL first instruction" % " ".join("%02x" % x for x in rest))
print("RAW\t%s" % hexs)
PY
)
    if [ -z "$OUT" ]; then
        echo "  *** read_entry produced NO OUTPUT for $1 --- the step did not happen." >&2
        echo "      Do not read the narration below as if it had. Check kubectl exec -i." >&2
        exit 1
    fi
    echo "$OUT" | grep -v '^RAW'
    # Hand the raw bytes back for comparison. The point of this demo is that disarm
    # restores them EXACTLY, and that is an assertion, not a thing to eyeball.
    LAST_RAW=$(echo "$OUT" | awk -F'\t' '/^RAW/{print $2}')
}

# Resolve the entry (and the pad offset) through the index, so no address is typed.
INFO=$(kubectl exec "$POD" -c f5-tmm -- sh -c \
  "grep -P '^$SYM\t' /usr/share/ls/hook-index.tsv" 2>/dev/null || true)
[ -n "$INFO" ] || { echo "*** $SYM is not in the image's hook index" >&2; exit 1; }
ARM_AT=$(echo "$INFO" | cut -f2)
METHOD=$(echo "$INFO" | cut -f3)
PAD_OFF=$(echo "$INFO" | cut -f4)
# The pad sits at entry+pad_offset; arm_at already includes it, so the ENTRY is
# arm_at - pad_offset. Print from the entry so endbr64 is visible.
ENTRY=$(python3 -c "print(hex($ARM_AT - $PAD_OFF))")

say "0 · $SYM, from the index baked into the image"
echo "  entry        : $ENTRY"
echo "  arm at       : $ARM_AT   (entry + $PAD_OFF)"
echo "  arm method   : $METHOD"
echo "  pod          : $POD"

say "1 · BEFORE --- the running process, nothing armed"
ctl "$POD" disarm "$SYM" >/dev/null 2>&1 || true      # ensure a clean start
read_entry "$ENTRY"
BEFORE="$LAST_RAW"

say "2 · load a verified program and ARM, while traffic flows"
echo "  $(ctl "$POD" load "$SLOT" "$PROG" 2 "$SYM")"
echo "  $(ctl "$POD" arm  "$SLOT" "$SYM" | tail -1)"
read_entry "$ENTRY"
ARMED="$LAST_RAW"
if [ "$ARMED" = "$BEFORE" ]; then
    echo "  *** the bytes did NOT change --- arming reported success but patched nothing." >&2
    exit 1
fi
cat <<'EOT'

  READ THE THIRD LINE. Five bytes changed. The endbr64 above them is untouched and
  the real first instruction below them is untouched --- NOTHING WAS DISPLACED, so
  there is nothing to relocate and no other thread's program counter can be inside
  a byte range being rewritten.
EOT

say "3 · DISARM --- and compare byte for byte"
echo "  $(ctl "$POD" disarm "$SYM" | tail -1)"
read_entry "$ENTRY"
AFTER="$LAST_RAW"
echo
if [ "$AFTER" = "$BEFORE" ]; then
    echo "  Back to $BEFORE"
    echo "  ASSERTED byte-identical to step 1. Not 'equivalent' --- identical."
else
    echo "  *** DISARM DID NOT RESTORE THE ORIGINAL BYTES." >&2
    echo "      before $BEFORE" >&2
    echo "      after  $AFTER" >&2
    echo "      This is the claim of the whole mechanism, so it is a hard failure." >&2
    exit 1
fi

say "4 · THE BOUNDARY: a function with NO pad is REFUSED"
# Pull a real unpadded entry out of the image's own index rather than naming one from
# memory: which functions lack a pad is a property of this build.
UNPAD=$(kubectl exec "$POD" -c f5-tmm -- sh -c \
  "awk -F'\t' '\$3==\"displace\" {print \$1; exit}' /usr/share/ls/hook-index.tsv" 2>/dev/null || true)
if [ -n "$UNPAD" ]; then
    echo "  trying $UNPAD (arm_method=displace, i.e. no compiler pad):"
    ctl "$POD" arm "$SLOT" "$UNPAD" 2>&1 | tail -2 | sed 's/^/    /'
    cat <<'EOT'

  That refusal is the honest boundary. Pad-based arming reaches the TMM core, which
  is what the build pads --- and nothing else. Reaching the rest means DISPLACING
  leading instructions, which is separate work with a different risk profile.
EOT
else
    echo "  (no displace-method entry in the index to contrast against)"
fi
