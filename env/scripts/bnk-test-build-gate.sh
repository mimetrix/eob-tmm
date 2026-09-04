#!/bin/sh
# Prove the loader ACTS on the signed build range, against a DEPLOYED build.
# RUNS ON THE DATKUBE HOST.
#
#   ssh <datkube> 'sh -s' < env/scripts/bnk-test-build-gate.sh
#
# WHY THIS EXISTS. build_min/build_max sat in the signed binding, covered by the
# signature, printed into every audit record, and compared to NOTHING until
# 2026-09-04 (CONTESTED-PREMISES.md 15). check_build_gate.c asserts the decision
# off-TMM; this asserts that the DEPLOYED LOADER reaches it. Those are different
# claims, and the off-TMM one passed 18/18 on a version of the gate that would
# have refused every operation the real client sends.
#
# WHY IT SENDS A DUMMY PAYLOAD AND NO SIGNATURE, both deliberate:
#
#   * The gate runs on the LOADER thread in ls_vm_load.c; signature verification
#     happens later on a TMM thread in ls_prep_run_pending. So the gate's verdict
#     is observable BEFORE any signature is consulted --- which is what isolates
#     it. An unsigned range shows the loader ACTS on the field; it does not show
#     the field is unforgeable. `make -C substrate check-sig` covers that half by
#     asserting a flipped bit in build_min is detected.
#   * A dummy program makes every stage AFTER the gate fail identically, so the
#     only thing varying between cases is the gate's answer. A real program would
#     add a second reason for the reply to change and weaken every case.
#
# THE CASE THAT MATTERS MOST IS 5. The first version of this gate sat before
# `switch (m->op)` and therefore answered for REVOKE --- the kill switch. A gate
# that can refuse a disarm on a live data plane is worse than the staleness it
# prevents. Case 5 asserts disarm still works while a bogus range is asserted.
set -e

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf "  ok    %s\n" "$1"; }
bad() { FAIL=$((FAIL+1)); printf "  FAIL  %s\n" "$1"
        [ -n "$2" ] && printf "        got: %s\n" "$2"
        return 0; }

POD=$(kubectl get pods -l app=f5-tmm --no-headers | awk '$3=="Running"{print $1}' | head -1)
[ -n "$POD" ] || { echo "*** no Running f5-tmm pod"; exit 2; }
SOCK=$(kubectl exec "$POD" -c f5-tmm -- sh -c 'ls /tmp/ls_load.sock.* 2>/dev/null | head -1')
[ -n "$SOCK" ] || { echo "*** no loader socket in $POD"; exit 2; }

# The running build id, from the pod, first 8 hex digits = the uint32 prefix the
# gate compares. Read from the binary tmm RESOLVES to, not from a name.
BID=$(kubectl exec "$POD" -c f5-tmm -- sh -c \
        'python3 /usr/share/ls/ls_buildid.py $(readlink -f /usr/bin/tmm) 2>/dev/null' | cut -c1-8)
[ -n "$BID" ] || { echo "*** could not read the running build id"; exit 2; }
echo "pod $POD   socket $SOCK   running build 0x$BID"
echo

# One LOAD with a chosen range. Prints the loader's reply on one line.
# $1 build_min  $2 build_max
send() {
kubectl exec -i "$POD" -c f5-tmm -- python3 - "$SOCK" "$1" "$2" <<'PY' 2>&1 | tr '\n' ' '
import socket, struct, sys
sock, bmin, bmax = sys.argv[1], int(sys.argv[2], 0), int(sys.argv[3], 0)
HDR = 192
# struct shield_msg: op@0 epoch@4 mode@8 prog_len@12, binding@16.
# binding.build_min@+96, build_max@+100, ctx_abi_version@+105 --- the offsets
# shield_abi.h's _Static_asserts pin.
PROG = b"\x7fELF" + b"\x00" * 60        # deliberately not a loadable object
b = bytearray(HDR)
struct.pack_into("<I", b, 0, 1)          # SHIELD_OP_LOAD
struct.pack_into("<I", b, 4, 9)          # epoch carries the slot
b[8] = 1                                 # MODE_MONITOR
struct.pack_into("<I", b, 12, len(PROG))
b[16 + 105] = 3                          # ctx_abi_version, or the abi gate answers first
struct.pack_into("<I", b, 16 + 96, bmin)
struct.pack_into("<I", b, 16 + 100, bmax)
b[16 + 32:16 + 32 + len(b"fentry/x")] = b"fentry/x"
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(20)
s.connect(sock)
s.sendall(bytes(b) + PROG)
try:
    print(s.recv(4096).decode(errors="replace").strip())
except socket.timeout:
    print("*** TIMEOUT")
PY
}

# CASE 0 EXISTS BECAUSE CASES 1-3 EXPECT A REFUSAL, and a refusal from the WRONG
# gate looks identical. The ctx-abi check sits immediately before the build gate and
# answers first; this script writes ctx_abi_version = 3 as a literal, so if
# SHIELD_CTX_ABI_VERSION is ever bumped, every load here is refused for the abi and
# cases 1-3 keep "passing" for a reason that has nothing to do with the build range.
# That is a test agreeing with itself, which is the failure this whole file guards.
# So: prove the abi gate is quiet before trusting any refusal below it.
echo "=== 0. pre-flight: it is the BUILD gate refusing, not the ctx-abi gate"
R=$(send 0 0)
case "$R" in
  *"ctx abi"*)
    echo "  *** REFUSED for the ctx ABI, not the build range. This script writes"
    echo "      ctx_abi_version = 3; SHIELD_CTX_ABI_VERSION has almost certainly moved."
    echo "      Every refusal below would be the wrong gate. Fix the literal first."
    echo "      got: $R"
    exit 2 ;;
  *) ok "the ctx-abi gate is satisfied, so a refusal below is the build gate" ;;
esac

echo
echo "=== 1. a range naming a DIFFERENT build is refused"
R=$(send 0x11111111 0x11111111)
case "$R" in
  *"build gate"*"different build"*) ok "refused, and the reason names the build: $(echo "$R" | cut -c1-72)" ;;
  *"build gate"*)                   bad "refused by the gate but with the wrong reason" "$R" ;;
  *)                                bad "NOT refused by the build gate --- the field is still unread" "$R" ;;
esac

echo
echo "=== 2. a PARTIAL range over a hash is refused, not waved through"
R=$(send 0x00000000 "0x$BID")
case "$R" in
  *"build gate"*"cannot be honoured"*) ok "refused: a range over a SHA-1 prefix means nothing" ;;
  *"build gate"*)                      bad "refused, but not as a bad range" "$R" ;;
  *)                                   bad "a partial range was ACCEPTED" "$R" ;;
esac

echo
echo "=== 3. an INVERTED range is refused (never silently empty)"
R=$(send 0xffffffff 0x00000001)
case "$R" in
  *"build gate"*) ok "refused" ;;
  *)              bad "an inverted range was ACCEPTED" "$R" ;;
esac

echo
echo "=== 4. the range naming THIS build passes the gate"
# It must then fail for a DIFFERENT reason --- the payload is not a real object.
# "passes the gate" is shown by the absence of a build-gate refusal, which is why
# the dummy payload matters: the later failure is identical in every case.
R=$(send "0x$BID" "0x$BID")
case "$R" in
  *"build gate"*) bad "the correct build was refused by its own gate" "$R" ;;
  *)              ok "no build-gate refusal; failed later as expected: $(echo "$R" | cut -c1-60)" ;;
esac

echo
echo "=== 5. an UNDECLARED range (0..0) is still accepted --- every client sends it"
# Same message as case 0; asserted again here as a RESULT rather than a pre-flight,
# because "the existing client keeps working" is the claim, not a precondition.
R=$(send 0 0)
case "$R" in
  *"build gate"*) bad "0..0 was refused --- this breaks ls_client.py, which never sets the field" "$R" ;;
  *)              ok "accepted as UNDECLARED, so the existing client still works" ;;
esac

echo
echo "=== 6. THE KILL SWITCH IS NOT GATED --- status and disarm answer regardless"
# ASSERT A REAL LOADER REPLY, NOT MERELY THE ABSENCE OF A REFUSAL.
#
# The first version of this case ran `ls-load.py status` with no slot argument and
# matched anything that did not say "build gate". The client refused it locally --
# "*** status takes 1 argument, got 0" -- so the case passed GREEN without a byte
# ever reaching the loader. A vacuous pass on the one case that exists to prove the
# kill switch is reachable is worse than no case at all.
#
# So both halves now require the loader's own wording: `OK armed=` for status, and
# for disarm either a real disarm or the loader's "not armed" -- both of which are
# answers from past the gate. A client-side usage error no longer satisfies either.
S=$(kubectl exec "$POD" -c f5-tmm -- env LS_LOAD_SOCKET="$SOCK" \
      python3 /usr/bin/ls-load.py status 0 2>&1 | head -3 | tr '\n' ' ')
case "$S" in
  *"build gate"*)  bad "STATUS was refused by the build gate --- it must not be gated" "$S" ;;
  *"OK armed="*)   ok "status answers FROM THE LOADER: $(echo "$S" | cut -c1-52)" ;;
  *"takes 1 arg"*) bad "the client refused this locally --- nothing reached the loader, so this case proved nothing" "$S" ;;
  "")              bad "STATUS returned nothing" ;;
  *)               bad "no recognisable loader status reply" "$S" ;;
esac
D=$(kubectl exec "$POD" -c f5-tmm -- env LS_LOAD_SOCKET="$SOCK" \
      python3 /usr/bin/ls-load.py disarm http_parse_client_headers 2>&1 | tail -1)
case "$D" in
  *"build gate"*)             bad "DISARM was refused by the build gate --- the kill switch must never be gated" "$D" ;;
  *"DISARMED"*|*"not armed"*) ok "disarm reaches the loader and it answers: $(echo "$D" | cut -c1-52)" ;;
  *)                          bad "no recognisable loader disarm reply --- did it reach the loader at all?" "$D" ;;
esac

echo
echo "=== 7. the loader SAYS what it decided, in the log"
L=$(kubectl logs "$POD" -c f5-tmm --tail=400 2>/dev/null | grep -E "ls_vm: (REFUSED --- (signed|build|no build)|build gate|build range)" | tail -4)
case "$L" in
  *"REFUSED"*) ok "the refusals are on the log, with the signed and running ids" ;;
  *)           bad "no build-gate line on the log --- a refusal nobody can audit" "$(echo "$L" | tr '\n' ' ')" ;;
esac
[ -n "$L" ] && echo "$L" | sed 's/^/        /'

echo
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
