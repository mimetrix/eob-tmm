#!/bin/sh
# The audit trail, against a DEPLOYED build. RUNS ON THE DATKUBE HOST.
#
#   ssh <datkube> 'sh -s' < env/scripts/bnk-test-audit.sh
#
# The off-TMM test (`make -C substrate check-audit`) proves the record's SHAPE: that it cannot be
# forged, cannot be silently truncated, and carries kernel-attested credentials. It cannot prove
# the two things that only a live TMM can answer:
#
#   F7g  emitting a record does not wedge the loader. This is the falsifier that FIRED when
#        signature verification shipped --- same thread, same allocator, and the reason was a
#        comment of mine that reasoned past an explanation written 350 lines above it. Arguing it
#        from the no-malloc discipline is not the same as watching the loader answer afterwards.
#   F7a  no operation escapes the trail, including the ones that fail early.
#
# Everything here reads the records out of the POD LOG, not out of the file sink, because the pod
# log is the sink the durability claim rests on.
set -e

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf "  ok    %s\n" "$1"; }
bad() { FAIL=$((FAIL+1)); printf "  FAIL  %s\n" "$1"
        [ -n "$2" ] && printf "        got: %s\n" "$2"
        return 0; }

POD=$(kubectl get pods -l app=f5-tmm --no-headers | awk '$3=="Running"{print $1}' | head -1)
[ -n "$POD" ] || { echo "*** no Running f5-tmm pod"; exit 2; }
SOCK=$(kubectl exec "$POD" -c f5-tmm -- sh -c 'ls /tmp/ls_load.sock.* 2>/dev/null | head -1')
[ -n "$SOCK" ] || { echo "*** no loader socket --- is LS_LOAD_SOCKET set?"; exit 2; }
K="kubectl exec $POD -c f5-tmm -- env LS_LOAD_SOCKET=$SOCK"
BUILD=$(kubectl exec "$POD" -c f5-tmm -- sh -c 'python3 /usr/share/ls/ls_buildid.py $(readlink -f /usr/bin/tmm) 2>/dev/null')

echo "pod $POD   socket $SOCK"
echo "build $BUILD"
echo

# How many records exist now. Everything below is measured as a DELTA, because the pod has been
# up for a while and the absolute count includes whatever came before.
records() { kubectl logs "$POD" -c f5-tmm 2>/dev/null | grep -c '^ls_audit: seq=' || true; }
BEFORE=$(records)
echo "=== 0. records already in the pod log: $BEFORE"

echo
echo "=== 1. does the loader even announce the trail at startup"
B=$(kubectl logs "$POD" -c f5-tmm 2>/dev/null | grep -m1 'ls_audit: recording')
case "$B" in
  *"kernel-attested"*) ok "startup line names the sink and what the credentials mean" ;;
  "")                  bad "no ls_audit startup line --- this build predates the audit trail" ;;
  *)                   bad "startup line present but unrecognised" "$B" ;;
esac

echo
echo "=== 2. F7a --- every operation leaves a record, including one that fails early"
R1=$($K python3 /usr/bin/ls-load.py status 5 2>&1 | tail -1)
R2=$($K python3 /usr/bin/ls-load.py status 99 2>&1 | tail -1)
# A deliberately malformed request: three bytes, no header. The client will not do this, so it is
# done directly --- the early-return paths are the ones most likely to have no record, and a trail
# that loses malformed traffic loses exactly the traffic worth keeping.
$K python3 -c "
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('$SOCK')
s.sendall(b'abc')
try:    print(s.recv(200).decode().strip())
except Exception as e: print('no reply:', e)
s.close()" 2>&1 | tail -1 | sed 's/^/        malformed request answered: /'
AFTER=$(records)
DELTA=$((AFTER - BEFORE))
[ "$DELTA" -ge 3 ] && ok "3 operations produced $DELTA record(s)" \
                   || bad "3 operations produced only $DELTA record(s) --- an operation escaped" ""
kubectl logs "$POD" -c f5-tmm 2>/dev/null | grep '^ls_audit: seq=' | grep -q 'op=MALFORMED' \
  && ok "the malformed request is recorded, as op=MALFORMED" \
  || bad "the malformed request left NO record --- F7a" ""

echo
echo "=== 3. F7b --- the record's verdict is what the caller was told"
LAST_STATUS=$(kubectl logs "$POD" -c f5-tmm 2>/dev/null | grep '^ls_audit: seq=' | grep 'op=STATUS' | tail -1)
# R2 asked for a slot that does not exist, so the reply was an error. Find that record and check
# it says so --- if a refusal can be recorded as an OK, nothing else here matters.
REFUSED=$(kubectl logs "$POD" -c f5-tmm 2>/dev/null | grep '^ls_audit: seq=' | grep 'slot=99' | tail -1)
case "$REFUSED" in
  *'verdict="ERR'*) ok "the slot=99 refusal is recorded as an ERR verdict" ;;
  *'verdict="OK'*)  bad "a refusal was recorded as an OK --- the trail disagrees with the reply" "$REFUSED" ;;
  "")               bad "no record found for the slot=99 request" ;;
  *)                bad "record found but its verdict is unreadable" "$REFUSED" ;;
esac
echo "        client was told : $(echo "$R2" | cut -c1-70)"
echo "        record says     : $(echo "$REFUSED" | sed -n 's/.*\(verdict=.*\)/\1/p' | cut -c1-70)"

echo
echo "=== 4. F7e --- the peer is identified by the kernel, not by the message"
case "$LAST_STATUS" in
  *peer_pid=0*)  bad "peer_pid=0 --- SO_PEERCRED failed, so there is no attested caller" "$LAST_STATUS" ;;
  *peer_pid=*)   ok "peer_pid is present and non-zero" ;;
  *)             bad "no peer_pid field" "$LAST_STATUS" ;;
esac
case "$LAST_STATUS" in
  *peer_comm=python3*) ok "peer_comm names the client process (python3)" ;;
  *peer_comm=*)        ok "peer_comm present: $(echo "$LAST_STATUS" | sed -n 's/.*\(peer_comm=[^ ]*\).*/\1/p')" ;;
  *)                   bad "no peer_comm field" ;;
esac

echo
echo "=== 5. F7f --- the record names the build the arming gate compares"
case "$LAST_STATUS" in
  *"tmm_build=$BUILD"*) ok "tmm_build matches the running binary's GNU build id" ;;
  *)                    bad "tmm_build does not match $BUILD" \
                            "$(echo "$LAST_STATUS" | sed -n 's/.*\(tmm_build=[^ ]*\).*/\1/p')" ;;
esac

echo
echo "=== 6. F7g --- the loader still answers immediately after recording"
# THE FALSIFIER THAT FIRED LAST TIME, on this thread, for this class of reason. Ten round trips
# back to back: if any allocation crept into the audit path, the first one parks the thread
# on-CPU forever and this hangs rather than failing.
i=0; okc=0
while [ $i -lt 10 ]; do
    r=$(timeout 5 $K python3 /usr/bin/ls-load.py status 5 2>&1 | tail -1)
    case "$r" in *OK*) okc=$((okc+1)) ;; esac
    i=$((i+1))
done
[ "$okc" -eq 10 ] && ok "10 of 10 round trips answered after emitting records --- not wedged" \
                  || bad "$okc of 10 answered --- the loader is wedged or slow" ""

echo
echo "=== 7. the two operations this trail exists for must be NAMED, not numbered"
# THE DEFECT THE FIRST LIVE RUN EXPOSED, which no off-TMM assertion had asked about: ARM and
# DISARM were recorded as op_4099 and op_4100, so the one record a reader would go looking for ---
# who armed what --- was the one that did not say what it was. Live, because the numbers come from
# the loader's own switch and only a real arm exercises that path.
HOOK=rst_why
$K python3 /usr/bin/ls-load.py load 5 /usr/share/ls/rst_watch.bpf.o 1 >/dev/null 2>&1 || true
$K python3 /usr/bin/ls-load.py arm 5 "$HOOK"    >/dev/null 2>&1 || true
$K python3 /usr/bin/ls-load.py disarm "$HOOK"   >/dev/null 2>&1 || true
LOG=$(kubectl logs "$POD" -c f5-tmm 2>/dev/null | grep '^ls_audit: seq=' | tail -4)
case "$LOG" in
  *"op=ARM "*)     ok "the arm is recorded as op=ARM" ;;
  *op=op_4099*)    bad "the arm is recorded as op_4099 --- the record this trail exists for does not name itself" ;;
  *)               bad "no ARM record found in the last four" ;;
esac
case "$LOG" in
  *"op=DISARM "*)  ok "the disarm is recorded as op=DISARM" ;;
  *op=op_4100*)    bad "the disarm is recorded as op_4100" ;;
  *)               bad "no DISARM record found in the last four" ;;
esac
# And the LOAD's program identity must be the hash the signature commits to, not zeros --- a
# record that cannot say WHICH program was armed is not an audit trail.
#
# ONE RECORD AT A TIME. The first version matched `*"op=LOAD "*prog_sha256=0000...*` against all
# four records joined, so it found "op=LOAD" in one line and an all-zero hash in a LATER one --- the
# ARM record, which legitimately carries no program --- and reported the load as unidentified. A
# glob that spans record boundaries is not a test of a record.
LOADREC=$(printf '%s\n' "$LOG" | grep 'op=LOAD ' | tail -1)
SHA=$(printf '%s' "$LOADREC" | sed -n 's/.*prog_sha256=\([0-9a-f]*\).*/\1/p')
if [ -z "$LOADREC" ]; then
    bad "no LOAD record found in the last four"
elif [ "$SHA" = "0000000000000000" ] || [ -z "$SHA" ]; then
    bad "the load recorded an all-zero program hash --- the record cannot say which program" "$LOADREC"
else
    ok "the load names the program by the hash its signature commits to ($SHA)"
fi

echo
echo "=== 8. one real record, in full"
kubectl logs "$POD" -c f5-tmm 2>/dev/null | grep '^ls_audit: seq=' | tail -1 | fold -w 150 | sed 's/^/    /'

echo
echo "=== summary"
printf "  %d passed, %d failed, on build %s\n" "$PASS" "$FAIL" "$BUILD"
[ "$FAIL" -eq 0 ] || exit 1
