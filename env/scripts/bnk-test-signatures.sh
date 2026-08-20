#!/bin/sh
# Re-run the signature gate against a DEPLOYED build. RUNS ON THE DATKUBE HOST.
#
#   ssh <datkube> 'sh -s' < env/scripts/bnk-test-signatures.sh
#
# WHY THIS IS A SCRIPT. The first run of these tests was typed inline, so the exact bytes that
# produced "signature verification works" were not recoverable --- the same failure the loader
# client was versioned to end. Worse, one of the cases (the reply's own wording) is a check on a
# STRING, and a string check typed from memory is a check on my memory.
#
# WHAT IT ASSERTS, and each one is a claim in GROUND_TRUTH.md:
#   1. a signed program is admitted, and the reply says signature=verified
#   2. the pre-verification log line no longer claims verification happened
#   3. the startup banner no longer claims the loader accepts unverified programs
#   4. an armed program fires on live traffic, and disarm restores the entry bytes
#   5. a flipped bit in the PROGRAM is refused, naming the body/hash mismatch
#   6. a flipped bit in the SIGNATURE is refused, naming the signature --- a DIFFERENT
#      message, which is the whole point of separating the two
#   7. a program with no signature is refused by the client, before anything is sent
set -e

PROG="${PROG:-/usr/share/ls/parse_watch.bpf.o}"
SLOT="${SLOT:-5}"
VIP="${VIP:-11.11.11.99}"
PASS=0; FAIL=0

ok()   { PASS=$((PASS+1)); printf "  ok    %s\n" "$1"; }
# `return 0` MATTERS. Without it the last command in this function is a test that FAILS when
# $2 is empty, so the function returns 1 --- and under `set -e` the first failure with no detail
# string killed the run silently after case 4. A reporting helper that aborts the suite it is
# reporting on is worse than no helper.
bad()  { FAIL=$((FAIL+1)); printf "  FAIL  %s\n" "$1"
         [ -n "$2" ] && printf "        got: %s\n" "$2"
         return 0; }

POD=$(kubectl get pods -l app=f5-tmm --no-headers | awk '$3=="Running"{print $1}' | head -1)
[ -n "$POD" ] || { echo "*** no Running f5-tmm pod"; exit 2; }
# The socket carries TMM's instance number, so it is NOT $LS_LOAD_SOCKET verbatim. Discovering
# it rather than assuming it: two checks earlier today reported "socket absent" for a socket
# that was there under a name one suffix away.
SOCK=$(kubectl exec "$POD" -c f5-tmm -- sh -c 'ls /tmp/ls_load.sock.* 2>/dev/null | head -1')
[ -n "$SOCK" ] || { echo "*** no loader socket in $POD --- is LS_LOAD_SOCKET set?"; exit 2; }
echo "pod $POD   socket $SOCK   program $PROG"
echo

K="kubectl exec $POD -c f5-tmm -- env LS_LOAD_SOCKET=$SOCK"
BUILD=$(kubectl exec "$POD" -c f5-tmm -- sh -c 'python3 /usr/share/ls/ls_buildid.py $(readlink -f /usr/bin/tmm) 2>/dev/null | cut -c1-8')
echo "build under test: $BUILD"
echo
echo "=== 0. pre-flight: leave no armed entry from a previous run"
# THE SUITE MUST BE IDEMPOTENT. When an earlier run aborted mid-way it left both pods armed.
# The next run then read an ARMED entry as its "before" bytes, watched disarm restore the nops
# correctly, and reported that as "entry bytes differ after disarm" --- a false failure produced
# entirely by the test's own leftovers. Disarm unconditionally, and do not count it as a result.
for pp in $(kubectl get pods -l app=f5-tmm --no-headers | awk '$3=="Running"{print $1}'); do
    ss=$(kubectl exec "$pp" -c f5-tmm -- sh -c 'ls /tmp/ls_load.sock.* 2>/dev/null | head -1')
    for h in http_parse_client_headers; do
        r=$(kubectl exec "$pp" -c f5-tmm -- env LS_LOAD_SOCKET="$ss" \
              python3 /usr/bin/ls-load.py disarm "$h" 2>&1 | tail -1)
        case "$r" in *DISARMED*) printf "  cleared a leftover arm on %s\n" "$pp" ;; esac
    done
done
echo

echo "=== 1. a signed program is admitted, and the reply says so"
R=$($K python3 /usr/bin/ls-load.py load "$SLOT" "$PROG" 1 2>&1 | head -2 | tr '\n' ' ')
case "$R" in
  *"signature=verified"*) ok "reply: signature=verified" ;;
  *"unverified=yes"*)     bad "the reply still says unverified=yes --- this build predates the fix" "$R" ;;
  *)                      bad "no signature verdict in the reply" "$R" ;;
esac

echo
echo "=== 2. the log line printed BEFORE verification no longer claims it happened"
# This one is the reason the test exists as a file. The old line said "LOAD accepted ---
# signature verified" and printed on the loader thread, before the TMM thread had looked at
# anything. It was a true-sounding sentence about an event that had not occurred.
L=$(kubectl logs "$POD" -c f5-tmm --tail=200 2>/dev/null | grep -E 'ls_vm: LOAD (received|accepted)' | tail -1)
case "$L" in
  *"LOAD received"*"signature checked on the"*) ok "log: LOAD received, verdict deferred to the prepare thread" ;;
  *"signature verified"*) bad "the pre-verification line still claims verification" "$L" ;;
  *) bad "no LOAD line found in the last 200 log lines" "$L" ;;
esac

echo
echo "=== 3. the startup banner states what is actually true"
B=$(kubectl logs "$POD" -c f5-tmm 2>/dev/null | grep -oE 'LOADER LISTENING on [^ ]+ --- .*' | head -1)
case "$B" in
  *"accepts UNVERIFIED programs"*) bad "banner still says the loader accepts unverified programs" "$B" ;;
  *"signature-checked"*"PEER is not"*) ok "banner: programs checked, peer not --- the property that holds" ;;
  *) bad "banner missing or unrecognised" "$B" ;;
esac

echo
echo "=== 4. arm it, drive traffic, disarm, and check the entry bytes came back"
# ls-load.py has no `hookname` or `entry` subcommand --- I wrote this test against two
# commands that do not exist, and only found out by grepping its dispatch. It DOES expose both
# as functions, so import the file rather than adding CLI surface to the tool under test.
PROBE="import importlib.util as I,sys
s=I.spec_from_file_location('L','/usr/bin/ls-load.py'); m=I.module_from_spec(s); s.loader.exec_module(m)"
HOOK=$($K python3 -c "$PROBE
print(m.elf_fentry_hook(open('$PROG','rb').read()).decode() or '')" 2>/dev/null | tr -d ' \n')
[ -n "$HOOK" ] && ok "hook read from the object's own fentry/ section: $HOOK" \
                || { HOOK=http_parse_client_headers; bad "could not read the hook from $PROG; assuming $HOOK"; }
ENTRY="print(' '.join('%02x'%x for x in (m.entry_bytes(m.resolve_hook('$HOOK')) or b'')))"
BEFORE=$($K python3 -c "$PROBE
$ENTRY" 2>/dev/null | tail -1)
A=$($K python3 /usr/bin/ls-load.py arm "$SLOT" "$HOOK" 2>&1 | tail -1)
case "$A" in
  *"ARMED LIVE"*) ok "armed $HOOK: $(echo "$A" | cut -c1-52)" ;;
  *)              bad "arm refused" "$A" ;;
esac
# ARM THE OTHER POD TOO. A TCP connection is handled by ONE TMM instance, so arming a single
# pod and then driving traffic measures which pod the proxy happened to pick. First run of this
# test reported fired=0 for exactly that reason --- the hook was fine, the test was wrong.
OTHER=$(kubectl get pods -l app=f5-tmm --no-headers | awk '$3=="Running"{print $1}' | grep -v "^$POD$" | head -1)
if [ -n "$OTHER" ]; then
    OSOCK=$(kubectl exec "$OTHER" -c f5-tmm -- sh -c 'ls /tmp/ls_load.sock.* 2>/dev/null | head -1')
    KO="kubectl exec $OTHER -c f5-tmm -- env LS_LOAD_SOCKET=$OSOCK"
    $KO python3 /usr/bin/ls-load.py load "$SLOT" "$PROG" 1 >/dev/null 2>&1 || true
    AO=$($KO python3 /usr/bin/ls-load.py arm "$SLOT" "$HOOK" 2>&1 | tail -1)
    case "$AO" in *"ARMED LIVE"*) ok "second pod armed too ($OTHER)" ;;
                  *) bad "second pod would not arm --- fired counts below may be a coin toss" "$AO" ;; esac
fi
# CHECK THE TRAFFIC PATH BEFORE BLAMING THE HOOK. fired=0 has two causes that look identical
# from the counter --- the hook is not on the path, or no traffic arrived at all --- and the
# second one has already cost this project a day (the VIP had no address; see
# env/scripts/bnk-traffic-path.sh).
# NO HOST-SIDE $(seq): it expands to NEWLINE-separated numbers, so the command that reached the
# pod was `for i in 1<newline>2<newline>3; do ...`, and the pod's shell answered `syntax error:
# unexpected word (expecting "do")`. With 2>/dev/null on the line that error became an empty
# string, and an empty string read as "no traffic reached the backend" --- while 14 hooks were
# firing at that exact moment, which is what exposed the contradiction. Second time in this
# session that a silenced stderr turned a broken command into a confident wrong measurement.
# So: count in the pod's own shell, and KEEP stderr.
CODES=$(kubectl exec client -- sh -c 'i=0; while [ $i -lt 20 ]; do curl -s -m 3 -o /dev/null -w "%{http_code} " http://'"$VIP"'/; i=$((i+1)); done' 2>&1 || true)
NOK=$(printf '%s' "$CODES" | tr -cd '0-9 ' | tr ' ' '\n' | grep -c '^200$' || true)
printf "        response codes: [%s]\n" "$CODES"
[ "${NOK:-0}" -gt 0 ] && ok "traffic reaches the backend through the VIP ($NOK of 20 returned 200)" \
                      || bad "no 200 seen --- a fired count below says nothing about the hook then" "$CODES"
TOTAL=0
for pp in $POD $OTHER; do
    ss=$(kubectl exec "$pp" -c f5-tmm -- env LS_LOAD_SOCKET=$(kubectl exec "$pp" -c f5-tmm -- sh -c 'ls /tmp/ls_load.sock.* | head -1') \
           python3 /usr/bin/ls-load.py status "$SLOT" 2>&1 | tail -1)
    f=$(echo "$ss" | sed -n 's/.*fired=\([0-9]*\).*/\1/p')
    printf "        %-28s fired=%s\n" "$pp" "${f:-?}"
    [ -n "$f" ] && TOTAL=$((TOTAL + f))
done
[ "$TOTAL" -gt 0 ] && ok "fired=$TOTAL across the armed pods on live traffic" \
                   || bad "nothing fired on either pod --- armed but not reached" ""
for pp in $POD $OTHER; do
    D=$(kubectl exec "$pp" -c f5-tmm -- env LS_LOAD_SOCKET=$(kubectl exec "$pp" -c f5-tmm -- sh -c 'ls /tmp/ls_load.sock.* | head -1') \
          python3 /usr/bin/ls-load.py disarm "$HOOK" 2>&1 | tail -1)
    case "$D" in *"DISARMED"*) ok "disarmed on $pp" ;; *) bad "disarm failed on $pp" "$D" ;; esac
done
AFTER=$($K python3 -c "$PROBE
$ENTRY" 2>/dev/null | tail -1)
if [ -n "$BEFORE" ] && [ "$BEFORE" = "$AFTER" ]; then
    ok "entry bytes restored byte-for-byte"
else
    bad "entry bytes differ after disarm" "before=[$BEFORE] after=[$AFTER]"
fi

echo
echo "=== 5-6. tamper with each half, and check the two messages DIFFER"
# Copied to a writable path inside the container. Nothing is left behind: both temporary files
# are removed at the end of this block, and neither is ever armed.
$K sh -c "cp $PROG /dev/shm/t.o && cp ${PROG%.o}.sig /dev/shm/t.sig" 2>/dev/null
# Flip one bit in the middle of the PROGRAM. The signature stays valid over the binding, so the
# refusal must come from the body hash, not from the signature.
$K python3 -c "
import io
p='/dev/shm/t.o'; b=bytearray(io.open(p,'rb').read()); b[len(b)//2]^=1; io.open(p,'wb').write(b)"
# THE SPECIFIC REASON IS NOT ON THE WIRE, AND THAT IS DELIBERATE. The reply is a generic
# refusal so a forger cannot use it as an oracle to learn which half of a forgery to fix; the
# distinguishing message goes to TMM's log, where an operator can read it and an attacker
# cannot. The first version of this test asserted against the reply and recorded two failures
# that were the design working. So: assert refusal on the wire, reason in the log.
R5=$($K python3 /usr/bin/ls-load.py load 6 /dev/shm/t.o 1 2>&1 | tr '\n' ' ')
case "$R5" in
  *"ERR"*|*"refused"*) ok "tampered body refused on the wire, with no reason leaked" ;;
  *) bad "a tampered program was ADMITTED" "$R5" ;;
esac
G5=$(kubectl logs "$POD" -c f5-tmm --tail=40 2>/dev/null | grep 'LOAD REFUSED' | tail -1)
case "$G5" in
  *"does not match the hash it commits to"*) ok "log names the body/hash mismatch" ;;
  *) bad "the log does not name the body mismatch" "$G5" ;;
esac
# Restore the body, flip one bit in the SIGNATURE instead.
$K sh -c "cp $PROG /dev/shm/t.o"
$K python3 -c "
import io
p='/dev/shm/t.sig'; b=bytearray(io.open(p,'rb').read()); b[10]^=1; io.open(p,'wb').write(b)"
R6=$($K python3 /usr/bin/ls-load.py load 6 /dev/shm/t.o 1 2>&1 | tr '\n' ' ')
case "$R6" in
  *"ERR"*|*"refused"*) ok "tampered signature refused on the wire" ;;
  *) bad "a program with a broken signature was ADMITTED" "$R6" ;;
esac
G6=$(kubectl logs "$POD" -c f5-tmm --tail=40 2>/dev/null | grep 'LOAD REFUSED' | tail -1)
case "$G6" in
  *"INVALID for these bytes and this key"*) ok "log names the signature --- a DIFFERENT message from the body case" ;;
  *"does not match the hash"*) bad "both tampering cases logged the same message; the split is lost" "$G6" ;;
  *) bad "the log does not name the signature failure" "$G6" ;;
esac

echo
echo "=== 7. no signature at all --- the client must refuse before sending"
$K sh -c "rm -f /dev/shm/t.sig"
R7=$($K python3 /usr/bin/ls-load.py load 6 /dev/shm/t.o 1 2>&1 | tr '\n' ' ')
case "$R7" in
  *"no signature found"*) ok "client refused, naming the missing .sig" ;;
  *) bad "a program with no signature was not stopped by the client" "$R7" ;;
esac
$K sh -c "rm -f /dev/shm/t.o /dev/shm/t.sig" 2>/dev/null || true

echo
echo "=== summary"
printf "  %d passed, %d failed, on build %s\n" "$PASS" "$FAIL" "$BUILD"
[ "$FAIL" -eq 0 ] || exit 1
