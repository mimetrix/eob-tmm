#!/bin/sh
# Can a shield arm on a binary that carries NO type information?
# RUNS ON THE DATKUBE HOST.
#
#   PROGDIR=~/nobtf-shields sh env/scripts/bnk-test-btfless.sh
#
# WHY THIS IS THE TEST THAT MATTERS. Everything else about phase 3
# (02-RESEARCH-PARAMETERS.md P9) was measured off-cluster: the offsets baked at
# sign time match an independent implementation, PREVAIL's verdict survives
# relocation on the pinned compiler, the emitted artifacts carry 0 `.BTF`
# sections, and the bake can produce a binary with the section absent. None of
# that shows a shield ARMING against such a binary, and until it does, "the
# shipped ELF carries no type information" stays ROADMAP in GROUND_TRUTH.md --
# because the loader could still refuse for a reason nobody predicted.
#
# WHAT IT REMOVES WHEN IT PASSES: 6,711,805 bytes naming 41,710 functions and
# 16,006 struct layouts, including http2_http_data_to_frames and the layout of the
# struct CVE-2025-41414 dereferences. F5 ships both binaries `stripped` with
# symtab FUNC: 0, so that section is the ONLY layout disclosure in the image, and
# it is ours (CONTESTED-PREMISES.md 14).
#
# CASE 5 IS THE ONE THAT COULD EMBARRASS US. A program that still carries
# `.BTF.ext` cannot be resolved against a binary with no `.BTF`, and the loader
# must REFUSE it saying so -- not run it against unresolved placeholder offsets
# (0, 1, 2 for a stub struct) pointed at a real TMM structure. That failure would
# be silent, would pass PREVAIL (the proof was taken against the placeholder) and
# would read whatever sits at the front of the real struct.
set -e

PROGDIR="${PROGDIR:-$HOME/nobtf-shields}"
PROG="${PROG:-$PROGDIR/shield_nullguard.bpf.o}"
UNSTRIPPED="${UNSTRIPPED:-$PROGDIR/unstripped/shield_nullguard.bpf.o}"
HOOK="${HOOK:-http_parse_client_headers}"
SLOT="${SLOT:-4}"
VIP="${VIP:-11.11.11.99}"
DELIVER="${DELIVER:-$HOME/gate-scripts/bnk-deliver-program.py}"
PASS=0; FAIL=0

ok()  { PASS=$((PASS+1)); printf "  ok    %s\n" "$1"; }
bad() { FAIL=$((FAIL+1)); printf "  FAIL  %s\n" "$1"
        [ -n "$2" ] && printf "        got: %s\n" "$2"
        return 0; }

POD=$(kubectl get pods -l app=f5-tmm --no-headers | awk '$3=="Running"{print $1}' | head -1)
[ -n "$POD" ] || { echo "*** no Running f5-tmm pod"; exit 2; }
SOCK=$(kubectl exec "$POD" -c f5-tmm -- sh -c 'ls /tmp/ls_load.sock.* 2>/dev/null | head -1')
[ -n "$SOCK" ] || { echo "*** no loader socket in $POD"; exit 2; }
K="kubectl exec $POD -c f5-tmm -- env LS_LOAD_SOCKET=$SOCK"
BID=$(kubectl exec "$POD" -c f5-tmm -- sh -c \
        'python3 /usr/share/ls/ls_buildid.py $(readlink -f /usr/bin/tmm) 2>/dev/null')
echo "pod $POD   socket $SOCK"
echo "running build $BID"
echo

echo "=== 0. the RUNNING binary carries no type information"
# Read the section headers in the pod. Measured, not inferred from the bake's log:
# the bake could have said one thing and the image shipped another, which is the
# family of failure this project keeps hitting.
# READ THE SECTION HEADERS WITH python3 -c, NOT A HEREDOC.
# The first version piped a heredoc into `kubectl exec -- python3 -` from inside a
# command substitution, and stdin never reached the container: the case reported
# "could not read the section headers" on an image that was in fact clean. A test
# that cannot read its own subject fails closed, which is right, but it failed for
# its own reason and not the subject's.
N=$(kubectl exec "$POD" -c f5-tmm -- python3 -c '
import struct
b=open("/usr/bin/tmm64.no_pgo","rb").read()
shoff,=struct.unpack_from("<Q",b,0x28)
shent,shnum,shstr=struct.unpack_from("<HHH",b,0x3A)
sh=lambda i: struct.unpack_from("<IIQQQQ",b,shoff+i*shent)
_,_,_,_,so,sz=sh(shstr); names=b[so:so+sz]
tot=0
for i in range(shnum):
    nm,_,_,_,o,z=sh(i)
    if names[nm:names.find(b"\0",nm)].decode().startswith(".BTF"): tot+=z
print(tot)' 2>&1 | tail -1)
case "$N" in
  0)  ok "0 bytes of .BTF in the running binary" ;;
  "") bad "could not read the section headers in the pod" ;;
  *)  bad "the running binary still carries $N bytes of .BTF --- this image was baked with LS_EMBED_BTF=1" "$N"
      echo "        Nothing below tests what it claims to. Stopping."; exit 1 ;;
esac

echo
echo "=== 1. a stripped, sign-time-relocated, SIGNED program loads"
[ -f "$PROG" ] || { echo "*** no program at $PROG"; exit 2; }
R=$(POD="$POD" python3 "$DELIVER" "$PROG" "$SLOT" 1 2>&1 | tail -2 | tr '\n' ' ')
case "$R" in
  *"signature=verified"*) ok "loaded, signature verified: $(echo "$R" | grep -oE 'OK loaded.*' | cut -c1-56)" ;;
  *"no target BTF"*|*"carries CO-RE"*) bad "refused for missing type information --- the program was NOT stripped/relocated" "$R" ;;
  *)                      bad "did not load" "$R" ;;
esac

echo
echo "=== 2. it arms by name"
A=$($K python3 /usr/bin/ls-load.py arm "$SLOT" "$HOOK" 2>&1 | tail -1)
case "$A" in
  *ARMED*) ok "armed: $(echo "$A" | cut -c1-60)" ;;
  *)       bad "did not arm" "$A" ;;
esac

echo
echo "=== 3. it RUNS --- armed on the poll loop, which needs no traffic path"
# WHY THE POLL LOOP AND NOT AN HTTP HOOK, learned the expensive way. Proving that a
# program with baked offsets executes on a BTF-less binary should not also depend on
# a working traffic path, and it did: this cluster's port-80 virtual server is
# fastL4 (`http:` empty, `httpRouter: false`), so http_parse_client_headers is never
# called and 10 requests returning 200 moved `fired` not at all; the HTTP/2 server on
# 8080 has no h2-speaking backend up. Neither is a phase 3 fact. device_poll runs
# whether or not anything is being served, so it isolates the mechanism.
#
# poll_probe carries a real CO-RE relocation on purpose: `max_usec` is declared
# first in its stub (local offset 0) and lives at offset 4 in TMM, so the relocation
# must patch 0 -> 4. A program with no field access would load on a BTF-less binary
# trivially and prove nothing about baked offsets.
POLLPROG="${POLLPROG:-$PROGDIR/poll_probe.bpf.o}"
if [ -f "$POLLPROG" ]; then
    L=$(POD="$POD" python3 "$DELIVER" "$POLLPROG" 6 1 2>&1 | tail -1)
    case "$L" in *"signature=verified"*) : ;; *) bad "poll_probe did not load" "$L" ;; esac
    PA=$($K python3 /usr/bin/ls-load.py arm 6 device_poll 2>&1 | tail -1)
    case "$PA" in *ARMED*) : ;; *) bad "poll_probe did not arm" "$PA" ;; esac
    B=$($K python3 /usr/bin/ls-load.py status 6 2>&1 | grep -oE 'fired=[0-9]+' | cut -d= -f2)
    sleep 3
    E=$($K python3 /usr/bin/ls-load.py status 6 2>&1 | grep -oE 'fired=[0-9]+' | cut -d= -f2)
    ER=$($K python3 /usr/bin/ls-load.py status 6 2>&1 | grep -oE 'errors=[0-9]+' | cut -d= -f2)
    if [ -n "$B" ] && [ -n "$E" ] && [ "$E" -gt "$B" ]; then
        ok "fired $B -> $E in 3s, errors=$ER --- a program with a BAKED offset EXECUTED on a binary with no type information"
    else
        bad "fired did not advance ($B -> $E)" "the poll loop should fire continuously"
    fi
    $K python3 /usr/bin/ls-load.py disarm device_poll >/dev/null 2>&1 || true
else
    echo "  SKIP --- no $POLLPROG. This is a SKIP, not a pass: without it nothing here"
    echo "         shows a program EXECUTING, only loading and arming."
fi

echo "=== 4. disarm is clean"
D=$($K python3 /usr/bin/ls-load.py disarm "$HOOK" 2>&1 | tail -1)
case "$D" in
  *DISARMED*) ok "disarmed live" ;;
  *)          bad "disarm did not report success" "$D" ;;
esac
echo "  pod restarts: $(kubectl get pods "$POD" --no-headers | awk '{print $4}')"

echo
echo "=== 5. a program that STILL carries .BTF.ext is REFUSED, naming the cause"
if [ -f "$UNSTRIPPED" ]; then
    U=$(POD="$POD" python3 "$DELIVER" "$UNSTRIPPED" 7 1 2>&1 | tail -2 | tr '\n' ' ')
    # THE REFUSAL REASON IS ON THE LOG, NOT IN THE REPLY, and the first version of
    # this case asserted against the reply. The client gets the generic
    # "ERR load refused (identity mismatch, malformed ELF, or uBPF rejected it)"
    # -- deliberately generic, so a caller cannot use it as an oracle -- while the
    # cause goes to stderr. Asserting on the reply reported FAIL for a refusal that
    # was working exactly as designed.
    case "$U" in
      *"OK loaded"*) bad "an UNRELOCATED program LOADED against a binary with no .BTF --- it is running on placeholder offsets" "$U" ;;
      *"refused"*|*"ERR"*)
        LG=$(kubectl logs "$POD" -c f5-tmm --tail=200 2>/dev/null | grep -c "carries CO-RE relocation records")
        if [ "${LG:-0}" -gt 0 ]; then
            ok "refused, and the LOG names the cause: no .BTF to resolve the records against"
        else
            bad "refused, but not by the relocation gate --- nothing on the log says why" "$U"
        fi ;;
      *) bad "unexpected reply" "$U" ;;
    esac
else
    echo "  SKIP --- no unstripped program at $UNSTRIPPED."
    echo "         Build one with bnk-build-programs.sh WITHOUT TMM_BTF set. This is a"
    echo "         SKIP, not a pass: the fail-dark path is the one that would be silent."
fi

echo
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
