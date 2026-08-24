#!/bin/sh
# Drive traffic at TMM and report what actually happened. RUNS ON THE DATKUBE HOST.
#
#   bnk-drive-traffic.sh <target> [count] [concurrency]
#   bnk-drive-traffic.sh 11.11.11.99 40 8
#   HOOK=rst_why bnk-drive-traffic.sh 11.11.11.99 40      also reports the hook's fired DELTA
#   ALPN=h2,http/1.1 bnk-drive-traffic.sh 11.11.11.99 5   TLS handshake with a chosen ALPN list
#
# WHY THIS EXISTS. Nine call sites in this repository drive traffic at TMM, in seven different
# spellings, and not one of them is shared. The committed loops are CORRECT --- both `$(seq)` sites
# expand inside the pod, which is what you want. The defects came from the one-off commands typed
# beside them, and they cost real time:
#
#   * `for i in $(seq 1 20)` written WITHOUT the escape expanded on the control node, so the pod
#     received `for i in 1<newline>2<newline>3` and answered "syntax error: unexpected word". With
#     2>/dev/null on the line that became an empty result, which read as "no traffic reached the
#     backend" --- while hooks were firing at that exact moment.
#   * `http_code=000` reported without curl's exit code, so a REFUSED connection (7) and a TIMED-OUT
#     one (28) looked identical. They point at completely different faults: 7 means TMM answered
#     with a reset and is refusing the port, 28 means nothing answered at all --- address or route.
#
# So the argument for this file is not that it fixes broken loops. It is that there is now a
# correct, tested thing to reach for, so the next measurement is not a fresh loop typed under time
# pressure. It loops INSIDE the pod, keeps stderr, separates the failure modes, and refuses to
# report success when nothing arrived. It is a measurement, not a hammer.
set -e

TARGET="${1:?usage: bnk-drive-traffic.sh <target> [count] [concurrency]}"
COUNT="${2:-20}"
CONC="${3:-1}"
CLIENT="${CLIENT:-client}"
PORT="${PORT:-80}"

pods() { kubectl get pods -l app=f5-tmm --no-headers | awk '$3=="Running"{print $1}'; }
sock() { kubectl exec "$1" -c f5-tmm -- sh -c 'ls /tmp/ls_load.sock.* 2>/dev/null | head -1'; }
firedof() {
    kubectl exec "$1" -c f5-tmm -- env LS_LOAD_SOCKET="$(sock "$1")" \
        python3 /usr/bin/ls-load.py status "${SLOT:-5}" 2>/dev/null \
        | sed -n 's/.*fired=\([0-9]*\).*/\1/p'
}

# fired is CUMULATIVE and a fresh load does not reset it. Always the delta, never the value.
if [ -n "${HOOK:-}" ]; then
    B=0; for p in $(pods); do B=$(( B + $(firedof "$p" 2>/dev/null || echo 0) )); done
    echo "  hook $HOOK baseline: fired=$B (cumulative across pods)"
fi

if [ -n "${ALPN:-}" ]; then
    # TLS with a chosen protocol list --- the client-controlled input an ALPN shield inspects.
    # curl cannot express an arbitrary list; openssl s_client can.
    echo "  driving: $COUNT TLS handshakes to $TARGET:${PORT} with alpn='$ALPN'"
    OUT=$(kubectl exec "$CLIENT" -- sh -c "
        i=0; ok=0; fail=0
        while [ \$i -lt $COUNT ]; do
          if echo | timeout 5 openssl s_client -connect $TARGET:$PORT -alpn '$ALPN' >/dev/null 2>&1; then
            ok=\$((ok+1)); else fail=\$((fail+1)); fi
          i=\$((i+1))
        done
        echo \"handshakes ok=\$ok failed=\$fail\"" 2>&1) || true
    echo "  $OUT"
else
    # THE LOOP RUNS IN THE POD. No $(seq) on this side --- see the note above.
    echo "  driving: $COUNT requests to http://$TARGET:$PORT/ (concurrency $CONC)"
    OUT=$(kubectl exec "$CLIENT" -- sh -c "
        run_one() {
          code=\$(curl -s -m 5 -o /dev/null -w '%{http_code}' \"http://$TARGET:$PORT/\" 2>/dev/null)
          echo \"\$code:\$?\"
        }
        i=0
        while [ \$i -lt $COUNT ]; do
          j=0
          while [ \$j -lt $CONC ] && [ \$i -lt $COUNT ]; do run_one & j=\$((j+1)); i=\$((i+1)); done
          wait
        done" 2>&1) || true

    OK=$(printf '%s\n' "$OUT" | grep -c '^200:' || true)
    REF=$(printf '%s\n' "$OUT" | grep -c ':7$'  || true)
    TMO=$(printf '%s\n' "$OUT" | grep -c ':28$' || true)
    OTH=$(printf '%s\n' "$OUT" | grep -c . || true)
    OTH=$(( OTH - OK - REF - TMO ))
    echo "  200 OK          : $OK"
    echo "  refused (exit 7): $REF   <- TMM answered with a RST. It is handling the packet and saying no."
    echo "  timed out  (28) : $TMO   <- nothing answered. Address or route, not a listener decision."
    [ "$OTH" -gt 0 ] && echo "  other           : $OTH"

    if [ "$OK" -eq 0 ]; then
        echo
        echo "  NOTHING SUCCEEDED --- so any hook count measured over this interval says nothing"
        echo "  about the hook. Fix the path first. If refused, arm rst_why and drain: TMM will"
        echo "  name its own reason, and 'Port denied' means no listener is open at that address"
        echo "  (see the runbook, 12g-bis)."
    fi
fi

if [ -n "${HOOK:-}" ]; then
    A=0; for p in $(pods); do A=$(( A + $(firedof "$p" 2>/dev/null || echo 0) )); done
    echo "  hook $HOOK: fired +$(( A - B )) over this run"
fi
