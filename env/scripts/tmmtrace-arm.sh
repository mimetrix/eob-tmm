#!/bin/sh
# tmmtrace-arm --- DEPLOY BOX half of `tmmtrace run`.
# Load a shipped, signed probe on slot 2, arm it at its hook, drive traffic, and
# report THIS run's delta (counters are per-slot and accumulate). No toolchain,
# no key here --- only a signed artifact gets loaded.
#
#   tmmtrace-arm <fn> <hook> <kind> [nreq]
set -e
FN="$1"; HOOK="$2"; KIND="$3"; NREQ="${4:-40}"; VS="${VS:-http://11.11.11.99/}"
POD=${POD:-$(kubectl get pods -l app=f5-tmm -o json | python3 -c '
import json, sys
pods = [p for p in json.load(sys.stdin)["items"] if not p["metadata"].get("deletionTimestamp")
        and any(c["type"] == "Ready" and c["status"] == "True" for c in p["status"].get("conditions", []))]
if len(pods) != 1: sys.exit("select one stable Ready pod with POD=...")
print(pods[0]["metadata"]["name"])
')}
[ -n "$POD" ] || { echo "*** no Running f5-tmm pod"; exit 1; }
echo "hook  : $HOOK   pod: $POD   slot: 2"
state=$(kubectl exec "$POD" -c f5-tmm -- /usr/bin/ls-load.py status 2)
echo "$state" | grep -q 'mode=0 ' || { echo "*** slot 2 is not disabled: $state"; exit 1; }

kubectl cp /tmp/$FN.bpf.o  "$POD":/tmp/$FN.bpf.o  -c f5-tmm
kubectl cp /tmp/$FN.bpf.sig "$POD":/tmp/$FN.bpf.sig -c f5-tmm
L=$(kubectl exec "$POD" -c f5-tmm -- /usr/bin/ls-load.py load 2 /tmp/$FN.bpf.o 1 2>&1)
echo "$L" | grep -q 'OK loaded' || { echo "*** load failed (slot 2 unchanged): $L"; exit 1; }
armed=0
cleanup() {
    if [ "$armed" = 1 ]; then
        D=$(kubectl exec "$POD" -c f5-tmm -- /usr/bin/ls-load.py disarm "$HOOK") || return 1
        echo "$D" | grep -q 'OK DISARMED LIVE' || { echo "*** disarm failed: $D"; return 1; }
        armed=0
    fi
    kubectl exec "$POD" -c f5-tmm -- /usr/bin/ls-load.py revoke 2
}
trap cleanup EXIT
A=$(kubectl exec "$POD" -c f5-tmm -- /usr/bin/ls-load.py arm 2 "$HOOK")
echo "$A" | grep -q 'OK ARMED LIVE' || { echo "*** arm failed: $A"; exit 1; }
armed=1

# baseline (per-slot counters accumulate), drive, delta
b=$(kubectl exec "$POD" -c f5-tmm -- /usr/bin/ls-load.py status 2)
bf=$(echo "$b"|grep -o 'fired=[0-9]*'|cut -d= -f2); bm=$(echo "$b"|grep -o 'safe_returns=[0-9]*'|cut -d= -f2)
echo "armed. driving $NREQ requests ..."
kubectl exec client -- sh -c 'for i in $(seq "$1"); do curl -x "" --http1.1 --fail --silent --show-error --max-time 8 -H "Connection: close" -o /dev/null "$2" || exit; done' trace "$NREQ" "$VS"
a=$(kubectl exec "$POD" -c f5-tmm -- /usr/bin/ls-load.py status 2)
af=$(echo "$a"|grep -o 'fired=[0-9]*'|cut -d= -f2); am=$(echo "$a"|grep -o 'safe_returns=[0-9]*'|cut -d= -f2)
F=$((af-bf)); M=$((am-bm))

echo "----------------------------------------"
if [ "$KIND" = count ]; then
  echo "  fired (hook hits) : $F"
  echo "  matched (count)   : $M"
  [ "$F" -gt 0 ] 2>/dev/null && echo "  match rate        : $(awk "BEGIN{printf \"%.1f%%\",100*$M/$F}")"
else
  echo "  fired (hook hits) : $F   ($KIND: per-value egress not wired --- use count()/predicate)"
fi
echo "----------------------------------------"
cleanup
trap - EXIT
echo "disarmed and disabled slot 2."
