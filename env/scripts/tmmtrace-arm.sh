#!/bin/sh
# tmmtrace-arm --- DEPLOY BOX half of `tmmtrace run`.
# Load a shipped, signed probe on slot 2, arm it at its hook, drive traffic, and
# report THIS run's delta (counters are per-slot and accumulate). No toolchain,
# no key here --- only a signed artifact gets loaded.
#
#   tmmtrace-arm <fn> <hook> <kind> [nreq]
set -e
FN="$1"; HOOK="$2"; KIND="$3"; NREQ="${4:-40}"; VS="${VS:-http://11.11.11.99/}"
POD=$(kubectl get pods -l app=f5-tmm --no-headers | grep Running | head -1 | awk '{print $1}')
[ -n "$POD" ] || { echo "*** no Running f5-tmm pod"; exit 1; }
echo "hook  : $HOOK   pod: $POD   slot: 2"

kubectl cp /tmp/$FN.bpf.o  "$POD":/tmp/$FN.bpf.o  -c f5-tmm
kubectl cp /tmp/$FN.bpf.sig "$POD":/tmp/$FN.bpf.sig -c f5-tmm
L=$(kubectl exec "$POD" -c f5-tmm -- /usr/bin/ls-load.py load 2 /tmp/$FN.bpf.o 1 2>&1)
echo "$L" | grep -q 'OK loaded' || { echo "*** load failed (slot 2 unchanged): $L"; exit 1; }
kubectl exec "$POD" -c f5-tmm -- /usr/bin/ls-load.py disarm "$HOOK" >/dev/null 2>&1 || true
kubectl exec "$POD" -c f5-tmm -- /usr/bin/ls-load.py arm 2 "$HOOK" >/dev/null

# baseline (per-slot counters accumulate), drive, delta
b=$(kubectl exec "$POD" -c f5-tmm -- /usr/bin/ls-load.py status 2)
bf=$(echo "$b"|grep -o 'fired=[0-9]*'|cut -d= -f2); bm=$(echo "$b"|grep -o 'safe_returns=[0-9]*'|cut -d= -f2)
echo "armed. driving $NREQ requests ..."
kubectl exec client -- sh -c "for i in \$(seq $NREQ); do curl -so /dev/null $VS; done" || true
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
kubectl exec "$POD" -c f5-tmm -- /usr/bin/ls-load.py disarm "$HOOK" >/dev/null 2>&1 || true
echo "disarmed slot 2."
