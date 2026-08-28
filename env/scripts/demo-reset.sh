#!/bin/sh
# demo-reset.sh --- REPEATABLE reset for the Live Surface shield demo.
#
# Run this on the datkube box (eob-bnk-datkube-01) before each take. It leaves
# you with a single, freshly-armed TMM pod whose evidence ring is live, so the
# two-window demo (ls_drain tail + curl) works immediately and repeatably.
#
#   bash demo-reset.sh
#
# WHY EACH STEP (so a failure is diagnosable):
#   1. ONE replica, restarted. Two replicas = a load-balancer coin-flip (only the
#      armed pod fires). Restarting resets the per-process rate-limit counter
#      (first 8 events stream, then 1-in-64) and clears the ring --- so every take
#      starts fresh. A plain re-arm without a restart inherits a used-up counter.
#   2. Deliver + load + arm. The shield is loaded over the socket into slot 1 and
#      armed at http_parse_client_headers (fires once per request). Signed, monitor.
#   3. Warm the ring. /dev/shm/ls_tp_ring is created lazily on the FIRST shield
#      fire, so ls_drain has nothing to map until traffic flows. A couple of
#      requests create it; the verify drain below consumes them, so your live run
#      starts clean.
#
# Files: needs the signed shield beside it (override with SHIELD_DIR=...):
#   $SHIELD_DIR/evidence_demo.bpf.o  and  .bpf.sig
set -e

SHIELD_DIR="${SHIELD_DIR:-$HOME/demo}"
HOOK=http_parse_client_headers
VS=http://11.11.11.99/

[ -f "$SHIELD_DIR/evidence_demo.bpf.o" ]  || { echo "*** missing $SHIELD_DIR/evidence_demo.bpf.o"; exit 1; }
[ -f "$SHIELD_DIR/evidence_demo.bpf.sig" ] || { echo "*** missing $SHIELD_DIR/evidence_demo.bpf.sig"; exit 1; }

echo "== 1. one replica, restarted (fresh counter, empty ring) =="
kubectl scale deploy/f5-tmm --replicas=1 >/dev/null
kubectl rollout restart deploy/f5-tmm >/dev/null
kubectl rollout status deploy/f5-tmm --timeout=180s | tail -1
POD=$(kubectl get pods -l app=f5-tmm --no-headers | grep Running | head -1 | awk '{print $1}')
[ -n "$POD" ] || { echo "*** no Running f5-tmm pod"; exit 1; }
echo "   pod: $POD"

echo "== 2. deliver + load + arm slot 1 (monitor) at $HOOK =="
kubectl cp "$SHIELD_DIR/evidence_demo.bpf.o"  "$POD":/tmp/evidence_demo.bpf.o  -c f5-tmm
kubectl cp "$SHIELD_DIR/evidence_demo.bpf.sig" "$POD":/tmp/evidence_demo.bpf.sig -c f5-tmm
kubectl exec "$POD" -c f5-tmm -- /usr/bin/ls-load.py load 1 /tmp/evidence_demo.bpf.o 1
kubectl exec "$POD" -c f5-tmm -- /usr/bin/ls-load.py arm  1 "$HOOK"

echo "== 3. warm the ring (creates /dev/shm/ls_tp_ring) =="
kubectl exec client -- sh -c "for i in \$(seq 2); do curl -so /dev/null $VS; done"

echo "== 4. verify =="
kubectl exec "$POD" -c f5-tmm -- /usr/bin/ls-load.py status 1
if kubectl exec "$POD" -c f5-tmm -- /usr/bin/ls_drain --segment /dev/shm/ls_tp_ring --once 2>/dev/null | grep -q '"hook":"shield"'; then
    echo "   ls_drain OK --- ring is live"
else
    echo "*** ls_drain produced no shield records --- check that traffic reached this pod"; exit 1
fi

cat <<EOF

============================================================
READY.  Demo pod:  $POD
------------------------------------------------------------
Window A  (evidence stream, leave running):
  kubectl exec $POD -c f5-tmm -- /usr/bin/ls_drain --segment /dev/shm/ls_tp_ring --no-stats

Window B  (drive traffic, then read counters):
  kubectl exec client -- sh -c 'for i in \$(seq 8); do curl -so /dev/null $VS; done'
  kubectl exec $POD -c f5-tmm -- /usr/bin/ls-load.py status 1
------------------------------------------------------------
~6 events will stream (2 of the first-8 burst went to warmup); status.fired
counts every hit. Re-run this script for a fresh take.
============================================================
EOF
