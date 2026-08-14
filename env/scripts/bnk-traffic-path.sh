#!/bin/sh
# Stand up a working traffic path through the BNK proxy, from nothing.
#
# WHY THIS EXISTS. "Traffic has never reached the hook --- connections are
# refused" sat in tmm-integration-findings.md section 6 as an open blocker for a
# day. It was not a hook problem and not a TMM problem: the virtual server had no
# routable address, because BNK allocates VIPs from an **IPAMRange** custom
# resource that nothing in the F5 examples mentions and that did not exist on this
# cluster. Without it the service stays pending forever and every connection is
# refused, which looks exactly like a broken data plane.
#
# IPAMRange appeared nowhere in this repo's docs until 2026-08-14. That is the
# single most expensive undocumented fact in the BNK setup, and it is step 2 here.
#
# Three pieces, in this order --- each depends on the one before:
#   1. a backend the proxy can actually reach
#   2. an IPAMRange, so the VIP gets an address
#   3. the virtual server binding the VIP to the backend
#
# Assumes `client` and `server` pods already exist (env/bnk-dev-runbook.md
# section 12e) and that kubectl targets the datkube cluster. All in `default`.
set -e

VIP="${VIP:-11.11.11.99}"
BACKEND="${BACKEND:-22.22.22.100}"
RANGE_START="${RANGE_START:-11.11.11.200}"
RANGE_END="${RANGE_END:-11.11.11.220}"

echo "=== 1. backend on $BACKEND:80"
kubectl exec server -- sh -c '
  pkill -f "http.server" 2>/dev/null
  mkdir -p /tmp/www && echo "served-by-backend" > /tmp/www/index.html
  cd /tmp/www && setsid nohup python3 -m http.server 80 --bind 0.0.0.0 >/tmp/httpd.log 2>&1 &
  sleep 2; echo "  listeners on :80 = $(ss -lnt 2>/dev/null | grep -c :80)"' 2>&1 | tail -2

echo "=== 2. IPAMRange --- without this the VIP never gets an address"
kubectl apply -f - <<YAML 2>&1 | tail -2 | sed 's/^/  /'
apiVersion: fic.f5.com/v1
kind: IPAMRange
metadata:
  name: eob-range
  namespace: default
spec:
  ipRanges:
  - ipFamily: ipv4
    ipamLabel: default
    startAddress: $RANGE_START
    endAddress: $RANGE_END
YAML

echo "  waiting for the IPAM controller (takes ~30s)"
sleep 30
kubectl get svc f5-tmm-tcp-service --no-headers 2>/dev/null | sed 's/^/  /'

echo "=== 3. pool + virtual server $VIP:80 -> $BACKEND"
# The kind is F5VirtualServer (CRD f5-virtualservers.k8s.f5net.com), and the pool
# is a SEPARATE resource referenced by name -- not an inline block. Check with
# `kubectl get crd | grep f5` before assuming any other shape: F5BigContextSecure
# is a different CRD that is NOT installed on this cluster, and applying it fails
# with "no matches for kind", which reads like a cluster fault rather than a typo.
#
# `http: {}` is not optional for our purposes: it puts the flow through TMM's HTTP
# processing, which is where the hooks of interest live. Without it the flow is
# L4-only and an HTTP hook never fires -- traffic flows, the hook reads zero, and
# nothing looks broken.
#
# THE ENUM CASING IS INCONSISTENT BETWEEN FIELDS AND THE CRD IS THE ONLY AUTHORITY:
#   loadBalancingMethod  UPPER_SNAKE  -- ROUND_ROBIN (round-robin is rejected)
#   snat.type            lowercase    -- automap (SRC_TRANS_AUTOMAP is rejected)
# Every combination of those was tried by hand at some point. Do not guess; run
#   kubectl apply --dry-run=server -f -
# which reports the supported values for whichever field is wrong.
kubectl apply -f - <<YAML 2>&1 | tail -2 | sed 's/^/  /'
apiVersion: k8s.f5net.com/v1
kind: Pool
metadata:
  name: eob-pool
  namespace: default
spec:
  members:
  - address: $BACKEND
    port: 80
  minActiveMembers: 0
---
apiVersion: k8s.f5net.com/v1
kind: F5VirtualServer
metadata:
  name: eob-vs
  namespace: default
spec:
  destinationAddress: $VIP
  destinationPort: 80
  protocol: tcp
  pool: eob-pool
  loadBalancingMethod: ROUND_ROBIN
  http: {}
  snat:
    type: automap
YAML
sleep 10
kubectl get f5virtualserver eob-vs \
    -o jsonpath='  vs: {.spec.destinationAddress}:{.spec.destinationPort} pool={.spec.pool}{"\n"}' 2>/dev/null

echo "=== 4. does traffic actually flow?"
kubectl exec client -- curl -s -m 10 -w "\n  http=%{http_code} time=%{time_total}s\n" \
    "http://$VIP/" 2>&1 | tail -3 | sed 's/^/  /'

echo
echo "  If http=000, read the reset payload rather than guessing --- runbook section 12e."
echo "  If the service still shows <pending>, the IPAMRange did not take: check the ipam"
echo "  controller's logs, and note it sometimes needs a restart to pick up a new range."
