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
# HOW LONG IT TAKES: about 60--90 seconds, most of it waiting for the IPAM
# controller and the virtual-server reconcile. I recorded "the launcher returns
# exit 124" against this script five separate times and started looking for an
# fd left open by the backgrounded server. Measured 2026-08-20: the backgrounding
# is fine (`setsid nohup ... >log 2>&1 &` returns in 1.2 s, with or without
# stdin closed). The 124s were my own `timeout 60` wrapper, set shorter than the
# script's unavoidable waits. Nothing was broken; I misread my own instrument
# five times because I never measured it. Allow 180 s.
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
  # [h]ttp.server, NOT http.server. This shell'"'"'s own command line contains the pattern, so an
  # unbracketed pkill -f kills the shell that is running it --- exit 143, and the backend never
  # starts. Measured twice: on 2026-08-20 the step reported "command terminated with exit code 143"
  # and left the server down, and on 2026-08-24 a rebuilt cluster had zero listeners on :80 for
  # exactly this reason, which then read as a broken data path rather than a missing daemon.
  # The bracket makes the pattern not match itself.
  pkill -f "[h]ttp.server" 2>/dev/null
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

# DO NOT POLL THE SERVICE'S EXTERNAL IP. I replaced the fixed 30 s sleep with a
# poll on svc/f5-tmm-tcp-service .status.loadBalancer.ingress[0].ip, ran it, and got
# "STILL PENDING after 60s" on a cluster whose data path was working. On this
# cluster that field stays <pending> permanently --- BNK programs the VIP into TMM
# over gRPC and does not write it back into the Service status. So the poll was
# checking something that is never true, and printing a scary and false diagnosis.
# A fixed sleep that was merely a guess became a confident wrong answer, which is
# worse. The condition that IS meaningful is the virtual server's own readiness,
# and that is polled in step 3 where the VS exists.
echo "  IPAMRange applied. Not polling the Service's external IP: on this cluster it"
echo "  stays <pending> for good, because BNK programs the address into TMM over gRPC"
echo "  rather than writing it back to the Service. Readiness is checked on the VS below."
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
# THE RESOURCE IS `f5-virtualservers`, HYPHENATED. `kubectl get f5virtualserver` ---
# the spelling that reads naturally from the CRD kind F5VirtualServer --- does not
# exist, and errors with "the server doesn't have a resource type". With 2>/dev/null
# on the line, that error became an empty result, and an empty result counted as
# "there are no virtual servers". I concluded the data path had no VS and went
# looking for the wrong problem. Check `kubectl api-resources | grep -i virtualserver`
# rather than trusting a plausible spelling, and never silence stderr on a get whose
# emptiness you intend to interpret.
#
# AND POLL ITS STATUS, which is the condition that actually decides whether HTTP is
# proxied. eob-vs sat at False --- "Waiting for one or more dependent CRs to be
# applied" --- for six days because its POOL had been deleted. Traffic still returned
# 200 the whole time, SNATed by TMM at layer 4, so nothing looked wrong: the only
# symptom was that an HTTP hook never fired.
echo "  waiting for the virtual server to reconcile (needs its pool to exist first)"
i=0
while [ $i -lt 120 ]; do
    VS=$(kubectl get f5-virtualservers eob-vs --no-headers 2>/dev/null | awk '{print $2}')
    [ "$VS" = "True" ] && break
    i=$((i + 5)); sleep 5
done
if [ "$VS" = "True" ]; then
    echo "  eob-vs ready after ${i}s"
else
    echo "  *** eob-vs is NOT ready after ${i}s:"
    kubectl get f5-virtualservers eob-vs --no-headers 2>&1 | sed 's/^/      /'
    echo "      Traffic may still return 200 --- TMM will proxy at layer 4 and SNAT it ---"
    echo "      while no HTTP profile is programmed, so any HTTP hook fires zero times."
fi
kubectl get f5-virtualservers eob-vs \
    -o jsonpath='  vs: {.spec.destinationAddress}:{.spec.destinationPort} pool={.spec.pool} http={.spec.http}{"\n"}' 2>/dev/null

echo "=== 4. does traffic actually flow?"
kubectl exec client -- curl -s -m 10 -w "\n  http=%{http_code} time=%{time_total}s\n" \
    "http://$VIP/" 2>&1 | tail -3 | sed 's/^/  /'

echo
echo "  If http=000, read the reset payload rather than guessing --- runbook section 12e."
echo "  If the service still shows <pending>, the IPAMRange did not take: check the ipam"
echo "  controller's logs, and note it sometimes needs a restart to pick up a new range."
