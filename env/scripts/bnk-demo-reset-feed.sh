#!/bin/sh
# The reset-feed demo. Run from the DATKUBE host. Five minutes, no hand-typed values.
#
#   bnk-demo-reset-feed.sh [addr]
#
# `addr` is rst_why's entry address. Omit it and the script refuses rather than
# guessing: get it from `bnk-preflight.sh <image> rst_why`, which resolves it from the
# binary in the image it just verified.
#
# WHY EVERY STEP LOOKS PARANOID. Each guard below stands for a specific way this
# demo broke on 2026-08-17:
#
#   - It arms EVERY TMM pod. Requests load-balance, so arming one pod and watching it
#     shows fired=0 while the other serves every request --- indistinguishable from a
#     hook that does not work. This cost an hour.
#   - It refuses a hand-carried address. rst_why moved 64 bytes between two builds;
#     the stale address armed rst_cause_match_peer, which also has a nop pad, so
#     arming reported OK ARMED LIVE and nothing ever fired.
#   - It drains stale records before measuring. The ring persists across arms, so old
#     records read as fresh evidence.
#   - It checks the VIP answers first. The Gateway reported PROGRAMMED=True with no
#     backend at all, which looks exactly like a working data path until you send a
#     request.
#
# The tools ship IN the image (/usr/bin/ls_drain, /usr/bin/ls-load.py), so nothing is
# copied into a running container while an audience watches.
set -e

ADDR="$1"
VIP="${VIP:-11.11.11.99}"
SLOT="${SLOT:-5}"
PROG="${PROG:-/usr/share/ls/rate_watch.bpf.o}"
SEG="${SEG:-/tmp/ls_tp_ring}"

if [ -z "$ADDR" ]; then
    cat >&2 <<'EOT'
usage: bnk-demo-reset-feed.sh 0x<rst_why-entry-address>

  Get the address from the image you are about to demo --- never from a previous run:

      bnk-preflight.sh <image-tag> rst_why 'ls_map: reloc'

  It prints the address resolved from the binary it just verified. A stale address
  arms a neighbouring function silently, because nop pads exist in many wrong places.
EOT
    exit 2
fi

say()  { printf '\n\033[1m%s\033[0m\n' "$1"; }
ctl()  { kubectl exec -i "$1" -c f5-tmm -- python3 /usr/bin/ls-load.py "$2" "$3" "$4" "$5" "$6" 2>&1; }
drain(){ kubectl exec "$1" -c f5-tmm -- sh -c "timeout ${2:-5} /usr/bin/ls_drain --segment $SEG 2>/dev/null" 2>/dev/null; }

PODS=$(kubectl get pods -l app=f5-tmm --no-headers | grep Running | awk '{print $1}')
[ -n "$PODS" ] || { echo "*** no Running f5-tmm pods" >&2; exit 1; }

# --- 0. is there a data path at all? ----------------------------------------------
say "0 · the data path answers"
# `|| echo 000` on a command that ALREADY printed 000 concatenates to "000000". curl
# writes the code even when it fails, so capture it and default only if empty.
CODE=$(kubectl exec client -- curl -s -m 8 -o /dev/null -w '%{http_code}' "http://$VIP/" 2>/dev/null) || true
CODE=${CODE:-000}
echo "  GET http://$VIP/  ->  HTTP $CODE"
if [ "$CODE" != "200" ]; then
    cat >&2 <<EOT

*** The VIP does not answer, so nothing below will produce records.
    Check the BACKEND, not the Gateway: a Gateway can report PROGRAMMED=True with
    address $VIP while spk-app-1 has no pods and no http-pool service at all.
        kubectl get pods,svc -n spk-app-1
        kubectl apply -f env/manifests/spk-app-1-backend.yaml
EOT
    exit 1
fi

# --- 1. nothing is armed yet ------------------------------------------------------
say "1 · before: TMM is stock, nothing armed"
for P in $PODS; do printf '  %-26s %s\n' "$P" "$(ctl "$P" status "$SLOT")"; done

# --- 2. load and arm, on EVERY pod, while traffic is flowing ----------------------
say "2 · load a verified program and arm rst_why --- on a RUNNING TMM, no restart"
for P in $PODS; do
    printf '  %-26s %s\n' "$P" "$(ctl "$P" load "$SLOT" "$PROG" 2 rst_why)"
    printf '  %-26s %s\n' ''   "$(ctl "$P" arm  "$SLOT" "$ADDR")"
done

# The ring outlives an arm, so anything already in it predates this demo.
for P in $PODS; do drain "$P" 3 >/dev/null 2>&1 || true; done
echo "  (stale records drained --- what follows is from this run only)"

# --- 3. drive the three distinguishable causes -----------------------------------
say "3 · drive traffic: normal requests, a client abort, and a closed port"
kubectl exec client -- sh -c 'for i in $(seq 1 15); do timeout 2 curl -s -o /dev/null http://'"$VIP"'/; done' >/dev/null 2>&1 || true
echo "  15 normal requests        (backend closes each connection -> proxy teardown)"
kubectl exec client -- sh -c 'for i in 1 2 3; do curl -s -o /dev/null --max-time 0.001 http://'"$VIP"'/; done' >/dev/null 2>&1 || true
echo "  3 client aborts           (remote sends RST)"
kubectl exec client -- sh -c 'for i in 1 2 3 4 5; do timeout 2 nc -z '"$VIP"' 9999; done' >/dev/null 2>&1 || true
echo "  5 connects to port 9999   (no listener -> flow rejected)"

# --- 4. the records ---------------------------------------------------------------
say "4 · the records --- every reset, with the line and the reason that caused it"
TMP=$(mktemp); trap 'rm -f "$TMP"' EXIT
for P in $PODS; do drain "$P" 6 >> "$TMP" || true; done
grep -c . "$TMP" | sed 's/^/  records: /'
head -3 "$TMP" | sed 's/^/    /'

say "5 · ranked by internal decision --- the question support actually asks"
if command -v jq >/dev/null 2>&1; then
    jq -r '"\(.file):\(.line)\t\(.cause)"' < "$TMP" 2>/dev/null \
      | sort | uniq -c | sort -rn \
      | awk -F'\t' '{printf "  %s  %s\n", $1, $2}'
else
    sed 's/.*"file":"\([^"]*\)","line":\([0-9]*\).*"cause":"\([^"]*\)".*/\1:\2  \3/' "$TMP" \
      | sort | uniq -c | sort -rn | sed 's/^/  /'
fi

cat <<'EOT'

  Read the ranking, not the individual lines. That is the diagnosis:

    tcp.c:4689           "TCP RST from remote system"   the REMOTE end reset ---
                                                        TMM did not decide to.
                                                        Investigate the server.
    http_mr_proxy.c:993  "Closing"                      normal proxy teardown,
                          + :994                        two adjacent RST_WHY calls,
                                                        one per side of the proxy.
    flow_table.c:2618    "No local listener"            a flow was REJECTED.
                                                        Misconfigured port or VIP.

  flow_table.c is the one to point at. Its cause is not a string literal --- the
  source reads flow_reject_cause[flow_reject_code], a lookup into an 18-entry table
  chosen at runtime ("VIP down", "Connection limit exceeded", "DOS Attack signature",
  "TCP 3WHS rejected", ...). No amount of reading the source recovers which one
  applied. It arrives only because the trampoline forwards all six arguments.

  None of this is reachable from iRules or WASM: RST_WHY is an internal macro on an
  internal path, not an event F5 exposed. The hook was chosen AFTER the binary
  shipped and armed into a live process with no restart.
EOT

# --- 6. disarm --------------------------------------------------------------------
say "6 · disarm --- the entry bytes go back exactly as they were"
for P in $PODS; do printf '  %-26s %s\n' "$P" "$(ctl "$P" disarm "$ADDR")"; done

cat <<'EOT'

  SAY THESE OUT LOUD, because a reviewer will ask inside five minutes:

    - The loader socket does NO signature verification. Lab only.
    - Per-invocation cost is UNMEASURED. Quote no per-call number.
    - LS_VM_JIT=1, and uBPF's compiled path never consults the bounds callback, so
      this run does not exercise memory safety --- only functionality.
    - The record carries NO flow identity. Records correlate by timestamp and
      thread, not to a request. Site-and-cause attribution is the claim.
EOT
