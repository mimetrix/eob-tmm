#!/bin/sh
# Part 3 of the demo: WHY THE TLS HANDSHAKE FAILED. Run on the DATKUBE host.
#
#   bnk-demo-sslerr.sh
#
# THE CLAIM. An iRule sees CLIENTSSL_HANDSHAKE fail and does not see why. The alert on
# the wire barely narrows it either --- of TMM's 475 ssl_err call sites, 210 pass
# SSL_A_INTERNAL_ERROR and 110 pass SSL_A_ILLEGAL_PARAM, so "internal_error" is what a
# client is told for 44% of every distinguishable failure. The diagnosis is the SITE
# (__func__ plus __LINE__) and the MESSAGE, and that pair exists only inside TMM.
#
# WHY THIS SITE AND NOT THE LAST ONE. The first HTTP tracepoint was rolled back because
# iRules already observed every field it captured. This one was chosen by asking what
# support actually asks, then checking the answer was unavailable elsewhere --- see
# ls_ctx_sslerr.h.
#
# NOTE ON __func__ vs __FILE__: ssl_err passes __func__ and __LINE__, the opposite of
# rst_why, so the record names the FUNCTION and not the file. That is why the drain emits
# "func" rather than "file" for this schema --- the two feeds are deliberately not
# interchangeable in that field.
set -e

HOOK="${HOOK:-ssl__err}"
SLOT="${SLOT:-8}"
PROG="${PROG:-/usr/share/ls/sslerr_watch.bpf.o}"
SEG="${SEG:-/tmp/ls_tp_ring}"
VIP="${VIP:-11.11.11.99}"

say()  { printf '\n\033[1m%s\033[0m\n' "$1"; }
ctl()  { kubectl exec -i "$1" -c f5-tmm -- python3 /usr/bin/ls-load.py "$2" "$3" "$4" "$5" "$6" 2>&1; }
drain(){ kubectl exec "$1" -c f5-tmm -- sh -c "timeout ${2:-6} /usr/bin/ls_drain --segment $SEG 2>/dev/null" 2>/dev/null; }

PODS=$(kubectl get pods -l app=f5-tmm --no-headers | grep Running | awk '{print $1}')
[ -n "$PODS" ] || { echo "*** no Running f5-tmm pods" >&2; exit 1; }

say "0 · is there a TLS listener at all?"
# Without one, every trigger below fails in the CLIENT and nothing reaches TMM --- which
# looks identical to a hook that does not fire. Check before measuring.
LST=$(kubectl get gateway -A -o jsonpath='{range .items[*]}{range .spec.listeners[*]}{.protocol}:{.port} {end}{end}' 2>/dev/null)
echo "  gateway listeners: $LST"
case "$LST" in
  *HTTPS*) echo "  ok  an HTTPS listener exists" ;;
  *) echo "  *** no HTTPS listener --- ssl__err cannot fire from client traffic." >&2
     echo "      Add a TLS listener before reading anything below as a result." >&2
     exit 1 ;;
esac

say "1 · load and arm ssl__err BY NAME, on every pod"
for P in $PODS; do
    printf '  %-26s %s\n' "$P" "$(ctl "$P" load "$SLOT" "$PROG" 1 "$HOOK")"
    printf '  %-26s %s\n' ''   "$(ctl "$P" arm  "$SLOT" "$HOOK" | tail -1)"
done
# mode 1 = MONITOR, deliberately. A tracepoint must not alter a TLS failure path; the
# program also has no `return LS_SAFE_RETURN` anywhere, so this is belt and braces.

for P in $PODS; do drain "$P" 3 >/dev/null 2>&1 || true; done
echo "  (stale records drained --- what follows is from this run only)"

say "2 · drive handshakes that FAIL, four different ways"
# Each targets a different failure class, so the records should differ in site AND alert
# rather than all landing on one line. openssl is in the client image; -brief keeps its
# own diagnosis short, since the point is TMM's answer and not openssl's.
t() {
    printf '  %-38s ' "$2"
    kubectl exec client -- sh -c "timeout 6 $1" >/dev/null 2>&1 && echo "connected" || echo "failed (expected)"
}
t "openssl s_client -connect $VIP:443 -tls1 -brief </dev/null"                "TLS 1.0 offered"
t "openssl s_client -connect $VIP:443 -cipher NULL-MD5 -brief </dev/null"     "only a NULL cipher offered"
t "openssl s_client -connect $VIP:443 -sigalgs RSA+SHA1 -brief </dev/null"    "only SHA1 signatures offered"
t "printf 'GARBAGE NOT A CLIENTHELLO\\n' | timeout 4 nc $VIP 443"             "garbage instead of a ClientHello"

say "3 · counters --- did the hook fire?"
for P in $PODS; do printf '  %-26s %s\n' "$P" "$(ctl "$P" status "$SLOT" | tail -1)"; done

say "4 · the records --- the site and message TMM chose, per failure"
TMP=$(mktemp); trap 'rm -f "$TMP"' EXIT
for P in $PODS; do drain "$P" 6 >> "$TMP" || true; done
grep -c . "$TMP" | sed 's/^/  records: /'
head -6 "$TMP" | sed 's/^/    /'

say "5 · ranked by site --- the question support actually asks"
if command -v jq >/dev/null 2>&1; then
    jq -r 'select(.hook=="sslerr") | "\(.func):\(.line)\t\(.alert_name)\t\(.msg)"' < "$TMP" 2>/dev/null \
      | sort | uniq -c | sort -rn \
      | awk -F'\t' '{printf "  %-44s %-20s %s\n", $1, $2, $3}'
else
    sed -n 's/.*"func":"\([^"]*\)","line":\([0-9]*\),"alert":[0-9]*,"alert_name":"\([^"]*\)".*"msg":"\([^"]*\)".*/\1:\2  \3  \4/p' "$TMP" \
      | sort | uniq -c | sort -rn | sed 's/^/  /'
fi

cat <<'EOT'

  What to point at: the alert column is what the CLIENT was told. The func:line and
  message columns are what TMM actually decided, and they are not derivable from the
  alert --- 210 of 475 sites send internal_error.

  And the flow cookie in these records is the SAME cookie the reset feed emits, because
  UFLOW_COOKIE resolves to CONNFLOW_COOKIE for a connflow and ssl_ctx already holds one.
  So "TLS failed here" and "the connection was reset there" join on one field.
  Caveat worth saying out loud: for an HTTP/2 STREAM the cookie additionally XORs the
  streamflow pointer, so the two feeds do not join there.
EOT

say "6 · disarm"
for P in $PODS; do printf '  %-26s %s\n' "$P" "$(ctl "$P" disarm "$HOOK" | tail -1)"; done
