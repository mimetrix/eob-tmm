#!/bin/sh
# tmmtrace-run.sh --- run a pre-built tmmtrace probe live on datkube (Phase 4).
#
#   bash tmmtrace-run.sh <name> [nreq]        run on the datkube box
#
# The build half (gen -> PREVAIL verify -> F5 sign) happens off-box, in the dev
# sandbox + at the signing key --- the same "compile in dev, sign at F5, load on
# target" split every program follows. This is the ON-TARGET half: it takes a
# signed probe staged in ~/demo/tmmtrace/<name>.{bpf.o,bpf.sig,meta.json}, arms it
# at its hook on SLOT 2 (the shield, if armed, is on slot 1 --- both run at once),
# drives a little traffic, reads the aggregate, and disarms.
#
# WHAT IT SHOWS. For a `count()` probe (optionally predicated), safe_returns is the
# match count and fired is the hook-hit count --- so you get "matched M of N", live,
# from one line of DSL. A `value`/`hist` probe needs its values streamed off the
# ring (not wired yet); this script reports that and stops.
#
# Run demo-reset.sh first if you want a single clean pod (otherwise traffic
# load-balances and only the armed replica counts).
set -e

DIR="${TMMTRACE_DIR:-$HOME/demo/tmmtrace}"
NAME="$1"; NREQ="${2:-40}"; VS=http://11.11.11.99/; SLOT=2
[ -n "$NAME" ] || { echo "usage: tmmtrace-run.sh <name> [nreq]"; ls "$DIR" 2>/dev/null | sed -n 's/\.meta\.json$//p' | sed 's/^/  have: /'; exit 1; }
META="$DIR/$NAME.meta.json"
[ -f "$META" ] || { echo "*** no $META"; exit 1; }

get() { python3 -c "import json;print(json.load(open('$META')).get('$1',''))"; }
HOOK=$(get hook); EXPR=$(get expr); KIND=$(get kind)
POD=$(kubectl get pods -l app=f5-tmm --no-headers | grep Running | head -1 | awk '{print $1}')
[ -n "$POD" ] || { echo "*** no Running f5-tmm pod"; exit 1; }
echo "probe : $EXPR"
echo "hook  : $HOOK   pod: $POD   slot: $SLOT"

kubectl cp "$DIR/$NAME.bpf.o"  "$POD":/tmp/$NAME.bpf.o  -c f5-tmm
kubectl cp "$DIR/$NAME.bpf.sig" "$POD":/tmp/$NAME.bpf.sig -c f5-tmm
kubectl exec "$POD" -c f5-tmm -- /usr/bin/ls-load.py load $SLOT /tmp/$NAME.bpf.o 1 >/dev/null
# A function entry holds ONE probe. If something (the shield, a prior run) is armed
# at this hook, FORCE=1 disarms it first; otherwise we stop with guidance.
[ "${FORCE:-0}" = 1 ] && kubectl exec "$POD" -c f5-tmm -- /usr/bin/ls-load.py disarm "$HOOK" >/dev/null 2>&1
if ! kubectl exec "$POD" -c f5-tmm -- /usr/bin/ls-load.py arm $SLOT "$HOOK" >/dev/null 2>&1; then
    echo "*** $HOOK is already armed (the shield, or a prior run) --- a function entry"
    echo "    holds only one probe. Either:"
    echo "      disarm it:  kubectl exec $POD -c f5-tmm -- /usr/bin/ls-load.py disarm $HOOK"
    echo "      or re-run:  FORCE=1 bash ~/demo/tmmtrace-run.sh $NAME"
    exit 1
fi
echo "armed. driving $NREQ requests ..."
kubectl exec client -- sh -c "for i in \$(seq $NREQ); do curl -so /dev/null $VS; done" || true

S=$(kubectl exec "$POD" -c f5-tmm -- /usr/bin/ls-load.py status $SLOT)
FIRED=$(echo "$S" | grep -o 'fired=[0-9]*' | cut -d= -f2)
MATCH=$(echo "$S" | grep -o 'safe_returns=[0-9]*' | cut -d= -f2)

echo "------------------------------------------------------------"
if [ "$KIND" = "count" ]; then
    echo "  fired  (hook hits) : ${FIRED:-0}"
    echo "  matched (count)    : ${MATCH:-0}"
    if [ "${FIRED:-0}" -gt 0 ] 2>/dev/null; then
        echo "  match rate         : $(awk "BEGIN{printf \"%.1f%%\", 100*${MATCH:-0}/${FIRED}}")"
    fi
else
    echo "  fired (hook hits)  : ${FIRED:-0}"
    echo "  ($KIND probe: per-value egress not wired yet --- values are not streamed off"
    echo "   the ring in this build. Use a count()/predicated probe for a live aggregate.)"
fi
echo "------------------------------------------------------------"
kubectl exec "$POD" -c f5-tmm -- /usr/bin/ls-load.py disarm "$HOOK" >/dev/null 2>&1 || true
echo "disarmed slot $SLOT (shield on slot 1, if any, untouched)."
