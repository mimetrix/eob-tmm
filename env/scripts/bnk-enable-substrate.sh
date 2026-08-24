#!/bin/sh
# Turn the substrate ON in a deployed TMM. RUNS ON THE DATKUBE HOST.
#
#   bnk-enable-substrate.sh            apply the env, roll, verify
#   bnk-enable-substrate.sh --show     print what is set now; change nothing
#   bnk-enable-substrate.sh --off      remove the variables (the substrate goes dormant)
#
# THE GAP THIS EXISTS FOR, found 2026-08-24 rebuilding the datkube box from nothing. The image
# shipped, the pods came up on the right build, signature verification announced itself --- and
# nothing else worked, because a freshly `datkube install`ed deployment carries **zero LS_*
# variables**. Every one of them had been set by hand on the box that died. The variables were
# mentioned in six documents and applyable from none of them.
#
# Without them TMM runs with the substrate compiled in and dormant: no loader socket, so nothing
# can be loaded; no built-in shield armed; no tracepoint ring, so nothing to drain. The pods look
# perfectly healthy. Every test suite in this repository needs LS_LOAD_SOCKET and would report a
# connection failure rather than a missing configuration.
#
# EVERY VARIABLE IS COMMENTED, because a value nobody can explain is a value nobody dares change.
set -e

DEPLOY="${DEPLOY:-f5-tmm}"
CONTAINER="${CONTAINER:-f5-tmm}"
MODE=""
for a in "$@"; do
    case "$a" in
        --show) MODE=show ;;
        --off)  MODE=off ;;
        *) echo "*** unknown option $a" >&2; exit 2 ;;
    esac
done

# The set, and why each one is here.
#   LS_SHIELD_ENABLE  1        arm the built-in shield at startup. 0 makes the whole substrate a
#                              no-op without reverting the integration --- the switch that exists
#                              so a misbehaving shield does not need a rebuild to disable.
#   LS_SHIELD_MODE    monitor  the built-in shield observes and falls through. `enforce` lets it
#                              return a hook's declared safe value, which is NOT yet demonstrated
#                              on live traffic and needs the safe-return policy work first.
#   LS_LOAD_SOCKET    path     the runtime load path. OFF unless set, and the socket the loader
#                              creates is this path plus TMM's instance number
#                              (/tmp/ls_load.sock.24), which is what every client must connect to.
#   LS_TP_RING        path     the tracepoint ring in shared memory; ls_drain reads it. Without
#                              this, programs emit records into nothing.
#   LS_VM_JIT         1        compile rather than interpret. Note the JIT does not consult the
#                              bounds callback, so this is the faster and less-checked path.
#   LS_VM_TIMING      1        per-invocation cycle counters. Preemption-polluted --- read the min.
#   LS_VM_SAMPLES     1        keep the last few ctx values a hook saw, for `samples`.
#   LS_VM_VERBOSE     1        the init and arm lines. Without it, a silent substrate and a
#                              dormant one look identical in the log.
VARS="LS_SHIELD_ENABLE=1 LS_SHIELD_MODE=monitor LS_LOAD_SOCKET=/tmp/ls_load.sock \
LS_TP_RING=/tmp/ls_tp_ring LS_VM_JIT=1 LS_VM_TIMING=1 LS_VM_SAMPLES=1 LS_VM_VERBOSE=1"

show() {
    kubectl get deploy "$DEPLOY" -o json | python3 -c '
import json,sys
d=json.load(sys.stdin)
for c in d["spec"]["template"]["spec"]["containers"]:
    ls=[(e["name"],e.get("value","")) for e in c.get("env",[])
        if e["name"].startswith("LS_") and not any(k in e["name"] for k in ("CERT","CA_","KEY_FILE"))]
    print("  %s: %d substrate variable(s)%s" % (c["name"], len(ls), "" if ls else "  <- DORMANT"))
    for n,v in sorted(ls): print("     %-18s %s" % (n,v))'
}

if [ "$MODE" = show ]; then show; exit 0; fi

if [ "$MODE" = off ]; then
    for kv in $VARS; do
        kubectl set env "deploy/$DEPLOY" -c "$CONTAINER" "${kv%%=*}-" >/dev/null
    done
    echo "  removed. The substrate is compiled in and dormant --- which looks exactly like healthy."
    kubectl rollout status "deploy/$DEPLOY" --timeout=300s | tail -1
    exit 0
fi

echo "=== 1. before"
show

echo
echo "=== 2. apply"
# One kubectl set env call, so there is one rollout rather than eight.
# shellcheck disable=SC2086
kubectl set env "deploy/$DEPLOY" -c "$CONTAINER" $VARS >/dev/null
echo "  8 variables set on container $CONTAINER"

echo
echo "=== 3. roll"
kubectl rollout status "deploy/$DEPLOY" --timeout=300s | tail -1 | sed 's/^/  /'

echo
echo "=== 4. VERIFY FROM THE LOG, not from the fact that kubectl accepted the patch"
# The substrate announces itself. If these lines are absent the variables reached the pod spec and
# not the process --- which has happened, via a container name that did not match.
for p in $(kubectl get pods -l app=f5-tmm --no-headers | awk '$3=="Running"{print $1}'); do
    printf '  %-28s\n' "$p"
    kubectl logs "$p" -c "$CONTAINER" 2>/dev/null \
      | grep -oE 'ls_vm: init[^,]*|ctx builders[^.]*|LOADER LISTENING on [^ ]*|ls_audit: recording|ARMED slot=[0-9]+[^ ]*|signature verification ARMED' \
      | sort -u | sed 's/^/      /'
    s=$(kubectl exec "$p" -c "$CONTAINER" -- sh -c 'ls /tmp/ls_load.sock.* 2>/dev/null | head -1')
    [ -n "$s" ] && echo "      socket: $s" || echo "      *** NO SOCKET --- the loader did not start"
done
