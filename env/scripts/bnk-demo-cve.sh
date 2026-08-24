#!/bin/sh
# The CVE move, measured rather than asserted. RUNS ON THE DATKUBE HOST.
#
#   bnk-demo-cve.sh            run both arms and write the result artifact
#   bnk-demo-cve.sh --show     print the last result without re-running
#
# WHY THIS IS A SEPARATE SCRIPT AND NOT A MOVE INSIDE bnk-demo.sh. The self-test runs at INIT,
# inside the pod, before any traffic exists. Changing the arm therefore means changing an
# environment variable and rolling the deployment --- minutes, and it takes the data path down
# with it. That does not belong in the middle of a live walkthrough. So the measurement happens
# here, writes what it measured to a file, and the demo READS that file. A number the demo did
# not take from a run is the exact move this whole demo argues against.
#
# WHAT IS REAL AND WHAT IS SYNTHESISED --- state this before anyone asks:
#   REAL         the bug, the shield program, the patched entry, the verdict, the crash.
#   SYNTHESISED  the input. `prot_transfer_log_profile` has no Kubernetes CRD, so no configuration
#                available on BNK can produce the NULL. The condition is synthesised because it
#                CANNOT BE CONFIGURED, not because synthesising was easier. See cve-selftest.md.
set -e

DEPLOY=f5-tmm; CONTAINER=f5-tmm
OUT="${OUT:-/tmp/ls-cve-result.json}"
BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m'); OFF=$(printf '\033[0m')
say(){ printf '\n%s== %s ==%s\n' "$BOLD" "$1" "$OFF"; }
note(){ printf '%s%s%s\n' "$DIM" "$1" "$OFF"; }

if [ "$1" = "--show" ]; then
    [ -f "$OUT" ] && cat "$OUT" || echo "no result yet --- run bnk-demo-cve.sh first"
    exit 0
fi

pods(){ kubectl get pods -l app=f5-tmm --no-headers | awk '$3=="Running"{print $1}'; }

# One arm. Sets the mode, rolls, and reads the verdict out of the log of the process that
# actually ran --- including, when it died, the log of the incarnation that died.
arm_run() {
    MODE="$1"
    say "arm: LS_SHIELD_MODE=$MODE"
    kubectl set env "deploy/$DEPLOY" -c "$CONTAINER" \
        LS_SHIELD_ENABLE=1 LS_SHIELD_MODE="$MODE" LS_VM_SELFTEST=2 LS_VM_VERBOSE=1 >/dev/null
    kubectl rollout status "deploy/$DEPLOY" --timeout=300s >/dev/null 2>&1 || true
    sleep 6

    VERDICT=""; SURVIVED=""; RESTARTS=0; SRC=current
    for P in $(pods); do
        R=$(kubectl get pod "$P" -o jsonpath='{.status.containerStatuses[?(@.name=="f5-tmm")].restartCount}' 2>/dev/null || echo 0)
        RESTARTS=$(( RESTARTS + ${R:-0} ))
        L=$(kubectl logs "$P" -c f5-tmm --tail=400 2>/dev/null | grep -a "SELFTEST" || true)
        # If this incarnation restarted, the arm that matters is the one that DIED. Reading a
        # neighbouring healthy pod here once produced a crash reported next to a log line proving
        # the opposite --- the pair proves nothing without the verdict from the dead process.
        if [ "${R:-0}" -gt 0 ]; then
            PREV=$(kubectl logs "$P" -c f5-tmm --previous --tail=400 2>/dev/null | grep -a "SELFTEST" || true)
            [ -n "$PREV" ] && { L="$PREV"; SRC=previous; }
        fi
        [ -n "$L" ] && { echo "$L" | sed 's/^/    /'; }
        echo "$L" | grep -q "SAFE_RETURN"  && VERDICT=SAFE_RETURN
        echo "$L" | grep -q "FALLTHROUGH"  && VERDICT=FALLTHROUGH
        echo "$L" | grep -q "survived"     && SURVIVED=yes
    done
    note "    verdict=${VERDICT:-NOT-SEEN} survived=${SURVIVED:-no} restarts=$RESTARTS log=$SRC"
    RES_VERDICT="$VERDICT"; RES_SURVIVED="$SURVIVED"; RES_RESTARTS="$RESTARTS"; RES_SRC="$SRC"
}

say "the bug"
note "  A logging path reads a name through a pointer the caller never set. When the profile is"
note "  absent the pointer is NULL, TMM reads through it, and the process dies. One request from"
note "  anyone who can reach the listener takes down the traffic it was carrying."
note ""
note "  The shield reads the same field FIRST and returns the safe value when it is NULL, so the"
note "  body that would dereference it never runs:"
kubectl get pods -l app=f5-tmm --no-headers >/dev/null 2>&1 || { echo "no cluster"; exit 1; }
P1=$(pods | head -1)
kubectl exec "$P1" -c f5-tmm -- sh -c 'cat /usr/share/ls/ls_2026_http_psm.src 2>/dev/null' 2>/dev/null \
    | sed 's/^/    /' || note "    (source not baked into the image --- see substrate/shields/ls_2026_http_psm.bpf.c)"

# ---- ENFORCE: the shield acts -------------------------------------------------------------
arm_run enforce
E_VERDICT="$RES_VERDICT"; E_SURVIVED="$RES_SURVIVED"; E_RESTARTS="$RES_RESTARTS"

# ---- MONITOR: the shield sees it and declines ---------------------------------------------
# NOT LS_SHIELD_ENABLE=0. Disabling skips arming entirely, so the self-test never runs and there
# is no verdict to compare --- an absence of evidence dressed as a control. Monitor is also the
# posture an operator actually uses before enforcing.
arm_run monitor
M_VERDICT="$RES_VERDICT"; M_SURVIVED="$RES_SURVIVED"; M_RESTARTS="$RES_RESTARTS"; M_SRC="$RES_SRC"

# ---- leave the cluster in the safe arm ----------------------------------------------------
say "restoring enforce"
kubectl set env "deploy/$DEPLOY" -c "$CONTAINER" LS_SHIELD_MODE=enforce >/dev/null
kubectl rollout status "deploy/$DEPLOY" --timeout=300s >/dev/null 2>&1 || true
note "  left in enforce --- the arm that survives."

# ---- the verdict of the pair --------------------------------------------------------------
say "result"
STAMP=$(date -u +%FT%TZ)
if [ "$E_VERDICT" = "SAFE_RETURN" ] && [ "$M_VERDICT" = "FALLTHROUGH" ]; then
    HELD=yes
    printf '  %sONE VARIABLE CHANGED --- the shield mode --- AND THE OUTCOME FLIPPED.%s\n' "$BOLD" "$OFF"
    note "    enforce : verdict=SAFE_RETURN, survived, restarts=$E_RESTARTS"
    note "    monitor : verdict=FALLTHROUGH, the dereference ran, restarts=$M_RESTARTS (log=$M_SRC)"
else
    HELD=no
    printf '  %sNOT DEMONSTRATED THIS RUN%s --- enforce=%s monitor=%s\n' \
           "$BOLD" "$OFF" "${E_VERDICT:-NOT-SEEN}" "${M_VERDICT:-NOT-SEEN}"
    note "    Say so rather than quoting the last good run. If both are NOT-SEEN the substrate is"
    note "    probably dormant: a fresh deployment carries ZERO LS_* variables and looks healthy."
    note "    Run bnk-enable-substrate.sh, then this again."
fi
note ""
note "  What this does NOT show: that live traffic reaches this hook. Measured 2026-08-24 on a"
note "  WORKING data path (40 requests, 40 x 200 OK, http_parse_client_headers fired +40): this"
note "  hook fired +0 across 30 requests. It needs a security log profile whose format string"
note "  contains \${profile_name}, and that has no CRD. The claim is 'the shield stops this"
note "  crash', never 'this CVE was mitigated on live traffic'."

cat > "$OUT" <<JSON
{"stamp":"$STAMP","held":"$HELD",
 "enforce":{"verdict":"${E_VERDICT:-NOT-SEEN}","survived":"${E_SURVIVED:-no}","restarts":$E_RESTARTS},
 "monitor":{"verdict":"${M_VERDICT:-NOT-SEEN}","restarts":$M_RESTARTS,"log":"$M_SRC"},
 "live_traffic_reaches_hook":"no --- needs a security log profile with \${profile_name}, no CRD exists"}
JSON
note ""
note "  written: $OUT   (bnk-demo.sh reads this rather than hardcoding a number)"
