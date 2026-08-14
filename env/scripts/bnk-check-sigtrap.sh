#!/bin/sh
# Does TMM block, or already catch, SIGTRAP on its threads?
#
# THIS DECIDES WHETHER THE WHOLE ARMING MECHANISM IS VIABLE, so it is worth
# running before anything else on a new form factor or a new TMM build.
#
# The text_poke_bp protocol arms a function by first writing INT3 (0xcc) over the
# entry pad. A core that executes that byte mid-patch takes a SYNCHRONOUS SIGTRAP,
# and our handler is what sends it to the right place. Two ways that goes wrong:
#
#   SigBlk bit set  => SIGTRAP is BLOCKED. A synchronous signal that is blocked
#                      cannot be delivered, so the kernel forces the default
#                      action and THE PROCESS DIES. This would rule the approach
#                      out entirely --- not a bug to fix, a mechanism to abandon.
#   SigCgt bit set  => something already handles SIGTRAP (TMM itself, crashagent).
#                      Ours must CHAIN to it, not replace it, or we break crash
#                      reporting for every fault that has nothing to do with us.
#
# SIGTRAP is signal 5, so bit index 4, so mask 0x10 in the hex fields of
# /proc/<pid>/task/<tid>/status.
#
# Run INSIDE the TMM pod:
#   kubectl exec -it <f5-tmm pod> -c f5-tmm -- sh < env/scripts/bnk-check-sigtrap.sh
set -e

pid=""
for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    c=$(cat /proc/$p/comm 2>/dev/null || true)
    case "$c" in tmm.*|tmm) pid=$p; break;; esac
done
[ -n "$pid" ] || { echo "no tmm process found --- are you inside the f5-tmm container?"; exit 1; }

echo "tmm pid=$pid comm=$(cat /proc/$pid/comm 2>/dev/null) threads=$(ls /proc/$pid/task 2>/dev/null | wc -l)"
echo
printf "%-8s %-16s %-18s %-14s %-18s %s\n" tid comm SigBlk TRAP_blocked SigCgt TRAP_caught

blocked=0
caught=0
for t in /proc/$pid/task/*; do
    tid=$(basename "$t")
    nm=$(cat "$t/comm" 2>/dev/null || true)
    blk=$(grep '^SigBlk' "$t/status" 2>/dev/null | sed 's/.*:[ \t]*//')
    cgt=$(grep '^SigCgt' "$t/status" 2>/dev/null | sed 's/.*:[ \t]*//')
    [ -n "$blk" ] || continue
    bb=$(( 0x$blk & 0x10 )); cc=$(( 0x$cgt & 0x10 ))
    [ "$bb" -ne 0 ] && blocked=$((blocked+1))
    [ "$cc" -ne 0 ] && caught=$((caught+1))
    printf "%-8s %-16s %-18s %-14s %-18s %s\n" "$tid" "$nm" "$blk" \
        "$( [ "$bb" -ne 0 ] && echo YES-BLOCKED || echo no )" "$cgt" \
        "$( [ "$cc" -ne 0 ] && echo yes || echo no )"
done

echo
if [ "$blocked" -ne 0 ]; then
    echo "*** $blocked thread(s) BLOCK SIGTRAP. text_poke_bp cannot be used on those threads:"
    echo "    a synchronous trap there kills the process. Stop and rethink the arming form."
else
    echo "ok  no thread blocks SIGTRAP --- a mid-patch trap can be delivered."
fi
if [ "$caught" -ne 0 ]; then
    echo "!!  $caught thread(s) already CATCH SIGTRAP. Our handler must chain to the existing"
    echo "    one for any address that is not one of our pads, and must not race crashagent."
else
    echo "ok  nothing else handles SIGTRAP today --- but do not assume that stays true across"
    echo "    builds; crashagent and apport are both in this pod."
fi
