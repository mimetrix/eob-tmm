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
printf "%-8s %-16s %-6s %-18s %-14s %-18s %s\n" tid comm role SigBlk TRAP_blocked SigCgt TRAP_caught

# WHICH THREAD blocks SIGTRAP is the whole question, not how many. Only threads
# that EXECUTE patched data-path text can take a mid-patch trap. On BNK the poll
# threads are named tmm.<N> (tmm.0, tmm.1, ...); a bare "tmm" is a housekeeping
# thread that does not run the hooked code, and it legitimately masks nearly every
# signal. Counting all threads together reports a false alarm --- an early version
# of this script did exactly that, and its verdict contradicted the fact that
# arming demonstrably works on this build.
poll_blocked=0
poll_total=0
other_blocked=0
caught=0
for t in /proc/$pid/task/*; do
    tid=$(basename "$t")
    nm=$(cat "$t/comm" 2>/dev/null || true)
    blk=$(grep '^SigBlk' "$t/status" 2>/dev/null | sed 's/.*:[ \t]*//')
    cgt=$(grep '^SigCgt' "$t/status" 2>/dev/null | sed 's/.*:[ \t]*//')
    [ -n "$blk" ] || continue
    bb=$(( 0x$blk & 0x10 )); cc=$(( 0x$cgt & 0x10 ))
    [ "$cc" -ne 0 ] && caught=$((caught+1))

    role=other
    case "$nm" in tmm.[0-9]*) role=poll;; esac
    if [ "$role" = poll ]; then
        poll_total=$((poll_total+1))
        [ "$bb" -ne 0 ] && poll_blocked=$((poll_blocked+1))
    else
        [ "$bb" -ne 0 ] && other_blocked=$((other_blocked+1))
    fi

    printf "%-8s %-16s %-6s %-18s %-14s %-18s %s\n" "$tid" "$nm" "$role" "$blk" \
        "$( [ "$bb" -ne 0 ] && echo YES-BLOCKED || echo no )" "$cgt" \
        "$( [ "$cc" -ne 0 ] && echo yes || echo no )"
done

echo
if [ "$poll_blocked" -ne 0 ]; then
    echo "*** $poll_blocked of $poll_total POLL thread(s) block SIGTRAP. That is the blocking"
    echo "    case: a mid-patch trap on a poll thread cannot be delivered, so the kernel's"
    echo "    default action kills the process. Stop and rethink the arming form."
else
    echo "ok  none of the $poll_total poll thread(s) block SIGTRAP --- a mid-patch trap on the"
    echo "    threads that execute hooked code can be delivered. This is the condition that"
    echo "    matters for text_poke_bp."
fi
if [ "$other_blocked" -ne 0 ]; then
    echo "--  $other_blocked non-poll thread(s) block SIGTRAP. Expected and harmless: they do not"
    echo "    execute hooked data-path text, so they never hit a patched pad."
fi
if [ "$caught" -ne 0 ]; then
    echo "!!  $caught thread(s) already CATCH SIGTRAP --- TMM or crashagent has a handler."
    echo "    Ours MUST chain to it for any address that is not one of our pads, or we break"
    echo "    crash reporting for faults that have nothing to do with us."
else
    echo "ok  nothing else handles SIGTRAP today --- but do not assume that holds across"
    echo "    builds; crashagent and apport are both in this pod."
fi
