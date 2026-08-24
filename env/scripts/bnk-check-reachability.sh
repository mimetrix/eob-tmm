#!/bin/sh
# Is this hook reached by traffic? And --- the part that matters --- what does a ZERO mean.
# RUNS ON THE DATKUBE HOST.
#
#   bnk-check-reachability.sh <hook> [seconds]     default 20s of ambient traffic
#
# WHY THIS EXISTS, and it is not the measurement. Measuring a fire count is four commands. The
# reason this is a script is that on 2026-08-20 a hook measured zero, "not reachable" was written
# into GROUND_TRUTH.md, and the CVE demonstration was set aside for four days --- while a tool for
# demonstrating exactly that shield against exactly that condition already existed, built and
# documented under the heading "Demonstrating the shield without traffic".
#
# The knowledge was not missing. It was unretrievable at the moment it was needed, which does the
# same damage as not having it and costs more, because the repository looked covered.
#
# So the measurement is the easy half. This script's job is to refuse to report a zero without
# also saying what a zero does and does not mean --- because "not reached by this traffic" and
# "cannot be demonstrated" are different sentences, and collapsing them is what happened.
#
# This repository's own rule, from bnk-package.sh: documentation that has to be remembered at the
# right moment is not a control; a script is.
set -e

HOOK="${1:?usage: bnk-check-reachability.sh <hook> [seconds]}"
SECS="${2:-20}"
PASS_TRAFFIC="${VIP:-}"

pods() { kubectl get pods -l app=f5-tmm --no-headers | awk '$3=="Running"{print $1}'; }
sock() { kubectl exec "$1" -c f5-tmm -- sh -c 'ls /tmp/ls_load.sock.* 2>/dev/null | head -1'; }
ctl()  { p=$1; shift; kubectl exec "$p" -c f5-tmm -- env LS_LOAD_SOCKET="$(sock "$p")" \
           python3 /usr/bin/ls-load.py "$@" 2>&1 | tail -1; }
fired() { echo "$1" | sed -n 's/.*fired=\([0-9]*\).*/\1/p'; }

SLOT="${SLOT:-7}"
PROG="${PROG:-/usr/share/ls/rst_watch.bpf.o}"

echo "=== hook: $HOOK"
P1=$(pods | head -1)
[ -n "$P1" ] || { echo "*** no Running f5-tmm pod"; exit 2; }

# 1. Is it even armable? A refusal here is a different answer from a zero, and saying so early
#    stops "unreachable" being recorded when the truth is "ambiguous name" or "no pad".
R=$(ctl "$P1" arm "$SLOT" "$HOOK" 2>&1 || true)
case "$R" in
  *"ARMED LIVE"*) echo "  armable : yes --- $R" ;;
  *"NO PROGRAM"*)
      ctl "$P1" load "$SLOT" "$PROG" 1 >/dev/null 2>&1
      R=$(ctl "$P1" arm "$SLOT" "$HOOK" 2>&1 || true)
      case "$R" in
        *"ARMED LIVE"*) echo "  armable : yes --- $R" ;;
        *) echo "  armable : NO --- $R"; echo; echo "  That is not a reachability answer. Resolve it first."; exit 1 ;;
      esac ;;
  *) echo "  armable : NO --- $R"
     echo
     echo "  NOT A REACHABILITY ANSWER. A refused arm means ambiguous name, no pad, or an"
     echo "  already-armed entry --- none of which say anything about whether traffic reaches it."
     exit 1 ;;
esac

# 2. fired is CUMULATIVE and a fresh load does NOT reset it (gen increments, the counter does not).
#    Take the difference across the interval, never the absolute value.
BEFORE=$(fired "$(ctl "$P1" status "$SLOT")")
echo "  baseline: fired=$BEFORE  (cumulative --- the delta is the measurement)"

if [ -n "$PASS_TRAFFIC" ]; then
    echo "  driving : 20 requests to $PASS_TRAFFIC"
    kubectl exec client -- sh -c "i=0; while [ \$i -lt 20 ]; do curl -s -m 3 -o /dev/null http://$PASS_TRAFFIC/; i=\$((i+1)); done" >/dev/null 2>&1 || true
else
    echo "  driving : nothing --- ${SECS}s of ambient traffic only (set VIP=<addr> to drive requests)"
    sleep "$SECS"
fi

AFTER=$(fired "$(ctl "$P1" status "$SLOT")")
DELTA=$(( ${AFTER:-0} - ${BEFORE:-0} ))
ctl "$P1" disarm "$HOOK" >/dev/null 2>&1 || true
echo "  result  : fired +$DELTA over the interval"
echo

# 3. THE PART THIS SCRIPT EXISTS FOR.
if [ "$DELTA" -gt 0 ]; then
    cat <<TXT
  REACHED. $HOOK executes on this traffic, so a program armed here observes real events.
  Reachability was the single thing that killed five earlier CVE candidates --- a hook with a
  non-zero count is a candidate that has already cleared the hardest gate.
TXT
    exit 0
fi

cat <<'TXT'
  NOT REACHED BY THIS TRAFFIC --- and that sentence is narrower than it looks.

  It means: nothing in the traffic that ran during this interval executed the function.
  It does NOT mean: the hook is wrong, the mechanism does not work here, or the behaviour
  cannot be demonstrated. Those are separate claims and collapsing them has cost this project
  four days once already.

  BEFORE RECORDING "unreachable" ANYWHERE, rule out the cheap explanations:

    1. Was there any traffic at all? A zero with no requests measures nothing. Drive some:
         VIP=<addr> bnk-check-reachability.sh <hook>
       and if the VIP does not answer, that is the data path, not the hook --- arm rst_why and
       drain, TMM will name the cause (see the "Port denied" note in the runbook).

    2. Is it the RIGHT traffic? An HTTP hook needs HTTP through a virtual server with an HTTP
       profile; ambient cluster noise is mostly TCP teardown. Wrong traffic reads as no traffic.

    3. Is the CONDITION configurable at all? Some functions run only when a specific
       configuration exists. If no CRD can create that configuration, no amount of traffic will
       ever reach it --- and that is a statement about the PLATFORM, not about the shield.

  AND IF (3) IS THE ANSWER, THE DEMONSTRATION IS STILL AVAILABLE:

    LS_VM_SELFTEST builds the ctx the vulnerable call site would build, runs it through the real
    armed program in the real VM inside the real TMM, and at level 2 performs the real
    dereference if the shield declines. Same binary, one variable, opposite outcomes.

       kubectl set env deploy/f5-tmm -c f5-tmm LS_SHIELD_MODE=enforce LS_VM_SELFTEST=2
       kubectl set env deploy/f5-tmm -c f5-tmm LS_SHIELD_MODE=monitor      # the control arm
       kubectl set env deploy/f5-tmm -c f5-tmm LS_VM_SELFTEST- LS_SHIELD_MODE=monitor   # NOT OPTIONAL

    What that proves and what it does not --- the boundary is at the ctx, and it matters --
    is written out in cve-selftest.md. Read it before quoting the result.

  So: record "not reached by this traffic, condition not configurable via CRD", never
  "cannot be demonstrated". The second sentence is not something this measurement can support.
TXT
exit 0
