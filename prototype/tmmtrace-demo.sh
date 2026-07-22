#!/usr/bin/env bash
# tmmtrace demo — one tool, both halves of the substrate.
#
# tmmtrace is a bpftrace-style front-end to TMM's embedded eBPF VM: you write a
# one-liner, it compiles to a shield, runs it through the PREVAIL verify gate,
# and loads it into minimm's embedded uBPF VM. The SAME grammar spans OBSERVE
# (tracepoint / diagnostics) and FILTER (the CVE shield) — chosen by the action
# verb. "Explore -> shield" in one language.
#
# Prereq:  make -C minimm ubpf    (builds minimm-ubpf + minimm-trace + libubpf.a)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TT="$HERE/tmmtrace"

hr(){ printf '\n\033[1m==== %s ====\033[0m\n' "$1"; }

hr "1. list the probes this build exposes (from the signed hook-point map)"
"$TT" list

hr "2. OBSERVE — watch the CVE precondition (read-only, lowest tier)"
echo '$ tmmtrace run '\''tmm:l7:frame /args.opcode >= 4/ { count(); }'\'''
"$TT" run 'tmm:l7:frame /args.opcode >= 4/ { count(); }'

hr "3. FILTER — ship the mitigation: SAME predicate, drop() instead of count()"
echo '$ tmmtrace run '\''tmm:l7:frame /args.opcode >= 4/ { drop(); }'\'''
"$TT" run 'tmm:l7:frame /args.opcode >= 4/ { drop(); }'

hr "4. COMBINED PLAY — drop the attack AND keep the forensics"
echo '$ tmmtrace run '\''tmm:l7:frame /args.opcode >= 4/ { drop(); snapshot(); }'\'''
"$TT" run 'tmm:l7:frame /args.opcode >= 4/ { drop(); snapshot(); }'

hr "5. the verify gate is real — an unsafe program is rejected, fail-closed"
echo '$ tmmtrace compile '\''tmm:l7:frame { drop(); }'\''   # (verified before load)'
"$TT" compile 'tmm:l7:frame /args.payload_len > 1024/ { drop(); }' | sed -n '1,10p'

echo
echo "### done — one grammar: explore (observe) -> shield (filter), same pipeline."
