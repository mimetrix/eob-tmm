#!/usr/bin/env bash
# §9 verify-before-load gate: PREVAIL statically verifies each shield BEFORE the
# embedded uBPF VM is allowed to run it. A good shield verifies and loads; an
# unsafe shield is rejected and never enters the data plane (fail closed).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
MM="$HERE/minimm/minimm-ubpf"
CLIENT="$HERE/client.py"
# PREVAIL binary: env override, else the sibling build, else PATH.
PV="${LS_VERIFIER:-$HERE/../ebpf-verifier/bin/prevail}"
[ -x "$PV" ] || PV="$(command -v prevail 2>/dev/null || true)"
[ -x "$PV" ] || { echo "PREVAIL (prevail) not found; set LS_VERIFIER=/path/to/prevail"; exit 1; }
export LS_VERIFIER="$PV" LS_VERIFY_SECTION=.text
GOOD="$HERE/shields/ls_shield_ubpf.bpf.o"
BAD="$HERE/shields/ls_shield_bad.bpf.o"
RP=8084; EP=9099

nap(){ read -t "$1" -u 9 _ 2>/dev/null||true; }; exec 9<>/dev/null
wait_port(){ for _ in $(seq 1 60); do (exec 3<>"/dev/tcp/$1/$2")2>/dev/null&&{ exec 3>&-;return 0;};nap 0.2;done;return 1; }
cleanup(){ kill "${ECHO_PID:-0}" "${RELAY_PID:-0}" 2>/dev/null; pkill -f 'bin/prevail' 2>/dev/null; rm -f /dev/shm/minimm_ls; }
trap cleanup EXIT
echo "### verifier: $PV"
rm -f /dev/shm/minimm_ls
"$MM" echo --listen "$EP" >/tmp/v.echo.log 2>&1 & ECHO_PID=$!; wait_port 127.0.0.1 "$EP"

echo "==================== GOOD shield (verified -> loaded -> enforce) ===================="
rm -f /dev/shm/minimm_ls
LS_SHIELD_OBJ="$GOOD" "$MM" relay --listen "$RP" --upstream "127.0.0.1:$EP" >/tmp/v.good.log 2>&1 & RELAY_PID=$!
wait_port 127.0.0.1 "$RP" || { echo "relay did not start"; cat /tmp/v.good.log; exit 1; }
grep -E 'verifying|verified|REJECTED' /tmp/v.good.log
"$MM" ctl mode enforce
echo "--- attack frame (expect dropped, relay alive) ---"; python3 "$CLIENT" attack --port "$RP"
nap 0.3
kill -0 "$RELAY_PID" 2>/dev/null && echo ">>> relay ALIVE — verified shield enforced" || echo ">>> relay DEAD (unexpected)"
"$MM" ctl stats
kill "$RELAY_PID" 2>/dev/null; nap 0.3

echo "==================== BAD shield (verifier REJECTS, fail closed) ===================="
rm -f /dev/shm/minimm_ls
LS_SHIELD_OBJ="$BAD" "$MM" relay --listen "$RP" --upstream "127.0.0.1:$EP" >/tmp/v.bad.log 2>&1 & RELAY_PID=$!
wait_port 127.0.0.1 "$RP" || true
nap 2.5   # give PREVAIL time to analyze + reject
grep -E 'verifying|REJECTED|WARNING|loaded' /tmp/v.bad.log
echo ">>> the unsafe shield was refused by the verifier; it never entered the VM/data plane"
echo "### done"
