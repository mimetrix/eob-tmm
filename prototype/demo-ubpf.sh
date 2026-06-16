#!/usr/bin/env bash
# Track 2 (real product model): the Live Shield as eBPF BYTECODE run by an
# EMBEDDED userspace VM (uBPF) inside minimm. The host calls the VM at the hook
# point and acts on its return value — no kernel, no injection, no privileges.
# This is the TMM-faithful model: TMM bypasses the kernel, so the eBPF runs in
# a VM embedded in the data-plane process itself.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
MM="$HERE/minimm/minimm-ubpf"
CLIENT="$HERE/client.py"
export LS_SHIELD_OBJ="${LS_SHIELD_OBJ:-$HERE/shields/ls_shield_ubpf.bpf.o}"
RP=8080; EP=9090

nap() { read -t "$1" -u 9 _ 2>/dev/null || true; }
exec 9<>/dev/null
wait_port() { for _ in $(seq 1 50); do (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null && { exec 3>&- 3<&-; return 0; }; nap 0.1; done; return 1; }
cleanup() { kill "${ECHO_PID:-0}" "${RELAY_PID:-0}" "${TRACE_PID:-0}" 2>/dev/null; rm -f /dev/shm/minimm_ls; }
trap cleanup EXIT

[ -f "$LS_SHIELD_OBJ" ] || { echo "shield object missing: $LS_SHIELD_OBJ (run: make -C minimm minimm-ubpf)"; exit 1; }
rm -f /dev/shm/minimm_ls
"$MM" echo --listen "$EP" >/tmp/u.echo.log 2>&1 & ECHO_PID=$!
wait_port 127.0.0.1 "$EP" || { echo "echo failed"; exit 1; }

start_relay() {
  "$MM" relay --listen "$RP" --upstream "127.0.0.1:$EP" >/tmp/u.relay.log 2>&1 & RELAY_PID=$!
  wait_port 127.0.0.1 "$RP" || { echo "relay failed:"; cat /tmp/u.relay.log; exit 1; }
}

echo "==================== ENFORCE (embedded uBPF shield) ===================="
start_relay; head -1 /tmp/u.relay.log
"$MM" ctl mode enforce
echo "--- attack frame (expect: VM returns DROP, relay survives) ---"; python3 "$CLIENT" attack
echo "--- benign frame (expect: forwarded + echoed) ---"; python3 "$CLIENT" benign
nap 0.3
kill -0 "$RELAY_PID" 2>/dev/null && echo ">>> relay ALIVE — embedded uBPF shield held the line" \
                                 || echo ">>> relay DEAD (unexpected)"
"$MM" ctl stats

echo "==================== MONITOR (crash-class, §7.1) ===================="
kill "$RELAY_PID" 2>/dev/null; nap 0.2
start_relay
"$MM" ctl mode monitor
echo "--- attack frame (expect: VM matches but monitor passes -> relay DIES) ---"; python3 "$CLIENT" attack
nap 0.3
kill -0 "$RELAY_PID" 2>/dev/null && echo ">>> relay ALIVE (unexpected)" \
                                 || echo ">>> relay DEAD — monitor did not save the data plane (§7.1)"
"$MM" ctl stats

echo "==================== FLIGHT RECORDER (observe mode, §3.1) ===================="
# Same embedded VM, OBSERVE mode: the program never changes flow, but it keeps a
# ring of recent frames and arms a dump on the crash precondition. The dump
# captures the run-up INTO the failure; because it is shm-backed, it SURVIVES the
# data-plane crash — the post-mortem a core dump cannot give you.
TRACE_MM="$HERE/minimm/minimm-trace"
TRACE_OBJ="$HERE/shields/ls_trace_ubpf.bpf.o"
kill "$RELAY_PID" 2>/dev/null; nap 0.2
if [ -x "$TRACE_MM" ] && [ -f "$TRACE_OBJ" ]; then
  rm -f /dev/shm/minimm_ls
  LS_SHIELD_OBJ="$TRACE_OBJ" "$TRACE_MM" relay --listen "$RP" --upstream "127.0.0.1:$EP" >/tmp/u.trace.log 2>&1 & TRACE_PID=$!
  wait_port 127.0.0.1 "$RP" || { echo "trace relay failed:"; cat /tmp/u.trace.log; }
  echo "--- run-up: benign frames (recorded into the ring; flow untouched) ---"
  set -- "1:alpha" "2:bravo" "3:charlie" "0:delta"
  for f in "$@"; do python3 "$CLIENT" raw --op "${f%%:*}" --data "${f#*:}" >/dev/null 2>&1; done
  echo "--- trigger: attack frame (observe never blocks -> dump, then relay dies) ---"
  python3 "$CLIENT" attack >/dev/null 2>&1
  nap 0.3
  kill -0 "$TRACE_PID" 2>/dev/null && echo ">>> relay ALIVE (unexpected for observe)" \
                                   || echo ">>> relay DEAD — observe did NOT block; the recorder captured the run-up first"
  echo "--- live dump (emitted at the hook, before the crash) ---"
  grep -A6 'FLIGHT RECORDER DUMP' /tmp/u.trace.log || echo "(no dump found)"
  echo "--- post-mortem: ctl flightrec reads the ring from shm — it SURVIVED the crash ---"
  "$TRACE_MM" ctl flightrec
else
  echo "(skipped: build minimm-trace with 'make -C minimm ubpf')"
fi
echo "### done"
