#!/usr/bin/env bash
# End-to-end Live Shield demo against the minimm bent-pipe relay.
#
#   Scenario A (MONITOR): the shield detects the attack frame but does not act;
#                         the relay runs the vulnerable parser and DIES (§7.1).
#   Scenario B (ENFORCE): the shield drops the attack frame before dispatch;
#                         the relay survives and still forwards benign traffic.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
MM="$HERE/minimm/minimm"
CLIENT="$HERE/client.py"
RELAY_PORT=8080
ECHO_PORT=9090

# sleep without /bin/sleep (read -t is a portable delay)
nap() { read -t "$1" -u 9 _ 2>/dev/null || true; }
exec 9<>/dev/null

wait_port() { # host port
  for _ in $(seq 1 50); do
    (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null && { exec 3>&- 3<&-; return 0; }
    nap 0.1
  done; return 1
}

cleanup() { kill "${ECHO_PID:-0}" "${RELAY_PID:-0}" 2>/dev/null; rm -f /dev/shm/minimm_ls; }
trap cleanup EXIT

start_relay() {
  "$MM" relay --listen "$RELAY_PORT" --upstream "127.0.0.1:$ECHO_PORT" >/tmp/minimm.relay.log 2>&1 &
  RELAY_PID=$!
  wait_port 127.0.0.1 "$RELAY_PORT" || { echo "relay failed to start"; cat /tmp/minimm.relay.log; exit 1; }
}

echo "### starting echo upstream :$ECHO_PORT"
rm -f /dev/shm/minimm_ls
"$MM" echo --listen "$ECHO_PORT" >/tmp/minimm.echo.log 2>&1 &
ECHO_PID=$!
wait_port 127.0.0.1 "$ECHO_PORT" || { echo "echo failed to start"; exit 1; }

echo
echo "==================== Scenario A: MONITOR ===================="
start_relay
"$MM" ctl mode monitor
echo "--- benign frame (expect: forwarded + echoed, relay alive) ---"
python3 "$CLIENT" benign
echo "--- attack frame (expect: detected but NOT blocked -> relay DIES) ---"
python3 "$CLIENT" attack
nap 0.3
if kill -0 "$RELAY_PID" 2>/dev/null; then
  echo "relay PID $RELAY_PID: STILL ALIVE (unexpected)"
else
  echo ">>> relay PID $RELAY_PID: DEAD — monitor mode did not save the data plane (§7.1)"
fi
"$MM" ctl stats

echo
echo "==================== Scenario B: ENFORCE ===================="
start_relay
"$MM" ctl mode enforce
echo "--- attack frame (expect: DROPPED before dispatch, relay survives) ---"
python3 "$CLIENT" attack
echo "--- benign frame (expect: still forwarded + echoed) ---"
python3 "$CLIENT" benign
nap 0.3
if kill -0 "$RELAY_PID" 2>/dev/null; then
  echo ">>> relay PID $RELAY_PID: ALIVE — shield held the line"
else
  echo "relay PID $RELAY_PID: DEAD (unexpected)"
fi
"$MM" ctl stats
echo
echo "### done"
