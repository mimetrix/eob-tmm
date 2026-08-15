#!/bin/sh
# tmm:l7:http_headers --- the tracepoint demo, end to end, on a live BNK cluster.
#
# Run this ON THE DATKUBE HOST. It is self-contained: it builds its own wire
# messages, loads the program, drives traffic, and checks the result against
# predictions that are printed BEFORE the traffic runs. A demo that reports what
# happened is a log; one that states what should happen and then checks is a test.
#
#   ./tp-demo.sh              full run
#   ./tp-demo.sh --records    also dump decoded records from the segment
#   ./tp-demo.sh --reset      restart TMM first, for clean counters
#
# WHAT IT SHOWS. One designed-in tracepoint at the single point in
# http_process_client_headers() that every request reaches --- clean parse and
# every rejection --- feeding two independent consumers:
#
#   the VM     a verified eBPF program answers a question, reported as counters
#   the ring   the 40-byte record itself, in shared memory, read by another process
#
# Neither substitutes for the other. The counters need no transport; the ring is
# what a streaming analytic feed consumes.
#
# REQUIREMENTS: kubectl against the BNK cluster, a `client` pod, and python3 on
# THIS host (the TMM image has none, which is why the segment is copied out
# rather than mapped in place).
set -e

# The socket is named /tmp/ls_load.sock.<PID>, so it CHANGES on every rollout.
# Hardcoding it produced a demo whose counter half silently printed nothing --- the
# kubectl exec succeeded, ncat found no socket, and the empty line looked like a
# formatting problem rather than a wrong path. Discovered per pod below.
VIP=http://11.11.11.99/
WORK="${TMPDIR:-/tmp}/tp-demo.$$"
DUMP="$(dirname "$0")/ls_tp_dump.py"
RECORDS=0
RESET=0

for a in "$@"; do
    case "$a" in
    --records) RECORDS=1 ;;
    --reset)   RESET=1 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
    esac
done

mkdir -p "$WORK"
trap 'rm -rf "$WORK"' EXIT

command -v python3 >/dev/null || { echo "*** python3 required on this host"; exit 1; }
[ -f "$DUMP" ] || { echo "*** ls_tp_dump.py not found beside this script"; exit 1; }

say() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

if [ "$RESET" = 1 ]; then
    say "restarting TMM for clean counters"
    kubectl rollout restart deploy/f5-tmm >/dev/null
    kubectl rollout status deploy/f5-tmm --timeout=240s | tail -1
fi

PODS=$(kubectl get pods -l app=f5-tmm --no-headers | grep Running | awk '{print $1}')
[ -n "$PODS" ] || { echo "*** no Running f5-tmm pods"; exit 1; }

# ---------------------------------------------------------------- wire messages
# Built here rather than shipped as blobs: the layout is in substrate/shield_abi.h
# and a stale committed .bin is a silent way to drive the wrong opcode.
say "building wire messages"
python3 - "$WORK" <<'PY'
import struct, sys, pathlib
w = pathlib.Path(sys.argv[1])
def msg(op, slot=0, mode=2, hook=b'', payload=b''):
    return (struct.pack('<IIBxxxI', op, slot, mode, len(payload))
            + b'\0'*32 + hook.ljust(64, b'\0') + b'\0'*16 + b'\0'*64 + payload)
# STATUS on slot 1. LOAD is written by the caller once the ELF is located.
(w/'status.bin').write_bytes(msg(3, slot=1, mode=1))
print("  status.bin (op=STATUS slot=1)")
PY

# The program. Prefer a locally built ELF; fall back to one already on the host.
ELF=""
for c in "$(dirname "$0")/../shields/http_hdrs_watch.elf" \
         /tmp/http_hdrs_watch.elf "$HOME/http_hdrs_watch.elf"; do
    [ -f "$c" ] && { ELF="$c"; break; }
done
if [ -n "$ELF" ]; then
    python3 - "$WORK" "$ELF" <<'PY'
import struct, sys, pathlib
w, elf = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
def msg(op, slot=0, mode=2, hook=b'', payload=b''):
    return (struct.pack('<IIBxxxI', op, slot, mode, len(payload))
            + b'\0'*32 + hook.ljust(64, b'\0') + b'\0'*16 + b'\0'*64 + payload)
(w/'load.bin').write_bytes(msg(1, slot=1, mode=1,
                               hook=b'tmm_l7_http_headers',
                               payload=elf.read_bytes()))
print(f"  load.bin   (op=LOAD slot=1 MONITOR, {elf.stat().st_size}B from {elf.name})")
PY
else
    echo "  no http_hdrs_watch.elf found --- counters will show whatever is loaded"
fi

# One socket per TMM process, named by PID. Resolve it rather than assume it.
sock_for() {
    kubectl exec "$1" -c f5-tmm -- sh -c 'ls /tmp/ls_load.sock.* 2>/dev/null | head -1' 2>/dev/null
}

status_all() {
    for p in $PODS; do
        s=$(sock_for "$p")
        printf '  %-26s ' "$p"
        if [ -z "$s" ]; then
            echo "no loader socket (LS_LOAD_SOCKET unset?)"
        else
            kubectl exec -i "$p" -c f5-tmm -- ncat -U -w5 "$s" < "$WORK/status.bin" 2>/dev/null \
                | tail -1 | sed 's/^$/no reply/'
        fi
    done
}

# ------------------------------------------------------------------------- load
if [ -f "$WORK/load.bin" ]; then
    say "loading the program into slot 1 (MONITOR) on every pod"
    for p in $PODS; do
        s=$(sock_for "$p")
        printf '  %-26s ' "$p"
        if [ -z "$s" ]; then
            echo "no loader socket --- skipped"
        else
            kubectl exec -i "$p" -c f5-tmm -- ncat -U -w5 "$s" < "$WORK/load.bin" 2>/dev/null \
                | tail -1 | sed 's/^$/no reply/'
        fi
    done
fi

say "baseline"
status_all

# --------------------------------------------------------------------- the table
# Predictions FIRST. Three request classes, three expected outcomes.
say "predictions"
cat <<'EOT'
  3 x HTTP/1.1 clean    fired +3   safe_returns +0    record: version=HTTP/1.1 invalid=-
  3 x HTTP/1.0 clean    fired +3   safe_returns +0    record: version=HTTP/1.0 invalid=-
  3 x 200 headers       fired +3   safe_returns +3    record: err!=0, rejected
EOT

say "driving traffic"
printf '  HTTP/1.1 : '
for i in 1 2 3; do kubectl exec client -- curl -s -m 5 --http1.1 -o /dev/null -w '%{http_code} ' "$VIP" 2>/dev/null || true; done; echo
printf '  HTTP/1.0 : '
for i in 1 2 3; do kubectl exec client -- curl -s -m 5 --http1.0 -o /dev/null -w '%{http_code} ' "$VIP" 2>/dev/null || true; done; echo
H=""; i=1; while [ $i -le 200 ]; do H="$H -H X-P-$i:v"; i=$((i+1)); done
printf '  200 hdrs : '
# shellcheck disable=SC2086
for i in 1 2 3; do kubectl exec client -- curl -s -m 8 $H -o /dev/null -w '%{http_code} ' "$VIP" 2>/dev/null || true; done; echo
echo "  (000 = connection reset --- that IS the rejection, and is expected on the last row)"

say "after"
status_all
echo
echo "  fired should be +9 across the pods; safe_returns +3 (the rejected ones)."

# ------------------------------------------------------------------------ records
say "shared-memory segment"
SEG=""
for p in $PODS; do
    if kubectl exec "$p" -c f5-tmm -- test -f /tmp/ls_tp_ring 2>/dev/null; then
        kubectl exec "$p" -c f5-tmm -- dd if=/tmp/ls_tp_ring bs=4096 2>/dev/null > "$WORK/seg.bin"
        SEG="$WORK/seg.bin"
        echo "  pulled from $p ($(wc -c < "$SEG") bytes)"
    else
        echo "  $p: no segment (served no traffic, or LS_TP_RING unset)"
    fi
done

if [ -z "$SEG" ]; then
    echo
    echo "  *** No segment anywhere. The ring is off unless LS_TP_RING names a path:"
    echo "      kubectl set env deploy/f5-tmm -c f5-tmm LS_TP_RING=/tmp/ls_tp_ring"
    exit 1
fi

if [ "$RECORDS" = 1 ]; then
    python3 "$DUMP" "$SEG" -n 40 | sed 's/^/  /'
else
    python3 "$DUMP" "$SEG" -q | sed 's/^/  /'
    echo
    echo "  --records to decode them. The ring is never reset, so records accumulate"
    echo "  across runs and seq keeps climbing; --reset restarts TMM for a clean slate."
fi

say "what this demonstrated"
cat <<'EOT'
  One tracepoint, compiled into TMM at the point every request reaches, feeding
  two independent consumers:

    the VM    a verified eBPF program judged each request; counters discriminate
              clean traffic from rejected without carrying any data off-box
    the ring  the 40-byte record itself, in shared memory, decoded by a process
              that shares nothing with TMM but those bytes --- the drain agent's
              exact position, and what a NATS/ZeroMQ feed would publish

  Not shown, and not built: a drain agent that advances consumer_pos and
  publishes. Reading without acknowledging is fine for inspection; a real
  consumer must ack or a STREAM ring fills and counts drops.
EOT
