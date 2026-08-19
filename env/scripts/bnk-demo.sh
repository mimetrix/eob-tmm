#!/bin/sh
# The six-move walkthrough. Run on the DATKUBE host.
#
#   bnk-demo.sh          full run, pausing between moves
#   bnk-demo.sh -y       no pauses (rehearsal / capture a transcript)
#   bnk-demo.sh 3        start at move 3, run to the end
#   bnk-demo.sh -o 3     run ONLY move 3 (rehearse one beat)
#
# EVERY COMMAND IS PRINTED BEFORE IT RUNS. That is the point of the format: an architect
# audience should see exactly what was typed and exactly what came back, with nothing
# happening inside a wrapper they cannot inspect. The helpers defined in move 0 are shown
# on screen for the same reason.
#
# THREE THINGS THIS ENCODES, each from a specific way the demo broke:
#
#  * It reads ENTRY BYTES, not `status`, to show whether a hook is live. `status` reports
#    armed=1 whenever the SLOT HOLDS A PROGRAM --- which stays true after a successful
#    disarm. Saying "nothing is armed" over armed=1 looks like either a broken demo or a
#    misrepresentation. Process memory is the only source of truth for "is this patched".
#  * It arms EVERY pod. Requests load-balance, so arming one and watching it shows fired=0
#    while the other serves everything. Rollout churn also replaces pods with empty slots.
#  * It DRAINS before every trigger. The ring persists, and ambient traffic produces ~7
#    records in 3 seconds with nobody sending anything, so undrained records read as fresh
#    evidence for whatever you just did.
set -e

YES=""; START=1; END=9; ONLY=""
for a in "$@"; do
    case "$a" in
        -y) YES=1 ;;
        -o) ONLY=1 ;;
        [0-9]) START=$a; [ -n "$ONLY" ] && { END=$a; YES=1; } ;;
    esac
done
# A move runs when it is at or after START and at or before END. `-o N` sets both, so one
# beat can be rehearsed without sitting through the ones before it.
want() { [ "$1" -ge "$START" ] && [ "$1" -le "$END" ]; }

VIP="${VIP:-11.11.11.99}"
BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m'); OFF=$(printf '\033[0m')

say()   { printf '\n%s%s%s\n' "$BOLD" "$1" "$OFF"; }
note()  { printf '%s\n' "$1"; }
pause() { [ -n "$YES" ] || { printf '\n%s      [Enter]%s' "$DIM" "$OFF"; read _ </dev/tty || true; echo; }; }

# run: print the command, then run it, indenting whatever it says.
run() { printf '\n  %s$ %s%s\n' "$DIM" "$*" "$OFF"; sh -c "$*" 2>&1 | sed 's/^/      /'; }

# kubectl may be a wrapper --- env/scripts/bin/kubectl-datkube runs it over ssh so this can be
# driven from the machine that has clang and PREVAIL. Bare kubectl when unset, so running this
# on the datkube host is unchanged.
KUBECTL="${KUBECTL:-kubectl}"

PODS=$("$KUBECTL" get pods -l app=f5-tmm --no-headers | awk '$3=="Running"{print $1}')
[ -n "$PODS" ] || { echo "*** no Running f5-tmm pods" >&2; exit 1; }
POD1=$(echo $PODS | awk '{print $1}')

# --- the two helpers, shown rather than hidden --------------------------------
# L: the loader client, inside a pod. D: drain the ring. Both use tooling ALREADY
# in the image --- nothing is copied into a running container.
# Each helper ECHOES THE REAL COMMAND before running it. A helper name on screen would
# hide the mechanism behind a wrapper the audience cannot inspect, which defeats the point
# of a live demo --- particularly for BYTES, where the whole claim is that we are reading
# the process's own memory rather than asking a tool that could be telling us anything.
L() {
    p=$1; shift
    printf '\n  %s$ "$KUBECTL" exec -i %s -c f5-tmm -- python3 /usr/bin/ls-load.py %s%s\n' \
        "$DIM" "$p" "$*" "$OFF"
    "$KUBECTL" exec -i "$p" -c f5-tmm -- python3 /usr/bin/ls-load.py "$@" 2>&1 | sed 's/^/      /'
}
D() {
    t=${1:-5}
    printf '\n  %s$ for p in $PODS; do "$KUBECTL" exec $p -c f5-tmm -- \\%s\n' "$DIM" "$OFF"
    printf '  %s      timeout %s /usr/bin/ls_drain --segment /tmp/ls_tp_ring; done%s\n' "$DIM" "$t" "$OFF"
    for p in $PODS; do
        "$KUBECTL" exec "$p" -c f5-tmm -- sh -c "timeout $t /usr/bin/ls_drain --segment /tmp/ls_tp_ring 2>/dev/null"
    done
}
DQ() { for p in $PODS; do "$KUBECTL" exec "$p" -c f5-tmm -- sh -c "timeout ${1:-4} /usr/bin/ls_drain --segment /tmp/ls_tp_ring 2>/dev/null" >/dev/null 2>&1 || true; done; }
# BYTES: read a function's entry out of /proc in the pod. The script is piped on stdin;
# `-i` is load-bearing --- without it kubectl attaches no stdin, python reads an empty
# program, and this prints NOTHING while returning success.
BYTES() {
printf '\n  %s$ "$KUBECTL" exec -i %s -c f5-tmm -- python3 - %s <<PY%s\n' "$DIM" "$1" "$2" "$OFF"
printf '  %s    # find the tmm pid, seek to the entry in /proc/<pid>/mem, read 14 bytes%s\n' "$DIM" "$OFF"
"$KUBECTL" exec -i "$1" -c f5-tmm -- python3 - "$2" <<'PY' 2>&1 | sed 's/^/      /'
import os, sys
pid = None
for d in os.listdir("/proc"):
    if not d.isdigit(): continue
    try: e = os.readlink("/proc/%s/exe" % d)
    except OSError: continue
    if os.path.basename(e).startswith("tmm"): pid = d; break
addr = int(sys.argv[1], 16)
with open("/proc/%s/mem" % pid, "rb") as m:
    m.seek(addr); b = m.read(14)
h = lambda s: " ".join("%02x" % x for x in s)
pad = b[4:9]
if pad == b"\x90" * 5:      what = "five reserved nops --- NOT ARMED"
elif pad[0] == 0xe8:        what = "call rel32 --- ARMED, calling the trampoline"
else:                       what = "?"
print("0x%x   %s" % (addr, h(b)))
print("         endbr64 %s | pad %s | body %s" % (h(b[:4]), h(pad), h(b[9:14])))
print("         pad is: %s" % what)
PY
}
RANK() {
python3 -c '
import sys, json, collections
c = collections.Counter()
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try: d = json.loads(line)
    except Exception: continue
    if d.get("hook") == "reset":     c[("reset",  "%s:%s" % (d["file"], d["line"]), d["cause"])] += 1
    elif d.get("hook") == "h2abort": c[("h2abort","error=%s" % d["error"],           d["why"])]   += 1
    elif d.get("hook") == "prog":    c[("prog",   "len=%s" % d["len"],               d["data"][:24])] += 1
for (h, site, why), n in c.most_common(8):
    print("%-8s %4d  %-24s %s" % (h, n, site, why))
if not c: print("(no records)")'
}

# --- ENTRY: any function's entry address, from the BUILD'S OWN ARTIFACT ------------------
#
# NOTHING IN THIS SCRIPT NAMES AN ADDRESS. This block used to read `RST=0x144f600`, a literal
# copied from whichever build was current when it was written. The next build moved rst_why to
# 0x144fbc4 --- 1,476 bytes away --- and the script would have read five bytes from the middle
# of another function and shown them on screen as evidence. In a demo about a stale address
# arming the wrong place. Packaging RE-LINKS the binary, so every address moves on every build;
# an address written down anywhere is wrong by the next one.
#
# WHERE THE ANSWER COMES FROM. `hook-index.tsv`, generated by substrate/mk_hook_map.py from the
# PACKAGED binary during the bake and baked into this image. It carries the build id of the
# binary it describes, and ls-load.py refuses to arm when that does not match the running
# process. So the address arrives from the same artifact chain that produced the binary, and
# there is no step where a human retypes it.
#
# It takes a NAME, so any move can ask about any function without an edit here.
#
# UNIQUENESS IS ASSERTED, not assumed. 591 names in this index carry between 2 and 21 entries
# --- file-scope statics repeated across translation units, .isra/.constprop clones, assembler
# labels (LOne/LTwo/LThree at 21 apiece) --- and taking the first match for one of those picks
# an arbitrary homonym and reports success. That is the stale-address failure with a nicer
# interface, so this refuses instead.
ENTRY() {
    _n=$1
    _out=$("$KUBECTL" exec -c f5-tmm "$POD1" -- sh -c \
           "awk -F'\t' -v n='$_n' '\$1==n{print \$2}' /usr/share/ls/hook-index.tsv" 2>/dev/null \
           | tr -d '\r')
    _c=$(printf '%s\n' "$_out" | grep -c '^0x' || true)
    if [ "$_c" -eq 0 ]; then
        echo "*** '$_n' is not in this image's hook index." >&2
        echo "    It takes no arguments, was inlined away, or the name is wrong. This script" >&2
        echo "    will not guess an address --- guessing one is the failure being demonstrated." >&2
        return 1
    fi
    if [ "$_c" -gt 1 ]; then
        echo "*** '$_n' has $_c entries in the index. Refusing to pick one:" >&2
        printf '%s\n' "$_out" | sed 's/^/      /' >&2
        return 1
    fi
    printf '%s\n' "$_out" | grep '^0x' | head -1
}

# Show the resolution once, so the audience sees where the number came from before it is used.
printf '\n  %s$ "$KUBECTL" exec %s -c f5-tmm -- awk -F"\\t" \x27$1=="rst_why"\x27 \\%s\n' \
       "$DIM" "$POD1" "$OFF"
printf '  %s      /usr/share/ls/hook-index.tsv        # the index the BAKE generated%s\n' "$DIM" "$OFF"
"$KUBECTL" exec -c f5-tmm "$POD1" -- sh -c \
    "awk -F'\t' '\$1==\"rst_why\"{print \"      \" \$0}' /usr/share/ls/hook-index.tsv" 2>/dev/null
"$KUBECTL" exec -c f5-tmm "$POD1" -- sh -c \
    "awk -F'\t' '/^#build_id/{print \"      build id: \" \$2}' /usr/share/ls/hook-index.tsv" 2>/dev/null

RST=$(ENTRY rst_why) || exit 1

# =============================================================================
if want 1; then
say "MOVE 1 of 6 --- a stock, running TMM"
note "  A proxy is a machine that makes decisions about connections. Accept or reject,"
note "  forward or hold, close cleanly or reset --- thousands of times a second. That is"
note "  not a feature of the product, it IS the product."
note ""
note "  So the most important question anyone can ask is: why did you do that to my"
note "  connection? And that is the one question we cannot currently answer."
run "kubectl get pods -l app=f5-tmm --no-headers"
note ""
note "  Nothing is armed. Do NOT ask the loader --- 'armed' in its status means the SLOT"
note "  HOLDS A PROGRAM, which stays true after a disarm. The only source of truth for"
note "  'is this function patched' is the process's own memory:"
BYTES "$POD1" "$RST"
note ""
note "  f3 0f 1e fa is endbr64 --- Intel CET's indirect-branch guard, put there by gcc's"
note "  default -fcf-protection. It is never ours. The five 90s after it are the pad the"
note "  build reserved with -fpatchable-function-entry=5,0, at a size cost of 0.182% of"
note "  the binary. Those five bytes are ours, and right now they are untouched."
pause
fi

# =============================================================================
if want 2; then
say "MOVE 2 of 6 --- the vocabulary TMM already has, and throws away"
note "  You would assume the reason a connection died is unavailable because nobody"
note "  recorded it. The opposite is true."
run ""$KUBECTL" exec $POD1 -c f5-tmm -- grep -c . /usr/share/ls/hook-index.tsv"
note ""
note "  net/rstcause.h defines 14 macros over 4 functions, used at 1,090 places:"
note "      rst_why              935 call sites"
note "      rst_why_va           131"
note "      rst_why_preserve      22"
note "      rst_why_preserve_va    2"
note ""
note "  A call site is a place in the source where a developer wrote 'tear this down,"
note "  and here is why' --- with __FILE__, __LINE__ and a string in English:"
note ""
note "      RST_WHY(cd->uf, \"No route to host\")"
note "      RST_WHY(cd->uf, \"No available SNAT addr\")"
note "      RST_WHY(cd->uf, \"Route domain not reachable (strict mode)\")"
note ""
note "  Somebody in this room wrote one of those. It goes into an in-memory ring that"
note "  overwrites and is not tied to any request. It reaches NO log --- net/rstcause.c"
note "  contains zero log macros. The client gets a bare TCP reset. An iRule gets nothing"
note "  at all when the reset precedes the parse, because there is no request object to"
note "  raise an event against."
pause
fi

# =============================================================================
if want 3; then
say "MOVE 3 of 6 --- arm it by name, on a running TMM, under traffic"
for p in $PODS; do
  L "$p" load 5 /usr/share/ls/rst_watch.bpf.o 2 rst_why
  L "$p" arm 5 rst_why
done
note ""
note "  By NAME, not address --- resolved through an index built from this exact binary"
note "  and gated on its build ID. rst_why has sat at three different addresses across"
note "  three builds of identical source, so a hand-carried address is wrong by default"
note "  and wrong SILENTLY: a nop pad exists at plenty of other addresses."
BYTES "$POD1" "$RST"
note ""
note "  FIVE BYTES CHANGED. endbr64 above is untouched; the real first instruction below"
note "  is untouched. NOTHING WAS DISPLACED --- so there is nothing to relocate, no"
note "  instruction decoder in the process, and no window in which another thread's"
note "  program counter is inside bytes being rewritten. That is why doing this to a"
note "  live data plane is arguable rather than reckless."
pause
fi

# =============================================================================
if want 4; then
say "MOVE 4 of 6 --- what TMM is actually deciding"
DQ 4
note "  (ring drained --- everything below is from this moment on)"
note ""
note "  First: three seconds, and I send nothing at all."
run "sleep 3"
D 5 2>/dev/null | RANK | sed 's/^/      /'
note ""
note "  I sent nothing. That is ambient --- health probes. And tcp.c:4689 says the REMOTE"
note "  end reset: TMM did not decide that. Fourteen of those and you go look at your"
note "  server, not at us."
pause
DQ 4
note "  Now six ordinary HTTPS requests, client -> TMM -> backend pool."
run ""$KUBECTL" exec client -- sh -c 'for i in 1 2 3 4 5 6; do timeout 3 curl -sk -o /dev/null https://$VIP/; done'"
D 5 2>/dev/null | RANK | sed 's/^/      /'
note ""
note "  Ten records for six requests --- a proxy is TWO connections, and :973 and :974 are"
note "  adjacent call sites, one per side. The feed reflects real internal structure."
pause
DQ 4
note "  Now five connects to a port with NO listener. The backend is never involved:"
note "  TMM rejects the flow before any proxying, so nothing else in the path can vary it."
run ""$KUBECTL" exec client -- sh -c 'for i in 1 2 3 4 5; do timeout 2 nc -z $VIP 9999; done' || true"
D 5 2>/dev/null | RANK | sed 's/^/      /'
note ""
note "  THE POINT. flow_table.c:2618 appeared in BOTH runs, with DIFFERENT causes ---"
note "  'No flow found for ACK' from ambient traffic, 'No local listener' from that"
note "  trigger. Same file. Same line. Two different answers, because the source says"
note ""
note "      RST_WHY_CF(&cf_static, flow_reject_cause[flow_reject_code]);"
note ""
note "  an 18-entry table indexed at RUNTIME: connection limit exceeded, VIP down, DOS"
note "  signature, 3WHS rejected. The line number tells you WHERE. Nothing in the source"
note "  tells you WHICH --- a developer with the code open cannot answer it. The record"
note "  can, and only because the hook forwards all six arguments instead of five."
pause
fi

# =============================================================================
if want 5; then
say "MOVE 5 of 6 --- you pick the target"
note "  41,148 functions in this binary are armable through the pad. Name one."
note "  Before arming, ask what will happen --- so any answer is a sentence:"
run "python3 /tmp/bnk-explore-hooks.py explain ssl_hs_process_client_hello || true"
note ""
note "  Four possible verdicts, and the refusals are the more honest half:"
note "     ARMABLE            padded, unique --- arm it"
note "     AMBIGUOUS          e.g. LOne has 21 entries; arming refuses rather than guess"
note "     NEEDS DISPLACEMENT no pad. An OpenSSL symbol. 30,009 of these, unbuilt path"
note "     NOT ARMABLE        inlined or folded away by the optimiser"
note ""
note "  That is the boundary of the mechanism, and better seen here than read in a caveat."
pause
say "         ...and then it goes back"
for p in $PODS; do L "$p" disarm rst_why; done
BYTES "$POD1" "$RST"
note ""
note "  Byte-identical to move 1. Not equivalent --- identical."
pause
fi

# =============================================================================
if want 6; then
say "MOVE 6 of 6 --- a decision made INSIDE the data plane"
note "  Everything so far is observation. This one is different: the same mechanism, but"
note "  the program decides what is worth reporting, using a clock, in the poll loop."
for p in $PODS; do
  L "$p" load 5 /usr/share/ls/rate_gate.bpf.o 1 rst_why
  L "$p" arm 5 rst_why
done
DQ 4
run ""$KUBECTL" exec client -- sh -c 'for i in \$(seq 1 40); do timeout 2 curl -sk -o /dev/null https://$VIP/ & done; wait' || true"
D 6 2>/dev/null | RANK | sed 's/^/      /'
note ""
note "  hook=reset is the host publishing one record per event. hook=prog is the PROGRAM"
note "  choosing to emit --- only when a site crossed five occurrences inside a window it"
note "  timed itself. Measured earlier: 86 events, 2 emitted records. 43 to 1, decided in"
note "  the poll loop, with nothing downstream counting anything."
note ""
note "  At 1,090 sites under load, streaming everything is a firehose. This is the"
note "  difference between telemetry and a decision."
pause
say "CLOSING --- the three things you would ask me anyway"
note "  1. Per-invocation cost is UNMEASURED. rdtsc is preemption-polluted --- one sample"
note "     in this run reads 23.8 million cycles, which is not real work --- and the node"
note "     blocks hardware counters. I will not quote a per-call number."
note "  2. There is NO signature verification. The loader accepts any program and says so"
note "     on every load. That makes this lab-only, and it is the single largest gap"
note "     between what runs and what could ship."
note "  3. The JIT never consults the bounds callback, so the interpreter and the JIT do"
note "     not agree on memory safety --- and the lab runs the JIT."
note ""
note "  What is proven: a verified program loads into a running TMM, arms at a function"
note "  entry with no restart, reports decisions no other surface exposes, and comes back"
note "  out leaving the bytes exactly as they were."
fi
