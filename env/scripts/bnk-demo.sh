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
# What to PRINT for it. The echoed commands are the whole point of this format, so they must
# read as something a person could type. Printing the literal string $KUBECTL shows plumbing;
# printing the basename shows `kubectl`, or `kubectl-datkube` when the ssh wrapper is in use ---
# which is true and is the thing an audience would want to know.
KDISP=$(basename "$KUBECTL")
REPO_DIR="${REPO_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"

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
    printf '\n  %s$ %s exec -i %s -c f5-tmm -- python3 /usr/bin/ls-load.py %s%s\n' \
        "$DIM" "$KDISP" "$p" "$*" "$OFF"
    "$KUBECTL" exec -i "$p" -c f5-tmm -- python3 /usr/bin/ls-load.py "$@" 2>&1 | sed 's/^/      /'
}
D() {
    t=${1:-5}
    printf '\n  %s$ for p in $PODS; do %s exec $p -c f5-tmm -- \\%s\n' "$DIM" "$KDISP" "$OFF"
    printf '  %s      timeout %s /usr/bin/ls_drain --segment /tmp/ls_tp_ring; done%s\n' "$DIM" "$t" "$OFF"
    for p in $PODS; do
        "$KUBECTL" exec "$p" -c f5-tmm -- sh -c "timeout $t /usr/bin/ls_drain --segment /tmp/ls_tp_ring 2>/dev/null"
    done
}
DQ() { for p in $PODS; do "$KUBECTL" exec "$p" -c f5-tmm -- sh -c "timeout ${1:-4} /usr/bin/ls_drain --segment /tmp/ls_tp_ring 2>/dev/null" >/dev/null 2>&1 || true; done; }
# BYTES: read a function's entry out of /proc in the pod. The script is piped on stdin;
# `-i` is load-bearing --- without it kubectl attaches no stdin, python reads an empty
# program, and this prints NOTHING while returning success.
# BYTES <pod> <arm-address> <pad-offset>
#
# THE PAD OFFSET IS PASSED IN, not inferred, and getting this wrong is silent. The index's
# address column is the ARM address --- the first byte of the pad --- not the function entry.
# This function previously assumed byte 0 was the start of endbr64 and that the pad lived at
# bytes 4..9, which is true only when handed a function entry. Given the arm address it read
# five bytes of the function BODY as the pad and printed "pad is: ?" while showing the five
# reserved nops mislabelled as endbr64. The bytes on screen were right and every label was wrong.
#
# pad_offset comes from the same index row as the address: 4 when gcc emitted endbr64 first
# (the -fcf-protection default, so most functions), 0 when it did not --- statics and
# .isra/.constprop clones, which are never indirect-call targets.
BYTES() {
printf '\n  %s$ %s exec -i %s -c f5-tmm -- python3 - %s %s <<PY%s\n' "$DIM" "$KDISP" "$1" "$2" "$3" "$OFF"
printf '  %s    # find the tmm pid, seek to the function entry in /proc/<pid>/mem, read 14 bytes%s\n' "$DIM" "$OFF"
"$KUBECTL" exec -i "$1" -c f5-tmm -- python3 - "$2" "$3" <<'PY' 2>&1 | sed 's/^/      /'
import os, sys
pid = None
for d in os.listdir("/proc"):
    if not d.isdigit(): continue
    try: e = os.readlink("/proc/%s/exe" % d)
    except OSError: continue
    if os.path.basename(e).startswith("tmm"): pid = d; break
arm = int(sys.argv[1], 16)
off = int(sys.argv[2])
entry = arm - off                      # the function's first byte
with open("/proc/%s/mem" % pid, "rb") as m:
    m.seek(entry); b = m.read(off + 10)
h = lambda s: " ".join("%02x" % x for x in s)
pad = b[off:off + 5]
if pad == b"\x90" * 5:      what = "five reserved nops --- NOT ARMED"
elif pad[0] == 0xe8:        what = "call rel32 --- ARMED, calling the trampoline"
else:                       what = "NEITHER --- not a pad, and not a hook. Do not write here."
print("entry 0x%x   pad at +%d (0x%x)" % (entry, off, arm))
print("         %s" % h(b))
if off:
    print("         endbr64 %s | pad %s | body %s" % (h(b[:off]), h(pad), h(b[off + 5:])))
else:
    print("         pad %s | body %s        (no endbr64 --- not an indirect-call target)"
          % (h(pad), h(b[5:])))
print("         pad is: %s" % what)
PY
}
# CLAIM <label> <pattern> --- check an assertion against the records we just captured,
# and say plainly whether it held.
#
# WHY THIS EXISTS. Move 4 used to NARRATE its findings: "flow_table.c:2618 appeared in BOTH
# runs with different causes", ":973 and :974 are adjacent call sites, one per side", "ten
# records for six requests". Those were true of the run during which the script was written.
# On 2026-08-19 none of them appeared --- the backend answers 404 over TLS on this cluster, so
# there is no proxy teardown at :973, and the port-9999 probe did not produce a local-listener
# reject. The script told the audience to look at four things that were not on the screen.
#
# That is the worst failure available to a live demo: it reads as either a broken system or a
# prepared script, and both are worse than the finding being absent. Ambient traffic also
# varies by cluster and by minute, so a fixed expectation cannot be right for long.
#
# So a claim is now CHECKED. It either says "confirmed, here it is" or "did not appear this
# run", and the second is a fine thing to say out loud --- the mechanism is the point, not any
# particular reset cause.
CLAIM() {
    _label=$1; _pat=$2; _file=$3
    if grep -qE "$_pat" "$_file" 2>/dev/null; then
        printf '  %sCONFIRMED this run: %s%s\n' "$BOLD" "$_label" "$OFF"
        grep -E "$_pat" "$_file" | head -3 | sed 's/^/      /'
    else
        printf '  %sNOT SEEN this run: %s%s\n' "$DIM" "$_label" "$OFF"
        printf '  %s  (this cluster/traffic did not produce it; the mechanism is unaffected)%s\n' \
               "$DIM" "$OFF"
    fi
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

# The pad offset for the same name, from the same row. Separate call rather than parsing a
# tuple, because a caller that wanted only the address and got "0x144fbc4 4" would pass the
# whole string to /proc and seek somewhere arbitrary.
# PADSTATE <pod> <arm-address> -> "nops" or "armed"
#
# A FUNCTION, because a here-document nested inside $( ) hangs. Written inline as
#   _pad=$("$KUBECTL" exec -i "$p" ... <<'PY' ... PY )
# it stalled the demo indefinitely at move 6 --- the process sat there with the run at a
# standstill and no output, which in front of an audience is indistinguishable from TMM having
# locked up. In a function the here-document is attached to the command, and only the
# function's output is captured, which is what BYTES has always done correctly.
PADSTATE() {
    "$KUBECTL" exec -i "$1" -c f5-tmm -- python3 - "$2" <<'PYQ' 2>/dev/null
import os, sys
pid = next((d for d in os.listdir("/proc") if d.isdigit()
            and os.path.basename(os.readlink("/proc/%s/exe" % d)).startswith("tmm")), None)
with open("/proc/%s/mem" % pid, "rb") as m:
    m.seek(int(sys.argv[1], 16)); print("nops" if m.read(5) == b"\x90" * 5 else "armed")
PYQ
}

PADOFF() {
    "$KUBECTL" exec -c f5-tmm "$POD1" -- sh -c \
        "awk -F'\t' -v n='$1' '\$1==n{print \$4}' /usr/share/ls/hook-index.tsv" 2>/dev/null \
        | tr -d '\r' | head -1
}

# Show the resolution once, so the audience sees where the number came from before it is used.
printf '\n  %s$ %s exec %s -c f5-tmm -- \\%s\n' "$DIM" "$KDISP" "$POD1" "$OFF"
printf '  %s      grep -P %s^rst_why\\t%s /usr/share/ls/hook-index.tsv%s\n' "$DIM" "'" "'" "$OFF"
printf '  %s      # the index mk_hook_map.py generated from the PACKAGED binary during the bake%s\n' "$DIM" "$OFF"
"$KUBECTL" exec -c f5-tmm "$POD1" -- sh -c \
    "awk -F'\t' '\$1==\"rst_why\"{print \"      name=\" \$1 \"  arm_at=\" \$2 \"  method=\" \$3 \"  pad_offset=\" \$4}' /usr/share/ls/hook-index.tsv" 2>/dev/null
"$KUBECTL" exec -c f5-tmm "$POD1" -- sh -c \
    "awk -F'\t' '/^#build_id/{print \"      build_id=\" \$2 \"   <- the binary this index describes\"}' /usr/share/ls/hook-index.tsv" 2>/dev/null

RST=$(ENTRY rst_why) || exit 1
RSTOFF=$(PADOFF rst_why)

# =============================================================================
if want 1; then
say "MOVE 1 of 6 --- a stock, running TMM"
note "  A proxy is a machine that makes decisions about connections. Accept or reject,"
note "  forward or hold, close cleanly or reset --- thousands of times a second. That is"
note "  not a feature of the product, it IS the product."
note ""
note "  So the most important question anyone can ask is: why did you do that to my"
note "  connection? And that is the one question we cannot currently answer."
run "$KUBECTL get pods -l app=f5-tmm --no-headers"
note ""
# ESTABLISH THE PRECONDITION, do not assert it.
#
# This move used to state "Nothing is armed" and then read the entry bytes. On 2026-08-19 a
# previous run had left rst_why armed, so the narration said nothing was armed and the byte
# dump immediately below it said "ARMED, calling the trampoline". The script contradicted
# itself on screen, in front of the audience, in the first thirty seconds --- and it is the
# same fault that was fixed in moves 4 and 6 the same day: narrating a state instead of
# reading it.
#
# A demo needs a KNOWN starting state, and the only honest way to get one is to make it and
# say so. Disarming visibly also demonstrates the mechanism a move early, which costs nothing.
for p in $PODS; do
    _b=$(PADSTATE "$p" "$RST")
    if [ "$_b" = "armed" ]; then
        printf '  %s# %s still has rst_why armed from an earlier run --- disarming so this
' "$DIM" "$p"
        printf '  # move starts from the state it describes.%s
' "$OFF"
        L "$p" disarm rst_why
    fi
done
note "  Nothing is armed --- and that was checked, not assumed. Do NOT ask the loader:"
note "  'armed' in its status means the SLOT HOLDS A PROGRAM, which stays true after a"
note "  successful disarm. The only source of truth for 'is this function patched' is the"
note "  process's own memory:"
BYTES "$POD1" "$RST" "$RSTOFF"
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
BYTES "$POD1" "$RST" "$RSTOFF"
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
AMB=/tmp/.demo_ambient.$$
REQ=/tmp/.demo_requests.$$
REJ=/tmp/.demo_reject.$$
trap 'rm -f "$AMB" "$REQ" "$REJ"' EXIT

DQ 4
note "  (ring drained --- everything below is from this moment on)"
note ""
note "  First: three seconds, and I send nothing at all."
run "sleep 3"
D 5 2>/dev/null > "$AMB" || true
RANK < "$AMB" | sed 's/^/      /'
note ""
note "  I sent nothing, and the feed is not empty. That is ambient traffic --- health"
note "  probes and the cluster talking to itself. Read the causes: anything attributed to"
note "  the REMOTE end is a reset TMM did not decide, and that sends you to your server"
note "  rather than to us. Which causes appear depends on the cluster and the minute."
pause
DQ 4
note "  Now six ordinary requests, client -> TMM -> backend pool."
run ""$KUBECTL" exec client -- sh -c 'for i in 1 2 3 4 5 6; do timeout 3 curl -s -o /dev/null http://$VIP/; done'"
D 5 2>/dev/null > "$REQ" || true
RANK < "$REQ" | sed 's/^/      /'
note ""
CLAIM "a proxy is TWO connections --- adjacent call sites, one per side" \
      '"file":"http_mr_proxy.c","line":(99[0-9]|10[0-9][0-9])' "$REQ"
pause
DQ 4
note "  Now five connects to a port with NO listener. The backend is never involved:"
note "  TMM rejects the flow before any proxying, so nothing else in the path can vary it."
run ""$KUBECTL" exec client -- sh -c 'for i in 1 2 3 4 5; do timeout 2 nc -z $VIP 9999; done' || true"
D 5 2>/dev/null > "$REJ" || true
RANK < "$REJ" | sed 's/^/      /'
note ""
note "  THE POINT, and it is checked against the two captures rather than asserted:"
note "  one file:line can carry DIFFERENT causes, because the source is"
note ""
note "      RST_WHY_CF(&cf_static, flow_reject_cause[flow_reject_code]);"
note ""
note "  an 18-entry table indexed at RUNTIME --- connection limit exceeded, VIP down, DOS"
note "  signature, 3WHS rejected. The line number tells you WHERE. Nothing in the source"
note "  tells you WHICH, so a developer with the code open cannot answer it. The record"
note "  can, and only because the hook forwards all six arguments instead of five."
note ""
python3 - "$AMB" "$REQ" "$REJ" <<'PYX' 2>/dev/null | sed 's/^/  /'
import sys, json, collections
sites = collections.defaultdict(set)
for f in sys.argv[1:]:
    try: lines = open(f).read().splitlines()
    except OSError: continue
    for l in lines:
        l = l.strip()
        if not l.startswith("{"): continue
        try: d = json.loads(l)
        except Exception: continue
        if d.get("hook") != "reset": continue
        if not d.get("file"): continue
        sites["%s:%s" % (d["file"], d["line"])].add(d.get("cause", ""))
multi = {k: v for k, v in sites.items() if len(v) > 1}
if multi:
    print("CONFIRMED this run --- one site, several causes:")
    for k, v in sorted(multi.items()):
        print("    %-26s %s" % (k, " | ".join(sorted(x for x in v if x))))
else:
    print("NOT SEEN this run: every site carried a single cause across these three captures.")
    print("  The runtime-table site is reached by paths this traffic did not take. What the")
    print("  captures DO show is %d distinct sites, each with the cause its source wrote:" % len(sites))
    for k, v in sorted(sites.items())[:6]:
        print("    %-26s %s" % (k, " | ".join(sorted(x for x in v if x))))
PYX
pause
fi

# =============================================================================
if want 5; then
say "MOVE 5 of 6 --- you pick the target"
# COUNTED FROM THIS IMAGE'S INDEX. These read "41,148" and "30,009" --- true of the build the
# script was written against. Every build relinks and the optimiser makes different inlining
# choices, so the populations move. Quoting last build's numbers at an audience looking at this
# build's binary is the same error as the hardcoded address, one step further from the machine.
POP=$("$KUBECTL" exec -c f5-tmm "$POD1" -- sh -c \
      "awk -F'\t' '!/^#/{c[\$3]++} END{printf \"%d %d\", c[\"pad\"], c[\"displace\"]}' /usr/share/ls/hook-index.tsv" \
      2>/dev/null | tr -d '\r')
NPAD=$(echo "$POP" | awk '{print $1}')
NDIS=$(echo "$POP" | awk '{print $2}')
note "  $NPAD functions in THIS binary are armable through the pad --- counted from the index"
note "  in this image, not from a number written down when the script was drafted. Name one."
note "  Before arming, ask what will happen --- so any answer is a sentence:"
# From the repo, not /tmp --- it was referenced at /tmp/bnk-explore-hooks.py, which is not
# there, so this move printed "No such file or directory" where the verdict should have been.
# It reads the index inside the pod and honours $KUBECTL, so it works from wherever the demo
# is being driven.
#
# THE EXAMPLE IS CHOSEN FROM THE LIVE INDEX, not written down. ssl_hs_process_client_hello was
# the hardcoded example and it is NOT ARMABLE on this build --- the optimiser folded it away.
# A demo that opens its "you pick the target" move on a refusal for a function nobody chose is
# making the wrong point by accident. So: one armable name taken from the index, then the
# refusals, all from this binary.
EXPLORE="$REPO_DIR/env/scripts/bnk-explore-hooks.py"
PICK=$("$KUBECTL" exec -c f5-tmm "$POD1" -- sh -c \
       "awk -F'\t' '\$3==\"pad\" && \$4==4 && \$1 ~ /^mrhttp_/ {print \$1}' /usr/share/ls/hook-index.tsv | sort | head -1" \
       2>/dev/null | tr -d '\r')
[ -n "$PICK" ] || PICK=rst_why
run "KUBECTL=$KUBECTL python3 $EXPLORE explain $PICK || true"
note ""
note "  ...and one the mechanism refuses, so the boundary is shown rather than described:"
run "KUBECTL=$KUBECTL python3 $EXPLORE explain LOne || true"
note ""
note "  Four possible verdicts, and the refusals are the more honest half:"
note "     ARMABLE            padded, unique --- arm it"
note "     AMBIGUOUS          e.g. LOne has 21 entries; arming refuses rather than guess"
note "     NEEDS DISPLACEMENT no pad. An OpenSSL symbol. $NDIS of these, unbuilt path"
note "     NOT ARMABLE        inlined or folded away by the optimiser"
note ""
note "  That is the boundary of the mechanism, and better seen here than read in a caveat."
pause
say "         ...and then it goes back"
for p in $PODS; do L "$p" disarm rst_why; done
BYTES "$POD1" "$RST" "$RSTOFF"
note ""
note "  Byte-identical to move 1. Not equivalent --- identical."
pause
fi

# =============================================================================
if want 6; then
say "MOVE 6 of 6 --- a decision made INSIDE the data plane"
note "  Everything so far is observation. This one is different: the same mechanism, but"
note "  the program decides what is worth reporting, using a clock, in the poll loop."
# LOAD, and arm ONLY IF the entry is not already patched.
#
# Changing the program at a live hook is a LOAD, not a re-arm: the trampoline is already in
# place, and ls_vm_reload swaps (vm, jit_fn) under it. Re-arming would rewrite the displacement
# over an existing call and lose the original bytes, which is why ls-load.py now refuses it ---
# and running this move on its own, after move 3 armed the same function, is exactly how that
# refusal shows up. Making the arm conditional turns a stumble into the point.
note "  Note what this does NOT do: it loads a different program into the SAME live hook."
note "  The trampoline is already there from move 3, so there is nothing to patch again ---"
note "  and re-arming is refused precisely because it would overwrite the displacement."
for p in $PODS; do
  L "$p" load 5 /usr/share/ls/rate_gate.bpf.o 1 rst_why
  _pad=$(PADSTATE "$p" "$RST")
  if [ "$_pad" = "nops" ]; then
      L "$p" arm 5 rst_why
  else
      printf '\n  %s# %s: entry already holds a call --- the hook is live, so no arm is needed.%s\n' \
             "$DIM" "$p" "$OFF"
  fi
done
GATE=/tmp/.demo_gate.$$
DQ 4
# HTTP, not HTTPS. The earlier form drove https:// and this cluster answers 404 over TLS
# without reaching the proxy path, so the gate had almost nothing to count and the move showed
# no program-emitted records while asserting them. Plain HTTP gets 200 and goes through both
# sides of the proxy, which is what generates enough events for a rate gate to have an opinion.
run ""$KUBECTL" exec client -- sh -c 'for i in \$(seq 1 40); do timeout 2 curl -s -o /dev/null http://$VIP/ & done; wait' || true"
D 6 2>/dev/null > "$GATE" || true
RANK < "$GATE" | sed 's/^/      /'
note ""
note "  hook=reset is the host publishing one record per event. hook=prog is the PROGRAM"
note "  choosing to emit --- only when a site crossed five occurrences inside a window it"
note "  timed itself, using the clock helper, in the poll loop."
note ""
# CHECKED, not asserted. This move used to state "86 events, 2 emitted records" --- a real
# measurement from a different run, presented as if it were this one. A rate gate is
# load-dependent by construction, so whether it fires here depends on how much of that burst
# landed on this pod within one window.
python3 - "$GATE" <<'PYX' 2>/dev/null | sed 's/^/  /'
import sys, json
prog = rest = 0
for l in open(sys.argv[1]):
    l = l.strip()
    if not l.startswith("{"): continue
    try: d = json.loads(l)
    except Exception: continue
    if d.get("hook") == "prog": prog += 1
    else: rest += 1
if prog:
    print("CONFIRMED this run: %d host record(s), %d PROGRAM-emitted --- a ratio of %.0f to 1,"
          % (rest, prog, (rest / prog) if prog else 0))
    print("decided inside the data plane with nothing downstream counting anything.")
else:
    print("NOT SEEN this run: %d host record(s) and 0 program-emitted." % rest)
    print("  The gate emits only when one site crosses five occurrences inside its own timed")
    print("  window, so this burst did not concentrate enough on this pod. The mechanism is")
    print("  the same one move 3 proved; what varies is whether the threshold was met.")
PYX
note ""
note "  At 1,090 sites under load, streaming everything is a firehose. That is the"
note "  difference between telemetry and a decision."
pause
say "CLOSING --- the four things you would ask me anyway"
# READ THE NUMBER FROM THIS RUN. It was hardcoded --- "one sample in this run reads 23.8
# million cycles" --- while the run being presented reported cycles_max=1628. A number
# introduced by the words "in this run" and not taken from the run is the exact move this
# demo exists to argue against, and it is the fourth hardcoded build fact removed from this
# script. If the slot cannot be read, say nothing about a sample rather than invent one.
CMAX=$("$KUBECTL" exec "$POD1" -c f5-tmm -- python3 /usr/bin/ls-load.py status 5 2>/dev/null \
        | sed -n 's/.*cycles_max=\([0-9]*\).*/\1/p' | head -1)
note "  1. Per-invocation cost is UNMEASURED, and rdtsc is preemption-polluted: a pair of"
if [ -n "$CMAX" ]; then
note "     reads spanning a context switch measures the scheduler, not the program. The worst"
note "     sample in THIS run is $CMAX cycles against a minimum in the tens --- same program,"
note "     same hook. The node also blocks hardware counters, so I will quote no per-call number."
else
note "     reads spanning a context switch measures the scheduler, not the program, and the node"
note "     blocks hardware counters. The slot's counters were not readable just now, so I am not"
note "     quoting a sample --- and I will quote no per-call number either way."
fi
note "  2. Every load above was signature-checked --- that is what signature=verified in"
note "     the replies means, and an unsigned or altered program is refused. What is NOT"
note "     checked is WHO asked: anything that can reach the loader socket can ask, the"
note "     verifying key is compiled into the binary with no way to revoke it, and no operator"
note "     identity travels with the request."
note "  3. Every operation IS recorded, though --- one line each, with the op, the target, the"
note "     program hash, the build id of this binary, and the verdict you were given, quoted"
note "     verbatim. The asker is the pid and uid the KERNEL reports, which cannot be forged and"
note "     is still a process rather than a person. That is what keeps this lab-only."
note "  4. The JIT never consults the bounds callback, so the interpreter and the JIT do"
note "     not agree on memory safety --- and the lab runs the JIT."
note ""
note "  What is proven: a verified program loads into a running TMM, arms at a function"
note "  entry with no restart, reports decisions no other surface exposes, and comes back"
note "  out leaving the bytes exactly as they were."
fi
