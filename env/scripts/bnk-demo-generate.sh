#!/bin/sh
# MOVE 7 --- idea to running bytecode, on a TMM nobody rebuilt.
#
#   bnk-demo-generate.sh [function] [slot]        default: http_abort, slot 8
#
# THE POINT OF THIS MOVE. Moves 1-6 arm functions somebody had already prepared for: a record
# layout was hand-written, a program was hand-written, both were compiled into the image. The
# obvious question from a TMM engineer watching that is "so you can hook the four functions
# you got ready in advance". This move answers it: name a function nobody prepared anything
# for, and watch a probe for it come into existence and start reporting.
#
# WHAT MAKES IT POSSIBLE, and it is one thing: the build emits a signature index. Every
# function's parameter names and types, read out of the build's own debug information once, at
# build time. Without it this same lookup walks 146 MB of DWARF and takes 1m54s, which is a
# batch job and not a demo. With it, 0.1s. See build-pipeline.md.
#
# WHERE IT RUNS. Generation and verification here; only the bytecode crosses to the target.
# That is the trust boundary the design asks for --- compile in dev or CI, verify and sign at
# F5, load on the target and nowhere else --- so the demo shows it rather than hiding it.
#
# NOTHING IS WRITTEN TO THE POD. bnk-deliver-program.py pipes the bytes over stdin into the
# loader socket. No kubectl cp, no file in the container.
#
# WHY mrhttp_proxy_route_message. It was not chosen for a nice name --- it was found. The
# functions with a hand-written record layout are the four this repo prepared; everything else
# had nothing. Picking a target meant intersecting two per-build indexes (armable at a five-byte
# pad after endbr64, and carrying at least one scalar argument, which is 15,834 functions) and
# then MEASURING which of them the traffic actually reaches. Several plausible choices --- 
# http_abort, http_header_entry_create, ssl_prf --- fired zero times, because BNK proxies through
# the message-routing path and not the classic HTTP filter. This one fires exactly once per
# proxied request: 12 requests gave fired=12, 17 gave fired=17.
#
# WHAT THIS MOVE DOES NOT SHOW, and do not let it look like it does: the FIELD VALUES. The
# counter is exact, but the record a generated probe publishes is mislabelled on this build ---
# the record's hook name and schema come from a hardwired slot table rather than from the armed
# function, so a probe in slot 2 has its bytes decoded as a 92-byte reset record and prints
# garbage. Both that and the scalars-only limit need a TMM rebuild. See the end of this script.
set -e

FN="${1:-mrhttp_proxy_route_message}"
SLOT="${2:-8}"
REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
SIG="${SIG:-$REPO/signatures.tsv}"
PREVAIL="${PREVAIL:-$REPO/ebpf-verifier/bin/prevail}"
WORK="${WORK:-$(mktemp -d)}"
# kubectl may be a WRAPPER, not the binary. Generation needs clang and PREVAIL; delivery
# needs cluster access; those are on different machines on purpose. env/scripts/bin/
# kubectl-datkube runs kubectl over ssh so this script works from the machine that can
# compile. bnk-deliver-program.py honours the same variable.
KUBECTL="${KUBECTL:-$REPO/env/scripts/bin/kubectl-datkube}"
export KUBECTL
DIM=$(printf '\033[2m'); OFF=$(printf '\033[0m'); B=$(printf '\033[1m')

say()  { printf '\n%s%s%s\n' "$B" "$1" "$OFF"; }
show() { printf '  %s$ %s%s\n' "$DIM" "$1" "$OFF"; }
pause() { [ -n "$YES" ] || { printf '\n  %s[enter]%s' "$DIM" "$OFF"; read _ ; }; }

[ -f "$SIG" ] || { echo "*** no signature index at $SIG."; echo "    Copy it from the build box: scp <build>:~/lstools/signatures.tsv $SIG"; echo "    It is also baked into the image at /usr/share/ls/signatures.tsv."; exit 1; }
[ -x "$PREVAIL" ] || { echo "*** no PREVAIL at $PREVAIL --- this move must not skip verification."; exit 1; }

say "1. The index knows this function's arguments. It came from the build, not from source."
show "grep -P '^$FN\\t' signatures.tsv"
grep -P "^$FN\t" "$SIG" | sed 's/^/      /' || { echo "      not in the index --- it takes no arguments, or the name is wrong"; exit 1; }
printf '\n  %sThe index carries the build id it describes. So does the hook index, and so does\n' "$DIM"
printf '  the binary. All three must agree or nothing will arm.%s\n' "$OFF"
show "head -2 signatures.tsv"
head -2 "$SIG" | sed 's/^/      /'
pause

say "2. Generate the record layout AND the program from it. No TMM source is read."
# --no-probe-read: SCALARS ONLY, because the build on the cluster does not register
# bpf_probe_read (helper 4). A program using an unregistered helper is refused at load with no
# indication of which helper --- so the constraint is applied here, where it can be explained,
# and the generated file records what was dropped and why.
show "time python3 substrate/mk_probe.py --index signatures.tsv --function $FN --no-probe-read -o probe.bpf.c"
python3 "$REPO/substrate/mk_probe.py" --index "$SIG" --function "$FN" \
        --no-probe-read -o "$WORK/probe.bpf.c" 2>&1 | sed 's/^/      /'
printf '\n  %sThat took a tenth of a second. The same lookup against the raw debug information\n' "$DIM"
printf '  takes 1m54s, because it walks every compilation unit of a 146 MB file.%s\n' "$OFF"
pause

say "3. What was generated. This is the whole program."
show "sed -n '/^struct rec/,/^}/p; /^int shield/,\$p' probe.bpf.c"
sed -n '/^struct .*rec/,/^};/p' "$WORK/probe.bpf.c" | sed 's/^/      /'
sed -n '/^int shield/,$p' "$WORK/probe.bpf.c" | sed 's/^/      /'
pause

say "4. Compile, then VERIFY. PREVAIL's defaults are permissive, so the flags are explicit."
show "clang -O2 -g -target bpf -I substrate -c probe.bpf.c -o probe.bpf.o"
clang -O2 -g -target bpf -I "$REPO/substrate" -c "$WORK/probe.bpf.c" -o "$WORK/probe.bpf.o"
SEC=$(llvm-readelf --sections "$WORK/probe.bpf.o" | grep -o 'fentry/[^ ]*' | head -1)
printf '      %s bytes, section %s\n' "$(stat -c%s "$WORK/probe.bpf.o")" "$SEC"
printf '\n  %sThe section name IS the hook. Nothing beside the object says what it attaches to,\n' "$DIM"
printf '  so the object cannot be loaded against a different function than it was built for.%s\n' "$OFF"
show "prevail probe.bpf.o $SEC --termination --strict --no-division-by-zero --stack-size 256"
"$PREVAIL" "$WORK/probe.bpf.o" "$SEC" --termination --strict \
           --no-division-by-zero --stack-size 256 2>&1 | tail -2 | sed 's/^/      /'
pause

say "5. Deliver the bytes over the socket. Nothing is written to the pod."
show "bnk-deliver-program.py probe.bpf.o $SLOT 1     # mode 1 = MONITOR"
sh -c "cd '$REPO' && python3 env/scripts/bnk-deliver-program.py '$WORK/probe.bpf.o' $SLOT 1" 2>&1 | sed 's/^/      /'
pause

say "6. Arm it at the function entry, on a TMM that has been running throughout."
printf '  %sarm reads the entry bytes first and refuses if they are not a five-byte nop pad.\n' "$DIM"
printf '  That is the check that was missing when a stale address armed a pad 64 bytes past\n'
printf '  its target, printed OK, and fired zero times across 16,000 requests.%s\n' "$OFF"
show "ls-load.py arm $SLOT $FN"
for p in $("$KUBECTL" get pods -l app=f5-tmm \
             -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.metadata.deletionTimestamp}{"\n"}{end}' \
           | awk 'NF==1 {print $1}'); do
    printf '      %-26s ' "$p"
    "$KUBECTL" exec -c f5-tmm "$p" -- python3 /usr/bin/ls-load.py arm "$SLOT" "$FN" 2>&1 | tail -1
done

printf '\n  %sNo rebuild. No restart. The pods have not changed age.%s\n' "$DIM" "$OFF"
show "kubectl get pods -l app=f5-tmm"
"$KUBECTL" get pods -l app=f5-tmm --no-headers \
  | awk '{print "      "$1"  "$3"  restarts="$4"  age="$5}'

say "7. Drive traffic. The counter is the claim being made here."
show "curl http://11.11.11.99/  x12"
"$KUBECTL" exec client -- sh -c 'for i in 1 2 3 4 5 6 7 8 9 10 11 12; do curl -s -o /dev/null http://11.11.11.99/; done' >/dev/null 2>&1 || true
sleep 2
for p in $("$KUBECTL" get pods -l app=f5-tmm \
             -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.metadata.deletionTimestamp}{"\n"}{end}' \
           | awk 'NF==1 {print $1}'); do
    printf '      %-26s ' "$p"
    "$KUBECTL" exec -c f5-tmm "$p" -- python3 /usr/bin/ls-load.py status "$SLOT" 2>&1 | tail -1
done
printf '\n  %s12 requests, and one pod counts 12 --- the requests land on one of the two. errors=0.\n' "$DIM"
printf '  A counter is all this move claims. The RECORD is not trustworthy yet on this build:\n'
printf '  the record header takes its hook name and schema from a hardwired slot table, not\n'
printf '  from the function that was armed, so these bytes get decoded as a reset record and\n'
printf '  print nonsense. That needs a rebuild, and so does capturing anything but scalars.%s\n' "$OFF"

say "8. Disarm. The entry goes back to five nops."
show "ls-load.py disarm $FN"
for p in $("$KUBECTL" get pods -l app=f5-tmm \
             -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.metadata.deletionTimestamp}{"\n"}{end}' \
           | awk 'NF==1 {print $1}'); do
    printf '      %-26s ' "$p"
    "$KUBECTL" exec -c f5-tmm "$p" -- python3 /usr/bin/ls-load.py disarm "$FN" 2>&1 | tail -1
done

printf '\n  %sWork dir: %s%s\n' "$DIM" "$WORK" "$OFF"
