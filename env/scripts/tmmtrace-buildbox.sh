#!/bin/sh
# tmmtrace-buildbox --- the BUILD BOX worker (staged as ~/tmmtrace).
# The Mac orchestrator calls into this over SSH. This box holds the pinned
# toolchain + PREVAIL + the signing key; nothing here reaches the data plane
# except to ship an already-signed, already-verified artifact.
#
#   tmmtrace verify|gen|list '<arg>'   pinned clang-18 + PREVAIL / hook map
#   tmmtrace build-ship      '<expr>'  gen->clang->PREVAIL->sign->ship to target,
#                                      echo "FN HOOK KIND" (only line on stdout)
set -e
export CLANG="${CLANG:-clang}"
export PREVAIL="${PREVAIL:-$HOME/eob-tmm-staged/ebpf-verifier/bin/prevail}"
export LS_SIGS="${LS_SIGS:-$HOME/lstools/signatures.tsv}"
export LS_TYPES="${LS_TYPES:-$HOME/lstools/types.json}"
export LS_HOOKMAP="${LS_HOOKMAP:-$HOME/lstools/hook-map.json}"
TT="$HOME/eob-tmm-staged/substrate/tmmtrace.py"
SIGN="$HOME/eob-tmm-staged/substrate/sign_shield.py"
SK="${SK:-$HOME/.ls-signing/shield_sk.pem}"
DK="${DK:-10.145.40.193}"; KEY="${KEY:-$HOME/.ssh/id_datpush}"

cmd="$1"; arg="$2"
case "$cmd" in
  verify|gen|list) exec python3 "$TT" "$cmd" "$arg" ;;
  build-ship) : ;;
  *) echo "usage: tmmtrace verify|gen|list|build-ship '<arg>'" >&2; exit 1 ;;
esac

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
python3 "$TT" build "$arg" "$tmp" >&2                        # gen+clang+PREVAIL (verifies)
o=$(ls "$tmp"/*.bpf.o); fn=$(basename "$o" .bpf.o)
hook=$(python3 -c "import json;print(json.load(open('$tmp/$fn.meta.json'))['hook'])")
kind=$(python3 -c "import json;print(json.load(open('$tmp/$fn.meta.json'))['kind'])")
python3 "$SIGN" --key "$SK" --prog "$o" --hook "$hook" --mode-ceiling monitor -o "$tmp/$fn.bpf.sig" >&2
scp -i "$KEY" -o StrictHostKeyChecking=no "$o" "$tmp/$fn.bpf.sig" starin@"$DK":/tmp/ >&2
echo "$fn $hook $kind"                                       # <- only stdout
