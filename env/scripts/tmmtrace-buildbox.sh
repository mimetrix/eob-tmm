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
export CLANG="${CLANG:-clang-18}"
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
sec=$(python3 -c "import json;print(json.load(open('$tmp/$fn.meta.json'))['section'])")
SUB="$HOME/eob-tmm-staged/substrate"
OBJCOPY="${OBJCOPY:-/usr/lib/llvm-18/bin/llvm-objcopy}"
gcc -O2 -DLS_CORE_RELO_TEST "$SUB/ls_core_relo.c" -o "$tmp/relo"
relos=$("$tmp/relo" --has-relos "$o")
case "$relos" in
  *'1  needs relocation')
    "$tmp/relo" "$o" "${TMM_BTF:-$HOME/lstools/tmm.btf}" "$tmp/relocated.o" >&2
    mv "$tmp/relocated.o" "$o" ;;
  *'0  offsets are baked') ;;
  *) echo "*** cannot determine relocation requirements: $relos" >&2; exit 1 ;;
esac
"$OBJCOPY" --remove-section=.BTF --remove-section=.BTF.ext --remove-section=.rel.BTF.ext "$o"
DEBS="${LS_TARGET_DEBS:-$HOME/code/tmm/docker_build/DEBS/amd64}"
mkdir -p "$tmp/target"
for deb in "$DEBS"/tmm_*.deb "$DEBS"/tmm-debuginfo_*.deb; do
  dpkg-deb -x "$deb" "$tmp/target"
done
RT="$tmp/target/usr/bin/tmm64.no_pgo"
DBG=$(find "$tmp/target" -name tmm64.no_pgo.debug)
python3 "$SUB/bind_target.py" --prog "$o" --binary "$RT" --debug "$DBG" \
    --index "${LS_HOOK_INDEX:-$HOME/lstools/hook-index.tsv}" --objcopy "$OBJCOPY" >&2
"$PREVAIL" "$o" "$sec" --termination --strict --no-division-by-zero --stack-size 256 >&2
BID=$(python3 "$SUB/ls_buildid.py" "$RT")
PREFIX=$(printf '%s' "$BID" | cut -c1-8)
python3 "$SIGN" --key "$SK" --prog "$o" --hook "$hook" --mode-ceiling monitor \
    --build-min "0x$PREFIX" --build-max "0x$PREFIX" -o "$tmp/$fn.bpf.sig" >&2
scp -i "$KEY" -o StrictHostKeyChecking=no "$o" "$tmp/$fn.bpf.sig" starin@"$DK":/tmp/ >&2
echo "$fn $hook $kind"                                       # <- only stdout
