#!/bin/sh
# Build-box-only live context probes. Run AFTER bnk-package.sh. No CO-RE field
# accesses: these programs need no BTF, but are signed for exactly this build.
set -eu
REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
DEBS="${DEBS:-$HOME/code/tmm/docker_build/DEBS/amd64}"
OUT="${OUT:-$HOME/ctx96-probes}"
PREVAIL="${PREVAIL:-$REPO/ebpf-verifier/bin/prevail}"
CLANG="${CLANG:-clang-18}"
SIGN_KEY="${SIGN_KEY:-$HOME/.ls-signing/shield_sk.pem}"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$OUT"
for deb in "$DEBS"/tmm_*.deb "$DEBS"/tmm-debuginfo_*.deb; do
    dpkg-deb -x "$deb" "$TMP"
done
RT=$(readlink -f "$TMP/usr/bin/tmm.default")
DBG=$(find "$TMP" -name tmm64.no_pgo.debug)
test -f "$RT" && test -f "$DBG" && test -f "$SIGN_KEY"
BID=$(python3 "$REPO/substrate/ls_buildid.py" "$RT")
sh "$REPO/env/scripts/bnk-receipt.sh" require package build_id "$BID"
PREFIX=$(printf '%s' "$BID" | cut -c1-8)
printf '%s\n' "$BID" > "$OUT/build-id"
python3 "$REPO/substrate/exit_admit.py" "$DBG" "$RT" http_parse_client_headers
for kind in fentry fexit; do
    first=5
    [ "$kind" = fentry ] || first=6
    obj="$OUT/ctx96-$kind.bpf.o"
    sec="$kind/http_parse_client_headers"
    "$CLANG" -O2 -target bpf -Wall -Werror "-DKIND=\"$sec\"" "-DFIRST=$first" \
        -c "$REPO/substrate/check_ctx_live.bpf.c" -o "$obj"
    "$PREVAIL" "$obj" "$sec" --termination --strict --no-division-by-zero \
        --stack-size 256
    python3 "$REPO/substrate/sign_shield.py" --key "$SIGN_KEY" --prog "$obj" \
        --hook http_parse_client_headers --mode-ceiling monitor \
        --build-min "0x$PREFIX" --build-max "0x$PREFIX" \
        -o "$OUT/ctx96-$kind.bpf.sig"
    sha256sum "$obj" "$OUT/ctx96-$kind.bpf.sig"
done
printf 'Context probes verified and signed for %s in %s\n' "$BID" "$OUT"
