#!/bin/sh
# Create the signing key a replication needs, and the header the build compiles against it.
#
#   bnk-init-signing-key.sh              create if absent, then emit the header
#   bnk-init-signing-key.sh --show       report what exists; change nothing
#   bnk-init-signing-key.sh --keyless    emit a header with NO key --- refuses every load
#
# THE GAP THIS CLOSES, found 2026-08-20 while checking whether this work can be reproduced from
# nothing. Every script that signs a program reads $SIGN_KEY, defaulting to
# ~/.ls-signing/shield_sk.pem, and NOTHING in the repository said how that file comes to exist.
# `make check-sig` generates throwaway keys for its own assertions, so the tests pass on a machine
# that could never sign a real program --- a replicator following the documents would reach the
# signing step and stop. The signature work was the largest thing built this week and it was the
# least reproducible.
#
# WHY THE KEY IS NOT IN THE REPOSITORY, and this is worth stating rather than assuming: a private
# key in a shared tree is a private key belonging to everyone who can clone it. It lives outside,
# mode 600, and `*_sk.pem` is gitignored so an accidental copy inside cannot be committed. That
# also means a replication produces a DIFFERENT key --- which is correct. Reproducing this work
# means reproducing the mechanism, not inheriting the trust.
set -e

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
KEYDIR="${KEYDIR:-$HOME/.ls-signing}"
SK="${SIGN_KEY:-$KEYDIR/shield_sk.pem}"
PK="${SK%.pem}_pub.pem"
HDR="${HDR:-$REPO/substrate/ls_sig_pubkey.h}"
MODE=""
for a in "$@"; do
    case "$a" in
        --show)    MODE=show ;;
        --keyless) MODE=keyless ;;
        *) echo "*** unknown option $a" >&2; exit 2 ;;
    esac
done

info() { printf '  %s\n' "$*"; }
fail() { printf '*** %s\n' "$*" >&2; exit 1; }

command -v openssl >/dev/null 2>&1 || fail "openssl is required (for Ed25519 keygen and signing)"

if [ "$MODE" = keyless ]; then
    # A DELIBERATE, VISIBLE CHOICE. The header says so loudly and ls_sig.c treats an all-zero key
    # as ABSENT, so such a build refuses every load including valid ones. That is the right default
    # for a tree nobody has configured, and the wrong thing to reach by forgetting a step.
    python3 "$REPO/substrate/gen_sig_pubkey.py" --none -o "$HDR"
    info "wrote $HDR with NO key --- this build will refuse EVERY load, valid ones included."
    info "That is fail-closed and it is not a working configuration."
    exit 0
fi

echo "=== 1. the private key"
if [ -f "$SK" ]; then
    info "exists: $SK"
    _m=$(stat -c%a "$SK" 2>/dev/null || echo "?")
    if [ "$_m" != "600" ]; then
        [ "$MODE" = show ] && info "mode is $_m, should be 600" \
                           || { chmod 600 "$SK"; info "mode was $_m, set to 600"; }
    else
        info "mode 600"
    fi
else
    [ "$MODE" = show ] && { info "ABSENT: $SK"; info "run without --show to create it"; } || {
        mkdir -p "$KEYDIR"; chmod 700 "$KEYDIR"
        openssl genpkey -algorithm ed25519 -out "$SK" 2>/dev/null
        chmod 600 "$SK"
        info "created $SK (Ed25519, mode 600)"
        info "THIS IS THE ONLY COPY. There is no escrow here, and nothing in this repository can"
        info "recover it. Losing it means every program signed with it must be re-signed."
    }
fi
[ -f "$SK" ] || exit 0

echo
echo "=== 2. the public half"
if [ "$MODE" != show ] || [ -f "$PK" ]; then
    openssl pkey -in "$SK" -pubout -out "$PK" 2>/dev/null
    chmod 644 "$PK"
    info "$PK"
fi
# The fingerprint, so the same key can be recognised in the loader's log line without handling it.
_fp=$(openssl pkey -in "$SK" -pubout -outform DER 2>/dev/null | tail -c 32 | sha256sum | cut -c1-16)
info "fingerprint (sha256 of the raw 32 bytes, first 8): $_fp"

echo
echo "=== 3. the header the build compiles in"
if [ "$MODE" = show ]; then
    if [ -f "$HDR" ]; then
        info "$HDR exists: $(grep -m1 -o 'fingerprint[^*]*' "$HDR" 2>/dev/null | cut -c1-60)"
    else
        info "ABSENT: $HDR --- a build from this tree would not compile the key in"
    fi
else
    python3 "$REPO/substrate/gen_sig_pubkey.py" "$PK" -o "$HDR"
    info "wrote $HDR"
    info "GENERATED, and gitignored: the key a build trusts is a property of that build, and"
    info "committing it is how a test key reaches production."
fi

echo
echo "=== 4. what to do with it"
info "sign a program:   python3 substrate/sign_shield.py --key $SK --prog <x.bpf.o> --hook <fn> -o <x.bpf.sig>"
info "or the whole set: env/scripts/bnk-build-programs.sh   (signs each program after PREVAIL accepts it)"
info "verify the gate:  make -C substrate check-sig   (uses its OWN throwaway keys, not this one)"
