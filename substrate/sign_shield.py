#!/usr/bin/env python3
"""Sign a shield program: emit the 112-byte binding and its Ed25519 signature.

    sign_shield.py --key sk.pem --prog p.bpf.o --hook rst_why [options] -o signed.bin

WHAT IT SIGNS, and why this is the whole security argument. The signature covers the BINDING,
not the program --- and the binding commits to the program by SHA-256. So one signature says:

    this key asserts that the program with THIS hash may be armed at THIS hook, on builds in
    THIS range, at no more than THIS mode, until THIS expiry

Everything a caller could otherwise lie about is inside the signed bytes. Signing the program
alone would let a valid signature be re-pointed at a different hook; signing the whole wire
message would tie it to a slot number for no benefit. See 02-RESEARCH-PARAMETERS.md P6, which
records this as a deliberate deviation from shield_abi.h's comment.

THE PRIVATE KEY DOES NOT BELONG HERE. This takes a path so a real deployment can point it at a
PKCS#11 URI or an HSM-backed key instead. A file is the prototype, not the design.
"""
import argparse
import hashlib
import struct
import subprocess
import sys
import tempfile
import os

BINDING_LEN = 112
HOOK_MAX = 64
MODES = {"disable": 0, "monitor": 1, "enforce": 2}


def build_binding(prog, hook, build_min, build_max, mode_ceiling, ctx_abi, expires_with):
    """struct shield_binding, byte for byte.

    Layout asserted in shield_abi.h by _Static_assert and re-asserted from C in check_sig.c ---
    a Python struct string that has drifted from the C is exactly the bug that produces a
    signature nobody can verify, so it is checked from both sides rather than trusted here.
    """
    h = hashlib.sha256(prog).digest()
    hb = hook.encode()
    if len(hb) >= HOOK_MAX:
        sys.exit("*** hook name %r is %d bytes; the field is %d including the terminator"
                 % (hook, len(hb), HOOK_MAX))
    b = bytearray(BINDING_LEN)
    b[0:32] = h                                     # prog_sha256
    b[32:32 + len(hb)] = hb                         # hook[64], NUL-padded
    struct.pack_into("<I", b, 96, build_min)
    struct.pack_into("<I", b, 100, build_max)
    b[104] = mode_ceiling
    b[105] = ctx_abi
    # 106,107 are padding that must be zero: they are inside the signed bytes, so garbage there
    # produces a signature the verifier cannot reproduce.
    struct.pack_into("<I", b, 108, expires_with)
    return bytes(b)


def sign(key, message):
    """Ed25519 via openssl, because the build box has it and a Python crypto dependency here
    would have to be installed on every machine that signs."""
    with tempfile.NamedTemporaryFile(delete=False) as mf:
        mf.write(message)
        mpath = mf.name
    spath = mpath + ".sig"
    try:
        r = subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", key,
                            "-rawin", "-in", mpath, "-out", spath],
                           capture_output=True)
        if r.returncode != 0:
            sys.exit("*** signing failed:\n    %s"
                     % r.stderr.decode(errors="replace").strip()[:300])
        sig = open(spath, "rb").read()
    finally:
        for p in (mpath, spath):
            try: os.unlink(p)
            except OSError: pass
    if len(sig) != 64:
        sys.exit("*** got a %d-byte signature; Ed25519 is 64. Is --key an Ed25519 key?" % len(sig))
    return sig


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", required=True, help="Ed25519 private key (PEM). A file is the "
                                                "prototype; point this at an HSM for real")
    ap.add_argument("--prog", required=True, help="the compiled, PREVAIL-verified .bpf.o")
    ap.add_argument("--hook", required=True, help="the function this program may be armed at")
    ap.add_argument("--build-min", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--build-max", type=lambda x: int(x, 0), default=0xffffffff)
    ap.add_argument("--mode-ceiling", choices=sorted(MODES), default="monitor",
                    help="the MOST this program may be run at. Default monitor, deliberately: "
                         "enforce should be asked for, not defaulted into")
    ap.add_argument("--ctx-abi", type=int, default=1)
    ap.add_argument("--expires-with", type=lambda x: int(x, 0), default=0xffffffff)
    ap.add_argument("-o", "--out", required=True)
    a = ap.parse_args()

    prog = open(a.prog, "rb").read()
    if prog[:4] != b"\x7fELF":
        sys.exit("*** %r is not an ELF object. Sign the .bpf.o, not the .bpf.c" % a.prog)

    binding = build_binding(prog, a.hook, a.build_min, a.build_max,
                            MODES[a.mode_ceiling], a.ctx_abi, a.expires_with)
    sig = sign(a.key, binding)

    with open(a.out, "wb") as fh:
        fh.write(binding + sig)

    print("  signed %s" % a.prog)
    print("    hook          : %s" % a.hook)
    print("    prog sha256   : %s" % hashlib.sha256(prog).hexdigest())
    print("    mode ceiling  : %s" % a.mode_ceiling)
    print("    builds        : 0x%x .. 0x%x" % (a.build_min, a.build_max))
    print("    out           : %s  (%d-byte binding + 64-byte signature)" % (a.out, BINDING_LEN))


if __name__ == "__main__":
    main()
