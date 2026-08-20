#!/usr/bin/env python3
"""Client for the in-TMM shield loader --- the thing that puts bytecode into a
running TMM.

WHY THIS FILE EXISTS. Every live result recorded in this repo (the load path
working, distinct bytecode discriminated, 10 loads under 9,000 requests, the
hook firing 1:1 with requests, arm/disarm/re-arm) was produced by ad-hoc scripts
that lived in a scratch directory and were never committed. The substrate half
was reproducible --- ls_vm_load.c and friends are in substrate/ --- and the
client half was not, which means none of those results could be re-run by anyone
else. This file closes that gap.

WHAT IT TALKS TO. ls_vm_loader_start() in substrate/ls_vm_load.c runs a loader
thread on an AF_UNIX SOCK_STREAM socket named by the LS_LOAD_SOCKET environment
variable. It is off unless that variable is set.

    THE PROGRAM IS CHECKED, THE CALLER IS NOT (scope item 4 built 2026-08-20).
    The loader verifies an Ed25519 signature over the 112-byte binding before
    admitting a program; it does nothing to establish who sent it. That is why the
    path stays env-gated rather than on by default, and why this client is a test
    tool and not the operator front-end (scope item 11, "not written" ---
    `shieldctl` in the walkthrough is illustrative naming for a tmsh subcommand
    that does not exist).

THE WIRE LAYOUT is struct shield_msg, and the offsets below are hand-encoded
from substrate/shield_abi.h. That is a real fragility: change the struct and
this file goes wrong silently rather than loudly. verify_layout() below asserts
the offsets it assumes so a mismatch is at least caught at import time by anyone
reading shield_abi.h alongside it.

    offset  field
         0  op          uint32   see OP_* below
         4  epoch       uint32   used as the slot index by this client
         8  mode        uint8    see MODE_* below
         9  _pad[3]
        12  prog_len    uint32   bytes of program following the header
        16  binding      --- struct shield_binding starts here
        48  binding.hook char[64]   the named symbol (hook-map key)
       128  sig[64]                 unused: item 4 is unbuilt
       192  prog[]                  the ELF, prog_len bytes

usage:
    ls_client.py status
    ls_client.py load  <file.elf> <hook-name> [--slot N] [--mode enforce|monitor]
    ls_client.py arm   <entry-hex>
    ls_client.py disarm <entry-hex>
"""
import argparse, glob, os, socket, struct, sys

HDR = 192

OFF_OP, OFF_EPOCH, OFF_MODE, OFF_PROG_LEN, OFF_HOOK, OFF_SIG = 0, 4, 8, 12, 48, 128
HOOK_MAX, SIG_LEN = 64, 64

OP_LOAD, OP_SET_MODE, OP_STATUS, OP_REVOKE = 1, 2, 3, 4
# Development-only ops. Not part of the product ABI; they exist so the mechanism
# could be exercised before the hook-map generator (item 5) resolves addresses.
# BENCH and SAMPLES still run on the LOADER thread and will wedge it --- see the
# note in load-path-scope.md section 7 and the standing task to convert them.
OP_DEV_BENCH, OP_DEV_SAMPLES, OP_DEV_ARM, OP_DEV_DISARM = 0x1001, 0x1002, 0x1003, 0x1004

MODE_DISABLE, MODE_MONITOR, MODE_ENFORCE = 0, 1, 2
MODES = {"disable": MODE_DISABLE, "monitor": MODE_MONITOR, "enforce": MODE_ENFORCE}


def verify_layout():
    """The offsets above are transcribed from shield_abi.h, not derived from it.

    This does not read the header --- it pins the arithmetic that produced the
    numbers, so a reader can check them against the struct in one pass. hook
    sits at binding+32, and the binding starts at 16.
    """
    assert OFF_HOOK == 16 + 32, "binding.hook is at binding + 32"
    assert OFF_SIG == OFF_HOOK + HOOK_MAX, "sig follows hook[64]"
    assert HDR == OFF_SIG + SIG_LEN, "prog follows sig[64]"


verify_layout()


def find_socket(path=None):
    """TMM names the socket per instance, so there is normally more than one."""
    if path:
        return path
    env = os.environ.get("LS_LOAD_SOCKET")
    if env and os.path.exists(env):
        return env
    found = sorted(glob.glob("/tmp/ls_load.sock*"))
    if not found:
        raise SystemExit(
            "no loader socket found (looked at $LS_LOAD_SOCKET and /tmp/ls_load.sock*).\n"
            "The loader is off unless TMM was started with LS_LOAD_SOCKET set."
        )
    return found[0]


def send(op, payload=b"", hook=b"", slot=0, mode=MODE_ENFORCE, timeout=30, sock=None):
    """One request, one reply. Returns the loader's reply text.

    Errors are returned as strings beginning with '***' rather than raised: the
    callers here are measurement drivers where a timeout is a datum, not an
    abort. A caller that wants exceptions should check the prefix.
    """
    if isinstance(hook, str):
        hook = hook.encode()
    if len(hook) > HOOK_MAX - 1:
        raise ValueError(f"hook name longer than {HOOK_MAX - 1} bytes: {hook!r}")

    buf = bytearray(HDR)
    struct.pack_into("<I", buf, OFF_OP, op)
    struct.pack_into("<I", buf, OFF_EPOCH, slot)
    buf[OFF_MODE] = mode
    struct.pack_into("<I", buf, OFF_PROG_LEN, len(payload))
    if hook:
        buf[OFF_HOOK:OFF_HOOK + len(hook)] = hook

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock or find_socket())
        s.sendall(bytes(buf) + payload)
        try:
            return s.recv(4096).decode(errors="replace").strip()
        except socket.timeout:
            return "*** TIMEOUT"
    except Exception as e:
        return f"*** {e}"
    finally:
        s.close()


def status(**kw):
    return send(OP_STATUS, **kw)


def load(path, hook, slot=0, mode=MODE_ENFORCE, **kw):
    with open(path, "rb") as f:
        return send(OP_LOAD, f.read(), hook=hook, slot=slot, mode=mode, **kw)


def arm(entry, **kw):
    """Arm a live function entry. `entry` is the address as a hex string.

    Until the hook-map generator (item 5) exists, the address is supplied by
    hand and moves with every rebuild --- read it from the matching
    tmm-debuginfo package, NOT from the build tree, because packaging re-links
    the binary and the build ID differs.
    """
    return send(OP_DEV_ARM, hook=entry, **kw)


def disarm(entry, **kw):
    return send(OP_DEV_DISARM, hook=entry, **kw)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--socket", help="override the socket path")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status")
    p = sub.add_parser("load")
    p.add_argument("elf")
    p.add_argument("hook")
    p.add_argument("--slot", type=int, default=0)
    p.add_argument("--mode", choices=sorted(MODES), default="enforce")
    for name in ("arm", "disarm"):
        q = sub.add_parser(name)
        q.add_argument("entry", help="entry address, hex")

    a = ap.parse_args()
    sk = find_socket(a.socket)
    print(f"socket: {sk}")

    if a.cmd == "status":
        r = status(sock=sk)
    elif a.cmd == "load":
        r = load(a.elf, a.hook, slot=a.slot, mode=MODES[a.mode], sock=sk)
    elif a.cmd == "arm":
        r = arm(a.entry, sock=sk)
    else:
        r = disarm(a.entry, sock=sk)

    print(r)
    return 1 if r.startswith("***") or r.startswith("ERR") else 0


if __name__ == "__main__":
    sys.exit(main())
