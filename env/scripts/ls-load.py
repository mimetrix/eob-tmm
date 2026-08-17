#!/usr/bin/env python3
"""Speak the live-surface loader protocol over its unix socket.

WHY THIS IS IN THE REPO. Every live result so far --- including "maps work in TMM"
--- was produced by a client typed inline and then thrown away. So the exact bytes
that produced a headline number were not recoverable, which is the same class of
problem as source living only on the build box. This is that client, versioned.

RUNS INSIDE THE TMM CONTAINER. The socket is at $LS_LOAD_SOCKET in the f5-tmm
container's own filesystem; a sidecar does not share it. Invoke as:

    kubectl exec -i <pod> -c f5-tmm -- python3 - status 5 < ls-load.py

WIRE LAYOUT is struct shield_msg from substrate/shield_abi.h. The offsets below
are not remembered, they were read out of the compiler:

    op=0  epoch=4  mode=8  prog_len=12  binding.hook=48  prog=192  sizeof=192

`epoch` carries the SLOT. That field name is a wart --- three ops once hardcoded
slot 0 while reporting success, so a load landed where nothing ran.

  arm   <slot> <addr>   0x1003  patch a live function entry, address as hex text
  disarm      <addr>    0x1004  restore the nops
  load  <slot> <file> [mode]  1  load an ELF (default mode 2 = enforce)
  status <slot>               3  armed/mode/gen/fired/safe_returns
  mode  <slot> <mode>         2  0 disable, 1 monitor, 2 enforce
  revoke <slot>               4

Signature verification is NOT part of this path (scope item 4, deferred): the
loader accepts unverified programs and says so on every load. Lab only.
"""
import os
import socket
import struct
import sys

HDR = 192
OFF_OP, OFF_EPOCH, OFF_MODE, OFF_PROGLEN, OFF_HOOK = 0, 4, 8, 12, 48

OP_LOAD, OP_SET_MODE, OP_STATUS, OP_REVOKE = 1, 2, 3, 4
OP_ARM, OP_DISARM = 0x1003, 0x1004

def resolve_sock():
    """The loader appends the TMM instance number: LS_LOAD_SOCKET=/tmp/ls_load.sock
    becomes /tmp/ls_load.sock.24. Connecting to the unsuffixed name fails with
    ENOENT, which reads exactly like "the loader is off" and is not. So resolve it,
    and if several instances are listening say so rather than picking one --- they
    are separate processes with separate slots, and guessing would attribute a
    result to the wrong one."""
    base = os.environ.get("LS_LOAD_SOCKET", "/tmp/ls_load.sock")
    if os.path.exists(base):
        return base
    d, name = os.path.dirname(base) or ".", os.path.basename(base)
    found = sorted(os.path.join(d, f) for f in os.listdir(d)
                   if f.startswith(name + "."))
    if not found:
        sys.exit("no loader socket at %s or %s.* --- is LS_LOAD_SOCKET set, and did "
                 "the loader thread start? Check the pod log for 'LOADER LISTENING'."
                 % (base, base))
    if len(found) > 1 and not os.environ.get("LS_SOCK_PICK"):
        sys.exit("several loaders listening:\n  " + "\n  ".join(found) +
                 "\nset LS_LOAD_SOCKET to one of them (separate processes, separate slots)")
    return found[0]


SOCK = resolve_sock()


def msg(op, slot=0, mode=0, hook=b"", prog=b""):
    """Build one shield_msg. Zero-filled: every field this op does not use must
    read as zero, not as residue from whatever was in the buffer before."""
    b = bytearray(HDR)
    struct.pack_into("<I", b, OFF_OP, op)
    struct.pack_into("<I", b, OFF_EPOCH, slot)
    struct.pack_into("<I", b, OFF_MODE, mode)
    struct.pack_into("<I", b, OFF_PROGLEN, len(prog))
    if hook:
        if len(hook) > 64:
            sys.exit("hook name/address longer than the 64-byte field")
        b[OFF_HOOK:OFF_HOOK + len(hook)] = hook
    return bytes(b) + prog


def send(payload):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(20)
        s.connect(SOCK)
    except OSError as e:
        sys.exit("cannot reach %s: %s  (is LS_LOAD_SOCKET set on the pod?)" % (SOCK, e))
    s.sendall(payload)
    try:
        s.shutdown(socket.SHUT_WR)          # tell the loader the request is complete
    except OSError:
        pass
    out = b""
    while True:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            out += b"\n<timed out waiting for a reply>"
            break
        if not chunk:
            break
        out += chunk
    s.close()
    return out.decode("utf-8", "replace").rstrip()


def main():
    a = sys.argv[1:]
    if not a:
        sys.exit(__doc__)
    cmd = a[0]

    if cmd == "arm":
        # The address goes in binding.hook AS TEXT --- the loader strtoull()s it.
        slot, addr = int(a[1]), a[2]
        print(send(msg(OP_ARM, slot=slot, hook=addr.encode())))
    elif cmd == "disarm":
        print(send(msg(OP_DISARM, hook=a[1].encode())))
    elif cmd == "load":
        slot, path = int(a[1]), a[2]
        mode = int(a[3]) if len(a) > 3 else 2
        with open(path, "rb") as f:
            prog = f.read()
        # The hook name becomes "fentry/<hook>", the section uBPF selects by. It
        # must match what the program was compiled with or the load is refused
        # (finding O14 --- section and function are two separate identities).
        hook = a[4].encode() if len(a) > 4 else b""
        print(send(msg(OP_LOAD, slot=slot, mode=mode, hook=hook, prog=prog)))
    elif cmd == "status":
        print(send(msg(OP_STATUS, slot=int(a[1]))))
    elif cmd == "mode":
        print(send(msg(OP_SET_MODE, slot=int(a[1]), mode=int(a[2]))))
    elif cmd == "revoke":
        print(send(msg(OP_REVOKE, slot=int(a[1]))))
    else:
        sys.exit("unknown command %r" % cmd)


if __name__ == "__main__":
    main()
