#!/usr/bin/env python3
"""Arm one function across EVERY TMM instance in this pod, live.

BNK runs one TMM instance per core, each its own process and address space, so
arming is per-instance: each has its own load socket ($LS_LOAD_SOCKET.<pid>) and
its own copy of the text to patch. Arming only one leaves the other core
unshielded -- which is why the loader now binds a per-instance path.

usage: arm_all.py <op-hex> <entry-address-hex> [slot]
       op 0x1003 = arm, 0x1004 = disarm
"""
import glob, os, socket, struct, sys

op   = int(sys.argv[1], 0)
addr = sys.argv[2]
slot = int(sys.argv[3]) if len(sys.argv) > 3 else 0

socks = sorted(glob.glob("/tmp/ls_load.sock*"))
if not socks:
    print("no loader sockets found"); sys.exit(1)

# shield_msg: op u32@0 | epoch u32@4 | mode u8@8 | prog_len u32@12
#             binding@16 (hook[64] at binding+32 = 48) | sig | prog
buf = bytearray(4096)
struct.pack_into("<I", buf, 0, op)
struct.pack_into("<I", buf, 4, slot)
buf[8] = 2
struct.pack_into("<I", buf, 12, 0)
h = addr.encode()[:63]
buf[48:48 + len(h)] = h

for path in socks:
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(path)
        s.sendall(bytes(buf))
        try:
            r = s.recv(4096).decode(errors="replace").strip()
        except socket.timeout:
            r = "(no reply -- loader not accepting)"
        s.close()
    except Exception as e:
        r = f"({e})"
    print(f"  {path}: {r}")

# show the entry bytes in every tmm instance: 90*5 = unarmed, e8+rel32 = armed
base = int(addr, 0)
for p in sorted(os.listdir("/proc")):
    if not p.isdigit():
        continue
    try:
        if not open(f"/proc/{p}/comm").read().startswith("tmm."):
            continue
        with open(f"/proc/{p}/mem", "rb") as f:
            f.seek(base)
            b = f.read(9)
        state = "ARMED (call)" if b[4] == 0xE8 else ("unarmed (nops)" if b[4] == 0x90 else "?")
        print(f"  pid {p} @ {addr}: {b.hex(' ')}   {state}")
    except Exception:
        pass
