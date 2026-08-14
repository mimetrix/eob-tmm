#!/usr/bin/env python3
"""Send an ARM (0x1003) / DISARM (0x1004) op to a RUNNING TMM's load socket.

Layout from src/base/shield_abi.h (verified against its own _Static_asserts):
  shield_msg:  op u32 @0 | epoch u32 @4 | mode u8 @8 | _pad[3] @9 | prog_len u32 @12
               binding @16 (112 bytes) | sig[64] @128 | prog[] @192
  shield_binding: prog_sha256[32] @0 | hook[64] @32 | build_min @96 | build_max @100
                  mode_ceiling @104 | expires_with @108

Field reuse for the dev ARM op (same style as 0x1001 reusing epoch as a count):
  binding.hook  <- the entry address as text, e.g. "0xcd5200"
  epoch         <- the VM slot the trampoline dispatches to
"""
import socket, struct, sys

SOCK = "/tmp/ls_load.sock"
MSG_SIZE, BINDING_OFF, HOOK_OFF = 192, 16, 16 + 32

op   = int(sys.argv[1], 0)          # 0x1003 arm, 0x1004 disarm
addr = sys.argv[2]                  # "0xcd5200"
slot = int(sys.argv[3]) if len(sys.argv) > 3 else 0

buf = bytearray(MSG_SIZE)
struct.pack_into("<I", buf, 0, op)          # op
struct.pack_into("<I", buf, 4, slot)        # epoch reused as slot
buf[8] = 2                                  # mode (ENFORCE) -- ignored by this op
hook = addr.encode()[:63]
buf[HOOK_OFF:HOOK_OFF + len(hook)] = hook   # address as text in binding.hook

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)
s.connect(SOCK)
s.sendall(bytes(buf))
try:
    reply = s.recv(4096).decode(errors="replace").strip()
except socket.timeout:
    reply = "(no reply within 10s)"
print(f"op=0x{op:x} addr={addr} slot={slot}\nreply: {reply}")
s.close()
