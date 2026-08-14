#!/usr/bin/env python3
"""Push a REAL, valid program into a running TMM over the socket.

The prog_len=0 probe was rejected before it could allocate, so it proved nothing
about the allocator. This sends the actual verified shield object -- the same
4320-byte ELF that is compiled into the binary and running in slot 0 -- which
forces the full path: parse the ELF, ubpf_create, ubpf_load_elf, JIT, publish.
That path allocates, and allocation on this thread is the thing in question.

Outcome is one of three, and each answers the question differently:
  OK ...            -> arbitrary bytecode CAN be inserted at runtime
  ERR ...           -> refused for a stated reason; loader still alive
  *** TIMEOUT       -> the predicted allocator freeze, loader wedged

The ARM probe afterwards distinguishes "refused cleanly" from "wedged".
"""
import glob, socket, struct, sys

HDR = 192
sock = sorted(glob.glob("/tmp/ls_load.sock*"))[0]
prog = open("/tmp/shield.elf", "rb").read()

def send(op, payload=b"", hook=b"", slot=0, timeout=20):
    buf = bytearray(HDR)
    struct.pack_into("<I", buf, 0, op)
    struct.pack_into("<I", buf, 4, slot)
    buf[8] = 2                                  # ENFORCE
    struct.pack_into("<I", buf, 12, len(payload))
    if hook:
        buf[48:48+len(hook)] = hook             # binding.hook = 16 + 32
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock); s.sendall(bytes(buf) + payload)
        try:    return s.recv(4096).decode(errors="replace").strip()
        except socket.timeout: return "*** TIMEOUT (loader did not reply)"
    except Exception as e: return f"*** {e}"
    finally: s.close()

print(f"socket : {sock}")
print(f"program: {len(prog)} bytes, ELF={prog[:4] == b'.ELF'.replace(b'.', bytes([0x7f]))}")

print("1. LOAD the real shield into slot 1 (full path: parse, create, JIT, publish):")
print("   ", send(1, prog, hook=b"http_psm_profile_name_lookup", slot=1))

print("2. ARM probe -- is the loader still alive?")
print("   ", send(0x1003, hook=b"0xcd4700"))

print("3. disarm (leave it clean):")
print("   ", send(0x1004, hook=b"0xcd4700"))
