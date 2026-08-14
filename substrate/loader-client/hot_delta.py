#!/usr/bin/env python3
"""Warm per-call cost of an armed hook, by delta between two traffic bursts.

The first measurement was polluted: cycles_max was 1,093,190 on a run whose mean
was 1,134, i.e. one cold invocation (cold i-cache, first touch of the JIT'd page)
accounted for a sixth of the total. Reporting that mean would overstate the
steady-state cost.

So this reads the counters between two identical bursts and reports the delta.
Every call in the second burst is warm, so (cycles2 - cycles1) / (fired2 - fired1)
is the steady-state per-call cost.

Still includes the rdtsc pair that produces the number (LS_VM_TIMING=1), which is
itself tens of cycles --- stated rather than subtracted, since it is real code the
hot path executes when timing is on.

usage: hot_delta.py <read|arm|restore> <entry-hex>
"""
import glob, socket, struct, sys

HDR = 192
sock = sorted(glob.glob("/tmp/ls_load.sock*"))[0]

def send(op, payload=b"", hook=b"", timeout=30):
    buf = bytearray(HDR)
    struct.pack_into("<I", buf, 0, op)
    struct.pack_into("<I", buf, 4, 0)
    buf[8] = 2
    struct.pack_into("<I", buf, 12, len(payload))
    if hook:
        buf[48:48 + len(hook)] = hook
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock); s.sendall(bytes(buf) + payload)
        try:    return s.recv(4096).decode(errors="replace").strip()
        except socket.timeout: return "*** TIMEOUT"
    except Exception as e: return f"*** {e}"
    finally: s.close()

what  = sys.argv[1]
entry = sys.argv[2].encode() if len(sys.argv) > 2 else b""

if what == "arm":
    print("   ", send(1, open("/tmp/demo_pass.elf", "rb").read(), hook=b"demo_pass"))
    print("   ", send(0x1003, hook=entry))
elif what == "read":
    print(send(3))
elif what == "restore":
    print("   ", send(0x1004, hook=entry))
    print("   ", send(1, open("/tmp/shield.elf", "rb").read(),
                      hook=b"http_psm_profile_name_lookup"))
