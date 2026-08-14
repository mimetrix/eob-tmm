#!/usr/bin/env python3
"""Measure what an ARMED hook costs on a function the traffic actually calls.

Every performance number so far is either bench-only or inferred from proxy
throughput, and throughput on this setup swings 291-369 rps run to run --- wider
than the effect being looked for. This measures the per-call cost directly, from
the trampoline's own counters, so noise in the load generator does not matter.

SAFETY: slot 0 is loaded with demo_pass, which always returns 0 (FALLTHROUGH).
The hooked function therefore always runs normally and behaviour is unchanged;
what is measured is pure overhead. Arming with a shield that could return
SAFE_RETURN on an arbitrary function would skip that function's body with a ctx
built from whatever happened to be in the argument registers --- which is how you
break a proxy, not measure one.

Reports fired (proves the hook is really on the request path), and cycles /
cycles_max from ls_stats.

usage: hot_hook_cost.py <phase> <entry-hex>
  phase 1  load demo_pass, arm, zero the counters
  phase 2  read the counters back, disarm, restore the real shield
"""
import glob, socket, struct, sys, time

HDR = 192
sock = sorted(glob.glob("/tmp/ls_load.sock*"))[0]

def send(op, payload=b"", hook=b"", slot=0, timeout=30):
    buf = bytearray(HDR)
    struct.pack_into("<I", buf, 0, op)
    struct.pack_into("<I", buf, 4, slot)
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

phase = sys.argv[1]
entry = sys.argv[2].encode()

if phase == "1":
    pss = open("/tmp/demo_pass.elf", "rb").read()
    print("  load demo_pass (always FALLTHROUGH -- no behaviour change):")
    print("   ", send(1, pss, hook=b"demo_pass"))
    print("  status before traffic:")
    print("   ", send(3))
    print(f"  arm {entry.decode()}:")
    print("   ", send(0x1003, hook=entry))

elif phase == "2":
    print("  status after traffic:")
    print("   ", send(3))
    print("  disarm:")
    print("   ", send(0x1004, hook=entry))
    real = open("/tmp/shield.elf", "rb").read()
    print("  restore the real CVE shield to slot 0:")
    print("   ", send(1, real, hook=b"http_psm_profile_name_lookup"))
