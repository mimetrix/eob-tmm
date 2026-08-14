#!/usr/bin/env python3
"""Load shields repeatedly while traffic flows, and time each one.

This is the measurement the load-path design owes. Preparation (ubpf_create,
ubpf_load_elf, ubpf_compile_ex) runs on a TMM poll thread, so every load spends
time inside a poll iteration that would otherwise be forwarding packets. B0
measured that at ~20 us median / 58 us max on the bench; this checks what it
does to a proxy actually carrying requests.

Reports each load's wall-clock round trip as seen by the client. That is not the
poll-thread stall itself -- it includes the timer's polling interval
(LS_PREP_TICKS, 10 ticks) and the loader's 1 ms wait granularity -- but it is the
upper bound the operator experiences, and any real stall would show up in it.
"""
import glob, socket, struct, sys, time

HDR = 192
N = int(sys.argv[1]) if len(sys.argv) > 1 else 5
sock = sorted(glob.glob("/tmp/ls_load.sock*"))[0]
prog = open("/tmp/shield.elf", "rb").read()
hook = b"http_psm_profile_name_lookup"

def load():
    buf = bytearray(HDR)
    struct.pack_into("<I", buf, 0, 1)          # SHIELD_OP_LOAD
    struct.pack_into("<I", buf, 4, 0)          # slot
    buf[8] = 2                                 # ENFORCE
    struct.pack_into("<I", buf, 12, len(prog))
    buf[48:48 + len(hook)] = hook
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(30)
    t0 = time.monotonic()
    try:
        s.connect(sock)
        s.sendall(bytes(buf) + prog)
        r = s.recv(4096).decode(errors="replace").strip()
    except Exception as e:
        r = f"*** {e}"
    finally:
        s.close()
    return (time.monotonic() - t0) * 1000.0, r

print(f"socket: {sock}   program: {len(prog)} bytes   loads: {N}")
times, ok = [], 0
for i in range(N):
    ms, r = load()
    times.append(ms)
    if r.startswith("OK"):
        ok += 1
    print(f"  load {i+1}: {ms:7.1f} ms   {r}")
    time.sleep(0.4)

times.sort()
print(f"\n  {ok}/{N} succeeded")
print(f"  round trip: min {times[0]:.1f} ms  median {times[len(times)//2]:.1f} ms  max {times[-1]:.1f} ms")
print("  (includes the timer's polling interval and the loader's 1 ms wait granularity,")
print("   so this is the operator-visible upper bound, not the poll-thread stall itself)")
