#!/usr/bin/env python3
"""The four-step CVE demonstration, driven from inside the TMM pod.

    crash  ->  arm the shield  ->  no crash  ->  disarm  ->  crash returns

WHY A TRIGGER IS NEEDED AT ALL. The unguarded dereference at http_psm.c:808 is
only reached when a PSM log record is built, which is gated on
`if (psmd->alarm_mask != 0)`. Every write to alarm_mask sits inside an
`enforce->*` guarded block, and BNK exposes no CRD for any enforce field -- it
offers protocolInspection logging but no enforcement tuning. So ordinary BNK
configuration cannot raise the alarm, and the fault is unreachable through
supported config. Dev op 0x1005 sets the bits directly.

WHAT IS AND IS NOT SIMULATED. Only the CONFIGURATION is reached by a route BNK
does not offer. The traffic is real, the code path is real, the fault is the real
one. Nothing about the crash is synthesized.

AN EBPF PROGRAM CANNOT DO THE TRIGGERING, and that is not a limitation to work
around -- it is the property that makes the design verifiable. A program is a
pure function of ctx returning a scalar; the host applies one of an enumerated
set of outcomes. It cannot write host state. So: one program (the shield) plus a
host-side trigger.

ADDRESSES MOVE EVERY BUILD. Regenerate with:
    python3 substrate/mk_hook_map.py --debs <DEBS> -o map.json
and pass --entry/--shield-entry from it. The defaults below were correct for
build ceafaf81 and will be wrong for the next one -- arming a stale address fails
silently, because nop pads exist in plenty of wrong places.

usage (inside the f5-tmm container):
    python3 cve_demo.py [--entry 0xcd12c0] [--shield-entry 0xcd4904] [--stage N]
"""
import argparse, glob, socket, struct, sys, time

HDR = 192
OP_LOAD, OP_STATUS = 1, 3
OP_SAMPLES, OP_ARM, OP_DISARM, OP_SET_ENFORCE = 0x1002, 0x1003, 0x1004, 0x1005


def sock_path():
    s = sorted(glob.glob("/tmp/ls_load.sock*"))
    if not s:
        raise SystemExit("*** no loader socket; TMM must run with LS_LOAD_SOCKET set")
    return s[0]


def send(op, payload=b"", hook=b"", slot=0, timeout=25):
    if isinstance(hook, str):
        hook = hook.encode()
    b = bytearray(HDR)
    struct.pack_into("<I", b, 0, op)
    struct.pack_into("<I", b, 4, slot)
    b[8] = 2                                    # ENFORCE
    struct.pack_into("<I", b, 12, len(payload))
    if hook:
        b[48:48 + len(hook)] = hook
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock_path())
        s.sendall(bytes(b) + payload)
        try:
            return s.recv(8192).decode(errors="replace").strip()
        except socket.timeout:
            return "*** TIMEOUT"
    except Exception as e:
        return f"*** {e}"
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--entry", default="0xcd12c0",
                    help="http_process_clientside_profile_rules --- arg0 is a struct http_cfg *")
    ap.add_argument("--shield-entry", default="0xcd4904",
                    help="http_psm_profile_name_lookup --- the vulnerable function")
    ap.add_argument("--stage", type=int, default=0, help="0=all, or run one stage")
    a = ap.parse_args()

    def stage(n):
        return a.stage in (0, n)

    if stage(1):
        print("1. demo_pass into slot 0 --- always FALLTHROUGH, so arming changes nothing")
        print("  ", send(OP_LOAD, open("/tmp/demo_pass.elf", "rb").read(), hook="demo_pass"))
        print(f"2. arm {a.entry} to capture a live http_cfg from arg0")
        print("  ", send(OP_ARM, hook=a.entry))
        print("   drive one request now, then run --stage 2")

    if stage(2):
        print("3. read the sample ring for arg0 (the http_cfg pointer)")
        r = send(OP_SAMPLES)
        print("  ", r[:400])
        print("   take arg0 from above and pass it to --stage 3 via --cfg")

    if stage(3):
        print("4. NOT run automatically: 0x1005 needs the http_cfg address from stage 2.")
        print("   send it yourself:  send(0x1005, hook='0x<cfg>')")
        print("   it prints the bitfield word before and after, so a drifted offset")
        print("   shows up at once rather than silently doing nothing.")

    if stage(9):
        print("recover: disarm both hooks")
        print("  ", send(OP_DISARM, hook=a.entry))
        print("  ", send(OP_DISARM, hook=a.shield_entry))
        print("  (the enforce bits live in a per-profile struct --- a pod restart clears them,")
        print("   so nothing persists and no crash-loop is possible)")


if __name__ == "__main__":
    sys.exit(main())
