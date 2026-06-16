#!/usr/bin/env python3
"""Send minimm frames through the bent pipe.

Frame wire format (big-endian): [2B opcode][2B payload_len][payload]

  client.py benign            # opcode 1, a normal frame the relay forwards
  client.py attack            # opcode 0x4242, the synthetic-CVE frame
  client.py --op N --data S   # arbitrary

Connects to the relay (default 127.0.0.1:8080), sends one frame, prints any
reply, and reports whether the connection survived.
"""
import argparse
import socket
import struct
import sys


def send_frame(host, port, opcode, payload):
    payload = payload.encode() if isinstance(payload, str) else payload
    frame = struct.pack(">HH", opcode, len(payload)) + payload
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect((host, port))
        s.sendall(frame)
        try:
            reply = s.recv(4096)
        except socket.timeout:
            reply = b""
        return True, reply
    except (ConnectionResetError, BrokenPipeError, ConnectionRefusedError) as e:
        return False, str(e).encode()
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", nargs="?", default="benign",
                    choices=["benign", "attack", "raw"])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--op", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--data", default="hello")
    args = ap.parse_args()

    if args.mode == "benign":
        opcode, data = 1, args.data
    elif args.mode == "attack":
        opcode, data = 0x4242, args.data        # opcode >> N_HANDLERS -> wild call
    else:
        opcode, data = (args.op if args.op is not None else 1), args.data

    ok, reply = send_frame(args.host, args.port, opcode, data)
    label = {1: "benign", 0x4242: "ATTACK (synthetic CVE)"}.get(opcode, f"op=0x{opcode:04x}")
    print(f"sent {label}: opcode=0x{opcode:04x} len={len(data)}")
    if ok:
        print(f"  connection survived; reply={reply!r}")
        sys.exit(0)
    else:
        print(f"  connection FAILED/RESET: {reply.decode(errors='replace')}")
        sys.exit(1)


if __name__ == "__main__":
    main()
