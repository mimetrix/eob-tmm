#!/usr/bin/env python3
"""Print an ELF's NT_GNU_BUILD_ID. Pure Python because the f5-tmm container has no
readelf, no nm and no objdump --- and `strings` is absent while silently returning
zero for everything, which is worse than missing.

Kept as its own file rather than inlined into a Dockerfile RUN: escaping a
multi-line Python program through sh inside RUN is how a verification step becomes
a verification step that always passes."""
import struct
import sys


def build_id(path):
    with open(path, "rb") as f:
        e = f.read(64)
        if e[:4] != b"\x7fELF" or e[4] != 2:
            return None
        phoff, = struct.unpack_from("<Q", e, 0x20)
        phentsize, phnum = struct.unpack_from("<HH", e, 0x36)
        for i in range(phnum):
            f.seek(phoff + i * phentsize)
            ph = f.read(phentsize)
            if struct.unpack_from("<I", ph, 0)[0] != 4:      # PT_NOTE
                continue
            off, = struct.unpack_from("<Q", ph, 0x08)
            sz, = struct.unpack_from("<Q", ph, 0x20)
            f.seek(off)
            note = f.read(sz)
            j = 0
            while j + 12 <= len(note):
                nsz, dsz, ntype = struct.unpack_from("<III", note, j)
                name = note[j + 12: j + 12 + nsz].rstrip(b"\x00")
                doff = j + 12 + ((nsz + 3) & ~3)
                if ntype == 3 and name == b"GNU":           # NT_GNU_BUILD_ID
                    return note[doff: doff + dsz].hex()
                j = doff + ((dsz + 3) & ~3)
    return None


if __name__ == "__main__":
    b = build_id(sys.argv[1])
    if b is None:
        sys.exit("no GNU build id in %s" % sys.argv[1])
    print(b)
