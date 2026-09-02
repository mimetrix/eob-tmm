#!/usr/bin/env python3
"""Extract a protobuf-c message descriptor straight out of an ELF binary.

WHY. The generated header (proto/tmosTmm/profile_http.pb-c.h) is produced outside the TMM tree,
so the wire schema is not readable from source here. But protobuf-c emits the descriptors as real
data symbols, so the binary IS the schema. This reads it.

SELF-VERIFYING: the ProtobufCFieldDescriptor stride differs across protobuf-c versions, so rather
than trusting one layout, try candidates and accept only the stride where EVERY field name
resolves to printable ASCII and every field id is plausible. A wrong stride fails loudly instead
of printing plausible-looking garbage.
"""
import struct, sys

TYPES = {0:"int32",1:"sint32",2:"sfixed32",3:"int64",4:"sint64",5:"sfixed64",6:"uint32",
         7:"fixed32",8:"uint64",9:"fixed64",10:"float",11:"double",12:"bool",13:"enum",
         14:"string",15:"bytes",16:"message"}
LABELS = {0:"required",1:"optional",2:"repeated",3:"none"}


class Elf:
    def __init__(self, path):
        self.f = open(path, "rb")
        d = self.f.read(64)
        assert d[:4] == b"\x7fELF" and d[4] == 2, "not ELF64"
        self.shoff, = struct.unpack_from("<Q", d, 0x28)
        self.shentsize, self.shnum = struct.unpack_from("<HH", d, 0x3a)
        self.secs = []
        for i in range(self.shnum):
            self.f.seek(self.shoff + i * self.shentsize)
            s = self.f.read(self.shentsize)
            sh_addr, sh_off, sh_size = struct.unpack_from("<QQQ", s, 0x10)
            sh_type, = struct.unpack_from("<I", s, 0x04)
            self.secs.append((sh_addr, sh_off, sh_size, sh_type))

    def read(self, vaddr, n):
        for addr, off, size, stype in self.secs:
            if stype != 8 and addr and addr <= vaddr < addr + size:   # skip NOBITS
                if vaddr - addr + n > size:
                    n = size - (vaddr - addr)
                self.f.seek(off + (vaddr - addr))
                return self.f.read(n)
        return None

    def cstr(self, vaddr, maxn=256):
        b = self.read(vaddr, maxn)
        if not b:
            return None
        z = b.find(b"\0")
        return b[:z if z >= 0 else maxn]


def main(path, desc_vaddr):
    e = Elf(path)
    d = e.read(desc_vaddr, 96)
    if not d:
        sys.exit("could not read descriptor at 0x%x" % desc_vaddr)
    magic, = struct.unpack_from("<I", d, 0)
    name_p, short_p, cname_p, pkg_p, sizeof_msg = struct.unpack_from("<QQQQQ", d, 8)
    n_fields, = struct.unpack_from("<I", d, 48)
    fields_p, = struct.unpack_from("<Q", d, 56)
    print("  magic          : 0x%08x %s" % (magic, "(protobuf-c message magic ok)" if magic == 0x28aaeef9 else "(UNEXPECTED)"))
    for lbl, p in (("name", name_p), ("short_name", short_p), ("c_name", cname_p), ("package", pkg_p)):
        s = e.cstr(p)
        print("  %-14s : %s" % (lbl, s.decode(errors="replace") if s else "?"))
    print("  sizeof_message : %d" % sizeof_msg)
    print("  n_fields       : %d" % n_fields)
    print("  fields @       : 0x%x" % fields_p)
    if not (0 < n_fields < 5000):
        sys.exit("  n_fields implausible -- descriptor layout mismatch")

    def try_stride(stride):
        out = []
        for i in range(n_fields):
            fd = e.read(fields_p + i * stride, stride)
            if not fd or len(fd) < 24:
                return None
            np_, = struct.unpack_from("<Q", fd, 0)
            fid, label, ftype = struct.unpack_from("<III", fd, 8)
            nm = e.cstr(np_, 128)
            if not nm or not nm or not all(32 <= c < 127 for c in nm):
                return None
            if not (0 < fid < (1 << 29)) or label not in LABELS or ftype not in TYPES:
                return None
            out.append((nm.decode(), fid, LABELS[label], TYPES[ftype]))
        return out

    fields = None
    for stride in (72, 80, 64, 88, 96):
        fields = try_stride(stride)
        if fields:
            print("  field stride   : %d bytes (validated: all %d names ASCII, ids/types sane)"
                  % (stride, n_fields))
            break
    if not fields:
        sys.exit("  no candidate stride validated -- refusing to print guesses")

    print("\n  === FIELDS ===")
    for nm, fid, lab, ty in fields:
        print("    %-4d %-10s %-9s %s" % (fid, ty, lab, nm))

    want = ("enforce_rfc_compliance", "max_header_count", "passthrough_excess_client_headers",
            "proxy_type", "max_header_size")
    print("\n  === THE ONES THAT MATTER ===")
    by = {n: (i, t) for n, i, l, t in fields}
    for w in want:
        if w in by:
            print("    PRESENT  %-34s field #%d  (%s)" % (w, by[w][0], by[w][1]))
        else:
            print("    absent   %s" % w)


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2], 16))
