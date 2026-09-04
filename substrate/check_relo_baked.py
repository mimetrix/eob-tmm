#!/usr/bin/env python3
"""check_relo_baked.py --- prove the offsets baked at SIGN TIME are the right ones.

WHY THIS EXISTS. Taking the 6.4 MB `.BTF` out of the shipped binary
(02-RESEARCH-PARAMETERS.md P9) means field offsets get resolved on the build box
and shipped baked in, instead of being resolved on-box against the running
binary's own type information. That deletes the property that currently makes a
stale offset structurally impossible (`ls_vm.c:594`, "it IS the binary's own
section"). Baked offsets with nothing checking them is the bitfield failure
family again: wrong values, every gate silent.

So before that property is removed, the baking has to be shown correct.

WHAT MAKES THIS A CHECK AND NOT A TAUTOLOGY. Running the offline relocator and
comparing it to the on-box relocator compares `ls_core_relo.c` to itself --- it is
the same source file, compiled into TMM as src/base/ls_core_relo.c and offline
with -DLS_CORE_RELO_TEST. Same code, same input, same answer, nothing learned.

This re-implements the whole path independently in Python: parse the program's
`.BTF.ext` CO-RE relocation records, resolve each one against the target BTF, and
compare the answer to the immediate the C relocator actually wrote into the
object. Two implementations that agree is evidence; one implementation run twice
is not. Same discipline as the two-DWARF-reader rule in CONTESTED-PREMISES.md 12.

IT ALSO SCREENS THE KNOWN HAZARD. ls_core_relo.c refuses a sub-byte bit offset,
but a bitfield that happens to START on a byte boundary is accepted and read as a
plain scalar --- which is silently wrong unless its width is also a whole byte.
gen_type_catalog.py had exactly this defect (6,960 entries). Every relocated
field is screened for it here, because a shield reading a bitfield as a scalar
passes PREVAIL, passes the signature, arms cleanly and reports the wrong answer.

USAGE
    check_relo_baked.py <tmm.btf> <prog.bpf.o> [prog.bpf.o ...] [--relo ./relo]

    --relo   path to the offline relocator, built from ls_core_relo.c with
             -DLS_CORE_RELO_TEST. Built automatically if a compiler is present.

Exit 0 only if every relocation in every program agrees and no hazard is found.
"""
import os
import struct
import subprocess
import sys
import tempfile

# ---- BTF on-disk (kernel Documentation/bpf/btf.rst) -------------------------
BTF_MAGIC = 0xEB9F
K_INT, K_PTR, K_ARRAY, K_STRUCT, K_UNION, K_ENUM = 1, 2, 3, 4, 5, 6
K_FWD, K_TYPEDEF, K_VOLATILE, K_CONST, K_RESTRICT = 7, 8, 9, 10, 11
K_FUNC, K_FUNC_PROTO, K_VAR, K_DATASEC, K_FLOAT = 12, 13, 14, 15, 16
K_DECL_TAG, K_TYPE_TAG, K_ENUM64 = 17, 18, 19

# bytes of kind-specific data trailing the 12-byte btf_type header
def _trailing(kind, vlen):
    if kind in (K_INT, K_VAR, K_DECL_TAG):          return 4
    if kind == K_ARRAY:                             return 12
    if kind in (K_STRUCT, K_UNION):                 return vlen * 12
    if kind == K_ENUM:                              return vlen * 8
    if kind in (K_ENUM64, K_DATASEC):               return vlen * 12
    if kind == K_FUNC_PROTO:                        return vlen * 8
    return 0


class Btf:
    """A parsed BTF blob. Deliberately a separate implementation from
    ls_core_relo.c's --- that is the entire point of this file."""

    def __init__(self, blob):
        if len(blob) < 24:
            raise ValueError("BTF blob shorter than its header")
        magic, ver, flags, hdr_len = struct.unpack_from("<HBBI", blob, 0)
        if magic != BTF_MAGIC:
            raise ValueError("bad BTF magic %#x" % magic)
        type_off, type_len, str_off, str_len = struct.unpack_from("<IIII", blob, 8)
        self.types_blob = blob[hdr_len + type_off: hdr_len + type_off + type_len]
        self.strs = blob[hdr_len + str_off: hdr_len + str_off + str_len]
        self.by_id = [None]          # id 0 is void
        self.by_name = {}
        self._index()

    def s(self, off):
        if off >= len(self.strs):
            return ""
        end = self.strs.find(b"\0", off)
        return self.strs[off:end if end >= 0 else None].decode("utf-8", "replace")

    def _index(self):
        b, off = self.types_blob, 0
        while off + 12 <= len(b):
            name_off, info, size_or_type = struct.unpack_from("<III", b, off)
            kind = (info >> 24) & 0x1F
            vlen = info & 0xFFFF
            kflag = (info >> 31) & 1
            trail = _trailing(kind, vlen)
            if off + 12 + trail > len(b):
                break                                  # truncated tail
            t = {
                "id": len(self.by_id), "kind": kind, "vlen": vlen, "kflag": kflag,
                "name": self.s(name_off), "size_or_type": size_or_type,
                "_data_off": off + 12,
            }
            self.by_id.append(t)
            if t["name"]:
                # first definition wins; a FWD must never shadow a real STRUCT
                key = (kind, t["name"])
                self.by_name.setdefault(key, t)
            off += 12 + trail

    def members(self, t):
        """[(name, type_id, bit_offset, bitfield_size)] for a STRUCT/UNION."""
        if t["kind"] not in (K_STRUCT, K_UNION):
            raise ValueError("type %r is not a struct/union" % t["name"])
        out = []
        for i in range(t["vlen"]):
            name_off, tid, off = struct.unpack_from(
                "<III", self.types_blob, t["_data_off"] + i * 12)
            if t["kflag"]:
                bitfield_size = (off >> 24) & 0xFF
                bit_off = off & 0xFFFFFF
            else:
                bitfield_size = 0
                bit_off = off
            out.append((self.s(name_off), tid, bit_off, bitfield_size))
        return out

    def strip(self, tid):
        """Follow typedef/const/volatile/restrict to the underlying type."""
        seen = 0
        while tid and seen < 32:
            t = self.by_id[tid] if tid < len(self.by_id) else None
            if t is None:
                return None
            if t["kind"] in (K_TYPEDEF, K_CONST, K_VOLATILE, K_RESTRICT, K_TYPE_TAG):
                tid = t["size_or_type"]
                seen += 1
                continue
            return t
        return None

    def find_struct(self, name):
        for kind in (K_STRUCT, K_UNION):
            t = self.by_name.get((kind, name))
            if t is not None:
                return t
        return None

    def size_of(self, tid):
        t = self.strip(tid)
        if t is None:
            return None
        if t["kind"] in (K_INT, K_STRUCT, K_UNION, K_ENUM, K_ENUM64, K_FLOAT):
            return t["size_or_type"]
        if t["kind"] == K_PTR:
            return 8
        if t["kind"] == K_ARRAY:
            etid, _nelems = struct.unpack_from("<II", self.types_blob, t["_data_off"])[0:2]
            nelems = struct.unpack_from("<I", self.types_blob, t["_data_off"] + 8)[0]
            esz = self.size_of(etid)
            return None if esz is None else esz * nelems
        return None


# ---- ELF (only what is needed: named section contents) ----------------------
def elf_sections(blob):
    """{name: (file_offset, size, data)} for an ELF64 LE object."""
    if blob[:4] != b"\x7fELF" or blob[4] != 2:
        raise ValueError("not an ELF64 object")
    e_shoff, = struct.unpack_from("<Q", blob, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", blob, 0x3A)
    def sh(i):
        o = e_shoff + i * e_shentsize
        name_off, _type, _flags, _addr, off, size = struct.unpack_from("<IIQQQQ", blob, o)
        return name_off, off, size
    _n, stroff, strsize = sh(e_shstrndx)
    shstr = blob[stroff:stroff + strsize]
    out = {}
    for i in range(e_shnum):
        name_off, off, size = sh(i)
        end = shstr.find(b"\0", name_off)
        name = shstr[name_off:end if end >= 0 else None].decode()
        out[name] = (off, size, blob[off:off + size])
    return out


# ---- .BTF.ext CO-RE relocation records --------------------------------------
CORE_RELO_FIELD_BYTE_OFFSET = 0

def core_relos(ext, local_btf):
    """[(prog_section, insn_off, local_type_name, access_spec, kind)]"""
    if len(ext) < 24:
        return []
    magic, ver, flags, hdr_len = struct.unpack_from("<HBBI", ext, 0)
    if magic != BTF_MAGIC:
        raise ValueError("bad .BTF.ext magic %#x" % magic)
    if hdr_len < 32:
        return []                       # no core_relo section in this version
    core_off, core_len = struct.unpack_from("<II", ext, 24)
    if core_len == 0:
        return []
    base = hdr_len + core_off
    rec_size, = struct.unpack_from("<I", ext, base)
    p, end, out = base + 4, base + core_len, []
    while p + 8 <= end:
        sec_name_off, num_info = struct.unpack_from("<II", ext, p)
        p += 8
        sec = local_btf.s(sec_name_off)
        for _ in range(num_info):
            if p + rec_size > end:
                break
            insn_off, type_id, access_off, kind = struct.unpack_from("<IIII", ext, p)
            out.append((sec, insn_off, type_id, local_btf.s(access_off), kind))
            p += rec_size
    return out


# ---- resolve one relocation against the target BTF --------------------------
# THE RULE, and getting it wrong was this file's first defect. CO-RE matches a
# field by NAME, not by member index. The access spec's indices address the
# PROGRAM'S OWN stub declaration; each one must be turned into that stub member's
# name, and the name looked up in the target. Walking the target's indices
# instead reads whatever field happens to sit in that slot --- which produced 7
# confident "MISMATCH" lines against a C relocator that was right every time.
# Two of the stubs here declare {state, version_num} and one declares
# {state, flags, version_num}, so index 1 legitimately means different fields in
# different programs. Index-based resolution cannot be right for both.

def _member_by_name(btf, st, want):
    """Find member `want` in struct/union `st`, descending through ANONYMOUS
    members (CO-RE flattens them). Returns (bit_offset, type_id, bitfield_size)
    or None."""
    for mname, mtid, mbit, mbfsz in btf.members(st):
        if mname == want:
            return mbit, mtid, mbfsz
        if mname == "":
            sub = btf.strip(mtid)
            if sub is not None and sub["kind"] in (K_STRUCT, K_UNION):
                deeper = _member_by_name(btf, sub, want)
                if deeper is not None:
                    return mbit + deeper[0], deeper[1], deeper[2]
    return None


def resolve(target, local, local_type_id, access_spec):
    """Independently compute the byte offset a FIELD_BYTE_OFFSET relo should get.

    Returns (byte_offset, hazards[])."""
    hazards = []
    lt = local.strip(local_type_id)
    if lt is None or not lt["name"]:
        return None, ["local type id %d has no name to match on" % local_type_id]
    tt = target.find_struct(lt["name"])
    if tt is None:
        return None, ["struct %r is absent from the target BTF" % lt["name"]]

    parts = [int(x) for x in access_spec.split(":") if x != ""]
    if not parts:
        return None, ["empty access spec"]
    if parts[0] != 0:
        # an array index on the type itself; only 0 is produced by our programs
        esz = target.size_of(tt["id"])
        if esz is None:
            return None, ["leading array index %d on a type of unknown size" % parts[0]]
        hazards.append("leading array index %d (stride %d)" % (parts[0], esz))

    bit = 0
    if parts[0]:
        bit += parts[0] * target.size_of(tt["id"]) * 8
    cur_local, cur_target = lt, tt
    path = [lt["name"]]

    for idx in parts[1:]:
        # an index into an ARRAY is a subscript, not a member number
        if cur_target is not None and cur_target["kind"] == K_ARRAY:
            etid = struct.unpack_from("<I", target.types_blob,
                                      cur_target["_data_off"])[0]
            esz = target.size_of(etid)
            if esz is None:
                return None, hazards + ["array element of unknown size"]
            bit += idx * esz * 8
            path.append("[%d]" % idx)
            cur_target = target.strip(etid)
            cur_local = local.strip(struct.unpack_from(
                "<I", local.types_blob, cur_local["_data_off"])[0]) \
                if cur_local is not None and cur_local["kind"] == K_ARRAY else cur_local
            continue

        if cur_local is None or cur_local["kind"] not in (K_STRUCT, K_UNION):
            return None, hazards + ["access spec walks into a non-struct locally"]
        lms = local.members(cur_local)
        if idx >= len(lms):
            return None, hazards + ["local member index %d out of range in %r (%d)"
                                    % (idx, cur_local["name"], len(lms))]
        lname, ltid, _lbit, _lbf = lms[idx]
        if not lname:
            return None, hazards + ["local member %d is anonymous --- not modelled" % idx]

        if cur_target is None or cur_target["kind"] not in (K_STRUCT, K_UNION):
            return None, hazards + ["target side is not a struct at %r" % ".".join(path)]
        hit = _member_by_name(target, cur_target, lname)
        if hit is None:
            return None, hazards + ["field %r is absent from target struct %r"
                                    % (lname, cur_target["name"] or "<anon>")]
        mbit, mtid, mbfsz = hit
        bit += mbit
        path.append(lname)

        if mbfsz:
            # THE HAZARD. ls_core_relo.c refuses a sub-byte BIT OFFSET but does not
            # look at the WIDTH, so a bitfield starting on a byte boundary is read as
            # a plain scalar. That is only correct if the width is a whole number of
            # bytes; otherwise the read picks up neighbouring bits and is silently
            # wrong. gen_type_catalog.py shipped exactly this defect.
            if mbit % 8:
                hazards.append("%s is a bitfield at bit %d --- NOT byte aligned"
                               % (".".join(path), mbit))
            elif mbfsz % 8:
                hazards.append("%s is a %d-bit bitfield --- byte aligned but not a "
                               "whole number of bytes; a scalar read is WRONG"
                               % (".".join(path), mbfsz))
            else:
                hazards.append("%s is a %d-bit bitfield on a byte boundary --- safe, "
                               "but only by alignment" % (".".join(path), mbfsz))

        cur_target = target.strip(mtid)
        cur_local = local.strip(ltid)

    if bit % 8:
        return None, hazards + ["resolved bit offset %d is not byte aligned" % bit]
    return bit // 8, hazards


# ---- what the C relocator actually wrote ------------------------------------
def baked_immediates(obj_blob, relos):
    """{(prog_section, insn_off): imm} read out of a relocated object.

    An eBPF instruction is 8 bytes and its 32-bit immediate is the last 4,
    little-endian. insn_off in a core_relo record is a BYTE offset into the
    program section."""
    secs = elf_sections(obj_blob)
    out = {}
    for sec, insn_off, _tid, _acc, _kind in relos:
        if sec not in secs:
            out[(sec, insn_off)] = None
            continue
        _off, size, data = secs[sec]
        if insn_off + 8 > size:
            out[(sec, insn_off)] = None
            continue
        out[(sec, insn_off)] = struct.unpack_from("<i", data, insn_off + 4)[0]
    return out


def build_relo(substrate_dir):
    """Build the offline relocator from ls_core_relo.c. Returns a path or None."""
    src = os.path.join(substrate_dir, "ls_core_relo.c")
    if not os.path.exists(src):
        return None
    out = os.path.join(tempfile.mkdtemp(prefix="relo."), "relo")
    for cc in ("cc", "gcc", "clang"):
        try:
            r = subprocess.run([cc, "-O2", "-w", "-DLS_CORE_RELO_TEST", src, "-o", out],
                               capture_output=True)
            if r.returncode == 0:
                return out
        except FileNotFoundError:
            continue
    return None


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    relo_path = None
    for i, a in enumerate(argv):
        if a == "--relo" and i + 1 < len(argv):
            relo_path = argv[i + 1]
            args = [x for x in args if x != relo_path]
    if len(args) < 2:
        sys.exit(__doc__)

    btf_path, objs = args[0], args[1:]
    here = os.path.dirname(os.path.abspath(__file__))

    if relo_path is None:
        relo_path = build_relo(here)
    if relo_path is None or not os.path.exists(relo_path):
        sys.exit("*** no offline relocator. Build it:\n"
                 "      cc -O2 -DLS_CORE_RELO_TEST ls_core_relo.c -o relo\n"
                 "    and pass --relo <path>.")

    target = Btf(open(btf_path, "rb").read())
    print("target BTF : %s (%d types, %d bytes)"
          % (btf_path, len(target.by_id) - 1, os.path.getsize(btf_path)))
    print("relocator  : %s" % relo_path)
    print()

    n_checked = n_agree = n_mismatch = n_unresolved = 0
    nondeterministic = []
    hazard_rows = []
    prog_rows = []

    for obj in objs:
        name = os.path.basename(obj)
        blob = open(obj, "rb").read()
        try:
            secs = elf_sections(blob)
        except ValueError as e:
            print("  %-26s SKIP --- %s" % (name, e))
            continue
        if ".BTF" not in secs or ".BTF.ext" not in secs:
            prog_rows.append((name, 0, 0, 0, "no .BTF/.BTF.ext --- nothing to relocate"))
            continue

        local = Btf(secs[".BTF"][2])
        try:
            relos = core_relos(secs[".BTF.ext"][2], local)
        except ValueError as e:
            prog_rows.append((name, 0, 0, 0, "bad .BTF.ext: %s" % e))
            continue
        field_relos = [r for r in relos if r[4] == CORE_RELO_FIELD_BYTE_OFFSET]
        if not field_relos:
            prog_rows.append((name, 0, 0, 0, "0 field relocations"))
            continue

        # run the C relocator into a temp file
        td = tempfile.mkdtemp(prefix="relobake.")
        src, dst = os.path.join(td, name), os.path.join(td, "out.o")
        open(src, "wb").write(blob)
        r = subprocess.run([relo_path, src, btf_path, dst], capture_output=True, text=True)
        if r.returncode != 0 or not os.path.exists(dst):
            prog_rows.append((name, len(field_relos), 0, 0,
                              "relocator REFUSED (rc=%d): %s"
                              % (r.returncode, (r.stderr or "").strip().splitlines()[-1:] or "")))
            continue

        # DETERMINISM (P9 falsifier). A relocator that is not reproducible cannot be
        # signed for: the artifact the signature covers would differ run to run.
        dst2 = os.path.join(td, "out2.o")
        subprocess.run([relo_path, src, btf_path, dst2], capture_output=True)
        import hashlib
        h1 = hashlib.sha256(open(dst, "rb").read()).hexdigest()
        h2 = hashlib.sha256(open(dst2, "rb").read()).hexdigest() \
             if os.path.exists(dst2) else "<second run produced nothing>"
        if h1 != h2:
            nondeterministic.append((name, h1[:12], h2[:12]))

        baked = baked_immediates(open(dst, "rb").read(), field_relos)
        agree = mismatch = unresolved = 0
        for sec, insn_off, tid, acc, _kind in field_relos:
            n_checked += 1
            want, hazards = resolve(target, local, tid, acc)
            got = baked.get((sec, insn_off))
            lt = local.strip(tid)
            label = "%s.%s" % (lt["name"] if lt else "?", acc)
            for h in hazards:
                hazard_rows.append((name, label, h))
            if want is None:
                unresolved += 1
                n_unresolved += 1
                print("  %-26s UNRESOLVED %-28s python could not resolve" % (name, label))
            elif got is None:
                unresolved += 1
                n_unresolved += 1
                print("  %-26s NO-IMM     %-28s insn_off %d not in section %r"
                      % (name, label, insn_off, sec))
            elif want == got:
                agree += 1
                n_agree += 1
            else:
                mismatch += 1
                n_mismatch += 1
                print("  %-26s MISMATCH   %-28s python=%d  C=%d"
                      % (name, label, want, got))
        prog_rows.append((name, len(field_relos), agree, mismatch, ""))

    print("=== per program ===")
    print("  %-26s %5s %6s %5s  %s" % ("program", "relos", "agree", "diff", "note"))
    for name, nrel, agree, mismatch, note in prog_rows:
        print("  %-26s %5d %6d %5d  %s" % (name, nrel, agree, mismatch, note))

    if hazard_rows:
        print()
        print("=== bitfield screen --- every relocated field that is a bitfield ===")
        for name, label, h in hazard_rows:
            print("  %-26s %-28s %s" % (name, label, h))

    print()
    if nondeterministic:
        print()
        print("=== NOT REPRODUCIBLE --- two runs, two different objects ===")
        for name, a, b in nondeterministic:
            print("  %-26s %s != %s" % (name, a, b))

    print("=== result ===")
    print("  relocations checked : %d" % n_checked)
    print("  agree               : %d" % n_agree)
    print("  MISMATCH            : %d" % n_mismatch)
    print("  unresolved          : %d" % n_unresolved)
    print("  non-reproducible    : %d" % len(nondeterministic))
    fatal = [h for h in hazard_rows if "WRONG" in h[2] or "NOT byte aligned" in h[2]]
    print("  fatal hazards       : %d" % len(fatal))
    if n_mismatch or n_unresolved or fatal or nondeterministic:
        print()
        print("  *** NOT clean. Sign-time baking is not yet shown correct; the embedded")
        print("      .BTF must stay until this passes (02-RESEARCH-PARAMETERS.md P9).")
        return 1
    print()
    print("  Two independent implementations agree on every relocation, and no")
    print("  relocated field is a bitfield that a scalar read would get wrong.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
