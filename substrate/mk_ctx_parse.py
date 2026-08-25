#!/usr/bin/env python3
"""mk_ctx_parse.py --- derive every number ls_ctx_parse.h needs from a build artifact.

THE RULE THIS ENFORCES: nothing numeric about TMM's layout is typed by a human. Field NAMES are
specification --- which of TMM's fields the program is allowed to see is a design choice --- but
every offset, width, shift, mask, size and bound is read out of the build.

WHY. ls_ctx_parse.h carried hand-written offsets under a banner reading "GENERATED for build
1778975c". By 2026-08-25 the debug tree was e35ed0ed and the cluster was running 499b8c30: three
builds, one frozen set of literals. They still matched, which is luck rather than design, and
nothing in the tree would have said otherwise. See CONTESTED-PREMISES.md 12.

TWO TRAPS, both of which produce a plausible wrong number:

  BITFIELDS. `&((struct http_parse_ctx *)0)->state` returns 8 for a field that lives at byte 10,
  because taking the address of a bitfield yields its 4-byte storage unit. Only `ptype /o` (or
  DW_AT_data_bit_offset) gives the real byte. A generator using offsetof alone emits 8 and the
  substrate then reads max_header_count as if it were the parser state.

  INCOMPLETE MEMBERS. `ptype /o struct http_parse_info` prints NO offset column at all, because
  it ends in a struct whose definition that unit does not carry. So offsets there come from
  offsetof, and bit positions from summing the declared widths --- still derived, never typed.

usage:
  mk_ctx_parse.py --debuginfo tmm.debug -o ls_ctx_parse_offsets.h
"""
import argparse, os, re, shutil, subprocess, sys

# WHAT the program may see. Names are specification; every number about them is derived.
#   role: "byte"    -> emit the field's byte offset
#         "bits"    -> emit byte offset of the unit, plus shift+mask of the named bitfield
#         "maskof"  -> emit a mask covering the run of bitfields sharing this prefix
CTX = "http_parse_ctx"
INFO = "http_parse_info"
WANT = [
    ("LS_OFF_PC_STATE",  CTX,  "state",        "byte"),
    ("LS_OFF_PC_OFFSET", CTX,  "offset",       "byte"),
    ("LS_OFF_PI_BITS0",  INFO, "is_trailer",   "byte"),
    ("LS_OFF_PI_METHOD", INFO, "method",       "byte"),
    ("LS_OFF_PI_HDRCOUNT", INFO, "header_count", "byte"),
    ("LS_OFF_PI_STATUS", INFO, "status_code",  "byte"),
    ("LS_OFF_PI_INVALID", INFO, "f_invalid_",  "maskof"),
    ("LS_PI_VERSION",    INFO, "version",      "bits"),
]
STATE_ENUM = "parse_state"


def sh(*a):
    return subprocess.run(a, capture_output=True, text=True).stdout


class Gdb:
    """The build box has gdb; mk_ctx.py already depends on it, so this is not a new tool."""
    def __init__(self, f): self.f = f
    def _p(self, expr):
        out = sh("gdb", "-q", "-batch", "-ex", "print %s" % expr, self.f)
        m = re.search(r"=\s*(-?\d+)", out)
        return int(m.group(1)) if m else None
    def sizeof(self, st): return self._p("sizeof(struct %s)" % st)
    def offsetof(self, st, f): return self._p("(long)&((struct %s *)0)->%s" % (st, f))
    def layout(self, st):
        """{field: (byte, bitpos_or_None, width_or_None)} for as much as gdb will lay out."""
        out, res = sh("gdb", "-q", "-batch", "-ex", "ptype /o struct %s" % st, self.f), {}
        for line in out.splitlines():
            m = re.match(r"\s*/\*\s*(\d+)(?::\s*(\d+))?\s*\|\s*\d+\s*\*/\s+.*?\b(\w+)\s*(?::\s*(\d+))?;", line)
            if m:
                res[m.group(3)] = (int(m.group(1)),
                                   int(m.group(2)) if m.group(2) is not None else None,
                                   int(m.group(4)) if m.group(4) is not None else None)
        return res
    def decls(self, st):
        """[(field, width_or_None)] in declaration order, from plain ptype (always available)."""
        out, res = sh("gdb", "-q", "-batch", "-ex", "ptype struct %s" % st, self.f), []
        for line in out.splitlines():
            m = re.match(r"\s+.*?\b(\w+)\s*(?::\s*(\d+))?\s*;\s*$", line)
            if m:
                res.append((m.group(1), int(m.group(2)) if m.group(2) else None))
        return res
    def enum_max(self, en):
        out = sh("gdb", "-q", "-batch", "-ex", "ptype enum %s" % en, self.f)
        names = re.findall(r"\b([A-Za-z_]\w*)\b", out.split("{", 1)[-1]) if "{" in out else []
        vals = [self._p("(int)%s" % n) for n in names]
        vals = [v for v in vals if v is not None]
        return max(vals) if vals else None


def _num(v):
    """Last integer in a readelf attribute value.

    readelf does not print one form. Real TMM DWARF yields all of these:
        DW_AT_const_value        : 0
        DW_AT_const_value        : 1 byte block: 0        <- block form
        DW_AT_data_member_location: 2
    The first version of this parser did int(v, 0) and died on the block form --- on the REAL
    build, after passing cleanly on a fixture. That is the argument for two readers rather than
    one trusted one.
    """
    m = re.findall(r"(0x[0-9a-fA-F]+|-?\d+)", v)
    return int(m[-1], 0) if m else None


class Readelf:
    """PRIMARY reader, because it is the only one present everywhere this runs.

    Surveyed 2026-08-25: the build box has gdb, readelf, objdump, pahole and eu-readelf but NOT
    llvm-dwarfdump; this workstation has llvm-dwarfdump, readelf and objdump but NOT gdb. Only
    readelf and objdump are on both. Preferring gdb -- which the first version of this file
    REQUIRED, and which mk_ctx.py still requires -- builds in a host assumption that is false on
    half the machines involved.

    readelf also states DIE depth explicitly ("<1><b3>:"), so nesting is read rather than
    inferred from indentation.
    """

    def __init__(self, f):
        txt = sh("readelf", "--debug-dump=info", f)
        self.structs, self.enums = {}, {}
        owner, owner_depth, kind, cur = None, -1, None, None
        for line in txt.splitlines():
            m = re.match(r"\s*<(\d+)><[0-9a-f]+>:.*\((DW_TAG_\w+)\)", line)
            if m:
                depth, tag = int(m.group(1)), m.group(2)
                if owner is not None and depth <= owner_depth:
                    owner = None
                cur = {"tag": tag, "depth": depth}
                if tag == "DW_TAG_structure_type":
                    cur["pending"] = "s"
                elif tag == "DW_TAG_enumeration_type":
                    cur["pending"] = "e"
                continue
            if cur is None:
                continue
            a = re.match(r"\s*<[0-9a-f]+>\s+(DW_AT_\w+)\s*:\s*(.*?)\s*$", line)
            if not a:
                continue
            at, raw = a.group(1), a.group(2)
            # names arrive bare or as "(indirect string, offset: 0x..): name"
            val = raw.rsplit("): ", 1)[-1] if raw.startswith("(") else raw
            if at == "DW_AT_name":
                if cur.get("pending") == "s":
                    owner, owner_depth, kind = val, cur["depth"], "s"
                    self.structs.setdefault(owner, {"size": None, "f": {}, "order": []})
                    cur.pop("pending")
                elif cur.get("pending") == "e":
                    owner, owner_depth, kind = val, cur["depth"], "e"
                    self.enums.setdefault(owner, [])
                    cur.pop("pending")
                else:
                    cur["name"] = val
            elif at == "DW_AT_byte_size" and kind == "s" and owner and cur["tag"] == "DW_TAG_structure_type":
                self.structs[owner]["size"] = _num(val)
            elif at == "DW_AT_bit_size":
                cur["bit_size"] = _num(val)
            elif at == "DW_AT_data_bit_offset":
                cur["bitoff"] = _num(val)
            elif at == "DW_AT_data_member_location":
                cur["loc"] = _num(val)
            elif at == "DW_AT_const_value":
                cur["const"] = _num(val)

            if owner and kind == "s" and cur["tag"] == "DW_TAG_member" and "name" in cur:
                st, nm = self.structs[owner], cur["name"]
                if "bitoff" in cur:
                    st["f"][nm] = (cur["bitoff"] // 8, cur["bitoff"] % 8, cur.get("bit_size"))
                elif "loc" in cur:
                    st["f"][nm] = (cur["loc"], None, cur.get("bit_size"))
                if nm in st["f"] and nm not in st["order"]:
                    st["order"].append(nm)
            elif owner and kind == "e" and cur["tag"] == "DW_TAG_enumerator" and "const" in cur:
                if cur["const"] not in self.enums[owner]:
                    self.enums[owner].append(cur["const"])

    def sizeof(self, st):     return self.structs.get(st, {}).get("size")
    def offsetof(self, st, f):
        v = self.structs.get(st, {}).get("f", {}).get(f)
        return v[0] if v else None
    def layout(self, st):     return self.structs.get(st, {}).get("f", {})
    def decls(self, st):
        d = self.structs.get(st, {})
        return [(f, d["f"][f][2]) for f in d.get("order", []) if f in d["f"]]
    def enum_max(self, en):
        v = self.enums.get(en) or []
        return max(v) if v else None


class Dwarfdump:
    """Second reader, for hosts without gdb --- `make check` runs on machines that have neither
    gdb nor TMM's debuginfo, and a test that cannot run is not a test.

    Bitfields are handled correctly: DWARF records DW_AT_data_bit_offset as an ABSOLUTE bit
    offset from the start of the struct, so the true byte is that divided by eight. Same trap the
    gdb path documents --- an address-of yields the 4-byte storage unit, not the field.
    """

    def __init__(self, f):
        dies = self._dies(sh(shutil.which("llvm-dwarfdump"), "--debug-info", f))
        self.structs, self.enums = {}, {}
        owner, owner_depth, kind = None, -1, None
        for depth, tag, at in dies:
            if owner is not None and depth <= owner_depth:
                owner = None
            if tag == "DW_TAG_structure_type" and "name" in at:
                owner, owner_depth, kind = at["name"], depth, "s"
                self.structs.setdefault(owner, {"size": at.get("byte_size"), "f": {}, "order": []})
                if at.get("byte_size") is not None:
                    self.structs[owner]["size"] = at["byte_size"]
            elif tag == "DW_TAG_enumeration_type" and "name" in at:
                owner, owner_depth, kind = at["name"], depth, "e"
                self.enums.setdefault(owner, [])
            elif owner and kind == "s" and tag == "DW_TAG_member" and "name" in at:
                st, nm = self.structs[owner], at["name"]
                if "data_bit_offset" in at:
                    st["f"][nm] = (at["data_bit_offset"] // 8, at["data_bit_offset"] % 8,
                                   at.get("bit_size"))
                else:
                    st["f"][nm] = (at.get("data_member_location", 0), None, at.get("bit_size"))
                st["order"].append(nm)
            elif owner and kind == "e" and tag == "DW_TAG_enumerator" and "const_value" in at:
                self.enums[owner].append(at["const_value"])

    @staticmethod
    def _dies(txt):
        """[(depth, tag, {attr: value})] --- depth is the indentation of the DW_TAG token."""
        out, cur = [], None
        for line in txt.splitlines():
            m = re.match(r"^(?:0x[0-9a-f]+:)?(\s*)(DW_TAG_\w+)\s*$", line)
            if m:
                cur = (len(m.group(1)), m.group(2), {})
                out.append(cur)
                continue
            if cur is None:
                continue
            a = re.match(r'\s*DW_AT_(\w+)\s+\((?:"([^"]*)"|([^)]*))\)\s*$', line)
            if not a:
                continue
            key, sval, nval = a.group(1), a.group(2), a.group(3)
            if sval is not None:
                cur[2][key] = sval
            else:
                v = nval.strip()
                if re.fullmatch(r"0x[0-9a-fA-F]+|-?\d+", v):
                    cur[2][key] = int(v, 0)
        return out

    def sizeof(self, st):
        return self.structs.get(st, {}).get("size")

    def offsetof(self, st, f):
        v = self.structs.get(st, {}).get("f", {}).get(f)
        return v[0] if v else None

    def layout(self, st):
        return self.structs.get(st, {}).get("f", {})

    def decls(self, st):
        d = self.structs.get(st, {})
        return [(f, d["f"][f][2]) for f in d.get("order", []) if f in d["f"]]

    def enum_max(self, en):
        v = self.enums.get(en) or []
        return max(v) if v else None


READERS = [("readelf", "readelf", Readelf),          # on every host involved -- the default
           ("gdb", "gdb", Gdb),                      # build box only
           ("dwarfdump", "llvm-dwarfdump", Dwarfdump)]  # workstation only


def pick(f, forced=None):
    for name, exe, cls in READERS:
        if forced and name != forced:
            continue
        if shutil.which(exe):
            return cls(f), name
    sys.exit("*** no usable DWARF reader (%s)" % ", ".join(e for _, e, _ in READERS))


def cross_check(f):
    """Every reader available here must produce the SAME DERIVED HEADER.

    It must compare the derived values, not the raw primitives: `offsetof` legitimately differs
    between readers for a bitfield --- readelf reports the bit-accurate byte (10) while gdb's
    address-of yields the 4-byte storage unit (8) --- and the generator already knows to use the
    layout map for bitfields. Comparing primitives reported a DISAGREE for two readers that in
    fact emit identical headers. The invariant worth holding is "any reader, same artifact, same
    output", so that is what is checked.
    """
    have = [(n, cls(f)) for n, e, cls in READERS if shutil.which(e)]
    if len(have) < 2:
        print("  cross-check: only %s available here, so nothing to compare against."
              % (have[0][0] if have else "no reader"))
        print("  That is a REAL gap, not a pass --- run it where a second reader exists.")
        return 0
    out = {}
    for n, r in have:
        try:
            out[n] = derive(r)[0]
        except SystemExit as e:
            print("  READER FAILED  %s: %s" % (n, e)); return 1
    ref = out[have[0][0]]
    bad = 0
    for n, vals in list(out.items())[1:]:
        for k in sorted(set(ref) | set(vals)):
            if ref.get(k) != vals.get(k):
                print("  DISAGREE  %-24s %s=%s  %s=%s"
                      % (k, have[0][0], ref.get(k), n, vals.get(k))); bad += 1
    print("  cross-check: %d reader(s) [%s], %d disagreement(s) over %d derived values"
          % (len(have), ", ".join(n for n, _ in have), bad, len(ref)))
    return 1 if bad else 0


def build_id(f):
    out = sh("readelf", "-n", f)
    m = re.search(r"Build ID:\s*([0-9a-f]+)", out)
    return m.group(1) if m else "unknown"


def derive(g):
    """{macro: value}, notes --- every number read out of the artifact, nothing typed."""
    vals, notes = {}, []
    for st in (CTX, INFO):
        z = g.sizeof(st)
        if not z:
            raise SystemExit("could not read sizeof(struct %s)" % st)
        vals["LS_SIZEOF_PARSE_" + ("CTX" if st == CTX else "INFO")] = z

    for name, st, field, role in WANT:
        lay, dec = g.layout(st), g.decls(st)
        if role == "byte":
            if field in lay and lay[field][2] is not None:
                off = lay[field][0]
                nai = g.offsetof(st, field)
                notes.append("%s: bitfield at byte %d%s"
                             % (field, off,
                                " (an address-of would say %s --- the storage unit)" % nai
                                if nai is not None and nai != off else
                                " (reader is bit-accurate; no address-of discrepancy)"))
            elif field in lay:
                off = lay[field][0]
            else:
                off = g.offsetof(st, field)
                if off is None:
                    raise SystemExit("no offset for %s.%s" % (st, field))
                notes.append("%s: struct not laid out (incomplete member); offsetof used" % field)
            vals[name] = off
        elif role == "bits":
            shift, width = 0, None
            for fl, w in dec:
                if fl == field:
                    width = w
                    break
                shift = 0 if w is None else shift + w
            if width is None:
                raise SystemExit("%s.%s is not a bitfield" % (st, field))
            vals[name + "_SHIFT"] = shift
            vals[name + "_MASK"] = (1 << width) - 1
            notes.append("%s: width %d at bit %d of its unit (widths summed, not typed)"
                         % (field, width, shift))
        elif role == "maskof":
            run = [(fl, w) for fl, w in dec if fl.startswith(field) and w is not None]
            if not run:
                raise SystemExit("no bitfields named %s* in struct %s" % (field, st))
            total = sum(w for _, w in run)
            vals[name] = g.offsetof(st, run[0][0])
            vals["LS_INVALID_MASK"] = (1 << total) - 1
            notes.append("%s*: %d field(s), %d bit(s) -> mask 0x%x (counted, not typed)"
                         % (field, len(run), total, (1 << total) - 1))

    smax = g.enum_max(STATE_ENUM)
    if smax is None:
        raise SystemExit("could not read enum %s" % STATE_ENUM)
    vals["LS_PARSE_STATE_MAX"] = smax
    return vals, notes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--debuginfo", required=True)
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--reader", choices=["readelf", "gdb", "dwarfdump"],
                    help="force one reader instead of the portable default")
    ap.add_argument("--cross-check", action="store_true",
                    help="run every available reader and fail if any disagrees")
    a = ap.parse_args()

    if a.cross_check and cross_check(a.debuginfo) != 0:
        return 3

    g, which = pick(a.debuginfo, a.reader)
    try:
        vals, notes = derive(g)
    except SystemExit as e:
        sys.exit("*** %s (reader=%s, artifact=%s)" % (e, which, a.debuginfo))

    bid = build_id(a.debuginfo)
    order = ["LS_OFF_PC_STATE", "LS_OFF_PC_OFFSET", "LS_OFF_PI_BITS0", "LS_OFF_PI_METHOD",
             "LS_OFF_PI_HDRCOUNT", "LS_OFF_PI_STATUS", "LS_OFF_PI_INVALID", "LS_INVALID_MASK",
             "LS_PI_VERSION_SHIFT", "LS_PI_VERSION_MASK", "LS_PARSE_STATE_MAX",
             "LS_SIZEOF_PARSE_CTX", "LS_SIZEOF_PARSE_INFO"]
    HEX = {"LS_INVALID_MASK", "LS_PI_VERSION_MASK"}

    with open(a.out, "w") as fh:
        fh.write("/* GENERATED by mk_ctx_parse.py --- DO NOT EDIT, DO NOT COMMIT.\n"
                 " *\n * source   : %s\n * build id : %s\n * reader   : %s\n"
                 " *\n"
                 " * Every value below was read out of that artifact. It is generated per build\n"
                 " * because the artifacts for any deployed build are always retrievable, so a\n"
                 " * stale number has no excuse to survive a rebuild.\n"
                 " *\n * how each was obtained:\n" % (os.path.basename(a.debuginfo), bid, which))
        for n in notes:
            fh.write(" *   %s\n" % n)
        fh.write(" */\n#ifndef LS_CTX_PARSE_OFFSETS_H\n#define LS_CTX_PARSE_OFFSETS_H\n")
        fh.write('#define LS_CTX_PARSE_BUILD_ID "%s"\n' % bid)
        for k in order:
            if k in vals:
                fh.write("#define %-24s %s\n"
                         % (k, ("0x%xu" % vals[k]) if k in HEX else ("%du" % vals[k])))
        fh.write("#endif\n")

    print("  wrote %s from build %s (via %s)" % (a.out, bid[:12], which))
    for n in notes:
        print("    %s" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
