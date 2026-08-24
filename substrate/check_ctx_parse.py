#!/usr/bin/env python3
"""check_ctx_parse.py --- verify ls_ctx_parse.h's byte offsets against the build's debug info.

WHY THIS EXISTS. ls_ctx_parse.h reaches into two TMM structs by hard-coded byte offset, because
the structs live in a source-tree header the substrate cannot include. Its own banner stated the
cost --- "here it is silent if wrong" --- and pointed at a checking function that DID NOT EXIST
for months. This is that check, built after the gap was found by trying to answer whether the
demonstrated CVE mitigation would hold for a real one. See CONTESTED-PREMISES.md 12.

WHAT IT COMPARES. The #defines in ls_ctx_parse.h against DW_AT_data_member_location and
DW_AT_byte_size read out of the shipped debuginfo. Nothing is asserted by a human here.

WHAT IT CANNOT DO, STATED. The header describes its fields ("UINT16", "BYTE") but not TMM's
member NAMES, which are not knowable from this repository. So each offset carries a list of
candidate names; a member that matches none is reported UNVERIFIED and is NOT counted as passing.
--strict makes any UNVERIFIED a failure, which is the setting the bake should use once someone
with the debuginfo has filled the real names in.

  check_ctx_parse.py --debuginfo tmm64.no_pgo.debug
  check_ctx_parse.py --debuginfo tmm64.no_pgo.debug --emit-bounds --strict
"""
import argparse, os, re, shutil, subprocess, sys

HERE   = os.path.dirname(os.path.abspath(__file__))
HEADER = os.path.join(HERE, "ls_ctx_parse.h")
BOUNDS = os.path.join(HERE, "ls_ctx_parse_bounds.h")

# define -> (struct, candidate member names). Candidates, not a name: see the banner.
FIELDS = {
    "LS_OFF_PC_STATE":    ("http_parse_ctx",  ["state", "parse_state", "st"]),
    "LS_OFF_PC_OFFSET":   ("http_parse_ctx",  ["offset", "off", "parse_offset"]),
    "LS_OFF_PI_METHOD":   ("http_parse_info", ["method"]),
    "LS_OFF_PI_HDRCOUNT": ("http_parse_info", ["header_count", "hdr_count", "num_headers",
                                               "header_cnt", "nheaders"]),
    "LS_OFF_PI_STATUS":   ("http_parse_info", ["status", "status_code"]),
    "LS_OFF_PI_INVALID":  ("http_parse_info", ["invalid", "invalid_flags", "f_invalid"]),
}
SIZES = {"http_parse_ctx": 64, "http_parse_info": 416}   # from the header's own comments
STATE_ENUM = "parse_state"


def declared():
    """The #define values the substrate actually compiles with."""
    out = {}
    for m in re.finditer(r"^#define\s+(LS_OFF_\w+)\s+(\d+)", open(HEADER).read(), re.M):
        out[m.group(1)] = int(m.group(2))
    return out


def dwarf(debuginfo):
    """{struct: (size, {member: offset})} and {enum: max_value}, via llvm-dwarfdump or gdb."""
    tool = shutil.which("llvm-dwarfdump") or shutil.which("llvm-dwarfdump-14")
    if not tool:
        # gdb is what mk_ctx.py uses and what the build box has.
        if not shutil.which("gdb"):
            sys.exit("*** neither llvm-dwarfdump nor gdb is available; cannot read debug info")
        return dwarf_gdb(debuginfo)
    txt = subprocess.run([tool, "--debug-info", debuginfo],
                         capture_output=True, text=True).stdout
    structs, enums = {}, {}
    cur_s = cur_e = None
    depth_s = depth_e = -1
    for line in txt.splitlines():
        m = re.match(r"^(0x[0-9a-f]+:)?(\s*)(DW_TAG_\w+)", line)
        if m:
            d, tag = len(m.group(2)), m.group(3)
            if cur_s is not None and d <= depth_s and tag != "DW_TAG_member": cur_s = None
            if cur_e is not None and d <= depth_e and tag != "DW_TAG_enumerator": cur_e = None
            if tag == "DW_TAG_structure_type": pend_s, depth_s = True, d; pend_e = False
            elif tag == "DW_TAG_enumeration_type": pend_e, depth_e = True, d; pend_s = False
            else: pend_s = pend_e = False
            last_tag, last_pend_s, last_pend_e = tag, pend_s, pend_e
            continue
        nm = re.search(r'DW_AT_name\s+\("([^"]+)"\)', line)
        if nm:
            if last_pend_s and nm.group(1) in SIZES:
                cur_s = nm.group(1); structs.setdefault(cur_s, [None, {}])
            elif last_pend_e and nm.group(1) == STATE_ENUM:
                cur_e = nm.group(1); enums.setdefault(cur_e, -1)
            elif last_tag == "DW_TAG_member" and cur_s:
                pending_member = nm.group(1); globals()["_pm"] = pending_member
            elif last_tag == "DW_TAG_enumerator" and cur_e:
                globals()["_pe"] = nm.group(1)
        bs = re.search(r"DW_AT_byte_size\s+\((0x[0-9a-f]+|\d+)\)", line)
        if bs and cur_s and structs[cur_s][0] is None:
            structs[cur_s][0] = int(bs.group(1), 0)
        ml = re.search(r"DW_AT_data_member_location\s+\((0x[0-9a-f]+|\d+)\)", line)
        if ml and cur_s and globals().get("_pm"):
            structs[cur_s][1][globals()["_pm"]] = int(ml.group(1), 0); globals()["_pm"] = None
        # HEX OR DECIMAL. llvm-dwarfdump prints enumerator values as 0x00; the first version
        # of this regex accepted only decimal, so every enumerator silently failed to match and
        # the enum came back "not found" --- a checker reporting UNVERIFIED for a reason that was
        # its own bug. Caught by the fixture below, which is why the fixture exists.
        cv = re.search(r"DW_AT_const_value\s+\((0x[0-9a-fA-F]+|-?\d+)\)", line)
        if cv and cur_e:
            enums[cur_e] = max(enums[cur_e], int(cv.group(1), 0))
    return {k: (v[0], v[1]) for k, v in structs.items()}, enums


def dwarf_gdb(debuginfo):
    structs, enums = {}, {}
    for st in SIZES:
        out = subprocess.run(["gdb", "-q", "-batch", "-ex", "ptype /o struct %s" % st, debuginfo],
                             capture_output=True, text=True).stdout
        members, size = {}, None
        for line in out.splitlines():
            m = re.match(r"^/\*\s*(\d+)\s*(?:\|\s*\d+)?\s*\*/\s+.*?\b(\w+);", line)
            if m: members[m.group(2)] = int(m.group(1))
            z = re.search(r"total size \(bytes\):\s*(\d+)", line)
            if z: size = int(z.group(1))
        structs[st] = (size, members)
    out = subprocess.run(["gdb", "-q", "-batch", "-ex", "ptype enum %s" % STATE_ENUM, debuginfo],
                         capture_output=True, text=True).stdout
    vals = [int(v) for v in re.findall(r"=\s*(-?\d+)", out)]
    enums[STATE_ENUM] = max(vals) if vals else -1
    return structs, enums


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--debuginfo")
    ap.add_argument("--emit-bounds", action="store_true")
    ap.add_argument("--strict", action="store_true")
    a = ap.parse_args()

    dec = declared()
    if not a.debuginfo:
        print("  no --debuginfo given: %d offsets declared, 0 verified." % len(dec))
        print("  Nothing here is checked without the build's debug info --- saying so is the point.")
        return 1 if a.strict else 0

    structs, enums = dwarf(a.debuginfo)
    bad = unver = ok = 0

    for st, want in SIZES.items():
        got = structs.get(st, (None, {}))[0]
        if got is None:
            print("  UNVERIFIED  sizeof(struct %-16s) --- not found in this debug info" % st); unver += 1
        elif got != want:
            print("  MISMATCH    sizeof(struct %-16s) header says %d, build says %d" % (st, want, got)); bad += 1
        else:
            print("  ok          sizeof(struct %-16s) = %d" % (st, got)); ok += 1

    for d, (st, cands) in sorted(FIELDS.items()):
        members = structs.get(st, (None, {}))[1]
        hit = next((c for c in cands if c in members), None)
        if hit is None:
            print("  UNVERIFIED  %-20s no member of struct %s matched %s" % (d, st, cands)); unver += 1
        elif members[hit] != dec.get(d):
            print("  MISMATCH    %-20s header says %s, build says %s->%d"
                  % (d, dec.get(d), hit, members[hit])); bad += 1
        else:
            print("  ok          %-20s = %d (%s.%s)" % (d, members[hit], st, hit)); ok += 1

    smax = enums.get(STATE_ENUM, -1)
    if smax < 0:
        print("  UNVERIFIED  enum %s not found --- tier 2 cannot be armed" % STATE_ENUM); unver += 1
    else:
        print("  ok          enum %s greatest enumerator = %d" % (STATE_ENUM, smax))
        if a.emit_bounds:
            open(BOUNDS, "w").write(
                "/* GENERATED by check_ctx_parse.py from %s --- do not edit.\n"
                " * Arms tier 2 of ls_ctx_parse_sane. Regenerate per build: these bounds are as\n"
                " * build-specific as the offsets they guard. */\n"
                "#ifndef LS_CTX_PARSE_BOUNDS_H\n#define LS_CTX_PARSE_BOUNDS_H\n"
                "#define LS_PARSE_STATE_MAX %du\n"
                "#endif\n" % (os.path.basename(a.debuginfo), smax))
            print("  wrote %s (tier 2 armed)" % os.path.basename(BOUNDS))

    print("  --- %d ok, %d MISMATCH, %d UNVERIFIED ---" % (ok, bad, unver))
    if bad:
        print("  A MISMATCH means the substrate is reading the wrong bytes out of a live TMM.")
        return 2
    if unver and a.strict:
        print("  --strict: an UNVERIFIED offset has not passed. It is unchecked, which is what")
        print("  this file exists to stop being confused with checked.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
