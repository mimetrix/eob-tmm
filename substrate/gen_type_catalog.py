#!/usr/bin/env python3
"""gen_type_catalog.py --- struct-field catalog from a build's BTF, for tmmtrace.

tmmtrace resolves `args.<field>` by (1) the hook's parameter types, from
signatures.tsv, and (2) each struct's scalar fields, from THIS catalog. Both are
per-build artifacts; this produces the second from the baked BTF.

    gen_type_catalog.py <tmm.btf> [out.json]     default out: types.json

Output: { "<struct>": { "<field>": "u8"|"u16"|"u32"|"u64", ... }, ... }
Only SCALAR/POINTER fields are kept --- those are what a probe reads and returns.
Struct/union/array fields are skipped (a nested read is a future path form).

Parses `bpftool btf dump ... format raw` rather than `format c`: the raw form
lists each struct's members flatly with type ids, so nested/anonymous members do
not confuse a brace-counting parser (they did --- the first cut lost every field
after the first anonymous union). Member type ids are resolved through
typedef/const/volatile to the underlying INT/PTR/ENUM to get a byte size.

NOTE: bitfield members are not yet emitted (e.g. connflow.mss) --- a known gap.
"""
import json
import re
import subprocess
import sys


def build(btf):
    raw = subprocess.run(["bpftool", "btf", "dump", "file", btf, "format", "raw"],
                         capture_output=True, text=True).stdout
    types = {}
    cur = None
    hdr = re.compile(r"^\[(\d+)\]\s+(\w+)\s+'([^']*)'(.*)$")
    anon = re.compile(r"^\[(\d+)\]\s+(\w+)\s+\(anon\)(.*)$")
    mem = re.compile(r"^\s+'([^']+)'\s+type_id=(\d+)")
    for ln in raw.splitlines():
        m = hdr.match(ln)
        a = None if m else anon.match(ln)
        if m or a:
            g = m or a
            tid = int(g.group(1))
            kind = g.group(2)
            name = m.group(3) if m else ""
            rest = m.group(4) if m else a.group(3)
            d = {"kind": kind, "name": name, "members": []}
            sm = re.search(r"size=(\d+)", rest)
            d["size"] = int(sm.group(1)) if sm else None
            rm = re.search(r"type_id=(\d+)", rest)
            d["ref"] = int(rm.group(1)) if rm else None
            types[tid] = d
            cur = tid
            continue
        mm = mem.match(ln)
        if mm and cur is not None and types[cur]["kind"] in ("STRUCT", "UNION"):
            types[cur]["members"].append((mm.group(1), int(mm.group(2))))

    def size_of(tid, depth=0):
        if tid is None or depth > 12:
            return 0
        t = types.get(tid)
        if not t:
            return 0
        k = t["kind"]
        if k == "PTR":
            return 8
        if k in ("INT", "ENUM", "ENUM64", "FLOAT"):
            return t["size"] or 0
        if k in ("TYPEDEF", "CONST", "VOLATILE", "RESTRICT", "TYPE_TAG"):
            return size_of(t["ref"], depth + 1)
        return 0

    W = {1: "u8", 2: "u16", 4: "u32", 8: "u64"}
    cat = {}
    for t in types.values():
        if t["kind"] != "STRUCT" or not t["name"]:
            continue
        fields = {}
        for fname, ftid in t["members"]:
            s = size_of(ftid)
            if s in W:
                fields[fname] = W[s]
        # keep the richest definition when a struct name repeats (fwd decls, dups)
        if fields and (t["name"] not in cat or len(fields) > len(cat[t["name"]])):
            cat[t["name"]] = fields
    return cat


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    cat = build(argv[1])
    out = argv[2] if len(argv) > 2 else "types.json"
    json.dump(cat, open(out, "w"))
    print("wrote %s: %d structs" % (out, len(cat)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
