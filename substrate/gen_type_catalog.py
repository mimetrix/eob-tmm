#!/usr/bin/env python3
"""gen_type_catalog.py --- struct-field catalog from a build's BTF, for tmmtrace.

tmmtrace resolves `args.<field>` by (1) the hook's parameter types, from
signatures.tsv, and (2) each struct's scalar fields, from THIS catalog. Both are
per-build artifacts; this produces the second from the baked BTF.

    gen_type_catalog.py <tmm.btf> [out.json]     default out: types.json

Output: { "<struct>": { "<field>": "u8"|"u16"|"u32"|"u64", ... }, ...,
           "__ptr_targets__": {...}, "__bitfields__": {...} }
Only SCALAR/POINTER fields are kept --- those are what a probe reads and returns.
Struct/union/array fields are skipped (a nested read is a future path form).

Parses `bpftool btf dump ... format raw` rather than `format c`: the raw form
lists each struct's members flatly with type ids, so nested/anonymous members do
not confuse a brace-counting parser (they did --- the first cut lost every field
after the first anonymous union). Member type ids are resolved through
typedef/const/volatile to the underlying INT/PTR/ENUM to get a byte size.

BITFIELDS --- read this before trusting a field width. The note that used to sit here
said bitfield members "are not yet emitted (e.g. connflow.mss) --- a known gap." That was
wrong, and wrong in the direction that costs the most: measured against this build's BTF,
1,050 bitfields were absent but **15,583 were emitted as plain scalars**. A consumer reading
`http_parse_info.is_trailer` as the "u32" this file advertised got the whole 32-bit word with
~17 packed flags in it, not the one bit. `ls_core_relo.c` cannot catch it either: it refuses a
sub-byte offset (`bit_off % 8`), so a bitfield at bit 1+ fails loudly, while one at **bit 0
succeeds silently with a wrong-width read**. For an enforce-mode shield that is a missed
mitigation or an outage, decided by which flags happen to share the word.

So bitfields are now (a) REMOVED from the flat scalar map, so no consumer can read one by
accident and the failure is a loud "no scalar 'x'", and (b) described under the reserved key
`__bitfields__` as {struct: {field: {unit, byte, shift, width}}} for a consumer that handles
them properly. Emitting them there is NOT the same as supporting them: a correct read also
needs `ls_core_relo.c` to carry clang's bitfield relocation kinds (byte size + left/right
shift). Until it does, the metadata here is build-pinned, and a program built on it is valid
for THIS build only.
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
    # bitfield members carry two extra keys; capture them so a bitfield can be told apart
    # from a scalar of the same declared type (it cannot be, from type_id alone).
    mem = re.compile(r"^\s+'([^']+)'\s+type_id=(\d+)"
                     r"(?:\s+bits_offset=(\d+))?(?:\s+bitfield_size=(\d+))?")
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
            boff = int(mm.group(3)) if mm.group(3) else 0
            bsz = int(mm.group(4)) if mm.group(4) else 0   # 0 == not a bitfield
            types[cur]["members"].append((mm.group(1), int(mm.group(2)), boff, bsz))

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

    def ptr_target(tid, depth=0):
        """For a PTR field, the STRUCT it points at --- the edge a multi-hop path walks.

        Without this the catalog knows `sc->sp` is 8 bytes but not that it is a
        `struct ssl_pcb *`, so a predicate on `args.sp.hs.<field>` cannot be resolved and
        the precondition of most real CVEs (several hops into connection state) is out of
        reach. Peels typedef/const/volatile on both sides of the pointer.
        """
        if tid is None or depth > 12:
            return None
        t = types.get(tid)
        if not t:
            return None
        if t["kind"] in ("TYPEDEF", "CONST", "VOLATILE", "RESTRICT", "TYPE_TAG"):
            return ptr_target(t["ref"], depth + 1)
        if t["kind"] != "PTR":
            return None
        # the pointee, peeled
        pt, d = types.get(t["ref"]), 0
        while pt is not None and pt["kind"] in ("TYPEDEF", "CONST", "VOLATILE", "RESTRICT",
                                               "TYPE_TAG") and d < 12:
            pt, d = types.get(pt["ref"]), d + 1
        if pt is not None and pt["kind"] == "STRUCT" and pt["name"]:
            return pt["name"]
        return None

    W = {1: "u8", 2: "u16", 4: "u32", 8: "u64"}
    cat = {}
    ptrs = {}
    bits = {}
    for t in types.values():
        if t["kind"] != "STRUCT" or not t["name"]:
            continue
        fields, edges, bfs = {}, {}, {}
        for fname, ftid, boff, bsz in t["members"]:
            s = size_of(ftid)
            if bsz:
                # A bitfield. Describe it, but keep it OUT of `fields` --- see the module
                # docstring: emitting it there is what made 15,583 reads silently wrong.
                # unit = the declared type's storage unit; byte = that unit's offset;
                # shift = the field's offset WITHIN the unit (little-endian).
                if s in W:
                    unit_bits = s * 8
                    byte = (boff // unit_bits) * s
                    bfs[fname] = {"unit": W[s], "byte": byte,
                                  "shift": boff - byte * 8, "width": bsz}
                continue
            if s in W:
                fields[fname] = W[s]
            tgt = ptr_target(ftid)
            if tgt:
                edges[fname] = tgt
        # keep the richest definition when a struct name repeats (fwd decls, dups)
        if fields and (t["name"] not in cat or len(fields) > len(cat[t["name"]])):
            cat[t["name"]] = fields
        if edges and (t["name"] not in ptrs or len(edges) > len(ptrs[t["name"]])):
            ptrs[t["name"]] = edges
        if bfs and (t["name"] not in bits or len(bfs) > len(bits[t["name"]])):
            bits[t["name"]] = bfs
    # pointer edges live under a reserved key so the flat {struct: {field: width}} shape
    # every existing consumer expects is unchanged.
    cat["__ptr_targets__"] = ptrs
    cat["__bitfields__"] = bits
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
