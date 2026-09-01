#!/usr/bin/env python3
"""Annotate the hook map with each function's INLINE STATUS, read from DWARF.

WHY THIS EXISTS --- it closes a correctness hazard, not a cosmetic gap.

`mk_hook_map.py` records whether a function has an arming pad, read from the bytes at
its entry. That answers "can I arm this name". It does NOT answer the question a shield
author actually needs answered:

    if I arm this function, do I cover EVERY call to it?

A function can be **partially inlined**: the compiler keeps an out-of-line copy (so the
symbol exists, the pad exists, arming succeeds) *and also* inlines it at some call sites.
A shield armed at the pad covers the out-of-line copy and silently misses every inlined
one --- while `fired` climbs, which reads as coverage. That is the false-success shape
`engine-hard-problems.md` 3.1 warns about, and on the 2026-09-01 audit it was real: three
HTTP request processors (`http_process_client_headers`, `http_process_server_headers`,
`http_process_1xx`) are partially inlined in the shipped binary.

So each entry gets:

    inline_status : "out-of-line"   the only instances are out-of-line --- arming is complete
                  | "partial"       ALSO inlined at N sites --- arming MISSES those sites
    inline_sites  : N               how many inlined copies exist

and functions that exist in the source but were inlined away entirely (no symbol, no pad,
unshieldable) are emitted in a separate `inlined_only` list, so `list` can say "this exists
and you cannot arm it" instead of just omitting it and looking like a typo.

READ THE SHIPPED BINARY. Inlining is an optimisation decision, so it differs per build:
on 2026-09-01 the same five compile units showed 42% out-of-line at `-O2` and 99% in the
debug build. A map annotated from the debug binary is worse than no annotation --- it says
"complete" about functions the shipped build inlines. This is the same trap
`mk_hook_map.py` documents for pads, one level up.

    mk_inline_status.py <hook-map.json> <binary> [-o out.json]

Streams `readelf --debug-dump=info`; no libdwarf dependency.
"""

import collections
import json
import re
import subprocess
import sys

DIE = re.compile(r"^\s*<\d+><([0-9a-f]+)>:.*\((DW_TAG_\w+)\)")
NAME = re.compile(r"DW_AT_name\s*:.*?:?\s*([A-Za-z_][\w.]*)\s*$")
ORIGIN = re.compile(r"DW_AT_abstract_origin:\s*<0x([0-9a-f]+)>")
LOWPC = re.compile(r"DW_AT_low_pc")


def scan(binary):
    """-> (out_of_line names, {name: inlined instance count})."""
    p = subprocess.Popen(["readelf", "--debug-dump=info", binary],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         text=True, errors="ignore", bufsize=1 << 20)
    subprog = {}                      # DIE offset -> [name, has_low_pc]
    inlined = collections.Counter()   # origin DIE offset -> instances
    cur = None
    for line in p.stdout:
        m = DIE.match(line)
        if m:
            cur = (m.group(1), m.group(2))
            if cur[1] == "DW_TAG_subprogram":
                subprog.setdefault(cur[0], [None, False])
            continue
        if cur is None:
            continue
        off, tag = cur
        if tag == "DW_TAG_subprogram":
            nm = NAME.search(line)
            if nm and subprog[off][0] is None:
                subprog[off][0] = nm.group(1)
            if LOWPC.search(line):
                subprog[off][1] = True
        elif tag == "DW_TAG_inlined_subroutine":
            om = ORIGIN.search(line)
            if om:
                inlined[om.group(1)] += 1
    p.stdout.close()
    p.wait()

    outline = {n for n, pc in subprog.values() if n and pc}
    by_name = collections.Counter()
    for off, cnt in inlined.items():
        e = subprog.get(off)
        if e and e[0]:
            by_name[e[0]] += cnt
    return outline, by_name


def main(argv):
    if len(argv) < 3:
        sys.exit(__doc__)
    map_path, binary = argv[1], argv[2]
    out_path = map_path
    if "-o" in argv:
        out_path = argv[argv.index("-o") + 1]

    doc = json.load(open(map_path))
    hooks = doc.get("hook_points", doc if isinstance(doc, list) else [])

    outline, inl = scan(binary)
    if not outline:
        sys.exit("*** no out-of-line subprograms found in %s --- is there DWARF in it?" % binary)

    mapped = {h.get("name") for h in hooks}
    partial = complete = 0
    for h in hooks:
        n = h.get("name", "")
        sites = inl.get(n, 0)
        # A name in the map has a pad, so it has an out-of-line instance by construction.
        h["inline_status"] = "partial" if sites else "out-of-line"
        h["inline_sites"] = sites
        if sites:
            partial += 1
        else:
            complete += 1

    # Functions the compiler dissolved entirely: inlined somewhere, no out-of-line copy,
    # therefore no symbol, no pad, unshieldable. Worth naming rather than omitting.
    only = sorted(({"name": n, "inline_sites": c}
                   for n, c in inl.items() if n not in outline and n not in mapped),
                  key=lambda e: -e["inline_sites"])

    if isinstance(doc, dict):
        doc["inlined_only"] = only
        doc["inline_status_source"] = binary
    json.dump(doc, open(out_path, "w"))

    print("  annotated %d hook(s) from %s" % (len(hooks), binary))
    print("    out-of-line (arming is complete) : %d" % complete)
    print("    PARTIAL (arming MISSES inlined sites) : %d" % partial)
    print("    inlined-only (no symbol, unshieldable) : %d" % len(only))
    if partial:
        print("  the partially-inlined hooks --- a shield here does NOT cover every call:")
        for h in sorted((h for h in hooks if h.get("inline_sites")),
                        key=lambda h: -h["inline_sites"])[:15]:
            print("    %-46s %4d inlined site(s) missed" % (h["name"], h["inline_sites"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
