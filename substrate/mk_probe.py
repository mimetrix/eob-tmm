#!/usr/bin/env python3
"""Generate a probe program for ANY function, from the build's own debug information.

WHAT THIS REPLACES. Until now, instrumenting a function whose arguments include pointers
needed a per-hook ctx builder: host C that dereferences and hands the verified program flat
scalars. That C is compiled into TMM, so a new argument shape cost a rebuild --- roughly a
40-minute `make tmm` plus packaging.

Two things together remove that. `bpf_probe_read` lets the PROGRAM dereference, so the
generated artifact is bytecode rather than host C. And DWARF already describes every
function's parameters, so the bytecode can be generated rather than written.

    DWARF from the existing build  ->  parameter types
                                  ->  a .bpf.c that reads them
                                  ->  clang -target bpf  ->  PREVAIL  ->  socket  ->  armed

Nothing in that chain rebuilds TMM.

    mk_probe.py --debuginfo <tmm64.debug> --function <name> [-o out.bpf.c]
    mk_probe.py --debs <DEBS/amd64> --function <name>
    mk_probe.py --debuginfo <f> --describe <name>      just print the signature

WHAT IT CANNOT DO, up front rather than discovered:

  * FIVE ARGUMENTS. The generic register context carries five; the trampoline saves six. A
    sixth parameter is invisible to a generated probe and needs a typed builder. rst_why's
    sixth argument is its cause string, which is exactly the field worth having --- so
    generation does not retire hand-written builders, it removes the rebuild from the
    common case.
  * SEMANTIC DERIVATIONS. UFLOW_COOKIE(uf) hashes three fields into a flow identity. That is
    judgement, not type information, and no amount of DWARF produces it.
  * A 96-BYTE CEILING on the record, which is PREVAIL's limit on context reads. Wide
    signatures get truncated, and the generator says which fields it dropped.
"""
import argparse
import os
import subprocess
import sys
import tempfile

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    sys.exit("*** needs pyelftools (python3 -m pip install pyelftools)")

STR_BYTES = 24          # bytes captured per char* argument
BLOB_BYTES = 16         # bytes captured from the head of a struct pointer
CTX_MAX = 96            # PREVAIL's ceiling on context reads, measured not assumed


def die_name(die):
    v = die.attributes.get("DW_AT_name")
    if v is None:
        return None
    n = v.value
    return n.decode("utf-8", "replace") if isinstance(n, bytes) else str(n)


def resolve(cu, die, depth=0):
    """Follow DW_AT_type to a description of the parameter's shape.

    Returns (kind, detail) where kind is one of:
        scalar   an integer, enum, boolean or float --- read the register directly
        string   char * --- probe_read a bounded prefix
        blob     pointer to a struct/union --- probe_read a bounded prefix of it
        opaque   pointer to something with no useful layout, or void *
        unknown  the chain could not be followed
    """
    if die is None or depth > 8:
        return ("unknown", "?")
    tag = die.tag
    if tag in ("DW_TAG_base_type",):
        return ("scalar", die_name(die) or "int")
    if tag in ("DW_TAG_enumeration_type",):
        return ("scalar", "enum %s" % (die_name(die) or "?"))
    if tag in ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type"):
        ref = die.attributes.get("DW_AT_type")
        if ref is None:
            return ("scalar", die_name(die) or "void")
        return resolve(cu, cu.get_DIE_from_refaddr(ref.value + cu.cu_offset), depth + 1)
    if tag == "DW_TAG_pointer_type":
        ref = die.attributes.get("DW_AT_type")
        if ref is None:
            return ("opaque", "void *")
        inner = cu.get_DIE_from_refaddr(ref.value + cu.cu_offset)
        # peel typedefs/qualifiers to see what is really pointed at
        peel, d = inner, 0
        while peel is not None and d < 8 and peel.tag in (
                "DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type"):
            r = peel.attributes.get("DW_AT_type")
            peel = cu.get_DIE_from_refaddr(r.value + cu.cu_offset) if r else None
            d += 1
        if peel is None:
            return ("opaque", "void *")
        if peel.tag == "DW_TAG_base_type" and (die_name(peel) or "").endswith("char"):
            return ("string", "%s *" % die_name(peel))
        if peel.tag in ("DW_TAG_structure_type", "DW_TAG_union_type"):
            return ("blob", "struct %s *" % (die_name(peel) or "anon"))
        return ("opaque", "%s *" % (die_name(peel) or peel.tag))
    return ("unknown", tag)


def signature(path, want):
    """Find `want` and return [(argname, kind, detail), ...], preferring a DEFINITION.

    A declaration carries the parameter TYPES but no names and no low_pc; a definition
    carries both. Both are present for an external function, so preferring the definition
    is what makes generated field names readable rather than arg0..argN.
    """
    best = None
    with open(path, "rb") as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            sys.exit("*** no DWARF in %s" % path)
        dw = elf.get_dwarf_info()
        for cu in dw.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram":
                    continue
                if die_name(die) != want:
                    continue
                params = []
                for child in die.iter_children():
                    if child.tag != "DW_TAG_formal_parameter":
                        continue
                    ref = child.attributes.get("DW_AT_type")
                    t = cu.get_DIE_from_refaddr(ref.value + cu.cu_offset) if ref else None
                    kind, detail = resolve(cu, t)
                    params.append((die_name(child), kind, detail))
                if not params:
                    continue
                has_def = "DW_AT_low_pc" in die.attributes
                named = sum(1 for p in params if p[0])
                score = (1 if has_def else 0, named)
                if best is None or score > best[0]:
                    best = (score, params)
                if has_def and named == len(params):
                    return params          # ideal: definition with every name
    if best is None:
        sys.exit("*** no DWARF subprogram named %r with parameters" % want)
    return best[1]


def layout(params):
    """Assign each reachable parameter a record field, inside the 96-byte ceiling.

    Returns (fields, dropped). A field is (argindex, name, kind, detail, bytes).
    Scalars first, then strings, then struct heads --- so a wide signature loses its
    least-informative fields rather than its line numbers.
    """
    reach = [(i, n or ("arg%d" % i), k, d) for i, (n, k, d) in enumerate(params)][:5]
    dropped = [(i, n or ("arg%d" % i), k, d) for i, (n, k, d) in enumerate(params)][5:]
    order = {"scalar": 0, "string": 1, "blob": 2, "opaque": 0, "unknown": 3}
    reach.sort(key=lambda f: order.get(f[2], 3))
    fields, used = [], 4          # 4 bytes of header: which args made it in
    for i, nm, kind, detail in reach:
        want = {"scalar": 8, "opaque": 8, "string": STR_BYTES, "blob": BLOB_BYTES}.get(kind)
        if want is None:
            dropped.append((i, nm, kind, detail)); continue
        if used + want > CTX_MAX:
            dropped.append((i, nm, kind, detail)); continue
        fields.append((i, nm, kind, detail, want))
        used += want
    return fields, dropped, used


def generate(fn, params, fields, dropped, used):
    """Emit a .bpf.c that reads the generic register context and probe_reads the pointers."""
    L = []
    A = L.append
    A("/* GENERATED by substrate/mk_probe.py --- do not edit.")
    A(" *")
    A(" * A probe for %s(), derived entirely from the build's own DWARF. No host-side ctx" % fn)
    A(" * builder exists for this function and none is needed: the program is handed the")
    A(" * GENERIC five-register context and does its own dereferencing through")
    A(" * bpf_probe_read, so this costs a program rather than a rebuild of TMM.")
    A(" *")
    A(" * Signature as DWARF describes it:")
    for i, (nm, kind, detail) in enumerate(params):
        A(" *     arg%d  %-14s %-8s %s%s" % (i, nm or "?", kind, detail,
          "   [UNREACHABLE: beyond 5 registers]" if i >= 5 else ""))
    if dropped:
        A(" *")
        A(" * DROPPED, and why --- so nothing is silently absent from the record:")
        for i, nm, kind, detail in dropped:
            why = ("beyond the five registers the generic context carries" if i >= 5
                   else "no room inside the 96-byte context ceiling"
                   if kind in ("scalar", "string", "blob", "opaque")
                   else "type not classifiable from DWARF (%s)" % detail)
            A(" *     arg%d %-14s %s" % (i, nm, why))
    A(" *")
    A(" * Record is %d of %d bytes. The ceiling is PREVAIL's limit on context reads." % (used, CTX_MAX))
    A(" */")
    A("typedef unsigned int  __u32;")
    A("typedef unsigned long long __u64;")
    A("")
    A("struct bpf_map_def { __u32 type, key_size, value_size, max_entries, map_flags; };")
    A("#define BPF_MAP_TYPE_HASH             1")
    A("#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4")
    A("")
    A('struct bpf_map_def probe_%s_out __attribute__((section("maps"), used)) = {' % fn)
    A("    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,")
    A("    .key_size = sizeof(__u32), .value_size = sizeof(__u32), .max_entries = 16,")
    A("};")
    A("")
    A("static long (*bpf_probe_read)(void *, __u32, const void *) = (void *)4;")
    A("static long (*bpf_perf_event_output)(void *, void *, __u64, void *, __u64) = (void *)25;")
    A("")
    A("struct ls_ctx_generic { __u64 arg[5]; };")
    A("")
    A("/* The record this probe emits. A consumer decodes it from the descriptor emitted")
    A(" * alongside --- the host validated its LENGTH and nothing else. */")
    A("struct rec {")
    A("    __u32 present;      /* bit i set = arg i was captured */")
    for i, nm, kind, detail, nb in fields:
        if kind in ("scalar", "opaque"):
            A("    __u64 %s;" % nm)
        else:
            A("    char  %s[%d];" % (nm, nb))
    A("};")
    A("_Static_assert(sizeof(struct rec) <= %d, \"record exceeds PREVAIL's context ceiling\");" % CTX_MAX)
    A("")
    A('__attribute__((section("fentry/%s"), used))' % fn)
    A("__u64")
    A("shield(struct ls_ctx_generic *c)")
    A("{")
    A("    struct rec r;")
    A("    int i;")
    A("")
    A("    /* Zero the whole record first. A field a probe_read fails on must read as absent,")
    A("     * not as whatever was on the stack --- and `present` is what says which is which. */")
    A("    for (i = 0; i < (int)sizeof r; i++)")
    A("        ((char *)&r)[i] = 0;")
    A("    r.present = 0;")
    A("")
    for i, nm, kind, detail, nb in fields:
        if kind in ("scalar", "opaque"):
            A("    r.%s = c->arg[%d];                    /* %s --- register, no read needed */"
              % (nm, i, detail))
            A("    r.present |= 1u << %d;" % i)
        else:
            A("    /* %s --- a pointer, so probe_read it. A bad address returns non-zero and" % detail)
            A("     * the field simply stays absent rather than faulting the data plane. */")
            A("    if (bpf_probe_read(r.%s, sizeof r.%s, (const void *)c->arg[%d]) == 0)"
              % (nm, nm, i))
            A("        r.present |= 1u << %d;" % i)
        A("")
    A("    bpf_perf_event_output(c, &probe_%s_out, 0, &r, sizeof r);" % fn)
    A("    return 0ull;                          /* observation only --- always fall through */")
    A("}")
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--debuginfo")
    ap.add_argument("--debs")
    ap.add_argument("--function", required=True)
    ap.add_argument("--describe", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    dbg = a.debuginfo
    tmp = None
    if a.debs:
        import glob
        tmp = tempfile.mkdtemp(prefix="mkprobe.")
        deb = glob.glob(os.path.join(a.debs, "**", "tmm-debuginfo_*.deb"), recursive=True)
        if not deb:
            sys.exit("*** no tmm-debuginfo_*.deb under %s" % a.debs)
        subprocess.run(["dpkg-deb", "-x", deb[0], tmp], check=True)
        cands = [os.path.join(r, f) for r, _, fs in os.walk(tmp) for f in fs
                 if os.path.getsize(os.path.join(r, f)) > 10 * 1024 * 1024]
        if not cands:
            sys.exit("*** no large file in the debuginfo package")
        dbg = cands[0]
    if not dbg:
        sys.exit("*** need --debuginfo or --debs")

    params = signature(dbg, a.function)
    print("  %s(" % a.function)
    for i, (nm, kind, detail) in enumerate(params):
        note = ""
        if i >= 5:
            note = "   <- BEYOND the 5 registers the generic context carries"
        print("      arg%d  %-14s %-10s %s%s" % (i, nm or "(unnamed)", kind, detail, note))
    print("  )")
    if len(params) > 5:
        print("\n  %d of %d parameters are reachable. A generated probe cannot see the rest."
              % (5, len(params)))
    if a.describe:
        return

    fields, dropped, used = layout(params)
    src = generate(a.function, params, fields, dropped, used)
    out = a.out or ("probe_%s.bpf.c" % a.function)
    with open(out, "w") as f:
        f.write(src)
    print()
    print("  generated %s --- %d lines, record %d/%d bytes, %d field(s) captured"
          % (out, src.count(chr(10)), used, CTX_MAX, len(fields)))
    for i, nm, kind, detail, nb in fields:
        print("      arg%d %-14s %-8s %2d bytes" % (i, nm, kind, nb))
    if dropped:
        print("  dropped, and the generated source says why:")
        for i, nm, kind, detail in dropped:
            print("      arg%d %-14s %s" % (i, nm, kind))


if __name__ == "__main__":
    main()
