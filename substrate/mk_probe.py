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

def _elffile():
    """pyelftools, imported ON DEMAND.

    It was imported at module scope and the script exited without it. But the whole reason
    --index exists is that a lookup needs no DWARF: it reads a text file. Requiring the DWARF
    library to read that file put the 146 MB dependency back on every machine that only wanted
    to generate a probe --- including, on the first try, the one running the demo.

    The index path now needs nothing but python3. Only --build-index and an uncached
    --debuginfo/--debs lookup touch this.
    """
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        sys.exit("*** reading DWARF needs pyelftools (python3 -m pip install pyelftools).\n"
                 "    A prebuilt --index needs none of it --- see build-pipeline.md.")
    return ELFFile

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
        elf = _elffile()(f)
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


def layout(params, no_probe_read=False):
    """Assign each reachable parameter a record field, inside the 96-byte ceiling.

    Returns (fields, dropped). A field is (argindex, name, kind, detail, bytes).
    Scalars first, then strings, then struct heads --- so a wide signature loses its
    least-informative fields rather than its line numbers.

    no_probe_read DROPS EVERY FIELD THAT NEEDS A DEREFERENCE, because a scalar argument
    arrives in a register and a pointer does not. TMM registers bpf_probe_read as helper 4,
    but a given BUILD only has the helpers it was compiled with: the binary on the cluster
    today has the clock (5) and the emit helper (25) and NOT probe_read, so a program using it
    is refused at load with no indication of which helper was the problem. Generating a probe
    the target cannot run is worse than generating a smaller one that works, so this makes the
    trade explicit and records it in the generated file rather than leaving it to be discovered
    at load time.
    """
    reach = [(i, n or ("arg%d" % i), k, d) for i, (n, k, d) in enumerate(params)][:5]
    dropped = [(i, n or ("arg%d" % i), k, d) for i, (n, k, d) in enumerate(params)][5:]
    order = {"scalar": 0, "string": 1, "blob": 2, "opaque": 0, "unknown": 3}
    reach.sort(key=lambda f: order.get(f[2], 3))
    fields, used = [], 4          # 4 bytes of header: which args made it in
    for i, nm, kind, detail in reach:
        if no_probe_read and kind in ("string", "blob"):
            dropped.append((i, nm, kind, detail)); continue
        want = {"scalar": 8, "opaque": 8, "string": STR_BYTES, "blob": BLOB_BYTES}.get(kind)
        if want is None:
            dropped.append((i, nm, kind, detail)); continue
        if used + want > CTX_MAX:
            dropped.append((i, nm, kind, detail)); continue
        fields.append((i, nm, kind, detail, want))
        used += want
    return fields, dropped, used


# The host records a map by its SYMBOL NAME in a fixed 32-byte table and REFUSES any name that
# would not round-trip (ls_map_glue.h: LS_MAP_NAME_MAX). A refused map is silent from the
# program's side --- bpf_perf_event_output gets a null map, returns -1, and the generated
# program does not read the return value --- so the probe fires, the counter is exact, and no
# record ever appears.
#
# MEASURED, 2026-08-19: probe_mrhttp_proxy_route_message_out is 36 characters. It was refused,
# slot 2 fired 29 times, and the ring stayed empty. The counter said the probe worked.
LS_MAP_NAME_MAX = 32

# EACH GENERATED PROBE CONSUMES ONE OF FOUR MAP REGISTRATIONS, and they are per PROCESS, not
# per program: ls_map.h sets LS_MAP_MAX to 4 and ls_map_glue.h keys the table by symbol name,
# so four distinct emitting programs fill it. `revoke` disables a slot's program but does NOT
# reclaim its map registration (item 0c --- reclaiming needs the quiescence pass), so the
# ceiling is four distinct map names for the LIFE OF THE PROCESS.
#
# OBSERVED 2026-08-19: five generated probes were loaded in one session --- flow_reject,
# flow_input_drop, flow_reject_dos, ip4_reject, mrhttp_proxy_route_message, each with its own
# uniquely named output map. flow_reject then counted fired=20 and published nothing. After
# revoking the others and reloading it, records appeared. LS_MAP_MAX=4 is the documented limit
# and the most plausible cause; it was not isolated further than that, so this is stated as an
# observation rather than a mechanism.
#
# WHAT IT COSTS THE PROCEDURE. Screening several candidates for reachability is exactly the
# right thing to do, and it burns registrations. Screen with the COUNTER --- fired is exact
# whether or not the map registered --- and only keep the probes whose records you intend to
# read. A probe past the fourth counts correctly and reports nothing, which is the most
# misleading shape available: the counter says it works.
LS_MAP_SLOTS = 4


def map_name(fn):
    """A map name for `fn` that always fits the host's table, and is unique per function.

    NOT the function name with a prefix and suffix: TMM has functions whose names alone exceed
    the budget. NOT a truncation either --- two functions sharing a 20-character prefix would
    collide, and a name collision with a DIFFERENT record shape is refused by the host, so one
    probe would break another that happened to be loaded.

    A short digest of the full name is unique in practice, deterministic across runs (so the
    same function regenerates byte-identically, which is what makes the index-vs-DWARF
    comparison meaningful), and fixed at 18 characters regardless of input.
    """
    import hashlib
    h = hashlib.sha256(fn.encode()).hexdigest()[:8]
    name = "probe_%s_out" % h
    # An assertion rather than a comment: if the format above is ever edited to something
    # longer, this fails at generation time instead of producing a probe that counts and
    # never reports.
    assert len(name) < LS_MAP_NAME_MAX, name
    return name


def generate(fn, params, fields, dropped, used, no_probe_read=False):
    """Emit a .bpf.c that reads the generic register context and probe_reads the pointers."""
    L = []
    A = L.append
    A("/* GENERATED by substrate/mk_probe.py --- do not edit.")
    A(" *")
    A(" * A probe for %s(), derived entirely from the build's own DWARF. No host-side ctx" % fn)
    A(" * builder exists for this function and none is needed: the program is handed the")
    if no_probe_read:
        A(" * GENERIC five-register context and reads SCALAR ARGUMENTS ONLY.")
        A(" *")
        A(" * GENERATED WITH --no-probe-read. Every pointer argument is dropped, because a")
        A(" * pointer has to be dereferenced and that needs bpf_probe_read (helper 4), which")
        A(" * the target build does not register. A program using an unregistered helper is")
        A(" * refused at load without saying which helper, so the choice is made here instead.")
        A(" * Regenerate without the flag once the target has helper 4 to capture the rest.")
    else:
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
    MAP = map_name(fn)
    A("/* Output map: %s  <-  %s" % (MAP, fn))
    A(" *")
    A(" * Named from a DIGEST of the function name, not from the name itself. The host records")
    A(" * a map by symbol name in a 32-byte table and refuses anything longer, and a refused")
    A(" * map is silent: the helper gets a null map, returns -1, this program does not read the")
    A(" * return value, so the probe fires and the counter is exact and no record ever appears.")
    A(" * A 36-character name did exactly that on 2026-08-19. */")
    A('struct bpf_map_def %s __attribute__((section("maps"), used)) = {' % MAP)
    A("    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,")
    A("    .key_size = sizeof(__u32), .value_size = sizeof(__u32), .max_entries = 16,")
    A("};")
    A("")
    # DECLARE ONLY WHAT IS CALLED. An unused function pointer initialised to a helper id is
    # harmless in principle --- no call means no relocation for uBPF to resolve --- but it puts
    # the id of a helper the target does not register into a program that claims not to need
    # it. Nothing should have to reason about that: if the probe does not dereference, the
    # declaration does not appear.
    if any(k in ("string", "blob") for _, _, k, _, _ in fields):
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
    A("    bpf_perf_event_output(c, &%s, 0, &r, sizeof r);" % MAP)
    A("    return 0ull;                          /* observation only --- always fall through */")
    A("}")
    return "\n".join(L) + "\n"


SIG_VERSION = 1


# THE CANONICAL BUILD-ID READER, not a local copy. There were six independent copies of this
# parse in the repo and the one written here read a TRUNCATED id --- see substrate/ls_buildid.py
# for why (the note straddles two PT_NOTE segments in the PGO debug build). Importing beats
# copying for exactly the reason six copies demonstrate.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ls_buildid import build_id                                     # noqa: E402


def build_index(dbg, out):
    """ONE DWARF walk, every function's signature, written to a flat file.

    WHY THIS IS A BUILD STEP RATHER THAN A LOOKUP. Finding one function costs a walk of every
    compilation unit in a 97 MB debuginfo --- measured at 1m34s. That is fine once and useless
    interactively, and the walk is the same whether you want one signature or all of them. So
    it happens at build time, alongside the hook index, and every later lookup is a dictionary
    hit.

    Keyed to the build id, because a signature index from another build describes different
    parameter layouts for the same names --- the same failure mode the hook index's build-id
    gate exists to prevent, one level up.
    """
    bid = build_id(dbg)
    n_fn = n_par = 0
    seen = {}
    with open(dbg, "rb") as f:
        elf = _elffile()(f)
        if not elf.has_dwarf_info():
            sys.exit("*** no DWARF in %s" % dbg)
        dw = elf.get_dwarf_info()
        for cu in dw.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram":
                    continue
                nm = die_name(die)
                if not nm:
                    continue
                params = []
                for child in die.iter_children():
                    if child.tag != "DW_TAG_formal_parameter":
                        continue
                    ref = child.attributes.get("DW_AT_type")
                    t = cu.get_DIE_from_refaddr(ref.value + cu.cu_offset) if ref else None
                    kind, detail = resolve(cu, t)
                    params.append((die_name(child) or "", kind, detail))
                if not params:
                    continue
                # PREFER THE DEFINITION. A declaration has the types but no parameter names;
                # both DIEs exist for an external function, and taking whichever came first
                # would give arg0..argN for half the tree.
                score = (1 if "DW_AT_low_pc" in die.attributes else 0,
                         sum(1 for q in params if q[0]))
                if nm not in seen or score > seen[nm][0]:
                    seen[nm] = (score, params)
    with open(out, "w") as fh:
        fh.write("#ls-sig-index\t%d\n" % SIG_VERSION)
        fh.write("#build_id\t%s\n" % bid)
        fh.write("#name\tnparams\tname:kind:detail|...\n")
        for nm in sorted(seen):
            params = seen[nm][1]
            n_fn += 1
            n_par += len(params)
            enc = "|".join("%s:%s:%s" % (a.replace(":", "_"), b, c.replace(":", "_").replace("|", "_"))
                           for a, b, c in params)
            fh.write("%s\t%d\t%s\n" % (nm, len(params), enc))
    print("  build id  : %s" % bid)
    print("  functions : %d with at least one parameter" % n_fn)
    print("  parameters: %d" % n_par)
    print("  written   : %s (%d bytes)" % (out, os.path.getsize(out)))


def load_index(path, want):
    """-> [(name, kind, detail), ...] for `want`, or None. A dictionary hit, not a walk."""
    with open(path) as f:
        for line in f:
            if line.startswith("#"):
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 3 or parts[0] != want:
                continue
            out = []
            for tok in parts[2].split("|"):
                bits = tok.split(":", 2)
                if len(bits) == 3:
                    out.append((bits[0] or None, bits[1], bits[2]))
            return out
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--debuginfo")
    ap.add_argument("--debs")
    ap.add_argument("--function")
    ap.add_argument("--describe", action="store_true")
    ap.add_argument("--build-index", metavar="OUT",
                    help="walk DWARF once and write a signature index for EVERY function")
    ap.add_argument("--index", metavar="FILE",
                    help="use a prebuilt signature index instead of walking DWARF")
    ap.add_argument("--no-probe-read", action="store_true",
                    help="capture SCALAR arguments only --- for a target build that does not "
                         "register bpf_probe_read (helper 4). Pointer arguments are dropped "
                         "and the generated file says so.")
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

        # PICK THE DEBUG FILE BY BUILD ID, NOT BY SIZE. This package ships TWO debug
        # binaries with DIFFERENT build ids:
        #
        #   usr/lib/debug/usr/bin/tmm64.debug          97 MB   PGO build
        #   usr/lib/debug/usr/bin/tmm64.no_pgo.debug  146 MB   what /usr/bin/tmm resolves to
        #
        # The first version of this code took the first file over 10 MB in os.walk order and
        # got tmm64.debug --- the one TMM does not run. Both are builds of the same source, so
        # the generated probes verified clean and read plausible fields; PGO changes inlining,
        # so which functions have parameter DIEs at all differs between them. A signature index
        # from the wrong build is the same class of fault as a stale address: correct-looking
        # and wrong, with nothing in the output to say so.
        #
        # The runtime DEB names the binary that ships, so its build id is the selector. Nothing
        # is inferred from a filename, because `no_pgo` being the shipped one is a property of
        # this build's configuration, not a rule.
        rdeb = glob.glob(os.path.join(a.debs, "**", "tmm_*.deb"), recursive=True)
        if not rdeb:
            sys.exit("*** no tmm_*.deb under %s. Without the runtime package there is nothing\n"
                     "    to identify WHICH of the debuginfo package's debug binaries ships."
                     % a.debs)
        rtmp = tempfile.mkdtemp(prefix="mkprobe.rt.")
        subprocess.run(["dpkg-deb", "-x", rdeb[0], rtmp], check=True)
        rbin = os.path.join(rtmp, "usr/bin/tmm.default")
        if not os.path.exists(rbin):
            sys.exit("*** no usr/bin/tmm.default in %s" % os.path.basename(rdeb[0]))
        want = build_id(os.path.realpath(rbin))

        cands = []
        for r, _, fs in os.walk(tmp):
            for f in fs:
                q = os.path.join(r, f)
                # islink FIRST: the package carries .build-id/ symlinks whose targets are
                # relative to the install root, so they dangle under an extraction dir and
                # getsize raises FileNotFoundError. That is what it did.
                if os.path.islink(q) or os.path.getsize(q) < 10 * 1024 * 1024:
                    continue
                try:
                    cands.append((build_id(q), q))
                except (OSError, ValueError):
                    continue
        match = [q for b, q in cands if b == want]
        if not match:
            sys.exit("*** no debug binary in %s matches the shipped binary's build id %s.\n"
                     "    Found: %s\n"
                     "    The DEB pair is mismatched --- do not generate an index from it."
                     % (os.path.basename(deb[0]), want,
                        ", ".join("%s=%s" % (os.path.basename(q), b[:12]) for b, q in cands)
                        or "none"))
        if len(match) > 1:
            sys.exit("*** %d debug binaries share build id %s; refusing to guess." % (len(match), want))
        dbg = match[0]
        if len(cands) > 1:
            print("  debuginfo : %s  (of %d candidates, selected by build id %s)"
                  % (os.path.basename(dbg), len(cands), want[:12]))
    if not dbg and not a.index:
        sys.exit("*** need --debuginfo, --debs, or a prebuilt --index")

    if a.build_index:
        build_index(dbg, a.build_index)
        return
    if not a.function:
        sys.exit("*** need --function (or --build-index)")

    params = None
    if a.index:
        params = load_index(a.index, a.function)
        if params is None:
            sys.exit("*** %r is not in %s. Either it has no parameters, or the index is from\n"
                     "    a different build --- check its #build_id header."
                     % (a.function, a.index))
    if params is None:
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

    fields, dropped, used = layout(params, a.no_probe_read)
    if not fields:
        sys.exit("*** nothing capturable in %s under these constraints.\n"
                 "    %s"
                 % (a.function,
                    "Every argument is a pointer and --no-probe-read drops those. Either the\n"
                    "    target needs helper 4, or this is the wrong function to probe."
                    if a.no_probe_read else
                    "No argument mapped to a field --- check the signature above."))
    src = generate(a.function, params, fields, dropped, used, a.no_probe_read)
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
