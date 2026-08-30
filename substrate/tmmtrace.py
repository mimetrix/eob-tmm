#!/usr/bin/env python3
"""tmmtrace --- the Live Surface trace DSL front-end.

bpftrace-for-the-data-plane. You write a one-line trace expression; tmmtrace emits
a CO-RE eBPF program in the shape the substrate's surfaces use, then (--verify)
compiles it with clang -target bpf and runs it through PREVAIL --- the same
admission gate a hand-written surface goes through. Everything downstream
(sign -> arm -> drain) already exists; this is the language layer.

GRAMMAR
    <probe> [ '/' <pred> '/' ] '{' <action> '}'
    <probe>  := ('fentry'|'fexit') '/' <hook>
    <pred>   := <value> <op> <int>              # op: == != < > <= >=   (gates count())
    <action> := 'count' | 'count()'             # -> SAFE_RETURN on match; host safe_returns
              | 'hist' '(' <value> ')'          # -> returns the value; tmmtrace buckets it
              | <value>                          # raw: return the value/field
              | 'count'                          # count every invocation
    <value>  := 'args.' <field>                  # resolved via signatures.tsv + BTF catalog
              | 'arg' <N> [ '.' <field> ]        # arg N, or a field of the struct at arg N
              | <struct> '(' 'arg' <N> ')' '.' <field> [':'<ty>]   # explicit (no catalog)

    A leading '@name =' before count()/hist() is accepted and ignored (bpftrace habit).

SUBCOMMANDS
    tmmtrace.py gen    '<expr>'          # print the generated CO-RE .bpf.c
    tmmtrace.py verify '<expr>'          # gen -> clang -> PREVAIL, report the verdict
    tmmtrace.py hist                     # read values on stdin -> a log2 histogram
    tmmtrace.py list   '<glob>'          # list hooks in the build's map matching <glob>

EXAMPLES
    tmmtrace.py verify 'fentry/http_parse_client_headers /args.version_num == 1/ { count() }'
    tmmtrace.py verify 'fentry/http_parse_client_headers { hist(args.version_num) }'
    tmmtrace.py verify 'fentry/dtls_tx { hist(args.sz) }'
    seq 1 200 | awk '{print 2**int(rand()*10)}' | tmmtrace.py hist
"""
import fnmatch
import json
import os
import re
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLANG = os.environ.get("CLANG", "clang-14")
PREVAIL = os.environ.get("PREVAIL", os.path.join(REPO, "ebpf-verifier", "bin", "prevail"))
SIGS = os.environ.get("LS_SIGS", os.path.expanduser("~/lstools/signatures.tsv"))
TYPES = os.environ.get("LS_TYPES", os.path.expanduser("~/lstools/types.json"))
HOOKMAP = os.environ.get("LS_HOOKMAP", os.path.expanduser("~/lstools/hook-map.json"))

CTYPE = {"u8": "__u8", "u16": "__u16", "u32": "__u32", "u64": "__u64"}
_OPS = {"==", "!=", "<", ">", "<=", ">="}

# <probe> [/pred/] { action }
_PROBE = re.compile(
    r"^\s*(fentry|fexit)/([A-Za-z_]\w*)\s*(?:/(?P<pred>[^/]*)/\s*)?\{\s*(?P<act>.*?)\s*\}\s*$")
_STRUCT_PTR = re.compile(r"struct\s+(\w+)\s*\*")
_FIELD = re.compile(
    r"^([A-Za-z_]\w*)\(arg([0-4])\)\.([A-Za-z_]\w*)(?::(u8|u16|u32|u64))?$")
_ARG = re.compile(r"^arg([0-4])$")
_ARGSDOT = re.compile(r"^args\.([A-Za-z_]\w*)$")
_ARGNDOT = re.compile(r"^arg([0-4])\.([A-Za-z_]\w*)$")
_COUNT = re.compile(r"^(?:@\w+\s*=\s*)?count(?:\(\))?$")
_HIST = re.compile(r"^(?:@\w+\s*=\s*)?hist\(\s*(.+?)\s*\)$")
_PRED = re.compile(r"^(.+?)\s*(==|!=|<=|>=|<|>)\s*(-?\d+)$")


class DslError(Exception):
    pass


_types_cache = None
_sigs_cache = None


def _types():
    global _types_cache
    if _types_cache is None:
        try:
            _types_cache = json.load(open(TYPES))
        except Exception:
            _types_cache = {}
    return _types_cache


def hook_params(hook):
    """[(name, kind, struct_or_None, detail)] for a hook, from signatures.tsv."""
    global _sigs_cache
    if _sigs_cache is None:
        _sigs_cache = {}
        try:
            for ln in open(SIGS):
                if ln.startswith("#"):
                    continue
                f = ln.rstrip("\n").split("\t")
                if len(f) >= 3:
                    _sigs_cache[f[0]] = f[2]
        except Exception:
            pass
    spec = _sigs_cache.get(hook)
    if not spec:
        return None
    out = []
    for p in spec.split("|"):
        parts = p.split(":", 2)
        if len(parts) != 3:
            continue
        name, kind, detail = parts
        m = _STRUCT_PTR.search(detail)
        out.append((name, kind, m.group(1) if m else None, detail))
    return out


def parse(expr):
    m = _PROBE.match(expr)
    if not m:
        raise DslError("expected  <fentry|fexit>/<hook> [/pred/] { <action> }")
    return m.group(1), m.group(2), (m.group("pred") or "").strip(), m.group("act").strip()


def resolve_value(hook, tok):
    """Normalize a <value> token to ('scalar', N) | ('field', struct, N, field, ty)."""
    m = _ARG.match(tok)
    if m:
        return ("scalar", int(m.group(1)))
    fe = _FIELD.match(tok)
    if fe:
        return ("field", fe.group(1), int(fe.group(2)), fe.group(3), fe.group(4) or "u64")
    ad, an = _ARGSDOT.match(tok), _ARGNDOT.match(tok)
    if ad or an:
        params = hook_params(hook)
        if params is None:
            raise DslError("no signature for '%s' (need %s); use the explicit "
                           "<struct>(argN).<field>:ty form" % (hook, SIGS))
        name = an.group(2) if an else ad.group(1)
        n_only = int(an.group(1)) if an else None
        for i, (pn, kind, struct, _d) in enumerate(params):
            if (n_only is None or i == n_only) and pn == name and kind in ("scalar", "string"):
                return ("scalar", i)
        for i, (pn, kind, struct, _d) in enumerate(params):
            if n_only is not None and i != n_only:
                continue
            if kind == "blob" and struct and name in _types().get(struct, {}):
                return ("field", struct, i, name, _types()[struct][name])
        raise DslError("could not resolve '%s' at %s; params: %s" % (
            name, hook, ", ".join("%s(%s)" % (p[0], p[2] or p[1]) for p in params)))
    raise DslError("bad value '%s' (want args.<field> | arg<N>[.<field>] | <struct>(argN).<field>)" % tok)


def _read(val, k):
    """C to read a resolved <value> into a fresh var. Returns (struct_decl, code, expr)."""
    if val[0] == "scalar":
        return "", "", "c->arg[%d]" % val[1]
    _, struct, n, field, ty = val
    ct = CTYPE[ty]
    sd = "struct %s { %s %s; } __attribute__((preserve_access_index));" % (struct, ct, field)
    code = ("    struct %s *p%d = (struct %s *)c->arg[%d];\n"
            "    %s v%d = 0;\n"
            "    if (bpf_probe_read(&v%d, sizeof v%d, &p%d->%s) != 0)\n"
            "        return 0ull;\n" % (struct, k, struct, n, ct, k, k, k, k, field))
    return sd, code, "(__u64)v%d" % k


def codegen(expr):
    section, hook, pred, action = parse(expr)
    fn = _ident(expr, hook, action)
    ctx = "ls_ctx_exit" if section == "fexit" else "ls_ctx_generic"
    ctxdef = ("struct ls_ctx_exit { __u64 arg[5]; __u64 ret; };" if section == "fexit"
              else "struct ls_ctx_generic { __u64 arg[5]; };")
    head = [
        "/* generated by tmmtrace from:  %s */" % expr,
        "typedef unsigned char __u8; typedef unsigned short __u16;",
        "typedef unsigned int __u32; typedef unsigned long long __u64;",
        "static long (*bpf_probe_read)(void *, __u32, const void *) = (void *)4;",
    ]
    structs, code, k = [], [], 0

    def take(tok):
        nonlocal k
        sd, cd, ex = _read(resolve_value(hook, tok), k)
        if sd and sd not in structs:
            structs.append(sd)
        if cd:
            code.append(cd)
        k += 1
        return ex

    # optional predicate gates a count()
    cond = None
    if pred:
        pm = _PRED.match(pred)
        if not pm:
            raise DslError("predicate must be  <value> <op> <int>")
        lhs, op, rhs = pm.group(1).strip(), pm.group(2), pm.group(3)
        cond = "%s %s %s" % (take(lhs), op, rhs)

    if _COUNT.match(action):
        # A zero-relocation program is refused by the CO-RE relocator (rc=-3), so an
        # unpredicated count() would not load. Add a harmless canary field read of
        # arg0's struct so the object carries a relocation; the value is ignored.
        if not cond and not code:
            for i, (pn, kind, struct, _d) in enumerate(hook_params(hook) or []):
                if kind == "blob" and struct and _types().get(struct):
                    fld = next(iter(_types()[struct]))
                    ct = CTYPE[_types()[struct][fld]]
                    sd = "struct %s { %s %s; } __attribute__((preserve_access_index));" % (struct, ct, fld)
                    if sd not in structs:
                        structs.append(sd)
                    # relocation-only canary: read it, DO NOT gate on the result, so
                    # count() returns 1 on every invocation regardless of the read.
                    code.append("    struct %s *pc = (struct %s *)c->arg[%d];\n"
                                "    %s vc = 0;\n"
                                "    (void)bpf_probe_read(&vc, sizeof vc, &pc->%s);  /* canary: relocation only */\n"
                                % (struct, struct, i, ct, fld))
                    break
        ret = ("    return (%s) ? 1ull : 0ull;   /* SAFE_RETURN on match; safe_returns = count */" % cond
               if cond else
               "    return 1ull;                 /* count every invocation (safe_returns) */")
    else:
        hm = _HIST.match(action)
        vtok = hm.group(1) if hm else action     # hist(<value>) or a bare <value>
        ex = take(vtok)
        if cond:
            ret = "    if (!(%s)) return 0ull;\n    return %s;   /* value; host samples it */" % (cond, ex)
        else:
            ret = "    return %s;                 /* value; host samples it */" % ex

    lines = head + structs + [ctxdef, "",
                              '__attribute__((section("%s/%s"), used))' % (section, hook),
                              "__u64 %s(struct %s *c)" % (fn, ctx), "{"] \
        + code + [ret, "}", ""]
    return "\n".join(l for l in lines if l is not None), fn, section, hook


def _ident(expr, hook, action):
    import hashlib
    tag = re.sub(r"[^A-Za-z0-9_]", "_", action)[:12].strip("_") or "probe"
    h = hashlib.sha1(expr.encode()).hexdigest()[:6]     # unique per full expr (section+pred+action)
    return "tt_%s_%s_%s" % (hook, tag, h)


def verify(expr):
    src, fn, section, hook = codegen(expr)
    if not os.path.exists(PREVAIL):
        sys.exit("*** PREVAIL not found at %s (run in the dev sandbox)" % PREVAIL)
    with tempfile.TemporaryDirectory() as d:
        c, o = os.path.join(d, fn + ".bpf.c"), os.path.join(d, fn + ".bpf.o")
        open(c, "w").write(src)
        cc = subprocess.run([CLANG, "-O2", "-g", "-target", "bpf", "-c", c, "-o", o],
                            capture_output=True, text=True)
        if cc.returncode != 0:
            print(src)
            sys.exit("*** clang failed:\n" + cc.stderr)
        sec = "%s/%s" % (section, hook)
        pv = subprocess.run([PREVAIL, o, sec, "--termination", "--allow-division-by-zero"],
                            capture_output=True, text=True)
        ok = pv.returncode == 0
        print("program : %s   section %s" % (fn, sec))
        print("clang   : ok")
        print("PREVAIL : %s" % ("VERIFIED" if ok else "REFUSED"))
        for l in (pv.stdout or pv.stderr or "").strip().splitlines()[:3]:
            print("          %s" % l)
        return 0 if ok else 1


def build_prog(expr, outdir):
    """gen -> verify(PREVAIL) -> clang -> <outdir>/<fn>.bpf.o + <fn>.meta.json.
    Signing is a separate F5-key step (sign_shield.py); this is the dev/CI half."""
    src, fn, section, hook = codegen(expr)
    os.makedirs(outdir, exist_ok=True)
    c = os.path.join(outdir, fn + ".bpf.c")
    o = os.path.join(outdir, fn + ".bpf.o")
    open(c, "w").write(src)
    cc = subprocess.run([CLANG, "-O2", "-g", "-target", "bpf", "-c", c, "-o", o],
                        capture_output=True, text=True)
    if cc.returncode != 0:
        sys.exit("*** clang failed:\n" + cc.stderr)
    sec = "%s/%s" % (section, hook)
    if os.path.exists(PREVAIL):
        pv = subprocess.run([PREVAIL, o, sec, "--termination", "--allow-division-by-zero"],
                            capture_output=True, text=True)
        if pv.returncode != 0:
            sys.exit("*** PREVAIL REFUSED %s:\n%s" % (fn, pv.stdout or pv.stderr))
        verified = True
    else:
        verified = False
    is_count = bool(_COUNT.match(parse(expr)[3]))
    json.dump({"expr": expr, "fn": fn, "section": sec, "hook": hook,
               "kind": "count" if is_count else "value", "verified": verified},
              open(os.path.join(outdir, fn + ".meta.json"), "w"))
    print("built %s  (%s)  section %s  verified=%s" % (o, "count" if is_count else "value", sec, verified))
    return o, fn, sec, hook


def hist_stdin():
    """bpftrace-style log2 histogram of whitespace-separated integers on stdin."""
    vals = [int(x) for x in sys.stdin.read().split() if x.lstrip("-").isdigit()]
    if not vals:
        print("(no values)")
        return 0
    buckets = {}
    for v in vals:
        b = v.bit_length() - 1 if v > 0 else -1     # log2 bucket; <=0 in one bin
        buckets[b] = buckets.get(b, 0) + 1
    hi = max(buckets.values())
    lo = min(buckets), max(buckets)
    print("count %d  min %d  max %d" % (len(vals), min(vals), max(vals)))
    for b in range(lo[0], lo[1] + 1):
        n = buckets.get(b, 0)
        rng = "(<=0)" if b < 0 else "[%d, %d)" % (1 << b, 1 << (b + 1))
        bar = "@" * int(40 * n / hi) if hi else ""
        print("  %-14s %6d |%s" % (rng, n, bar))
    return 0


def list_hooks(glob):
    try:
        d = json.load(open(HOOKMAP))
    except Exception:
        sys.exit("*** hook map not found at %s (set $LS_HOOKMAP)" % HOOKMAP)
    hp = d.get("hook_points", d if isinstance(d, list) else [])
    names = sorted(h["name"] for h in hp if fnmatch.fnmatch(h.get("name", ""), glob))
    for n in names:
        print(n)
    print("# %d hook(s) match %r" % (len(names), glob), file=sys.stderr)
    return 0


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    cmd = argv[1]
    try:
        if cmd == "gen":
            sys.stdout.write(codegen(argv[2])[0]); return 0
        if cmd == "verify":
            return verify(argv[2])
        if cmd == "build":
            build_prog(argv[2], argv[3] if len(argv) > 3 else "."); return 0
        if cmd == "hist":
            return hist_stdin()
        if cmd == "list":
            return list_hooks(argv[2] if len(argv) > 2 else "*")
        sys.exit(__doc__)
    except DslError as e:
        sys.exit("*** DSL error: %s\n    in: %s" % (e, argv[2] if len(argv) > 2 else ""))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
