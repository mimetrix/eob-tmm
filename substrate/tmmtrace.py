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
    <pred>   := <term> [ ('&&'|'||') <term> ]*  # all && or all || --- never mixed
    <term>   := <value> <op> <int>              # op: == != < > <= >=   (gates count())
    <action> := 'count' | 'count()'             # -> SAFE_RETURN on match; host safe_returns
              | 'hist' '(' <value> ')'          # -> returns the value; tmmtrace buckets it
              | 'shield' '(' <safe value> ')'   # ENFORCE: MATCH -> SAFE_RETURN, host skips the
                                                #   body and returns <safe value>. Predicate REQUIRED.
                                                #   Signed mode-ceiling=enforce; arming is a gated step.
              | <value>                          # raw: return the value/field
    <value>  := 'args.' <field>                  # resolved via signatures.tsv + BTF catalog
              | 'arg' <N> [ '.' <field> ]        # arg N, or a field of the struct at arg N
              | <struct> '(' 'arg' <N> ')' '.' <field> [':'<ty>]   # explicit (no catalog)

    A leading '@name =' before count()/hist() is accepted and ignored (bpftrace habit).

SUBCOMMANDS
    tmmtrace.py gen    '<expr>'          # print the generated CO-RE .bpf.c
    tmmtrace.py verify '<expr>'          # gen -> clang -> PREVAIL, report the verdict
    tmmtrace.py hist                     # read values on stdin -> a log2 histogram
    tmmtrace.py list '<glob>' [--mode observe|enforce] [--path hot|cold] [--armable] [--no-noise]

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
# multi-hop: args.a.b.c / argN.a.b.c --- a pointer chase through connection state, which is
# where most real CVE preconditions live (e.g. sc->sp->hs->ks_ext_brainpoolp256_sz).
_ARGSPATH = re.compile(r"^args\.([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)$")
_ARGNPATH = re.compile(r"^arg([0-4])\.([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)$")
_COUNT = re.compile(r"^(?:@\w+\s*=\s*)?count(?:\(\))?$")
_HIST = re.compile(r"^(?:@\w+\s*=\s*)?hist\(\s*(.+?)\s*\)$")
_SHIELD = re.compile(r"^shield\(\s*(.+?)\s*\)$")   # enforce: MATCH -> SAFE_RETURN(safe value)
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


def _ptr_edges():
    """{struct: {field: target_struct}} --- the pointer graph, from the BTF catalog."""
    return _types().get("__ptr_targets__", {})


def resolve_path(hook, argidx, parts):
    """Resolve args.a.b.c to a chain of reads.

    -> ('chain', arg_index, [(struct, field, 'ptr', target), ..., (struct, field, 'scalar', ctype)])

    Every hop but the last must be a POINTER field whose target the catalog knows; the last
    must be a scalar. Tries each struct-typed argument unless one was named explicitly.
    """
    params = hook_params(hook)
    if params is None:
        raise DslError("no signature for '%s' (need %s)" % (hook, SIGS))
    starts = [(i, st) for i, (pn, kind, st, _d) in enumerate(params)
              if kind == "blob" and st and (argidx is None or i == argidx)]
    if not starts:
        raise DslError("no struct-typed argument to start '%s' from at %s"
                       % (".".join(parts), hook))
    tried = []
    for i, s0 in starts:
        hops, cur, ok = [], s0, True
        for j, f in enumerate(parts):
            if j == len(parts) - 1:
                ty = _types().get(cur, {}).get(f)
                if not ty:
                    tried.append("%s has no scalar '%s'" % (cur, f)); ok = False; break
                hops.append((cur, f, "scalar", CTYPE[ty]))
            else:
                tgt = _ptr_edges().get(cur, {}).get(f)
                if not tgt:
                    tried.append("%s has no pointer field '%s'" % (cur, f)); ok = False; break
                hops.append((cur, f, "ptr", tgt))
                cur = tgt
        if ok:
            return ("chain", i, hops)
    raise DslError("could not resolve path '%s' at %s (%s). Needs pointer targets in the "
                   "catalog --- regenerate types.json with gen_type_catalog.py"
                   % (".".join(parts), hook, "; ".join(tried[:3])))


def resolve_value(hook, tok):
    """Normalize a <value> token to ('scalar', N) | ('field', struct, N, field, ty)."""
    m = _ARG.match(tok)
    if m:
        return ("scalar", int(m.group(1)))
    fe = _FIELD.match(tok)
    if fe:
        return ("field", fe.group(1), int(fe.group(2)), fe.group(3), fe.group(4) or "u64")
    ap, np = _ARGSPATH.match(tok), _ARGNPATH.match(tok)
    if ap or np:
        parts = (np.group(2) if np else ap.group(1)).split(".")
        return resolve_path(hook, int(np.group(1)) if np else None, parts)
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


def _read(val, k, reg):
    """C to read a resolved <value> into a fresh var. Returns (code, expr).

    `reg(struct, field, ctype)` registers a field the program must see. Fields are
    ACCUMULATED PER STRUCT and emitted as one declaration each --- emitting one
    declaration per (struct, field) pair produced `error: redefinition of 'xbuf'` the
    moment two fields of the same struct were referenced, which a multi-hop chain does
    by construction. `preserve_access_index` means the local layout is irrelevant:
    clang emits a CO-RE relocation per field and the loader patches the real offset.
    """
    if val[0] == "scalar":
        return "", "c->arg[%d]" % val[1]

    if val[0] == "chain":
        _, n, hops = val
        lines, src = [], "c->arg[%d]" % n
        for h, (struct, field, kind, extra) in enumerate(hops):
            pv = "p%d_%d" % (k, h)
            reg(struct, field, "__u64" if kind == "ptr" else extra)
            lines.append("    struct %s *%s = (struct %s *)(%s);" % (struct, pv, struct, src))
            if kind == "ptr":
                hv = "h%d_%d" % (k, h)
                lines.append("    __u64 %s = 0;" % hv)
                lines.append("    if (bpf_probe_read(&%s, sizeof %s, &%s->%s) != 0 || %s == 0)"
                             % (hv, hv, pv, field, hv))
                lines.append("        return 0ull;   /* unreadable or NULL hop --- decline */")
                src = hv
            else:
                vv = "v%d" % k
                lines.append("    %s %s = 0;" % (extra, vv))
                lines.append("    if (bpf_probe_read(&%s, sizeof %s, &%s->%s) != 0)"
                             % (vv, vv, pv, field))
                lines.append("        return 0ull;")
                return "\n".join(lines) + "\n", "(__u64)%s" % vv
        raise DslError("chain did not end in a scalar")

    _, struct, n, field, ty = val
    ct = CTYPE[ty]
    reg(struct, field, ct)
    code = ("    struct %s *p%d = (struct %s *)c->arg[%d];\n"
            "    %s v%d = 0;\n"
            "    if (bpf_probe_read(&v%d, sizeof v%d, &p%d->%s) != 0)\n"
            "        return 0ull;\n" % (struct, k, struct, n, ct, k, k, k, k, field))
    return code, "(__u64)v%d" % k


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
    sfields, code, k = {}, [], 0        # struct -> {field: ctype}, accumulated

    def reg(struct, field, ctype):
        sfields.setdefault(struct, {})[field] = ctype

    def take(tok):
        nonlocal k
        cd, ex = _read(resolve_value(hook, tok), k, reg)
        if cd:
            code.append(cd)
        k += 1
        return ex

    # Optional predicate, one or more terms joined by && or ||.
    #
    # WHY CONJUNCTION IS NOT A LUXURY. A real vulnerability is usually the CONJUNCTION of a
    # state and a value, and predicating on only one half is not a weaker shield --- it is a
    # different, wrong one. Measured case (2026-09-02): the brainpool CVE's stale size reads
    # ~65535 on EVERY TLS connection, not only brainpool ones, so a size-only predicate at
    # ssl_hs_compute_key would SAFE_RETURN on all TLS traffic. That is an outage, not a
    # mitigation. The correct predicate is "negotiated curve is brainpool AND size implausible".
    #
    # && and || are never MIXED in one predicate --- mixing them means the reader has to know
    # this tool's precedence, and a misread predicate on an enforce shield takes traffic down.
    # Refuse instead, and say so.
    cond = None
    if pred:
        has_and, has_or = "&&" in pred, "||" in pred
        if has_and and has_or:
            raise DslError("predicate mixes '&&' and '||'; precedence is deliberately not "
                           "guessed here --- use one or the other, or split into two probes")
        join = "||" if has_or else "&&"
        terms = [t.strip() for t in re.split(r"\|\||&&", pred) if t.strip()]
        if not terms:
            raise DslError("empty predicate")
        parts = []
        for t in terms:
            pm = _PRED.match(t)
            if not pm:
                raise DslError("predicate term must be  <value> <op> <int>  (got %r)" % t)
            lhs, op, rhs = pm.group(1).strip(), pm.group(2), pm.group(3)
            parts.append("%s %s %s" % (take(lhs), op, rhs))
        # Reads for every term are emitted before the test, so a term whose read fails
        # declines the whole predicate --- conservative, and never a dereference.
        cond = (" %s " % join).join("(%s)" % x for x in parts) if len(parts) > 1 else parts[0]

    is_shield = bool(_SHIELD.match(action))
    if _COUNT.match(action) or is_shield:
        if is_shield and not cond:
            raise DslError("shield(...) needs a predicate to gate the SAFE_RETURN: "
                           "fentry/<hook> /field op N/ { shield(<safe value>) }")
        # A zero-relocation program is refused by the CO-RE relocator (rc=-3). Add a
        # harmless canary field read of arg0's struct so the object carries a relocation
        # whenever none was emitted --- an unpredicated count(), or a predicate on a scalar
        # arg (c->arg[N], no bpf_probe_read). The value is ignored either way.
        if not code:
            for i, (pn, kind, struct, _d) in enumerate(hook_params(hook) or []):
                if kind == "blob" and struct and _types().get(struct):
                    fld = next(iter(_types()[struct]))
                    ct = CTYPE[_types()[struct][fld]]
                    reg(struct, fld, ct)
                    # relocation-only canary: read it, DO NOT gate on the result, so
                    # count() returns 1 on every invocation regardless of the read.
                    code.append("    struct %s *pc = (struct %s *)c->arg[%d];\n"
                                "    %s vc = 0;\n"
                                "    (void)bpf_probe_read(&vc, sizeof vc, &pc->%s);  /* canary: relocation only */\n"
                                % (struct, struct, i, ct, fld))
                    break
        if is_shield:
            ret = ("    return (%s) ? 1ull : 0ull;   /* MATCH -> SAFE_RETURN; under ENFORCE the host "
                   "skips the body and returns the arm-time safe value */" % cond)
        else:
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

    # one declaration per struct, carrying every field the program touches
    structs = ["struct %s { %s } __attribute__((preserve_access_index));"
               % (st, " ".join("%s %s;" % (ct, f) for f, ct in sorted(fl.items())))
               for st, fl in sorted(sfields.items())]
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
    act = parse(expr)[3]
    sm = _SHIELD.match(act)
    kind = "shield" if sm else ("count" if _COUNT.match(act) else "value")
    meta = {"expr": expr, "fn": fn, "section": sec, "hook": hook,
            "kind": kind, "verified": verified}
    if sm:
        meta["safe_value"] = sm.group(1)     # arm-time LS_SHIELD_SAFE_VALUE, not baked in the program
    json.dump(meta, open(os.path.join(outdir, fn + ".meta.json"), "w"))
    print("built %s  (%s)  section %s  verified=%s" % (o, kind, sec, verified))
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


_NOISE = ('.isra.', '.part.', '.constprop.', '.cold', '.lto_priv')

def _is_noise(n):
    return (any(s in n for s in _NOISE) or n.startswith(('TCL_', '_ZN', '_ZL'))
            or '_setentry_' in n or n.startswith('__'))

def list_hooks(glob, mode=None, path=None, armable=False, no_noise=False):
    """Focus the build's hook catalog. Beyond the name <glob>, the hook map carries
    per-hook metadata (attach_mode, path_class, relocatable) --- filter on it to show
    the subset you'd actually probe rather than every symbol in the binary."""
    try:
        d = json.load(open(HOOKMAP))
    except Exception:
        sys.exit("*** hook map not found at %s (set $LS_HOOKMAP)" % HOOKMAP)
    hp = d.get("hook_points", d if isinstance(d, list) else [])

    def keep(h):
        n = h.get("name", "")
        if not fnmatch.fnmatch(n, glob):                     return False
        if mode    and h.get("attach_mode") != mode:         return False
        if path    and h.get("path_class")  != path:         return False
        if armable and not h.get("relocatable", False):      return False
        if no_noise and _is_noise(n):                        return False
        return True

    # Honesty: --mode / --path only bite if the generator populated those fields. This
    # build's map stamps everything observe/unclassified, so say so rather than return 0.
    for fld, req, flag in (("attach_mode", mode, "mode"), ("path_class", path, "path")):
        if req:
            vals = sorted(set(str(h.get(fld)) for h in hp))
            if len(vals) == 1:
                print("#   note: every hook here has %s=%s --- the map generator does not classify "
                      "%s yet, so --%s cannot narrow the set" % (fld, vals[0], fld, flag),
                      file=sys.stderr)

    kept = sorted((h for h in hp if keep(h)), key=lambda h: h.get("name",""))
    hits = [h.get("name","") for h in kept]
    # inline_status (mk_inline_status.py) turns a silent hazard into a visible one: a
    # PARTIAL hook has a pad AND inlined copies, so arming it covers the out-of-line
    # instance and misses the rest --- while `fired` climbs, which reads as coverage.
    npart = 0
    for h in kept:
        n = h.get("name","")
        if h.get("inline_status") == "partial":
            npart += 1
            print("%s   [PARTIAL: %d inlined site(s) a shield here would MISS]"
                  % (n, h.get("inline_sites", 0)))
        else:
            print(n)
    filt = " · ".join(f for f in [
        ("mode=%s" % mode) if mode else "", ("path=%s" % path) if path else "",
        "armable" if armable else "", "de-noised" if no_noise else ""] if f)
    print("# %d hook(s) match %r%s   (of %d in the build)"
          % (len(hits), glob, (" · " + filt) if filt else "", len(hp)), file=sys.stderr)
    if npart:
        print("#   *** %d PARTIALLY INLINED --- arming those does NOT cover every call site;"
              " the counter still climbs. See engine-hard-problems.md 3.1" % npart,
              file=sys.stderr)
    elif not any("inline_status" in h for h in hp):
        print("#   (no inline_status in this map --- run substrate/mk_inline_status.py against"
              " the SHIPPED binary; without it a partially-inlined hook looks complete)",
              file=sys.stderr)
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
            g, mode, path, armable, no_noise = "*", None, None, False, False
            it = iter(argv[2:])
            for a in it:
                if   a == "--mode":     mode = next(it)
                elif a == "--path":     path = next(it)
                elif a == "--armable":  armable = True
                elif a == "--no-noise": no_noise = True
                elif not a.startswith("-"): g = a
            return list_hooks(g, mode, path, armable, no_noise)
        sys.exit(__doc__)
    except DslError as e:
        sys.exit("*** DSL error: %s\n    in: %s" % (e, argv[2] if len(argv) > 2 else ""))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
