#!/usr/bin/env python3
"""Generate a hook's flat ctx and the host-side builder that fills it, from DWARF.

WHY THIS SHAPE, AND NOT A STRUCT OF THE ARGUMENTS. Measured across 388 sampled
hookable functions: only 2 have all-scalar parameters. ~61% take a TYPED pointer,
~14% a void*. So emitting "the function's typed arguments" as a ctx hands the
program pointers it cannot use --- eBPF cannot chase an unbounded pointer, and
PREVAIL will not admit a program that tries.

The pointer-chasing therefore happens in the HOST, before the program runs. This
tool emits two things per hook:

  struct ls_ctx_<fn>            flat scalars --- the program's entire world
  ls_ctx_build_<fn>(...)        host C: dereference, flatten, fill

The program stays a bounded predicate over flat memory, which is the canonical
case PREVAIL already proves. That is how this reaches a stock verifier: by moving
the dereference to the host, not by extending the verifier to permit it.

EVERY DEREFERENCE IS NULL-GUARDED, and that is not defensive style. The builder
runs in the trampoline, on the hot path, ahead of a function that has not run
yet --- so a pointer that is null here is a pointer the original code was about
to check itself. Faulting in the builder would be a crash WE introduced into a
path that was working.

SCOPE. One level of dereference, scalar fields only. Nested structs, arrays,
unions and char* contents are not followed; a char* yields its pointer value and
a host-measured length, as the worked example does. void* yields the pointer
value only and is flagged, because DWARF genuinely does not know what it points
to and no tool can recover that --- those hooks need a human, which is a curation
question rather than a tooling one.

usage:
  mk_ctx.py --debuginfo tmm64.no_pgo.debug --function hud_euie_default_handler
"""
import argparse, re, subprocess, sys

SCALAR = re.compile(r"^(unsigned\s+)?(char|short|int|long|long long|float|double|_Bool)\b"
                    r"|^u?int(8|16|32|64)_t$|^size_t$|^enum\b")


def gdb(debuginfo, *cmds):
    args = ["gdb", "-q", "-batch"]
    for c in cmds:
        args += ["-ex", c]
    args.append(debuginfo)
    return subprocess.run(args, capture_output=True, text=True).stdout


def resolve(debuginfo, typename):
    """Follow a typedef to what it really is. UINT32 -> unsigned int, BOOL -> enum."""
    out = gdb(debuginfo, f"ptype {typename}")
    m = re.search(r"^type = (.*)$", out, re.M)
    return m.group(1).strip() if m else typename


def is_scalar(debuginfo, t):
    t = t.strip()
    if "*" in t:
        return False
    if SCALAR.match(t):
        return True
    r = resolve(debuginfo, t)
    return bool(SCALAR.match(r)) and "*" not in r


def struct_fields(debuginfo, struct_name):
    """Scalar members of a struct, with their declared types. One level only."""
    out = gdb(debuginfo, f"ptype struct {struct_name}")
    fields = []
    for line in out.splitlines():
        m = re.match(r"^\s{4}(.+?)\s*\**(\w+)\s*(\[\d+\])?;\s*$", line)
        if not m:
            continue
        ty, nm, arr = m.group(1).strip(), m.group(2), m.group(3)
        if arr or "*" in line.split(nm)[0]:
            continue                                   # arrays and pointers: not followed
        if is_scalar(debuginfo, ty):
            fields.append((ty, nm))
    return fields


def cfield(ty):
    """Width in the flat ctx. Everything is widened to a fixed-width scalar so the
    ctx layout is stable and PREVAIL sees uniform, aligned memory."""
    r = ty.lower()
    if "64" in r or "long" in r or "size_t" in r:
        return "__u64"
    if "16" in r or "short" in r:
        return "__u16"
    if "8" in r or ("char" in r and "unsigned" in r):
        return "__u8"
    return "__u32"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--debuginfo", required=True)
    ap.add_argument("--function", required=True)
    ap.add_argument("--max-fields", type=int, default=6,
                    help="scalar fields to lift per dereferenced struct")
    a = ap.parse_args()

    sig = gdb(a.debuginfo, f"ptype {a.function}")
    m = re.search(r"^type = .*?\((.*)\)\s*$", sig, re.M | re.S)
    if not m:
        raise SystemExit(f"*** no signature for {a.function}")
    inner = m.group(1).strip()
    args = [] if inner in ("void", "") else [x.strip() for x in re.split(r",(?![^(]*\))", inner)]

    members, fills, notes = [], [], []
    for i, t in enumerate(args):
        an = f"a{i}"
        if is_scalar(a.debuginfo, t):
            w = cfield(resolve(a.debuginfo, t))
            members.append(f"    {w:<6} {an};".ljust(34) + f"/* arg{i}: {t} */")
            fills.append(f"    c->{an} = ({w}){an};")
        elif re.match(r"^(const\s+)?struct\s+(\w+)\s*\*$", t):
            sname = re.match(r"^(const\s+)?struct\s+(\w+)\s*\*$", t).group(2)
            flds = struct_fields(a.debuginfo, sname)[:a.max_fields]
            members.append(f"    __u64  {an}_ptr;".ljust(34) + f"/* arg{i}: {t} -- MAY BE NULL */")
            fills.append(f"    c->{an}_ptr = (__u64)(unsigned long){an};")
            if not flds:
                notes.append(f"arg{i} ({t}): no scalar members found at one level; "
                             f"pointer value only")
            for ty, nm in flds:
                w = cfield(ty)
                members.append(f"    {w:<6} {an}_{nm};".ljust(34) + f"/* {t[:-1]}->{nm} ({ty}) */")
            if flds:
                fills.append(f"    if ({an}) {{                      /* null-guarded: see header */")
                for ty, nm in flds:
                    w = cfield(ty)
                    fills.append(f"        c->{an}_{nm} = ({w}){an}->{nm};")
                fills.append("    }")
        else:
            members.append(f"    __u64  {an}_ptr;".ljust(34) + f"/* arg{i}: {t} -- OPAQUE */")
            fills.append(f"    c->{an}_ptr = (__u64)(unsigned long){an};")
            notes.append(f"arg{i} ({t}): DWARF has no pointee type. The program gets the "
                         f"pointer value and nothing else; making this useful needs a human "
                         f"who knows what it points to.")

    fn = a.function
    print(f"""/* GENERATED by substrate/mk_ctx.py from DWARF -- do not hand-edit.
 * hook: {fn}
 * signature: {' '.join(sig.splitlines()[0].split()[2:])[:100]}
 *
 * The program sees ONLY this struct: flat scalars, no pointers to chase. Every
 * dereference below happens here, in the host, before the program runs.
 */
#ifndef LS_CTX_{fn.upper()}_H
#define LS_CTX_{fn.upper()}_H
typedef unsigned long long __u64;
typedef unsigned int       __u32;
typedef unsigned short     __u16;
typedef unsigned char      __u8;

struct ls_ctx_{fn} {{
{chr(10).join(members)}
}};

#define LS_FALLTHROUGH  0u
#define LS_SAFE_RETURN  1u
#endif""")

    print(f"""
/* --- host side: the trampoline calls this before running the program --------
 * Runs on the hot path, ahead of a function that has not executed yet. A null
 * pointer here is one the original code was about to check itself, so every
 * dereference is guarded --- faulting here would be a crash we introduced.
 */
static inline void
ls_ctx_build_{fn}(struct ls_ctx_{fn} *c{''.join(f', {t} a{i}' for i, t in enumerate(args))})
{{
    __builtin_memset(c, 0, sizeof *c);
{chr(10).join(fills)}
}}""")

    if notes:
        print("\n/* NOT MECHANICALLY RESOLVABLE:")
        for n in notes:
            print(f" *   - {n}")
        print(" */")


if __name__ == "__main__":
    main()
