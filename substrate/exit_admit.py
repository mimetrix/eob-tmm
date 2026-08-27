#!/usr/bin/env python3
"""exit_admit.py --- the admission gate for a function-EXIT (fexit) hook.

Arming an exit hook does two things an entry hook does not: it READS the return
value, and it HIJACKS the return address. Each imposes a requirement on the target
function, and both are checkable offline from the build's own binary --- so they
are gates, not hopes. This tool answers, for one function on one build:

  #5  Is the return type rax-representable?  The exit stub captures rax(:rdx). A
      float/double is returned in xmm0, and a by-value struct via a hidden pointer
      (or in memory) --- in neither case is rax "the value", so a program reading
      c->ret would get garbage. Admit only integer/enum/pointer/bool returns
      (rdx:rax for a <=16-byte integer pair). Refuse float, by-value struct/union,
      and void (nothing to read).

  #4  Can a non-local exit unwind THROUGH the frame?  The return-address hijack
      corrupts a stack unwind that walks the frame. TMM initiates no unwind ---
      P8, verified on the build box: zero _Unwind_* / __cxa_* imports --- so no TMM
      frame can sit on a completed throw->catch chain. This RE-CHECKS that property
      against the actual runtime binary. If it ever fails (TMM gains C++ exception
      handling), exit hooks are refused wholesale, because the empty-exclusion-set
      argument no longer holds and a real per-target reachability analysis is owed.

Usage:
    exit_admit.py <debug-binary> <runtime-binary> <function>

Exit status: 0 = ADMIT, 1 = REFUSE (reasons on stderr), 2 = could not decide
(missing tool / symbol) --- which is also a refusal, because an exit hook admitted
on an undecided target is exactly the failure this gate exists to prevent.
"""
import re
import subprocess
import sys

UNWIND_INITIATORS = (
    "_Unwind_RaiseException", "_Unwind_ForcedUnwind", "_Unwind_Resume",
    "__cxa_throw", "__cxa_begin_catch", "__cxa_rethrow",
)


def sh(*argv):
    return subprocess.run(argv, capture_output=True, text=True)


def return_type(debug_bin, fn):
    """The function's declared return type, via the build's DWARF. Returns the
    type string, or None if gdb or the symbol is unavailable."""
    r = sh("gdb", "-q", "-batch", "-ex", "ptype %s" % fn, debug_bin)
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line.startswith("type = "):
            continue
        body = line[len("type = "):]
        # "type = <ret> (<params>)"  --- the parameter list is the LAST top-level
        # "(...)"; everything before it is the return type. enum {...} and struct
        # names carry no parens, so rsplit on the last " (" is safe here.
        if " (" in body:
            body = body.rsplit(" (", 1)[0]
        return body.strip()
    return None


def classify_return(t):
    """(safe: bool, reason: str) for a return-type string."""
    if t is None:
        return False, "return type could not be read from DWARF"
    ts = t.strip()
    if ts.endswith("*"):
        return True, "pointer (in rax)"
    if ts == "void":
        return False, "void return --- there is no value for the exit program to read"
    if ts.startswith(("float", "double", "long double", "_Float", "__float")):
        return False, "floating-point return (xmm0, NOT rax) --- c->ret would be garbage"
    if ts.startswith(("struct ", "union ", "class ")):
        return False, ("by-value %s return (hidden pointer / memory, NOT the value) --- "
                       "refused conservatively" % ts.split()[0])
    # integer family, enums, bool
    if ts.startswith(("enum", "int", "unsigned", "char", "short", "long",
                      "signed", "_Bool", "bool", "uint", "u_int", "size_t",
                      "ssize_t", "int8", "int16", "int32", "int64",
                      "uint8", "uint16", "uint32", "uint64")):
        return True, "%s (rax)" % (ts if len(ts) < 40 else ts[:37] + "...")
    return False, "unrecognised return type %r --- refused conservatively" % ts


def unwind_clear(runtime_bin):
    """(clear: bool, found: list) --- P8: the binary must import no unwind
    initiator. Reads .dynsym for UND symbols."""
    r = sh("readelf", "--dyn-syms", runtime_bin)
    found = []
    for line in r.stdout.splitlines():
        if " UND " not in line:
            continue
        for s in UNWIND_INITIATORS:
            # match the bare symbol (may carry an @GLIBC version suffix)
            if re.search(r"\b%s\b" % re.escape(s), line):
                found.append(s)
    return (len(found) == 0), sorted(set(found))


def main(argv):
    if len(argv) != 4:
        sys.stderr.write(__doc__)
        return 2
    debug_bin, runtime_bin, fn = argv[1], argv[2], argv[3]

    rt = return_type(debug_bin, fn)
    safe_ret, why_ret = classify_return(rt)

    clear, found = unwind_clear(runtime_bin)

    print("exit-admit: %s" % fn)
    print("  #5 return type : %s --- %s" % (rt if rt else "?", why_ret))
    if clear:
        print("  #4 unwind      : clear --- TMM imports no unwind initiator (P8 holds)")
    else:
        print("  #4 unwind      : VIOLATED --- binary imports %s" % ", ".join(found))

    ok = safe_ret and clear
    if ok:
        print("  VERDICT        : ADMIT")
        return 0

    if not safe_ret:
        sys.stderr.write("*** REFUSE %s: %s\n" % (fn, why_ret))
    if not clear:
        sys.stderr.write("*** REFUSE %s: TMM now initiates unwinds (%s); the empty-exclusion-set\n"
                         "    argument (P8) no longer holds. A per-target unwind-reachability\n"
                         "    analysis is owed before any exit hook is admitted.\n"
                         % ", ".join(found))
    print("  VERDICT        : REFUSE")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
