#!/usr/bin/env python3
"""Screen each finding: is the value the fix checks derivable from the function's ARGUMENTS at entry?

WHY THIS IS THE FRONT FILTER. Our hook sits at the patched function entry, so a predicate can only
see the arguments as the function received them. A fix whose check reads a value the function
COMPUTES cannot be imposed from entry, no matter how simple the check looks. B22F115D looked like
the best candidate found until the source showed the packet is received inside the function --- this
screen rejects that shape mechanically, before anyone spends an afternoon on it.

THIS IS A SCREEN, NOT A VERDICT. It classifies by identifier provenance in the guard expression and
says REVIEW when it cannot tell. A REVIEW is not a pass.

TWO KNOWN BIASES, measured on the 2026-08-25 run (ENTRY=0 PARTIAL=7 REVIEW=1 INSIDE=15
NOT-A-GUARD=9) --- read the classes with these in mind rather than the totals:

  IT IS STRICTER THAN THE MECHANISM. The host builder dereferences pointers before the program
  runs, by design, so a guard reading `param->field` is expressible even though this screen calls
  it PARTIAL. PARTIAL is therefore the CANONICAL candidate class here, not a weaker one.

  IT PRODUCES FALSE NEGATIVES ON RECOMPUTABLE LOCALS. D5FCBB04 is marked INSIDE because its guard
  reads `len`, a local --- but `len` is computed from the parameters oid_len and oid_value_len plus
  two sizeof constants, so a predicate can recompute it at entry. Any INSIDE whose local is a pure
  function of the parameters is a candidate this screen will reject.

  And NOT-A-GUARD mixes two things: fixes that genuinely are not guards (A3009782 changes an
  allocation size, 50189B90 reorders around a free, DE078BFB swaps sprintf for vsnprintf) and
  guards this regex misses because they clamp rather than branch (DF46CA3F clamps field->val.len).
"""
import re, subprocess, sys, os

TREE = os.path.expanduser("~/code/tmm")
INDEX = os.path.expanduser("~/lstools/hook-index.tsv")

def sh(*a, cwd=TREE):
    return subprocess.run(a, cwd=cwd, capture_output=True, text=True).stdout

log = open("/tmp/allog.txt").read().splitlines()
hashes = [h.strip() for h in open("/tmp/allh.txt") if h.strip()]

armable = set()
if os.path.exists(INDEX):
    for line in open(INDEX):
        if line and not line.startswith("#"):
            armable.add(line.split("\t")[0])

def commit_for(h):
    for l in log:
        if re.search(r"BIGIP-(tmm|tmos-source)-%s" % h, l):
            return l.split("|")[0]
    return None

def params_of(path, func):
    """Parameter names from the definition in the tree at HEAD."""
    txt = sh("git", "show", "HEAD:%s" % path)
    if not txt:
        return None
    m = re.search(r"^[A-Za-z_][\w \*]*\n?%s\s*\(([^;{]*?)\)\s*\{" % re.escape(func),
                  txt, re.M | re.S)
    if not m:
        m = re.search(r"%s\s*\(([^;{]*?)\)\s*\{" % re.escape(func), txt, re.S)
    if not m:
        return None
    names = []
    for part in m.group(1).split(","):
        w = re.findall(r"[A-Za-z_]\w*", part)
        if w and w[-1] not in ("void",):
            names.append(w[-1])
    return names

rows = []
for h in hashes:
    C = commit_for(h)
    if not C:
        rows.append((h, "-", "-", "-", "NO-COMMIT", "-")); continue
    diff = sh("git", "show", "--format=", "-U0", C)
    # source files only; a fix that only touches tests is not a fix we can screen
    cur, best = None, []
    for line in diff.splitlines():
        m = re.match(r"^\+\+\+ b/(.*)", line)
        if m:
            cur = m.group(1)
            continue
        m = re.match(r"^@@ .*@@\s*(.*)$", line)
        if m:
            ctx = m.group(1); continue
        if line.startswith("+") and not line.startswith("+++") and cur and "/test" not in cur:
            if re.search(r"\bif\s*\(", line) and re.search(r"[<>]|>=|<=|==|!=", line):
                best.append((cur, ctx if 'ctx' in dir() else "", line.strip()))
    if not best:
        rows.append((h, "test-only or no guard", "-", "-", "NOT-A-GUARD", "-")); continue

    path, ctx, guard = best[0]
    fm = re.search(r"([A-Za-z_]\w*)\s*\(", ctx or "")
    func = fm.group(1) if fm else "?"
    ps = params_of(path, func) if func != "?" else None
    ids = [i for i in re.findall(r"[A-Za-z_]\w*", guard)
           if i not in ("if", "sizeof", "return", "goto", "NULL", "struct", "unsigned", "int")]
    ids = [i for i in ids if not i.isupper()]           # macros/constants are build-derivable
    if ps is None:
        verdict = "REVIEW"
    elif not ids:
        verdict = "ENTRY"                               # pure constants
    elif all(i in ps for i in ids):
        verdict = "ENTRY"
    elif any(i in ps for i in ids):
        verdict = "PARTIAL"
    else:
        verdict = "INSIDE"
    rows.append((h, path.replace("src/", ""), func,
                 guard[:44], verdict, "yes" if func in armable else "no"))

order = {"ENTRY": 0, "PARTIAL": 1, "REVIEW": 2, "INSIDE": 3, "NOT-A-GUARD": 4, "NO-COMMIT": 5}
rows.sort(key=lambda r: (order.get(r[4], 9), r[1]))
print("  %-9s %-11s %-4s %-34s %-26s %s" % ("HASH", "VERDICT", "ARM", "FUNCTION", "GUARD", "FILE"))
for h, path, func, guard, verdict, arm in rows:
    print("  %-9s %-11s %-4s %-34s %-26s %s" % (h, verdict, arm, func[:34], guard[:26], path[:44]))
from collections import Counter
print("\n  " + "  ".join("%s=%d" % (k, v) for k, v in Counter(r[4] for r in rows).items()))
