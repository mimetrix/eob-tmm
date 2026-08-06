#!/usr/bin/env python3
"""Compile the candidate skeletons in ../development-scope-code.md.

Those skeletons are the exemplar an engineer reads to see the shape of each
development-scope item. Until this existed they were prose: fenced C that no
compiler had read. That is how the JIT typedef came to be written as uBPF's
2-argument BasicJitMode form while the design requires the 4-argument extended
form with a per-core stack — a defect a human reviewer caught and a compiler
would have caught for nothing.

So each ```c block is extracted and syntax-checked against shield_abi.h,
example_hook_ctx.h and platform_stub.h. Blocks that are deliberately fragments
(a struct field list, a few illustrative lines) are wrapped so they still parse;
blocks that declare functions are compiled as-is.

What a pass means: the skeletons agree with the ABI header on types, field
names, function arity and signatures. It does NOT mean they run — every platform
symbol is a no-op stub (see platform_stub.h) and nothing here is linked.
"""

import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DOC = os.path.join(os.path.dirname(HERE), "development-scope-code.md")
CC = os.environ.get("CC", "cc")

PROLOGUE = '#include "platform_stub.h"\n#include "example_hook_ctx.h"\n'

# A block that never declares a function or a type is a fragment — an excerpt of
# a body, or a field list. Wrapping it in a function lets the compiler check the
# statements without pretending the block was ever a translation unit.
DECL = re.compile(r"^\s*(?:static|extern|struct\s+\w+\s*\{|enum\s+\w+\s*\{|"
                  r"typedef|#|int\s+\w+\s*\(|void\s+\w+\s*\(|uint\d+_t\s+\w+\s*\()",
                  re.M)


def blocks():
    with open(DOC, encoding="utf-8") as fh:
        md = fh.read()
    out = []
    for m in re.finditer(r"```c\n(.*?)```", md, re.S):
        line = md[:m.start()].count("\n") + 1
        out.append((line, m.group(1)))
    return out


def heading_for(line):
    """Nearest preceding `## Item ...` heading, for a useful label."""
    with open(DOC, encoding="utf-8") as fh:
        lines = fh.readlines()
    for i in range(min(line, len(lines)) - 1, -1, -1):
        s = lines[i].strip()
        if s.startswith("#") and ("Item" in s or "shield program" in s):
            return re.sub(r"^#+\s*", "", s)[:44]
    return "(no heading)"


def main(argv):
    verbose = "-v" in argv[1:]
    bs = blocks()
    if not bs:
        print("FAIL  check_skeletons  no ```c blocks found in %s"
              % os.path.basename(DOC))
        return 1

    failed = 0
    skipped = []
    with tempfile.TemporaryDirectory() as td:
        for n, (line, body) in enumerate(bs, 1):
            # An explicit opt-out, and it is never silent: a block the document
            # itself marks as illustrative (a retired form kept for contrast)
            # must say so in the block, and gets reported below either way.
            m = re.search(r"not-compiled:\s*(.+)", body)
            if m:
                skipped.append((n, line, m.group(1).strip().rstrip("*/ ").strip()))
                continue
            fragment = not DECL.search(body)
            src = PROLOGUE + (
                "static void _frag_%d(void){\n%s\n}\n" % (n, body)
                if fragment else body)
            path = os.path.join(td, "blk%02d.c" % n)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(src)
            r = subprocess.run(
                [CC, "-fsyntax-only", "-std=c11",
                 "-Wimplicit-function-declaration", "-I", HERE, path],
                capture_output=True, text=True)
            errs = [l for l in r.stderr.splitlines() if ": error:" in l]
            if errs:
                failed += 1
                print("FAIL  block %d (line %d, %s) — %d error(s)%s"
                      % (n, line, heading_for(line), len(errs),
                         " [fragment]" if fragment else ""))
                for e in errs[:6]:
                    print("        %s" % e.split(": error: ")[-1][:96])
            elif verbose:
                print("      block %d (line %d, %s)%s ok"
                      % (n, line, heading_for(line),
                         " [fragment]" if fragment else ""))

    for n, line, why in skipped:
        print("      block %d (line %d) NOT COMPILED — %s" % (n, line, why[:88]))

    if failed:
        print("FAIL  check_skeletons  %d of %d block(s) do not compile"
              % (failed, len(bs)))
        return 1
    print("ok    check_skeletons  (%d of %d C blocks compile against the ABI "
          "header + platform stubs, %d opted out above; nothing is linked or run)"
          % (len(bs) - len(skipped), len(bs), len(skipped)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
