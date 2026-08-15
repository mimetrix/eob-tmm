#!/usr/bin/env python3
"""check_pad_shapes.c mirrors ls_arm.c's shape logic. Prove they still agree.

A mirrored test is a test of the mirror. It passes happily while the real
function drifts, which is worse than no test because it reports confidence. This
extracts both helpers from each file, normalises away comments and whitespace,
and fails if the bodies differ.

ls_arm.c cannot simply be #included by the test: it pulls in /proc/self/mem
writes and x86 swap machinery, so on a non-x86 host it would not build and the
shape logic --- which is arch-independent --- would go untested exactly where it
is least likely to be noticed.
"""
import re, sys, os

HERE = os.path.dirname(os.path.abspath(__file__))

def body(path, name):
    src = open(os.path.join(HERE, path), encoding="utf-8").read()
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)          # comments
    m = re.search(r"\n" + re.escape(name) + r"\s*\(void \*fn\)\s*\{(.*?)\n\}", src, re.S)
    if not m:
        sys.exit(f"*** {path}: could not extract {name}()")
    return re.sub(r"\s+", " ", m.group(1)).strip()

rc = 0
for fn in ("ls_find_pad", "ls_find_armed"):
    a, b = body("ls_arm.c", fn), body("check_pad_shapes.c", fn)
    if a != b:
        print(f"FAIL  {fn}() has drifted between ls_arm.c and check_pad_shapes.c")
        print(f"      ls_arm.c        : {a[:150]}")
        print(f"      check_pad_shapes: {b[:150]}")
        rc = 1
if rc == 0:
    print("ok    pad-shape mirror  (ls_find_pad + ls_find_armed identical to ls_arm.c)")
sys.exit(rc)
