#!/usr/bin/env python3
"""Compile the candidate shields in shields/ and assert PREVAIL's verdict on each.

Every program here has an EXPECTED verdict, and a surprise in either direction is a
failure. A program that should pass and does not means the authoring chain broke; a
program that should be rejected and passes means a gate stopped working, which is the
dangerous direction.

Skips (does not fail) when clang lacks a BPF target or prevail is not built, since both
are environment-dependent -- but says so rather than reporting silent success.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SHIELDS = os.path.join(HERE, "shields")
PREVAIL = os.path.join(HERE, os.pardir, "ebpf-verifier", "bin", "prevail")

# The flags item 3a says must be explicit. PREVAIL's own --help calls --termination
# "Default: ignore" and --allow-division-by-zero "Default: allow", so a verdict obtained
# without these means materially less than it appears to.
GATES = ["--termination", "--no-division-by-zero", "--strict"]

CASES = [
    # (source, section, expect_pass_with_gates, note)
    ("ls_2026_http_psm.bpf.c", "filter/http_psm_profile_name_lookup", True,
     "the CVE shield: restores the NULL check missing at http_psm.c:806"),
    ("reject_memory.bpf.c", "filter/reject_memory", False,
     "chases a raw pointer -- must fail the memory-safety gate"),
    ("reject_termination.bpf.c", "filter/reject_termination", False,
     "unbounded trip count, body -O2 cannot fold -- must fail the termination gate"),
    ("folded_loop.bpf.c", "filter/folded_loop", True,
     "PASSES because -O2 folded its loop to closed form -- verify the object, not the source"),
]


def have_bpf_clang():
    try:
        out = subprocess.check_output(["clang", "-print-targets"], stderr=subprocess.DEVNULL).decode()
        return " bpf " in out or "bpf " in out
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def main():
    if not have_bpf_clang():
        print("skip  check_shields  (clang has no BPF target here)")
        return 0
    if not os.path.exists(PREVAIL):
        print("skip  check_shields  (ebpf-verifier/bin/prevail not built)")
        return 0

    rc = 0
    for src, sec, expect_pass, note in CASES:
        srcp = os.path.join(SHIELDS, src)
        objp = os.path.join(SHIELDS, src.replace(".bpf.c", ".bpf.o"))
        comp = subprocess.run(
            ["clang", "-O2", "-g", "-target", "bpf", "-I", SHIELDS, "-c", srcp, "-o", objp],
            capture_output=True, text=True)
        if comp.returncode != 0:
            print(f"FAIL  {src}  did not compile\n{comp.stderr.strip()[:400]}")
            rc = 1
            continue
        ver = subprocess.run([PREVAIL, objp, sec] + GATES, capture_output=True, text=True)
        passed = ver.stdout.startswith("PASS")
        ok = (passed == expect_pass)
        verdict = "PASS" if passed else "FAIL"
        want = "PASS" if expect_pass else "FAIL"
        detail = (ver.stdout.strip() or ver.stderr.strip()).splitlines()
        detail = detail[0][:100] if detail else ""
        print(f"{'ok   ' if ok else 'FAIL '} {src:32s} prevail={verdict} (want {want})  {detail}")
        if not ok:
            rc = 1
            print(f"       ^ {note}")

    # The termination gate must actually be doing something: the program that fails with
    # it must pass without it. If both verdicts agree, the flag is not the thing rejecting.
    obj = os.path.join(SHIELDS, "reject_termination.bpf.o")
    if os.path.exists(obj):
        loose = subprocess.run([PREVAIL, obj, "filter/reject_termination",
                                "--no-division-by-zero", "--strict"],
                               capture_output=True, text=True)
        if loose.stdout.startswith("PASS"):
            print("ok    termination gate is load-bearing  (passes without --termination, fails with it)")
        else:
            print("FAIL  reject_termination fails even WITHOUT --termination "
                  "— something other than the termination gate is rejecting it, so this "
                  "case no longer tests what it claims to")
            rc = 1

    for f in os.listdir(SHIELDS):
        if f.endswith(".bpf.o"):
            os.unlink(os.path.join(SHIELDS, f))
    return rc


if __name__ == "__main__":
    sys.exit(main())
