#!/usr/bin/env python3
"""Item 6a — does the verifier's model of the runtime match the runtime?

PREVAIL proves memory safety against a *declared* machine: a per-subprogram stack
frame size, a maximum call depth, and a set of enabled checks. uBPF then executes
the program on an *actual* machine with its own frame size, depth and checks. The
proof is only about the program that runs if those two descriptions agree.

Nothing enforces that agreement. They are separate upstream projects, versioned
independently, with no shared header and no build-time relationship. A divergence
does not fail loudly: the artifact is still authentic, the signature still
verifies, and PREVAIL's theorem is still valid --- it is just a theorem about
different hardware. That is the one failure mode a signing gate cannot catch,
which is why this has to be a check rather than a paragraph.

This reads the constants out of the two vendored trees and compares them. It does
not assume; every number printed below was parsed from source at run time, so it
stays true when either upstream moves.

Exit status:
    default   0 --- report the comparison. Divergence is printed as FINDING.
    --gate    1 if anything diverges. This is the mode a real admission
              pipeline would run: once item 6a is actually reconciled, the gate
              is what keeps it reconciled.

The split exists because the divergence below is *known and unfixed*. Making
`make check` red would mean the next person cannot tell their own breakage from
this standing finding. The gate is the same check with the exit code the build
pipeline needs.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

PREVAIL_CONFIG = os.path.join(ROOT, "ebpf-verifier", "src", "config.hpp")
UBPF_HEADER    = os.path.join(ROOT, "ubpf", "vm", "inc", "ubpf.h")
UBPF_VM        = os.path.join(ROOT, "ubpf", "vm", "ubpf_vm.c")


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def cxx_field(src, name):
    """`int name = 512;` / `bool name = false;` -> 512 / False."""
    m = re.search(r"\b(?:int|bool|unsigned|size_t)\s+" + re.escape(name)
                  + r"\s*=\s*([A-Za-z0-9_]+)\s*;", src)
    if not m:
        return None
    v = m.group(1)
    if v == "true":
        return True
    if v == "false":
        return False
    try:
        return int(v, 0)
    except ValueError:
        return v


def define(src, name):
    """`#define NAME 8` or `#define NAME (A * 512)` -> 8 / the expression."""
    m = re.search(r"^\s*#\s*define\s+" + re.escape(name) + r"\s+(.+?)\s*$",
                  src, re.M)
    if not m:
        return None
    raw = m.group(1).strip()
    try:
        return int(raw, 0)
    except ValueError:
        return raw


def struct_init(src, name):
    """`vm->name = false;` inside ubpf_create -> False."""
    m = re.search(r"->\s*" + re.escape(name) + r"\s*=\s*(true|false)\s*;", src)
    if not m:
        return None
    return m.group(1) == "true"


def resolve(expr, env):
    """Evaluate a tiny `NAME * 512` style macro body against known defines."""
    if isinstance(expr, int):
        return expr
    if not isinstance(expr, str):
        return None
    e = expr.strip().strip("()")
    for k, v in env.items():
        if isinstance(v, int):
            e = re.sub(r"\b" + re.escape(k) + r"\b", str(v), e)
    if not re.fullmatch(r"[\d\s*+\-()]+", e):
        return None
    try:
        return eval(e, {"__builtins__": {}}, {})  # noqa: S307 - digits and * + - only
    except Exception:
        return None


def main(argv):
    gate = "--gate" in argv[1:]

    prevail = read(PREVAIL_CONFIG)
    ubpf_h  = read(UBPF_HEADER)
    ubpf_c  = read(UBPF_VM)

    missing = [p for p, s in ((PREVAIL_CONFIG, prevail),
                              (UBPF_HEADER, ubpf_h),
                              (UBPF_VM, ubpf_c)) if s is None]
    if missing:
        print("SKIP  check_vm_geometry  (vendored source absent: %s)"
              % ", ".join(os.path.relpath(p, ROOT) for p in missing))
        return 0

    # ---- the declared machine (PREVAIL) --------------------------------
    p_frame  = cxx_field(prevail, "subprogram_stack_size")
    p_depth  = cxx_field(prevail, "max_call_stack_frames")
    p_term   = cxx_field(prevail, "check_for_termination")
    p_strict = cxx_field(prevail, "strict")
    p_div0   = cxx_field(prevail, "allow_division_by_zero")

    # ---- the actual machine (uBPF) -------------------------------------
    u_depth  = define(ubpf_h, "UBPF_MAX_CALL_DEPTH")
    u_total  = resolve(define(ubpf_h, "UBPF_EBPF_STACK_SIZE"),
                       {"UBPF_MAX_CALL_DEPTH": u_depth})
    u_frame  = define(ubpf_h, "UBPF_EBPF_LOCAL_FUNCTION_STACK_SIZE")
    u_bounds = struct_init(ubpf_c, "bounds_check_enabled")
    u_ub     = struct_init(ubpf_c, "undefined_behavior_check_enabled")
    u_blind  = struct_init(ubpf_c, "constant_blinding_enabled")
    u_ro     = struct_init(ubpf_c, "readonly_bytecode_enabled")

    unparsed = [n for n, v in (
        ("subprogram_stack_size", p_frame), ("max_call_stack_frames", p_depth),
        ("check_for_termination", p_term), ("strict", p_strict),
        ("allow_division_by_zero", p_div0),
        ("UBPF_MAX_CALL_DEPTH", u_depth), ("UBPF_EBPF_STACK_SIZE", u_total),
        ("UBPF_EBPF_LOCAL_FUNCTION_STACK_SIZE", u_frame),
        ("bounds_check_enabled", u_bounds),
        ("undefined_behavior_check_enabled", u_ub),
        ("constant_blinding_enabled", u_blind),
        ("readonly_bytecode_enabled", u_ro),
    ) if v is None]
    if unparsed:
        # A parse failure is itself a finding: the check has stopped tracking
        # upstream and must not be read as agreement.
        print("FAIL  check_vm_geometry  could not parse: %s" % ", ".join(unparsed))
        return 1

    findings = []

    print("      declared machine  (PREVAIL, ebpf-verifier/src/config.hpp)")
    print("        per-subprogram stack frame ....... %d bytes" % p_frame)
    print("        max call frames .................. %d" % p_depth)
    print("        implied total .................... %d bytes" % (p_frame * p_depth))
    print("      actual machine    (uBPF, vm/inc/ubpf.h, vm/ubpf_vm.c)")
    print("        local function stack frame ....... %d bytes" % u_frame)
    print("        max call depth ................... %d" % u_depth)
    print("        total VM stack ................... %d bytes" % u_total)

    # 1. The comparison that matters, and the reason it is easy to miss.
    if p_frame != u_frame:
        findings.append(
            "per-frame stack disagrees: PREVAIL proves against %d bytes per "
            "subprogram, uBPF gives a local function %d. A program admitted "
            "under the defaults may use %.3gx the stack the runtime provides."
            % (p_frame, u_frame, p_frame / float(u_frame)))
        if p_frame * p_depth == u_total:
            findings.append(
                "and the TOTALS agree (%d == %d), so a check that compared only "
                "totals would report success. That is why this compares frames."
                % (p_frame * p_depth, u_total))

    # 2. Depth has to agree too, or the total is not what either side thinks.
    if p_depth != u_depth:
        findings.append("max call depth disagrees: PREVAIL %d, uBPF %d"
                        % (p_depth, u_depth))

    # 3. Defaults that must be set explicitly rather than inherited (item 3a).
    permissive = []
    if p_term is False:
        permissive.append("PREVAIL check_for_termination=false (memory safety "
                          "proves nothing about finishing)")
    if p_strict is False:
        permissive.append("PREVAIL strict=false")
    if p_div0 is True:
        permissive.append("PREVAIL allow_division_by_zero=true")
    if u_blind is False:
        permissive.append("uBPF constant_blinding=false (JIT-spray mitigation "
                          "off; and it is x86-64 only upstream)")
    if u_ub is False:
        permissive.append("uBPF undefined_behavior_check=false")
    if u_bounds is not True:
        permissive.append("uBPF bounds_check is NOT on by default any more")
    if u_ro is not True:
        permissive.append("uBPF readonly_bytecode is NOT on by default any more")

    if permissive:
        print("      defaults that must be set explicitly, not inherited (item 3a)")
        for p in permissive:
            print("        - %s" % p)

    if not findings:
        print("ok    check_vm_geometry  (declared machine == actual machine)")
        return 0

    label = "FAIL " if gate else "FINDING"
    for f in findings:
        print("%s %s" % (label, f))
    if gate:
        print("FAIL  check_vm_geometry  (item 6a is not reconciled)")
        return 1
    print("ok    check_vm_geometry  (ran; %d finding(s) above, item 6a open --- "
          "`make gate` to fail on them)" % len(findings))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
