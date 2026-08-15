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
import re
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
    ("ls_2026_http_psm.bpf.c", "fentry/http_psm_profile_name_lookup", True,
     "the CVE shield: restores the NULL check missing at http_psm.c:806"),
    ("reject_memory.bpf.c", "fentry/reject_memory", False,
     "chases a raw pointer -- must fail the memory-safety gate"),
    ("reject_termination.bpf.c", "fentry/reject_termination", False,
     "unbounded trip count, body -O2 cannot fold -- must fail the termination gate"),
    ("folded_loop.bpf.c", "fentry/folded_loop", True,
     "PASSES because -O2 folded its loop to closed form -- verify the object, not the source"),
    ("parse_watch.bpf.c", "fentry/http_parse_client_headers", True,
     "SUPERSEDED, kept because the failure is the lesson: it verifies clean and is "
     "useless. Armed at http_parse_client_headers' ENTRY it reads header_count, "
     "status_code and the f_invalid_* bits BEFORE that function writes them, so every "
     "field is legitimately zero. A verifiable program over a struct that does not yet "
     "hold data. Replaced by http_hdrs_watch.bpf.c."),
    ("http_hdrs_watch.bpf.c", "fentry/tmm_l7_http_headers", True,
     "tmm:l7:http_headers: the designed-in tracepoint. Reads the record built at the "
     "one point every request reaches after the parse, so the fields are filled, and "
     "counts rejected or malformed requests. Validated by triggering it -- curl -X "
     "BOGUS must move safe_returns, a plain GET must not."),
    ("http_waived_watch.bpf.c", "fentry/tmm_l7_http_headers", True,
     "the WAIVED class: malformed AND forwarded anyway. TMM logs nothing when a "
     "passthru_* waiver fires, so this is the only record that it happened. Same "
     "tracepoint and record as http_hdrs_watch --- a different question, chosen "
     "at load time rather than compiled in."),
]


def fallback_prefix_guard():
    """The ELF section name is not a label -- it SELECTS the program type, and with it the
    ctx descriptor PREVAIL verifies against.

    PREVAIL matches the section name against a compiled-in prefix table and, when nothing
    matches, silently `return linux_socket_filter_program_type` -- whose descriptor is
    __sk_buff: 192 bytes with pointer slots at 76/80/140. Any ctx smaller than 192 bytes
    then verifies clean while touching none of those slots, which demonstrates a small
    struct fitting inside a big one and nothing else (finding O3).

    These shields use `fentry/`, which selects `tracing`: a 96-byte ctx with NO pointer
    slots -- the fentry model, and an honest description of a TMM entry hook that receives
    argument values. This guard fails if a section name stops matching a real prefix, so
    a rename cannot quietly drop the shields back onto the fallback.
    """
    plat = os.path.join(HERE, os.pardir, "ebpf-verifier", "src", "linux", "linux_platform.cpp")
    if not os.path.exists(plat):
        print("skip  section-prefix guard  (PREVAIL sources not present)")
        return 0
    with open(plat, encoding="utf-8", errors="replace") as fh:
        src = fh.read()

    # Prefixes live in the brace list of each PTYPE entry, and NOT all of them end in "/"
    # -- socket_filter's is bare "socket", kprobe's is "kprobe/". Matching only
    # slash-terminated literals would call a valid prefix unmatched.
    prefixes = set()
    for block in re.findall(r"PTYPE[_A-Z]*\([^{]*\{([^}]*)\}", src):
        prefixes.update(re.findall(r'"([^"]+)"', block))
    if not prefixes:
        print("skip  section-prefix guard  (could not parse PREVAIL's prefix table)")
        return 0

    # PREVAIL's own rule, from get_program_type(): section.find(prefix) == 0, first match
    # wins, and no match falls through to socket_filter.
    FALLBACK_PREFIXES = {"socket"}  # these select socket_filter *deliberately*
    sec = CASES[0][1]               # all cases share one prefix; one report is enough
    matched = sorted((p for p in prefixes if sec.startswith(p)), key=len, reverse=True)

    if matched and matched[0] not in FALLBACK_PREFIXES:
        print(f"ok    section prefix {matched[0]!r} selects a real program type "
              f"(not the socket_filter fallback)")
        return 0
    why = ("selects socket_filter explicitly" if matched
           else "matches no program type, so PREVAIL falls through to socket_filter")
    print(f"FAIL  section {sec!r} {why} — its 192-byte __sk_buff descriptor has pointer "
          f"slots at 76/80/140, so a ctx smaller than that verifies while touching none "
          f"of them. That is a small struct fitting inside a big one, not evidence (O3).")
    return 1


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

    rc = fallback_prefix_guard()
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
        loose = subprocess.run([PREVAIL, obj, "fentry/reject_termination",
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
