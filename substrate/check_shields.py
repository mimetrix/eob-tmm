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
    ("rate_watch.bpf.c", "fentry/rst_why", True,
     "THE MAP PROGRAM. Counts per reset site across invocations and selects over a "
     "threshold -- a question no stateless program can express, since it has no way "
     "to know this is the sixth. Declares a standard SEC(\"maps\") hash and calls "
     "helpers 1/2/3; PREVAIL verifies it UNCHANGED, which is why maps needed no "
     "verifier work at all."),
    ("generic_probe.bpf.c", "fentry/rst_why", True,
     "PROOF THAT A HOOK NEEDS NO ctx BUILDER. Takes the GENERIC five-register context and "
     "dereferences TMM's __FILE__ pointer itself, through bpf_probe_read (helper 4), which "
     "PREVAIL admits with every gate on. Every other program here is handed a typed record "
     "assembled by host C compiled INTO TMM --- so a new argument shape costs a rebuild. "
     "This one costs a new program. It does not see rst_why's sixth argument, because the "
     "generic context carries five, so probe_read removes the REBUILD rather than every "
     "reason to write a builder."),
    ("sslerr_watch.bpf.c", "fentry/ssl__err", True,
     "tmm:ssl:err. Verifies and works --- and is DISQUALIFIED as a headline by test 2 of "
     "the uniqueness screen: ssl__err already logs its reason at LOG_WARNING with "
     "function, line, alert and the INTERPOLATED message, which is more than an entry "
     "hook gets. Proven from the binary: \"Connection error\" occurs 4 times in "
     "tmm.no_pgo. Kept as a working artifact and as the record of why a site can pass "
     "the iRule test and fail the log test."),
    ("h2abort_watch.bpf.c", "fentry/http2_stream_abort", True,
     "tmm:http2:abort --- the one hook of the four whose reason reaches NOTHING else. "
     "http2_stream_abort's only narration is TRACES() inside #if HTTP2_DEBUG, which the "
     "build leaves undefined, so \"initiates ABORT in\" occurs 0 times in the shipped "
     "binary. 36 call sites, 23 distinct reason literals. Keyed by error code rather "
     "than by reason string because a program cannot iterate its own map, so a "
     "string-keyed table could be filled and never summarised."),
    ("rate_gate.bpf.c", "fentry/rst_why", True,
     "WHAT THE CLOCK AND THE EMIT HELPER BOUGHT. Rate, not total: without "
     "bpf_ktime_get_ns every threshold means \"ever\" (rate_watch's \"over 5\" is true "
     "on a healthy box after an hour), and without bpf_ringbuf_output the host publishes "
     "per event so a program cannot decide what is worth emitting. One record per site "
     "per second instead of one per event. NOTE it carries 4 BACKWARD JUMPS and passes "
     "--termination anyway: they are clang tail-merging to a shared map_update+return "
     "block, not iteration. 'Zero backedges' is a proxy that coincides with 'no loops' "
     "for straight-line programs and is not the test --- --termination is."),
    ("http_waived_watch.bpf.c", "fentry/tmm_l7_http_headers", True,
     "the WAIVED class: malformed AND forwarded anyway. Verifies and decodes, but "
     "has NEVER selected a live record: every client-side waiver is gated on "
     "proxy_type == TRANSPARENT and BNK is a reverse proxy. Note also that TMM "
     "already counts waivers (mcp/stats.h passthrough_*); the gap is per-request "
     "detail, not observability as such. Same tracepoint and record as "
     "http_hdrs_watch --- a different question, chosen at load time."),
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
