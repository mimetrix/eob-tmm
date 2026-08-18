#!/usr/bin/env python3
"""check_ls_load.py --- the loader client's name resolution and its build-id gate.

WHY THIS TEST EXISTS, AND WHY IT IS MOSTLY REFUSALS. Arming used to take a raw hex
address, and on 2026-08-17 a stale one armed `rst_cause_match_peer` instead of
`rst_why`. That is the function 64 bytes away, it also carries a nop pad, so the
patch SUCCEEDED: the loader printed OK ARMED LIVE and `fired` stayed 0 across
16,000 requests through the proxy. An hour went into looking for a broken hook.

Nothing in the system could have caught it. A nop pad cannot distinguish itself
from another nop pad. A build id can, so `arm <slot> <name>` now resolves through
an index that carries the build id it was generated from, compared against the
build id of the binary the pod is ACTUALLY running.

Every path below that returns an address is one assertion. Every path that must
REFUSE is worth more, because a resolver that silently fell back to *something*
would reproduce the original bug with extra steps.

The build-id reader is cross-checked against `readelf -n` rather than against
itself --- a hand-written ELF parser passing a hand-written test proves little.
The f5-tmm container has no readelf, no nm and no objdump (and `strings` is absent
too, silently returning zero for everything), which is why the parser is
hand-written in the first place.
"""
import importlib.util
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CLIENT = os.path.join(HERE, "..", "env", "scripts", "ls-load.py")


def load_client():
    """Import ls-load.py as a module.

    This is only possible because socket resolution is LAZY. As a module-level
    `SOCK = resolve_sock()` it exited on import when no loader was listening, so
    this file could not exist and the gate below shipped untested.
    """
    spec = importlib.util.spec_from_file_location("lsload", CLIENT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def readelf_build_id(path):
    """None when readelf is unavailable, so the cross-check skips rather than fails."""
    try:
        r = subprocess.run(["readelf", "-n", path], capture_output=True,
                           text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    for line in r.stdout.splitlines():
        if "Build ID" in line:
            return line.split(":")[-1].strip()
    return None


def write_index(path, bid, rows):
    with open(path, "w") as f:
        f.write("#ls-hook-index\t1\n")
        f.write("#build_id\t%s\n" % bid)
        f.write("#tmos_version\ttest\n")
        f.write("#ctx_abi_version\t3\n")
        f.write("#name\tarm_at\tarm_method\tpad_offset\tdisplace_bytes\n")
        for r in rows:
            f.write("\t".join(str(x) for x in r) + "\n")


def main():
    m = load_client()
    n = 0

    # --- 1. the ELF reader, against an independent tool ---------------------
    checked = agreed = 0
    for cand in ("/proc/self/exe", "/bin/sh", "/bin/ls", "/usr/bin/python3"):
        p = os.path.realpath(cand)
        if not os.path.exists(p):
            continue
        want = readelf_build_id(p)
        if want is None:
            continue
        checked += 1
        got = m.elf_build_id(p)
        assert got == want, "%s: readelf says %s, elf_build_id says %s" % (p, want, got)
        agreed += 1
        n += 1
    if checked:
        print("  ok    elf_build_id agrees with readelf on %d binaries" % agreed)
    else:
        print("  SKIP  readelf unavailable --- ELF reader not cross-checked")

    work = tempfile.mkdtemp(prefix="lsload.")
    notelf = os.path.join(work, "notelf.bin")
    with open(notelf, "wb") as f:
        f.write(b"not an elf, not even close\n" * 40)
    assert m.elf_build_id(notelf) is None, "a non-ELF must not yield a build id"
    n += 1
    print("  ok    a non-ELF returns None --- no exception, no invented id")

    # The resolver's job is the comparison and the lookup. Which /proc entry is
    # tmm is not under test, so point it at a binary that certainly exists.
    me = os.path.realpath("/proc/self/exe")
    bid = m.elf_build_id(me)
    assert bid, "the test interpreter has no build id --- cannot run the gate tests"
    m.running_binary = lambda: me

    rows = [("rst_why", "0x144e3c0", "pad", 4, 0),
            ("ssl__err", "0xa1b2c3", "pad", 0, 0),
            ("some_unpadded", "0xdeadbe", "displace", "-", 7)]

    def refuses(label, spec, *needles):
        try:
            m.resolve_hook(spec)
        except SystemExit as e:
            msg = str(e)
            for want in needles:
                assert want.lower() in msg.lower(), \
                    "%s: refusal did not mention %r:\n%s" % (label, want, msg)
            print("  ok    REFUSED  %-30s (%s)" % (label, needles[0]))
            return
        raise AssertionError("%s was ACCEPTED and must not be" % label)

    # --- 2. a matching build id resolves ------------------------------------
    ok_idx = os.path.join(work, "idx_ok.tsv")
    write_index(ok_idx, bid, rows)
    m.HOOK_INDEX = ok_idx
    assert m.resolve_hook("rst_why") == "0x144e3c0"; n += 1
    assert m.resolve_hook("ssl__err") == "0xa1b2c3"; n += 1
    # A displaceable entry resolves too: it is armable, by the other route.
    assert m.resolve_hook("some_unpadded") == "0xdeadbe"; n += 1
    print("  ok    resolves by name when the build id matches (pad and displace)")

    # --- 3. THE ONE THAT MATTERS: a mismatched build id must refuse ---------
    bad_idx = os.path.join(work, "idx_bad.tsv")
    write_index(bad_idx, "00" * 20, rows)
    m.HOOK_INDEX = bad_idx
    refuses("build id mismatch", "rst_why", "BUILD ID MISMATCH", "refusing to arm"); n += 1

    # --- 4. the remaining refusals ------------------------------------------
    m.HOOK_INDEX = ok_idx
    refuses("symbol not in the index", "no_such_function", "not in the index"); n += 1

    m.HOOK_INDEX = os.path.join(work, "absent.tsv")
    refuses("index file missing", "rst_why", "no hook index"); n += 1

    nobid = os.path.join(work, "idx_nobid.tsv")
    with open(nobid, "w") as f:
        f.write("#ls-hook-index\t1\n#name\tarm_at\tarm_method\nrst_why\t0x1\tpad\n")
    m.HOOK_INDEX = nobid
    refuses("index carries no build id", "rst_why", "no #build_id"); n += 1

    m.HOOK_INDEX = ok_idx
    saved = m.running_binary
    m.running_binary = lambda: None
    refuses("no running tmm under /proc", "rst_why", "cannot find the running tmm"); n += 1
    m.running_binary = saved

    # --- 5. a raw address still works, unchecked and saying so --------------
    assert m.resolve_hook("0x144e3c0") == "0x144e3c0"; n += 1
    print("  ok    a raw 0x address is still accepted, and warns that it is unchecked")

    refuses("neither hex nor a symbol", "0xzzz", "not a hex address"); n += 1

    print("  ok    check_ls_load: %d assertions, 6 of them refusals" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
