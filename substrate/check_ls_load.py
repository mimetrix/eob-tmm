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
import re
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

    # --- 6. AN AMBIGUOUS NAME MUST REFUSE -----------------------------------
    # Names are not unique. This build's index holds 71,148 lines under 70,020
    # distinct names --- 591 names have 2 to 21 entries each: file-scope statics
    # repeated across translation units, .isra/.constprop clones, and assembler
    # labels (LOne/LTwo/LThree, 21 apiece). Keeping one entry per name silently kept
    # whichever came last, so arming one of those would patch an arbitrary homonym
    # and report success --- the stale-address failure with a nicer interface.
    dup = os.path.join(work, "idx_dup.tsv")
    write_index(dup, bid, [("twin", "0xaaaa", "pad", 4, 0),
                           ("twin", "0xbbbb", "pad", 0, 0),
                           ("only_one", "0xcccc", "pad", 4, 0)])
    m.HOOK_INDEX = dup
    refuses("a name with two entries", "twin", "AMBIGUOUS", "0xaaaa", "0xbbbb"); n += 1
    # ...and a unique name in the same index still resolves, so the refusal is about
    # ambiguity rather than the index being rejected wholesale.
    assert m.resolve_hook("only_one") == "0xcccc"; n += 1
    print("  ok    an ambiguous name REFUSES; a unique one in the same index resolves")

    # --- 7. THE BUILD-ID READER: TWO COPIES MUST AGREE, AND BOTH WITH readelf -------
    # ls-load.py carries its own ELF note parser because it runs inside a container with no
    # readelf, no objdump and no nm. That copy is forced; two DIFFERENT answers are not.
    #
    # The copy it replaced walked PT_NOTE segments only, and on TMM's PGO debug build that
    # returns 16 bytes where readelf reports 20 --- two adjacent PT_NOTE segments with the
    # build-id note straddling the boundary. Nothing complained, because the only thing it
    # was ever compared against was another copy of itself.
    #
    # So: compare against substrate/ls_buildid.py AND against readelf, on whatever real
    # binaries this machine has. readelf is the referee; without it the two copies could
    # agree on the same wrong answer, which is the situation this replaces.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import ls_buildid
    import shutil
    import subprocess

    readelf = shutil.which("readelf")
    cands = [q for q in ("/bin/ls", "/usr/bin/python3", "/bin/sh", "/usr/bin/env",
                         os.path.realpath(sys.executable))
             if os.path.isfile(q)]
    seen = set()
    checked = 0
    for q in cands:
        q = os.path.realpath(q)
        if q in seen:
            continue
        seen.add(q)
        a = m.elf_build_id(q)
        b = ls_buildid.build_id(q)
        assert a == b, ("the two build-id readers disagree on %s:\n"
                        "    ls-load.py     %s\n"
                        "    ls_buildid.py  %s" % (q, a, b))
        n += 1
        if readelf:
            out = subprocess.run([readelf, "-n", q], capture_output=True, text=True).stdout
            ref = re.search(r"Build ID:\s*([0-9a-f]+)", out)
            if ref:
                assert a == ref.group(1), ("both readers disagree with readelf on %s:\n"
                                           "    readers  %s\n"
                                           "    readelf  %s" % (q, a, ref.group(1)))
                n += 1
                checked += 1
    assert seen, "no ELF binary to check the build-id readers against"
    print("  ok    build-id readers agree on %d binaries%s"
          % (len(seen), ", %d cross-checked against readelf" % checked if checked
             else " (readelf absent --- NOT cross-checked)"))

    # --- 8. THE TWO FAULTS, SYNTHESISED ------------------------------------------------
    # Assertion 7 compares the readers on this machine's binaries and they all agree, which
    # is exactly why the bug survived review: /bin/ls has one PT_NOTE and no property note,
    # so it exercises neither fault. Both need a binary shaped like TMM's, so build two.
    #
    #   (a) THE STRADDLE --- what tmm64.debug actually does. Two ADJACENT PT_NOTE segments
    #       with the build-id note crossing the boundary: segment one's p_filesz ends 16
    #       bytes into a 20-byte descriptor. A per-segment reader returns those 16 bytes and
    #       calls them the build id --- a 32-hex-character answer where readelf says 40. It
    #       still discriminated builds, so nothing ever disagreed with it.
    #
    #   (b) PER-NOTE ALIGNMENT --- a .note.gnu.property note whose name IS padded to 8 bytes,
    #       followed by a build-id note padded to 4, in one segment. No single stride walks
    #       both: 4 skips past the build-id header, 8 mis-locates its descriptor by 4 bytes.
    #       The first fix for (a) walked with one alignment and lost the id entirely, which
    #       is why this case is here and not just (a).
    #
    # Neither file has section headers, so the section path cannot rescue either and it is
    # the fallback under test.
    import struct as _st

    def synth(path, idhex, prop_pad, cut_back):
        """A 2-PT_NOTE ELF. prop_pad: bytes of name padding in the property note (0 mirrors
        the real binary, 4 makes it 8-aligned). cut_back: how many bytes of the build-id
        descriptor land in the SECOND segment (0 = no straddle)."""
        idb = bytes.fromhex(idhex)
        prop = (_st.pack("<III", 4, 16, 5) + b"GNU\x00" + b"\x00" * prop_pad + b"\xaa" * 16)
        bid = _st.pack("<III", 4, len(idb), 3) + b"GNU\x00" + idb
        notes = prop + bid
        cut = len(notes) - cut_back if cut_back else len(notes)
        base, ehsize, pes = 0x1000, 64, 56
        eh = bytearray(64)
        eh[0:4] = b"\x7fELF"
        eh[4], eh[5], eh[6] = 2, 1, 1                     # 64-bit, LSB, EV_CURRENT
        _st.pack_into("<HH", eh, 0x10, 2, 0x3e)           # ET_EXEC, EM_X86_64
        _st.pack_into("<I", eh, 0x14, 1)
        _st.pack_into("<Q", eh, 0x20, ehsize)             # e_phoff
        _st.pack_into("<Q", eh, 0x28, 0)                  # e_shoff --- NO section headers
        _st.pack_into("<HH", eh, 0x36, pes, 2)
        _st.pack_into("<HH", eh, 0x3a, 0, 0)
        _st.pack_into("<H", eh, 0x3e, 0)
        segs = [(base, cut, 8), (base + cut, len(notes) - cut, 4)]
        phs = b""
        for off, sz, align in segs:
            ph = bytearray(pes)
            _st.pack_into("<I", ph, 0x00, 4)              # PT_NOTE
            _st.pack_into("<I", ph, 0x04, 4)              # PF_R
            for o in (0x08, 0x10, 0x18):
                _st.pack_into("<Q", ph, o, off)
            _st.pack_into("<Q", ph, 0x20, sz)             # p_filesz --- where (a) truncates
            _st.pack_into("<Q", ph, 0x28, sz)
            _st.pack_into("<Q", ph, 0x30, align)
            phs += bytes(ph)
        with open(path, "wb") as fh:
            fh.write(bytes(eh) + phs + b"\x00" * (base - ehsize - len(phs)) + notes)

    def naive(path):
        """The parse that shipped before this fix: per-segment, one 4-byte stride."""
        with open(path, "rb") as fh:
            e = fh.read(64)
            phoff, = _st.unpack_from("<Q", e, 0x20)
            pes_, pn = _st.unpack_from("<HH", e, 0x36)
            for i in range(pn):
                fh.seek(phoff + i * pes_)
                ph = fh.read(pes_)
                if _st.unpack_from("<I", ph, 0)[0] != 4:
                    continue
                off, = _st.unpack_from("<Q", ph, 0x08)
                sz, = _st.unpack_from("<Q", ph, 0x20)
                fh.seek(off)
                nt = fh.read(sz)
                j = 0
                while j + 12 <= len(nt):
                    ns, ds, t = _st.unpack_from("<III", nt, j)
                    nm = nt[j + 12:j + 12 + ns].rstrip(b"\x00")
                    d = j + 12 + ((ns + 3) & ~3)
                    if t == 3 and nm == b"GNU":
                        return nt[d:d + ds].hex()
                    j = d + ((ds + 3) & ~3)
        return None

    want = "47a10fc43398caa9af9dddbd8bed82cec2cde196"
    cases = (("(a) straddle, mirroring tmm64.debug", 0, 4),
             ("(b) 8-aligned property note",         4, 0))
    for label, prop_pad, cut_back in cases:
        f = os.path.join(work, "synth_%d_%d.elf" % (prop_pad, cut_back))
        synth(f, want, prop_pad, cut_back)
        bad = naive(f)
        # THE FILE MUST REPRODUCE THE FAULT. Without this the two asserts below would pass
        # against a reader that is still broken, which is the whole failure mode being fixed.
        assert bad != want, ("%s does not reproduce a fault --- the old parse got the right "
                             "answer, so this case proves nothing" % label); n += 1
        got_l = m.elf_build_id(f)
        got_c = ls_buildid.build_id(f)
        assert got_l == want, "%s: ls-load.py got %r, want %s" % (label, got_l, want); n += 1
        assert got_c == want, "%s: ls_buildid.py got %r, want %s" % (label, got_c, want); n += 1
        if readelf:
            out = subprocess.run([readelf, "-n", f], capture_output=True, text=True).stdout
            ref = re.search(r"Build ID:\s*([0-9a-f]+)", out)
            if ref:
                assert ref.group(1) == want, "%s: readelf disagrees" % label
                n += 1
        print("  ok    %-38s old parse: %-42s now: full 40 hex"
              % (label, "%s (%d hex)" % (bad, len(bad or ""))))

    print("  ok    check_ls_load: %d assertions, 7 of them refusals" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
