#!/usr/bin/env python3
"""Emit the per-build hook map: every function, its entry address, and whether it
actually carries an arming pad --- read from the binary, never assumed.

WHAT THIS SOLVES. Without a map, arming a function means supplying a raw address
by hand, and that address moves with every rebuild. Worse, it must come from the
matching tmm-debuginfo package rather than the build tree, because packaging
re-links the binary. Getting it wrong is SILENT: nop pads exist at plenty of
wrong places, so a mis-armed address patches something else and looks fine.

SCOPE --- PHASE A, DELIBERATELY. This emits *addresses and pad status*. It does
NOT emit arg_btf, the typed argument layout a program is verified against; that
needs DWARF parameter classification and is Phase B/C. A map from this tool is
enough to arm a function by name and not enough to write a program against one.
The schema marks the fields a product map must add.

WHICH BINARY, AND WHY IT MATTERS MORE THAN IT LOOKS. A TMM image can carry BOTH
tmm64.no_pgo (padded) and tmm64.debug (not), with /usr/bin/tmm pointing at the
debug one --- `make tmm-gdb` does exactly that. The debug build overrides
CFLAGS_OPTIMIZE, which is where -fpatchable-function-entry lives, so it has no
pads on TMM-core functions and NOTHING IN IT CAN BE ARMED. A map generated from
tmm64.no_pgo and used against a pod running tmm64.debug produces addresses that
are wrong twice over: wrong binary, and no pad at the destination anyway. Arming
then fails with "no pad", which reads like a stale address and is not. Confirm
what the pod actually runs (readlink -f /usr/bin/tmm) before trusting a map.

WHY THE PAD IS READ RATHER THAN INFERRED. `-fpatchable-function-entry=5,0` is
applied to every translation unit we compile, but at -O2 the optimiser inlines
and folds functions away, so the flag being on does not mean a given symbol has
an emitted body with a pad. The only reliable answer is the bytes at the entry:

    f3 0f 1e fa   endbr64          <- only on indirect-call targets
    90 90 90 90 90                   <- the pad; arming rewrites it into `call rel32`

TWO SHAPES, AND MISSING THE SECOND UNDERCOUNTS THE HOOKABLE SET. `-fcf-protection`
emits `endbr64` only on functions that can be reached by an INDIRECT call. A
function only ever called directly does not get one, so its pad sits at offset 0
rather than offset 4. An earlier version of this tool required endbr64 and
discarded 4,227 armable functions in our own tree -- mostly `.isra`/`.constprop`
clones, which are never indirect-call targets. Both shapes are accepted, and the
map records `pad_offset` because the arming code has to know where to write.

Anything else means not padded --- and note what that does NOT mean. In a file on
disk there is no "armed" state: arming happens at runtime, in memory. A function
whose entry reads `endbr64` then `e8` is simply an unpadded function whose first
instruction is a call, which is exactly what turned up on the first run
(`galois_create_mult_tables`, from the separately-built erasure-coding library).
Reporting that as armed would be wrong and would hide a real unpadded function.

Against a LIVE process the same bytes would be ambiguous, and resolving them
needs more than the pattern: the call target has to resolve to our trampoline.
This tool reads a file, so it does not have that problem and does not pretend to.

usage:
  mk_hook_map.py --binary tmm64.no_pgo --debuginfo tmm64.no_pgo.debug [-o map.json]
  mk_hook_map.py --debs ~/code/tmm/docker_build/DEBS/amd64      (extracts the pair itself)
"""
import argparse, json, os, re, shutil, subprocess, sys, tempfile

ENDBR64 = b"\xf3\x0f\x1e\xfa"
PAD5    = b"\x90" * 5


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"*** {cmd[0]} failed: {p.stderr.strip()[:200]}")
    return p.stdout


def build_id(path):
    out = run(["readelf", "-n", path])
    m = re.search(r"Build ID:\s*([0-9a-f]+)", out)
    return m.group(1) if m else None


def text_section(path):
    """(vaddr, file_offset, size) of .text. The binary is non-PIE (ET_EXEC), so a
    symbol's vaddr is also its runtime address --- no relocation math anywhere."""
    out = run(["readelf", "-S", "-W", path])
    m = re.search(r"\.text\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", out)
    if not m:
        raise SystemExit("*** no .text section found")
    return int(m.group(1), 16), int(m.group(2), 16), int(m.group(3), 16)


def functions(debuginfo):
    """Function symbols from the debuginfo. The shipped binary is stripped, so nm
    on it returns nothing --- the symbols only exist on this side of the pair."""
    out = run(["nm", "--defined-only", debuginfo])
    fns = []
    for line in out.splitlines():
        f = line.split()
        if len(f) == 3 and f[1] in ("t", "T"):
            fns.append((int(f[0], 16), f[2]))
    return fns


def extract_debs(debs_dir, workdir):
    binp = next((os.path.join(debs_dir, f) for f in os.listdir(debs_dir)
                 if f.startswith("tmm_") and f.endswith(".deb")), None)
    dbgp = None
    for root, _, files in os.walk(debs_dir):
        for f in files:
            if f.startswith("tmm-debuginfo_") and f.endswith(".deb"):
                dbgp = os.path.join(root, f)
    if not binp or not dbgp:
        raise SystemExit(f"*** need tmm_*.deb and tmm-debuginfo_*.deb under {debs_dir}\n"
                         f"    (the debuginfo deb is one level down, in tmm_debs/)")
    b, d = os.path.join(workdir, "b"), os.path.join(workdir, "d")
    os.makedirs(b); os.makedirs(d)
    run(["dpkg-deb", "-x", binp, b])
    run(["dpkg-deb", "-x", dbgp, d])
    return (os.path.join(b, "usr/bin/tmm64.no_pgo"),
            os.path.join(d, "usr/lib/debug/usr/bin/tmm64.no_pgo.debug"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary")
    ap.add_argument("--debuginfo")
    ap.add_argument("--debs")
    ap.add_argument("-o", "--out", default="-")
    ap.add_argument("--tmos-version", default=None)
    a = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix="hookmap.")
    try:
        if a.debs:
            binary, dbg = extract_debs(a.debs, tmp)
        elif a.binary and a.debuginfo:
            binary, dbg = a.binary, a.debuginfo
        else:
            raise SystemExit("*** need --debs, or both --binary and --debuginfo")

        bid_b, bid_d = build_id(binary), build_id(dbg)
        if bid_b != bid_d:
            raise SystemExit("*** BUILD IDs DIFFER --- the pair is mismatched.\n"
                             f"    binary    {bid_b}\n    debuginfo {bid_d}\n"
                             "    Every address from this pair would be wrong.")

        taddr, toff, tsize = text_section(binary)
        with open(binary, "rb") as f:
            f.seek(toff)
            text = f.read(tsize)

        padded, unpadded, callfirst, outside = [], 0, 0, 0
        for addr, name in functions(dbg):
            if not (taddr <= addr < taddr + tsize - 9):
                outside += 1
                continue
            head = text[addr - taddr: addr - taddr + 9]
            if head[:4] == ENDBR64 and head[4:9] == PAD5:
                pad_off = 4                      # indirect-call target: pad follows endbr64
            elif head[:5] == PAD5:
                pad_off = 0                      # direct-call only: pad at the entry
            else:
                unpadded += 1
                if head[:4] == ENDBR64 and head[4] == 0xE8:
                    callfirst += 1               # first instruction is a call; not a pad
                continue
            padded.append({"name": name, "symbol": name,
                           "entry": f"0x{addr:x}",
                           "pad_offset": pad_off,
                           "arm_at": f"0x{addr + pad_off:x}",
                           "patchable_pad_bytes": 5,
                           "attach_mode": "observe", "path_class": "unclassified",
                           "enumerated_outcomes": ["LS_FALLTHROUGH", "LS_SAFE_RETURN"]})

        doc = {
            "_comment": ("PHASE A: addresses and pad status only, read from the binary. "
                         "NOTE pad_offset: ls_arm.c currently REQUIRES endbr64 and arms at "
                         "entry+4, so it can arm only the pad_offset==4 entries. The "
                         "pad_offset==0 entries are real and armable in principle, but need "
                         "ls_arm to honour pad_offset first; today it refuses them, which is "
                         "the safe direction. Filter on pad_offset==4 for what works now. "
                         "arg_btf (the typed argument layout a program is verified against) "
                         "is NOT emitted --- that needs DWARF parameter classification. "
                         "Enough to arm a function by name; not enough to write a program "
                         "against one."),
            "tmos_version": a.tmos_version or "unknown",
            "build_id": bid_b,
            "ctx_abi_version": 1,
            "generated_by": "substrate/mk_hook_map.py (phase A: addresses + pad status)",
            "hook_points": padded,
        }
        out = json.dumps(doc, indent=2)
        if a.out == "-":
            sys.stdout.write(out + "\n")
        else:
            open(a.out, "w").write(out + "\n")

        print(f"  build id      : {bid_b}", file=sys.stderr)
        e4 = sum(1 for h in padded if h["pad_offset"] == 4)
        e0 = len(padded) - e4
        print(f"  padded        : {len(padded):,}   <- armable by name", file=sys.stderr)
        print(f"    pad after endbr64 : {e4:,}", file=sys.stderr)
        print(f"    pad at entry      : {e0:,}   (no endbr64: direct-call-only, clones)",
              file=sys.stderr)
        print(f"  armable by ls_arm TODAY: {e4:,}  --- it requires endbr64 and arms at entry+4;",
              file=sys.stderr)
        print(f"    the other {e0:,} need ls_arm to honour pad_offset (it refuses them now).",
              file=sys.stderr)
        print(f"  no pad        : {unpadded:,}   <- inlined, folded, or another build's",
              file=sys.stderr)
        print(f"    of which start with a call: {callfirst}  (not armed --- a file has no armed state)",
              file=sys.stderr)
        print(f"  outside .text : {outside:,}", file=sys.stderr)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
