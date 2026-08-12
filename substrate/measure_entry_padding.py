#!/usr/bin/env python3
"""Price -fpatchable-function-entry on a real build, and refuse to price it if the flag
did not actually take effect.

This answers the static column of design-review-findings.md §4: build TMM twice from one
source revision, once with entry padding, and report what the padding costs in image size
--- plus, crucially, WHAT FRACTION OF THE BINARY IT REACHED.

    ./measure_entry_padding.py --baseline BIN --flagged BIN \
        [--baseline-debug DBG --flagged-debug DBG] [--nops 5] [--sample 1200]

Why this exists as a script rather than a few shell one-liners: measuring this by hand
produced three consecutive wrong answers, every one of which looked clean and favourable.

  1. Patching the root gcc.mk does nothing. Makefile.inc includes it, then reassigns
     CFLAGS_OPTIMIZE with `:=` and clobbers it. The build recompiles everything with plain
     -O2 and emits a byte-identical binary --- which reads as "padding is free".
  2. Comparing tmm64.debug against tmm64.no_pgo. Different artifacts with different
     build-ids, so every symbol address is meaningless. Check build-ids, always.
  3. Looking for five nop bytes on one objdump line. Five single-byte nops disassemble to
     five SEPARATE lines, so the pattern can never match and every function looks unpadded.

And a fourth that only turned up because coverage was computed rather than assumed: on
x86-64 with CET the pad goes AFTER `endbr64`, not at offset 0. Checking offset 0 alone
reported 6.2% where the true figure was 54%.

So: this reads bytes straight out of the file at symbol addresses (no disassembler to
misparse), verifies build-ids before trusting any address, accepts the pad at either
offset 0 or after endbr64, and reports coverage next to every size number. A size delta
without a coverage figure is not a measurement --- it is a number.

Exit status: 0 if the flag demonstrably landed, 1 if it did not (so CI can gate on it).
"""

import argparse
import collections
import random
import re
import subprocess
import sys

ENDBR64 = b"\xf3\x0f\x1e\xfa"


def build_id(path):
    """Return the GNU build-id hex, or None. Two artifacts must agree before symbol
    addresses from one may be applied to the other."""
    try:
        out = subprocess.check_output(["readelf", "-n", path], stderr=subprocess.DEVNULL).decode()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    m = re.search(r"Build ID:\s*([0-9a-f]+)", out)
    return m.group(1) if m else None


def section_reader(path):
    """Map virtual addresses to file bytes via the section headers.

    Deliberately not objdump: the padding is single-byte nops, which disassemble one per
    line, and any regex expecting N bytes on one line silently matches nothing.
    """
    out = subprocess.check_output(["readelf", "-S", "-W", path]).decode()
    secs = []
    for m in re.finditer(
        r"\[\s*\d+\]\s+(\.\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", out
    ):
        name, kind, addr, off, size = m.group(1), m.group(2), int(m.group(3), 16), int(m.group(4), 16), int(m.group(5), 16)
        # NOBITS carries no file bytes --- a separated .debug file's .text is NOBITS, which
        # is exactly how attempt 3 above managed to read nothing and report it as "unpadded".
        if addr and kind != "NOBITS":
            secs.append((addr, off, size))
    fh = open(path, "rb")

    def get(vaddr, n):
        for addr, off, size in secs:
            if addr <= vaddr < addr + size:
                fh.seek(off + (vaddr - addr))
                return fh.read(n)
        return b""

    return get


def text_size(path):
    out = subprocess.check_output(["size", "-A", path]).decode()
    m = re.search(r"^\.text\s+(\d+)", out, re.M)
    return int(m.group(1)) if m else None


def functions(debug_path):
    """Out-of-line function symbols: nm types T (global) and t (local)."""
    out = subprocess.check_output(["nm", "--defined-only", debug_path]).decode()
    addrs = []
    for line in out.splitlines():
        f = line.split()
        if len(f) == 3 and f[1] in ("T", "t"):
            addrs.append(int(f[0], 16))
    return addrs


def is_padded(get, addr, nops):
    """The pad sits at the entry, or immediately after endbr64 when CET is on."""
    pad = b"\x90" * nops
    if get(addr, nops) == pad:
        return True
    if get(addr, 4) == ENDBR64 and get(addr + 4, nops) == pad:
        return True
    return False


def source_bucket(src):
    """Group a DWARF source path into something worth tabulating."""
    if not src or src in ("?", "??"):
        return "(no DWARF line info)"
    parts = [p for p in src.split("/") if p and p not in (".", "..")]
    if not parts:
        return "(unknown)"
    return "/".join(parts[:2]) if len(parts) > 1 else parts[0]


def attribute(debug_path, addrs):
    """addr -> source bucket, in one addr2line call rather than thousands."""
    proc = subprocess.run(
        ["addr2line", "-f", "-e", debug_path] + [hex(a) for a in addrs],
        capture_output=True, text=True,
    )
    lines = proc.stdout.splitlines()
    out = {}
    for i, a in enumerate(addrs):
        src = lines[2 * i + 1] if 2 * i + 1 < len(lines) else "?"
        out[a] = source_bucket(src.split(":")[0])
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--baseline", required=True, help="unflagged runtime binary")
    ap.add_argument("--flagged", required=True, help="binary built with -fpatchable-function-entry")
    ap.add_argument("--baseline-debug", help="matching separated debug file (for symbols)")
    ap.add_argument("--flagged-debug", help="matching separated debug file (for symbols)")
    ap.add_argument("--nops", type=int, default=5, help="pad width in bytes (default 5)")
    ap.add_argument("--sample", type=int, default=1200, help="functions to sample (default 1200)")
    ap.add_argument("--seed", type=int, default=11, help="sampling seed, for reproducibility")
    args = ap.parse_args()

    bdbg = args.baseline_debug or args.baseline
    fdbg = args.flagged_debug or args.flagged
    rc = 0

    print("== artifact identity ==")
    matched = {}
    for label, binp, dbgp in (("baseline", args.baseline, bdbg), ("flagged", args.flagged, fdbg)):
        bb, bd = build_id(binp), build_id(dbgp)
        ok = (binp == dbgp) or bool(bb and bb == bd)
        matched[label] = ok
        print(f"  {label:9s} binary={bb or '(none)'} debug={bd or '(none)'}  {'MATCH' if ok else 'MISMATCH'}")
    if not matched["flagged"]:
        # Coverage is computed from flagged symbol addresses, so this one is fatal.
        print(f"\n  REFUSING: symbol addresses from {fdbg} do not describe {args.flagged},")
        print("  so every coverage figure below would be meaningless. Re-extract both from")
        print("  the SAME build's debs --- a stale /tmp is the usual cause.")
        return 1
    if not matched["baseline"]:
        print("\n  Baseline debug file does not match its binary, so the baseline control")
        print("  falls back to a symbol-free scan (below). Size deltas are unaffected ---")
        print("  they come from section headers, not symbols.")

    print("\n== size ==")
    bt, ft = text_size(args.baseline), text_size(args.flagged)
    import os
    bs, fs = os.path.getsize(args.baseline), os.path.getsize(args.flagged)
    print(f"  {'':14s}{'baseline':>14}{'flagged':>14}{'delta':>14}")
    for name, b, f in ((".text", bt, ft), ("file", bs, fs)):
        if b and f:
            print(f"  {name:14s}{b:>14,}{f:>14,}{f - b:>+14,}   ({100 * (f - b) / b:+.3f}%)")

    print("\n== did the flag land? ==")
    get_b, get_f = section_reader(args.baseline), section_reader(args.flagged)
    syms = functions(fdbg)
    random.seed(args.seed)
    sample = random.sample(syms, min(args.sample, len(syms)))
    pad_f = sum(1 for a in sample if is_padded(get_f, a, args.nops))
    cov = pad_f / len(sample)
    print(f"  functions (flagged build) ...... {len(syms):,}")
    print(f"  sampled ........................ {len(sample):,}")
    if matched["baseline"]:
        bsyms = functions(bdbg)
        random.seed(args.seed)
        bsample = random.sample(bsyms, min(args.sample, len(bsyms)))
        pad_b = sum(1 for a in bsample if is_padded(get_b, a, args.nops))
        print(f"  padded in baseline ............. {pad_b} / {len(bsample):,} (expect ~0)")
    else:
        # Symbol-free control: count exactly-N runs of 0x90 in .text. Needs no addresses,
        # so it survives a build-id mismatch; an unflagged build has only incidental runs.
        pad = b"\x90" * args.nops
        rx = re.compile(rb"(?<!\x90)" + re.escape(pad) + rb"(?!\x90)")
        runs = {}
        for label, path in (("baseline", args.baseline), ("flagged", args.flagged)):
            out = subprocess.check_output(["readelf", "-S", "-W", path]).decode()
            m = re.search(r"\[\s*\d+\]\s+\.text\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", out)
            with open(path, "rb") as fh:
                fh.seek(int(m.group(2), 16))
                runs[label] = len(rx.findall(fh.read(int(m.group(3), 16))))
        print(f"  exactly-{args.nops} 0x90 runs in .text  baseline={runs['baseline']:,}"
              f"  flagged={runs['flagged']:,}")
    print(f"  padded in flagged .............. {pad_f}  = {100 * cov:.1f}% coverage")
    if pad_f == 0:
        print("\n  THE FLAG DID NOT TAKE EFFECT. Any size delta above is something else.")
        print("  Check: is the override in $(TOPDIR)/Makefile.overrides? Makefile.inc")
        print("  reassigns CFLAGS_OPTIMIZE with := after including gcc.mk, so patching")
        print("  gcc.mk is inert. See env/tmm-build-environment.md.")
        return 1
    if cov < 0.02:
        print("\n  Coverage is under 2% --- treat as 'did not land' rather than 'is cheap'.")
        rc = 1

    if bt and ft and pad_f:
        padded_total = len(syms) * cov
        eff = (ft - bt) / padded_total
        print(f"\n  effective bytes per padded entry  {eff:.2f}  (nominal {args.nops}"
              f" --- alignment absorbs {100 * (1 - eff / args.nops):.0f}%)")
        print(f"  extrapolated to 100% coverage ... .text {(ft - bt) / cov:+,.0f} bytes"
              f"  ({100 * ((ft - bt) / cov) / bt:+.2f}%)")
        print("  (extrapolation, one platform, one pad width --- not a measurement)")

    print("\n== coverage by source bucket ==")
    attr = attribute(fdbg, sample)
    buckets = collections.defaultdict(lambda: [0, 0])
    for a in sample:
        b = buckets[attr.get(a, "(unknown)")]
        b[1] += 1
        if is_padded(get_f, a, args.nops):
            b[0] += 1
    print(f"  {'source bucket':46s}{'padded':>8}{'total':>8}{'pct':>6}")
    for k, (pc, n) in sorted(buckets.items(), key=lambda kv: -kv[1][1])[:24]:
        print(f"  {k[:46]:46s}{pc:>8}{n:>8}{100 * pc / n:>5.0f}%")
    print("\n  A bucket at 0% is usually a separately-built component or vendored third")
    print("  party --- its build never saw the override. That gap is the finding: the")
    print("  paddable set is smaller than the hookable set, and closing it means changing")
    print("  other teams' builds, not one flag.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
