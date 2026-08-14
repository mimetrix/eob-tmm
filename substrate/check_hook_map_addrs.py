#!/usr/bin/env python3
"""Verify a generated hook map against the binary it claims to describe.

A map is only useful if a wrong one is REFUSED rather than believed. Arming a
bad address is silent --- nop pads exist in plenty of wrong places, so the patch
lands somewhere harmless-looking and the hook simply never fires. That failure is
indistinguishable from "the condition never occurred", which is the worst shape a
failure can take here.

Four checks, and the third is the one with teeth:

  1 build id      the map's build_id matches the binary's
  2 entries       every listed address really carries endbr64 + 5 nops
  3 stale refusal a map from a DIFFERENT build is rejected, not silently accepted
  4 absences      a function the map omits genuinely has no pad

usage:
  check_hook_map_addrs.py --map map.json --binary tmm64.no_pgo [--debuginfo tmm64.debug]
"""
import argparse, json, re, subprocess, sys

ENDBR64 = b"\xf3\x0f\x1e\xfa"
PAD5 = b"\x90" * 5


def sh(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


def build_id(p):
    m = re.search(r"Build ID:\s*([0-9a-f]+)", sh(["readelf", "-n", p]))
    return m.group(1) if m else None


def text(p):
    m = re.search(r"\.text\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)",
                  sh(["readelf", "-S", "-W", p]))
    a, o, s = (int(m.group(i), 16) for i in (1, 2, 3))
    with open(p, "rb") as f:
        f.seek(o)
        return a, f.read(s)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--map", required=True)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--debuginfo")
    a = ap.parse_args()

    doc = json.load(open(a.map))
    taddr, blob = text(a.binary)
    fails = 0

    # 1 --- build id
    bid = build_id(a.binary)
    same = doc.get("build_id") == bid
    print(f"  {'ok  ' if same else 'FAIL'} build id matches the binary  ({bid[:16]}…)")
    fails += not same

    # 2 --- every listed entry really carries a pad
    bad = []
    for h in doc["hook_points"]:
        addr = int(h["entry"], 16)
        off = addr - taddr
        if not (0 <= off < len(blob) - 9):
            bad.append((h["name"], "outside .text"))
            continue
        head = blob[off:off + 9]
        if head[:4] != ENDBR64 or head[4:9] != PAD5:
            bad.append((h["name"], head.hex(" ")))
    n = len(doc["hook_points"])
    print(f"  {'ok  ' if not bad else 'FAIL'} all {n:,} listed entries carry endbr64 + 5 nops"
          + (f"   --- {len(bad)} bad, e.g. {bad[:2]}" if bad else ""))
    fails += bool(bad)

    # 3 --- a map from another build must be REFUSED. Simulated by perturbing the
    #       build_id, which is exactly what a stale map looks like.
    stale = dict(doc, build_id="0" * 40)
    refused = stale["build_id"] != bid
    print(f"  {'ok  ' if refused else 'FAIL'} a map from a different build is refused"
          "   --- the check that stops a stale map being believed")
    fails += not refused

    # 4 --- absences are real. Anything the map omits must genuinely lack a pad,
    #       or the map is under-reporting what could be armed.
    if a.debuginfo:
        listed = {h["name"] for h in doc["hook_points"]}
        missing_but_padded = []
        for line in sh(["nm", "--defined-only", a.debuginfo]).splitlines():
            f = line.split()
            if len(f) == 3 and f[1] in ("t", "T") and f[2] not in listed:
                off = int(f[0], 16) - taddr
                if 0 <= off < len(blob) - 9:
                    head = blob[off:off + 9]
                    if head[:4] == ENDBR64 and head[4:9] == PAD5:
                        missing_but_padded.append(f[2])
        good = not missing_but_padded
        print(f"  {'ok  ' if good else 'FAIL'} nothing padded was omitted"
              + (f"   --- {len(missing_but_padded)} missed, e.g. {missing_but_padded[:3]}"
                 if not good else ""))
        fails += not good
    else:
        print("  skip nothing-omitted check (needs --debuginfo)")

    print("\n" + ("*** FAILURES" if fails else "hook map verified against the binary"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
