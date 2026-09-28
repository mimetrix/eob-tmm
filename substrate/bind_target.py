#!/usr/bin/env python3
"""Resolve one attachment on the build box, before PREVAIL and signing.

The 64-byte .ls.target section is authenticated through the signed program hash.
Only that target record travels; the hook index and debug/type data stay here.
Version 1 supports the padded, non-PIE x86-64 TMM build only.
"""
import argparse
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from ls_buildid import build_id

FORMAT = "<8s40sQBB6x"
MAGIC = b"LSTARG1\0"


def sections(blob):
    if len(blob) < 64 or blob[:6] != b"\x7fELF\x02\x01":
        raise ValueError("expected little-endian ELF64")
    off = struct.unpack_from("<Q", blob, 40)[0]
    size, count, strings = struct.unpack_from("<HHH", blob, 58)
    if size != 64 or not count or strings >= count or off + size * count > len(blob):
        raise ValueError("invalid ELF section table")
    table = [struct.unpack_from("<IIQQQQIIQQ", blob, off + i * size) for i in range(count)]
    s = table[strings]
    if s[4] + s[5] > len(blob):
        raise ValueError("truncated section names")
    names = blob[s[4]:s[4] + s[5]]
    for sh in table:
        end = names.find(b"\0", sh[0])
        if end < 0:
            raise ValueError("unterminated section name")
        yield names[sh[0]:end].decode("ascii"), sh


def program_section(blob):
    found = [n for n, _ in sections(blob) if n.startswith(("fentry/", "fexit/"))]
    if len(found) != 1:
        raise ValueError("expected exactly one fentry/ or fexit/ section")
    return found[0]


def resolve(index, binary, hook):
    bid = build_id(str(binary))
    if not bid or len(bid) != 40:
        raise ValueError("target requires a full 20-byte GNU build ID")
    meta, candidates = {}, []
    for line in Path(index).read_text().splitlines():
        fields = line.split("\t")
        if line.startswith("#") and len(fields) >= 2:
            meta[fields[0][1:]] = fields[1]
        elif fields[0] == hook:
            candidates.append(fields)
    if meta.get("build_id") != bid:
        raise ValueError("hook index BUILD ID MISMATCH")
    if len(candidates) != 1:
        raise ValueError("target missing or ambiguous in hook index: " + hook)
    row = candidates[0]
    if len(row) < 4 or row[2] != "pad" or row[3] not in ("0", "4"):
        raise ValueError("target is not a supported +0/+4 padded entry: " + repr(row))
    # arm_at names the first NOP, not the function entry. Preserve endbr64 in
    # the record by subtracting the declared pad offset.
    pad = int(row[3])
    entry = int(row[1], 0) - pad
    blob = Path(binary).read_bytes()
    if blob[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<HH", blob, 16) != (2, 62):
        raise ValueError("target must be x86-64 ET_EXEC; PIE is not supported")
    phoff = struct.unpack_from("<Q", blob, 32)[0]
    size, count = struct.unpack_from("<HH", blob, 54)
    if size != 56 or phoff + count * size > len(blob):
        raise ValueError("invalid executable segment table")
    expected = (b"\xf3\x0f\x1e\xfa" if pad else b"") + b"\x90" * 5
    for i in range(count):
        typ, flags, off, va, _, filesz, _, _ = struct.unpack_from("<IIQQQQQQ", blob, phoff + i * size)
        if typ == 1 and flags & 1 and va <= entry and entry - va + len(expected) <= filesz:
            at = off + entry - va
            if blob[at:at + len(expected)] != expected:
                raise ValueError("index target does not have its declared entry pad")
            return bid, entry, pad
    raise ValueError("target is outside file-backed executable segments")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--prog", required=True)
    ap.add_argument("--index", required=True)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--debug", help="matching debug ELF; required for fexit admission")
    ap.add_argument("--objcopy", default="llvm-objcopy")
    a = ap.parse_args()
    try:
        blob = Path(a.prog).read_bytes()
        sec = program_section(blob)
        bid, entry, pad = resolve(a.index, a.binary, sec.split("/", 1)[1])
        is_exit = sec.startswith("fexit/")
        if is_exit:
            if not a.debug or build_id(a.debug) != bid:
                raise ValueError("fexit requires a matching debug binary for return/unwind admission")
            subprocess.run([sys.executable, str(Path(__file__).with_name("exit_admit.py")),
                            a.debug, a.binary, sec.split("/", 1)[1]], check=True)
        record = struct.pack(FORMAT, MAGIC, bid.encode("ascii"), entry, is_exit, pad)
        with tempfile.TemporaryDirectory(prefix="ls-target-") as tmp:
            target = Path(tmp) / "target"
            output = Path(tmp) / "program.o"
            target.write_bytes(record)
            subprocess.run([a.objcopy, "--remove-section=.ls.target",
                            "--add-section=.ls.target=" + str(target),
                            "--set-section-flags=.ls.target=readonly", a.prog, str(output)], check=True)
            result = output.read_bytes()
            found = [s for n, s in sections(result) if n == ".ls.target"]
            if len(found) != 1 or result[found[0][4]:found[0][4] + found[0][5]] != record:
                raise ValueError("objcopy did not preserve the target record")
            Path(a.prog).write_bytes(result)
        print("  bound %s -> 0x%x (+%d pad), full build %s" % (sec, entry, pad, bid))
        print("  Run PREVAIL on these final bytes, then sign.")
    except (ValueError, OSError, struct.error, subprocess.CalledProcessError) as exc:
        sys.exit("*** target binding refused: " + str(exc))


if __name__ == "__main__":
    main()
