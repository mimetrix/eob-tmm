#!/usr/bin/env python3
"""Bind all entry sections of one ELF to a signed, build-specific target set."""
import argparse
from pathlib import Path
import struct
import subprocess
import tempfile

from bind_target import FORMAT, MAGIC, resolve, sections

SET_MAGIC = b"LSTSET1\0"
HEADER = "<8sII"
ROW = "<80s64s"
MAX_TARGETS = 12


def bind(prog, binary, index, objcopy):
    blob = prog.read_bytes()
    names = [n for n, _ in sections(blob) if n.startswith(("fentry/", "fexit/"))]
    if not 2 <= len(names) <= MAX_TARGETS or len(set(names)) != len(names):
        raise ValueError("expected 2..12 distinct entry sections")
    rows, targets, entries = [], [], set()
    for section in names:
        if not section.startswith("fentry/") or not section[7:] or len(section) >= 80:
            raise ValueError("target sets support named entry hooks only")
        bid, entry, pad = resolve(index, binary, section[7:])
        if entry in entries:
            raise ValueError("two sections resolve to the same entry")
        entries.add(entry)
        target = struct.pack(FORMAT, MAGIC, bid.encode("ascii"), entry, 0, pad)
        rows.append(struct.pack(ROW, section.encode("ascii"), target))
        targets.append(dict(section=section, build_id=bid, entry=entry, pad=pad))
    record = struct.pack(HEADER, SET_MAGIC, len(rows), 0) + b"".join(rows)
    with tempfile.TemporaryDirectory(prefix="ls-targets-") as temp:
        path = Path(temp)
        (path / "targets").write_bytes(record)
        subprocess.run([objcopy, "--remove-section=.ls.target",
                        "--add-section=.ls.target=" + str(path / "targets"),
                        "--set-section-flags=.ls.target=readonly",
                        str(prog), str(path / "bound.o")], check=True)
        result = (path / "bound.o").read_bytes()
        found = [sh for name, sh in sections(result) if name == ".ls.target"]
        if len(found) != 1 or result[found[0][4]:found[0][4] + found[0][5]] != record:
            raise ValueError("objcopy did not preserve the target set")
        prog.write_bytes(result)
    return targets


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prog", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--objcopy", default="llvm-objcopy")
    args = parser.parse_args()
    for target in bind(args.prog, args.binary, args.index, args.objcopy):
        print("bound {section} -> {entry:#x} (+{pad}), build {build_id}".format(**target))
    print("Run PREVAIL for each section on these bytes, then sign each hook binding.")


if __name__ == "__main__":
    main()
