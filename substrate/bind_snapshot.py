#!/usr/bin/env python3
"""Bind the separately versioned completion-only contract before signing."""
import argparse
from pathlib import Path
import struct
import subprocess
import tempfile

from bind_target import FORMAT, program_section, resolve, sections
from completion_admit import admit

PREFIX = "fexit/snapshot/"
MAGIC = b"LSTARG2\0"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prog", type=Path, required=True)
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--debug", type=Path, required=True)
    parser.add_argument("--objcopy", default="/usr/lib/llvm-18/bin/llvm-objcopy")
    args = parser.parse_args()
    section = program_section(args.prog.read_bytes())
    if not section.startswith(PREFIX) or not section[len(PREFIX):]:
        raise ValueError("expected one completion-only snapshot section")
    function = section[len(PREFIX):]
    qualification = admit(args.debug, args.binary, function)
    build, entry, pad = resolve(args.index, args.binary, function)
    if build != qualification["build_id"] or entry != qualification["address"]:
        raise ValueError("admission and attachment target differ")
    record = struct.pack(FORMAT, MAGIC, build.encode("ascii"), entry, 1, pad)
    with tempfile.TemporaryDirectory(prefix="ls-snapshot-") as directory:
        target = Path(directory) / "target"
        output = Path(directory) / "program.o"
        target.write_bytes(record)
        subprocess.run([args.objcopy, "--remove-section=.ls.target",
                        "--add-section=.ls.target=" + str(target),
                        "--set-section-flags=.ls.target=readonly", args.prog, output],
                       check=True, timeout=120)
        blob = output.read_bytes()
        found = [row for name, row in sections(blob) if name == ".ls.target"]
        if len(found) != 1 or blob[found[0][4]:found[0][4] + found[0][5]] != record:
            raise ValueError("objcopy did not preserve the snapshot contract")
        args.prog.write_bytes(blob)
    print("bound completion-only", section, qualification)
    print("Run PREVAIL on these bytes, then sign with a monitor-only ceiling.")


if __name__ == "__main__":
    main()
