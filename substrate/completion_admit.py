#!/usr/bin/env python3
"""Admit a void target for completion-only snapshots; tool errors refuse it."""
import argparse
import re
import subprocess
from pathlib import Path

from exit_admit import UNWIND_INITIATORS
from ls_buildid import build_id


def checked(*argv):
    result = subprocess.run(list(map(str, argv)), capture_output=True, text=True,
                            timeout=180, check=True)
    return result.stdout


def admit(debug, binary, function):
    if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9.]*", function):
        raise ValueError("unsupported function name")
    runtime_id = build_id(str(binary))
    if not runtime_id or len(runtime_id) != 40 or build_id(str(debug)) != runtime_id:
        raise ValueError("matching full runtime and debug build IDs required")
    types = checked("gdb", "-q", "-batch", "-ex", "ptype " + function, debug)
    lines = [line.strip() for line in types.splitlines() if line.startswith("type = ")]
    if len(lines) != 1 or not lines[0].startswith("type = void ("):
        raise ValueError("completion snapshots require an exact void return: " + types)
    symbols = checked("nm", "--defined-only", debug)
    matches = [line.split() for line in symbols.splitlines()
               if len(line.split()) == 3 and line.split()[2] == function
               and line.split()[1] in ("t", "T", "w", "W")]
    if len(matches) != 1:
        raise ValueError("missing or ambiguous target symbol")
    address = int(matches[0][0], 16)
    dynamic = checked("readelf", "--wide", "--dyn-syms", binary)
    for line in dynamic.splitlines():
        if " UND " in line and any(re.search(r"\b" + re.escape(name) + r"\b", line)
                                   for name in UNWIND_INITIATORS):
            raise ValueError("runtime imports an unwind initiator: " + line)
    frames = checked("/usr/lib/llvm-18/bin/llvm-dwarfdump", "--eh-frame", binary)
    current = False
    for line in frames.splitlines():
        match = re.search(r"FDE .*pc=([0-9a-f]+)\.\.\.([0-9a-f]+)", line)
        if match:
            current = int(match[1], 16) <= address < int(match[2], 16)
        elif current and "LSDA Address" in line:
            raise ValueError("target frame carries an LSDA")
    return dict(build_id=runtime_id, function=function, address=address,
                return_type="void", unwind_imports=False, target_lsda=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("debug", type=Path)
    parser.add_argument("binary", type=Path)
    parser.add_argument("function")
    args = parser.parse_args()
    result = admit(args.debug, args.binary, args.function)
    print("ADMIT completion-only:", result)


if __name__ == "__main__":
    main()
