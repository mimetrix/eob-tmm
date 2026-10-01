#!/usr/bin/env python3
"""Check the pinned verifier's context-write contract before host integration."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir()
    source = Path(__file__).resolve().parent
    result = dict(passed=False, scope="snapshot_context_verifier_preflight",
                  sources={}, commands=[])
    with (args.output / "preflight.json").open("x") as receipt:
        try:
            for name in ("ENTRY-SNAPSHOT.md", "check_snapshot_context.bpf.c",
                         "entry_snapshot_preflight.py"):
                path = source / name
                result["sources"][name] = dict(
                    sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                    text=path.read_text())
            obj = args.output / "context.o"
            commands = [
                ["uname", "-m"], ["clang-18", "--version"],
                ["clang-18", "-O2", "-Wall", "-Wextra", "-Werror", "-target", "bpf",
                 "-c", source / "check_snapshot_context.bpf.c", "-o", obj],
                ["/home/starin/eob-tmm-staged/ebpf-verifier/bin/prevail", obj,
                 "fexit/snapshot/snapshot_victim", "--termination", "--strict",
                 "--no-division-by-zero", "--stack-size", "256"],
            ]
            for command in commands:
                argv = list(map(str, command))
                row = subprocess.run(argv, capture_output=True, text=True,
                                     timeout=120, check=False)
                result["commands"].append(dict(argv=argv, rc=row.returncode,
                                               stdout=row.stdout, stderr=row.stderr))
                print(row.stdout, row.stderr, end="", flush=True)
                row.check_returncode()
            result["passed"] = True
        except BaseException as error:
            result["error"] = repr(error)
            raise
        finally:
            json.dump(result, receipt, indent=2)


if __name__ == "__main__":
    main()
