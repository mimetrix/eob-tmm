#!/usr/bin/env python3
"""Record source and machine-code inputs for bounded header correlation."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    tree = Path("/home/starin/code/tmm")
    package = Path("/home/starin/observability-20260925/image-context")
    record = {"passed": False, "sources": {}, "commands": []}
    with args.output.open("x") as output:
        try:
            for path in (tree / "AGENTS.md", tree / "src/modules/hudfilter/http/http_parser.c",
                         tree / "src/modules/hudfilter/http/http_parser.h",
                         tree / "src/modules/hudfilter/http/http.c",
                         package / "hook-index.tsv", package / "runtime-identity.json",
                         Path(__file__)):
                record["sources"][str(path)] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                               "text": path.read_text()}
            binary = package / "tmm64.no_pgo"
            record["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
            for argv in (["git", "-C", str(tree), "rev-parse", "HEAD"],
                         ["git", "-C", str(tree), "status", "--porcelain", "src/"],
                         ["objdump", "-d", "--start-address=0xcc8240", "--stop-address=0xcc8340", str(binary)],
                         ["objdump", "-d", "--start-address=0xccc600", "--stop-address=0xccc740", str(binary)],
                         ["docker", "compose", "ls", "--format", "json"]):
                result = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
                record["commands"].append({"argv": argv, "rc": result.returncode,
                                           "stdout": result.stdout, "stderr": result.stderr})
                result.check_returncode()
            record["passed"] = True
        finally:
            json.dump(record, output, indent=2)


if __name__ == "__main__":
    main()
