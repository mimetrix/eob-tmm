#!/usr/bin/env python3
"""Retain authoritative callers, reset paths and packaged lifecycle targets."""
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
    context = Path("/home/starin/observability-20260925/image-context")
    record = {"passed": False, "commands": [], "files": {}}
    with args.output.open("x") as output:
        try:
            pattern = (r"http_parse_ctx_(init|fini)|http_parse_client_headers|"
                       r"http_parse_server_headers|http_parse_headers|"
                       r"http_reset_(http|scb)_context")
            command = ["git", "-C", str(tree), "grep", "-n", "-E", pattern, "--", "src"]
            result = subprocess.run(command, text=True, capture_output=True, check=False)
            record["commands"].append({"argv": command, "rc": result.returncode,
                                       "stdout": result.stdout, "stderr": result.stderr})
            result.check_returncode()
            paths = {tree / line.split(":", 1)[0] for line in result.stdout.splitlines()}
            paths |= {tree / "AGENTS.md", tree / "src/modules/hudfilter/http/http.h",
                      context / "runtime-identity.json", context / "hook-index.tsv"}
            for path in sorted(paths):
                data = path.read_bytes()
                record["files"][str(path)] = {"sha256": hashlib.sha256(data).hexdigest(),
                                             "text": data.decode()}
            for command in (["git", "-C", str(tree), "rev-parse", "HEAD"],
                            ["git", "-C", str(tree), "status", "--porcelain", "src/"],
                            ["docker", "compose", "ls", "--format", "json"]):
                result = subprocess.run(command, text=True, capture_output=True, check=False)
                record["commands"].append({"argv": command, "rc": result.returncode,
                                           "stdout": result.stdout, "stderr": result.stderr})
                result.check_returncode()
            record["driver"] = Path(__file__).read_text()
            record["passed"] = True
        finally:
            json.dump(record, output, indent=2)


if __name__ == "__main__":
    main()
