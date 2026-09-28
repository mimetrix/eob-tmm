#!/usr/bin/env python3
"""Cache authoritative HTTP source and runtime inputs for the attribution gate."""
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
    record = {"completed": False, "files": {}, "commands": []}
    with args.output.open("x") as output:
        try:
            paths = [tree / name for name in (
                "AGENTS.md", "src/modules/hudfilter/http/http.h",
                "src/modules/hudfilter/http/http_parser.h",
                "src/modules/hudfilter/http/http_parser.c",
                "src/modules/hudfilter/http/http.c", "src/sys/xbuf.h")]
            paths += [context / "runtime-identity.json", context / "hook-index.tsv"]
            for path in paths:
                data = path.read_bytes()
                record["files"][str(path)] = {
                    "sha256": hashlib.sha256(data).hexdigest(), "text": data.decode()
                }
            for command in (
                ["git", "-C", str(tree), "rev-parse", "HEAD"],
                ["git", "-C", str(tree), "status", "--porcelain", "src/"],
                ["docker", "inspect", "eob-template-20260925-tmm-1", "--format",
                 "{{json .Id}} {{json .Image}} {{json .State}} {{.RestartCount}}"],
            ):
                result = subprocess.run(command, capture_output=True, text=True,
                                        check=False, timeout=30)
                record["commands"].append({"argv": command, "rc": result.returncode,
                                           "stdout": result.stdout, "stderr": result.stderr})
                result.check_returncode()
            record["completed"] = True
        finally:
            json.dump(record, output, indent=2)


if __name__ == "__main__":
    main()
