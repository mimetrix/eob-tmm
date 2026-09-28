#!/usr/bin/env python3
"""Retain a map-reuse falsifier and start a separate tutorial SSA fixture."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    """Use the existing packaged image and preserve the older fixture."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path("/home/starin/eob-config-20260925")
    staged = Path("/home/starin/eob-tmm-staged/substrate")
    record = {"passed": False, "commands": []}

    def run(*command, expected=0):
        result = subprocess.run([str(item) for item in command], cwd=root,
                                capture_output=True, text=True, timeout=240, check=False)
        record["commands"].append({"command": [str(item) for item in command],
                                   "returncode": result.returncode,
                                   "stdout": result.stdout, "stderr": result.stderr})
        assert result.returncode == expected, record["commands"][-1]
        return result

    with args.output.open("x") as output:
        try:
            checked = json.loads(Path("/home/starin/template-20260925/check-05/receipt.json").read_text())
            record["sources"] = {}
            for path in (staged / "ls_map.h", staged / "ls_map_glue.h", root / "check_map_reuse.c"):
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                record["sources"][str(path)] = digest
                if path.parent == staged:
                    assert digest == checked["sources"][path.name]
            binary = root / "check-map-reuse"
            assert not binary.exists()
            run("gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-I" + str(staged),
                "-I/home/starin/code/tmm/.ubpf/vm/inc", "-I/home/starin/code/tmm/.ubpf/build/vm",
                root / "check_map_reuse.c", "-o", binary)
            falsifier = run(binary, expected=1)
            record["falsifier"] = json.loads(falsifier.stdout)
            assert record["falsifier"] == {"index": 0, "registered_type": 1,
                                           "storage_is_ring": 1, "update_result": -1, "passed": False}
            run("docker", "logs", "eob-config-20260925-tmm-1")
            run("docker", "compose", "--env-file", "template-fixture.env", "--project-name",
                "eob-template-20260925", "-f", "icap-compose.yaml", "-f", "config-compose.yaml",
                "up", "-d", "--wait", "--wait-timeout", "180")
            record["passed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            json.dump(record, output, indent=2)


if __name__ == "__main__":
    main()
