#!/usr/bin/env python3
"""Cache scope receipts, exact fixture sources and final loader/check state."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--live", nargs="+", type=Path, required=True)
    args = parser.parse_args()
    root = Path("/home/starin/eob-config-20260925")
    record = {"completed": False, "files": {}, "commands": []}
    names = (
        "request_scope_suite.py", "request_scope_build.py", "request_scope_snapshot.py",
        "attribution_discover.py", "attribution.py", "attribution_suite.py",
        "attribution_join.py", "config_live_run.py", "config_suite.py", "icap_suite.py",
        "icap-run-suite.sh", "icap_check_result.py", "template-fixture.env",
        "observability-compose.yaml", "scope-build-01/scope-program-build.json",
        "attribution-gate-20260928.md",
    )
    with args.output.open("x") as output:
        try:
            for path in [*(root / name for name in names), *args.live]:
                data = path.read_bytes()
                record["files"][str(path)] = {
                    "sha256": hashlib.sha256(data).hexdigest(), "text": data.decode()
                }
            fixture = "eob-template-20260925-fixture-1"
            for command in (
                ["docker", "exec", fixture, "python3", "/work/ls-load.py", "status", "5"],
                ["docker", "exec", fixture, "python3", "/work/ls-load.py", "status", "6"],
                ["docker", "exec", fixture, "python3", "/work/ls-load.py", "config-status", "5"],
                ["docker", "exec", fixture, "python3", "-m", "black", "--check", "/work/request_scope_suite.py"],
                ["docker", "exec", fixture, "python3", "-m", "pylint", "/work/request_scope_suite.py"],
                ["bash", "-n", str(root / "icap-run-suite.sh")],
            ):
                result = subprocess.run(command, capture_output=True, text=True,
                                        check=False, timeout=60)
                record["commands"].append({"argv": command, "rc": result.returncode,
                                           "stdout": result.stdout, "stderr": result.stderr})
                if "config-status" in command:
                    assert result.returncode != 0
                else:
                    result.check_returncode()
                if "status" in command:
                    assert "mode=0" in result.stdout
            record["completed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            json.dump(record, output, indent=2)


if __name__ == "__main__":
    main()
