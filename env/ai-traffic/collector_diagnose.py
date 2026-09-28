#!/usr/bin/env python3
"""Retain the first isolated collector startup failure and its direct retry."""
import json
from pathlib import Path
import subprocess

ROOT = Path("/home/starin/eob-config-20260925")


def main():
    result = {"commands": [], "source": Path(__file__).read_text()}
    commands = [
        ["python3", "-c", "import sys; print(sys.executable); print(sys.version)"],
        ["python3", "-c", 'import pathlib; p=pathlib.Path("/run/ls-stream/collector-live-01/collector.log"); print(repr(p.read_bytes())); print(list(p.parent.iterdir()))'],
        ["python3", "/tmp/collector-live-01-collector/stream_collector.py", "collect", "--once",
         "--journal", "/run/ls-stream/collector-diagnostic-01.sqlite",
         "--reader", "/tmp/collector-live-01-collector/ls_stream",
         "--segment", "/run/ls-stream/ls_tp_ring", "--pid", "7", "--start", "327796383"],
    ]
    with (ROOT / "collector-diagnostic-01.json").open("x") as output:
        try:
            for command in commands:
                row = subprocess.run(["docker", "exec", "eob-template-20260925-tmm-1"] + command,
                                     capture_output=True, text=True, timeout=20, check=False)
                result["commands"].append({"argv": command, "rc": row.returncode,
                                           "stdout": row.stdout, "stderr": row.stderr})
        finally:
            json.dump(result, output, indent=2)
    print(json.dumps(result["commands"], indent=2))


if __name__ == "__main__":
    main()
