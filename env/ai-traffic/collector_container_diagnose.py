#!/usr/bin/env python3
"""Retain process-access checks after the first separate-container refusal."""
import json
from pathlib import Path
import subprocess

ROOT = Path("/home/starin/eob-config-20260925")
IMAGE = "sha256:9df8cd780e6c5ef1d58cdc3a0057875e759e35dcaa55d6df7d64ba9f45dfff94"
SOURCE = str(ROOT / "collector-source-01")
TMM = "eob-template-20260925-tmm-1"
IDENTITY = '''import json,pathlib
p=pathlib.Path("/proc")
print(json.dumps({"self_profile":(p/"self/attr/current").read_text(),
 "target_profile":(p/"7/attr/current").read_text(),
 "self_security":[l for l in (p/"self/status").read_text().splitlines() if l.startswith(("Cap","Seccomp","NoNewPrivs"))]}))
'''


def main():
    record = {"source": Path(__file__).read_text(), "commands": []}
    base = ["docker", "run", "--rm", "--network", "none", "--pid", "container:" + TMM,
            "--cap-drop", "ALL", "--cap-add", "SYS_PTRACE", "--security-opt", "no-new-privileges",
            "-v", SOURCE + ":/source:ro"]
    commands = [
        ["docker", "inspect", TMM, "--format", "{{json .AppArmorProfile}}"],
        base + ["--entrypoint", "python3", IMAGE, "-c", IDENTITY],
        base + ["--security-opt", "apparmor=unconfined", "--entrypoint", "python3", IMAGE, "-c", IDENTITY],
        base + ["--security-opt", "apparmor=unconfined", IMAGE, "--check-source"],
        base + ["--security-opt", "apparmor=unconfined", IMAGE, "--source", "/source/wrong-start.json", "--check-source"],
    ]
    with (ROOT / "collector-container-diagnostic-01.json").open("x") as output:
        try:
            for command in commands:
                row = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
                record["commands"].append({"argv": command, "rc": row.returncode,
                                           "stdout": row.stdout, "stderr": row.stderr})
        finally:
            json.dump(record, output, indent=2)
    print(json.dumps(record["commands"], indent=2))


if __name__ == "__main__":
    main()
