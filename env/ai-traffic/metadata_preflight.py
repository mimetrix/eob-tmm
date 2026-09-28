#!/usr/bin/env python3
"""Record the isolated fixture's native-filter configuration interfaces."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

SCRIPT = r'''
import hashlib, importlib, inspect, json
from pathlib import Path
import pru_ssa_config_builder as builder
result = {"builder": {}, "profiles": {}, "sources": {}}
path = Path(inspect.getfile(builder))
result["sources"][str(path)] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "text": path.read_text()}
for name in dir(builder):
    if name.startswith("create_default_") and any(key in name for key in ("a2a", "mcp", "json", "sse", "http")):
        result["builder"][name] = inspect.getsource(getattr(builder, name))
for name in ("profile_a2a", "profile_aimcp", "profile_json", "profile_sse"):
    module = importlib.import_module(name + "_pb2")
    desc = getattr(module, name).DESCRIPTOR
    result["profiles"][name] = [{"name": f.name, "type": f.type,
        "enum": {v.name: v.number for v in f.enum_type.values} if f.enum_type else None}
        for f in desc.fields]
    path = Path(module.__file__)
    result["sources"][str(path)] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "text": path.read_text()}
print(json.dumps(result))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    record = {"passed": False, "script": SCRIPT}
    with args.output.open("x", encoding="utf-8") as stream:
        try:
            argv = ["docker", "exec", "eob-template-20260925-fixture-1", "python3", "-c", SCRIPT]
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
            record["command"] = {"argv": argv, "rc": proc.returncode,
                                 "stdout": proc.stdout, "stderr": proc.stderr}
            if proc.returncode:
                print(proc.stderr, flush=True)
            proc.check_returncode()
            result = json.loads(proc.stdout)
            record["result"] = result
            record["passed"] = True
            print(json.dumps({k: result[k] for k in ("builder", "profiles")}, indent=2))
        finally:
            json.dump(record, stream, indent=2)


if __name__ == "__main__":
    main()
