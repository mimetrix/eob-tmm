#!/usr/bin/env python3
"""Compile the separate collector reader and retain its native gate receipt."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import sqlite3
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir()
    base = Path("/home/starin/eob-tmm-staged/substrate")
    record = {"passed": False, "commands": [], "sources": {},
              "host": platform.node(), "machine": platform.machine(),
              "python": sys.version, "sqlite": sqlite3.sqlite_version}

    def run(*argv):
        result = subprocess.run(list(map(str, argv)), capture_output=True, text=True,
                                check=False, timeout=180)
        record["commands"].append({"argv": list(map(str, argv)), "rc": result.returncode,
                                   "stdout": result.stdout, "stderr": result.stderr})
        result.check_returncode()
        return result.stdout

    with (args.output / "collector-build.json").open("x") as receipt:
        try:
            assert platform.machine() == "x86_64"
            paths = [base / name for name in (
                "drain/ls_stream.c", "drain/check_stream_source.c", "drain/ls_drain.c",
                "ls_ring.h", "ls_tp_ring.h", "ls_tp.h", "ls_json.h")]
            paths += [Path(__file__).with_name(name) for name in (
                "collector_build.py", "check_stream_collector.py", "stream_collector.py",
                "method_decode.py", "COLLECTOR.md")]
            paths.append(Path(__file__).with_name("collector_client.py"))
            for path in paths:
                record["sources"][str(path)] = {
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "text": path.read_text()}
            assert "13.3.0" in run("gcc", "--version")
            for source, output in (("ls_stream.c", "ls_stream"),
                                   ("check_stream_source.c", "source"),
                                   ("ls_drain.c", "legacy")):
                target = args.output / output
                run("gcc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                    base / "drain" / source, "-o", target)
                record[output + "_sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
            run(sys.executable, Path(__file__).with_name("check_stream_collector.py"),
                "--reader", args.output / "ls_stream", "--source", args.output / "source",
                "--legacy", args.output / "legacy",
                "--work", args.output)
            record["passed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            json.dump(record, receipt, indent=2)
    print(json.dumps({"passed": record["passed"], "output": str(args.output)}))


if __name__ == "__main__":
    main()
