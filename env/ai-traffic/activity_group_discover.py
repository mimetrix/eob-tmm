#!/usr/bin/env python3
"""Capture the source and runtime layout for the proposed activity exchange key."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path("/home/starin/eob-config-20260925")
    tree = Path("/home/starin/code/tmm")
    package = root / "activity-integration-01"
    binary = package / "image-context/tmm64.no_pgo"
    debug = package / "debug/usr/lib/debug/usr/bin/tmm64.no_pgo.debug"
    record = dict(passed=False, sources={}, commands=[])

    def run(*argv):
        result = subprocess.run(list(map(str, argv)), capture_output=True, text=True,
                                timeout=120, check=False)
        record["commands"].append(dict(argv=list(map(str, argv)), rc=result.returncode,
                                       stdout=result.stdout, stderr=result.stderr))
        result.check_returncode()
        return result.stdout

    with args.output.open("x") as receipt:
        try:
            names = ("AGENTS.md", "src/base/flow_table.h", "src/modules/modules.h",
                     "src/modules/hudfilter/aimcp/aimcp.c",
                     "src/modules/hudfilter/json/json_filter.c",
                     "src/modules/hudfilter/http/http_api.h",
                     "src/modules/hudfilter/hud_orbit.h")
            for path in [tree / n for n in names] + [Path(__file__), root / "ACTIVITY-COMBINED.md"]:
                data = path.read_bytes()
                record["sources"][str(path)] = dict(sha256=hashlib.sha256(data).hexdigest(), text=data.decode())
            assert not run("git", "-C", tree, "status", "--porcelain", *names[1:])
            record["tree"] = run("git", "-C", tree, "rev-parse", "HEAD").strip()
            record["runtime_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
            assert record["runtime_sha256"] == "9d3670067daa0f960f90257870cea79b9e70ca2a8cf3c3ac8a2ced87ad514a7f"
            run("readelf", "-n", binary)
            record["layout"] = run("gdb", "-q", "-nx", "-batch", debug,
                "-ex", "ptype /o struct connflow", "-ex", "ptype /o struct http_data",
                "-ex", "p/d HUDEVT_REQUEST", "-ex", "p/d HUDCTL_RESPONSE_DONE",
                "-ex", "p/d HUDEVT_FLOW_INIT", "-ex", "p/d HUDCTL_ABORT",
                "-ex", "p/d HUDCTL_TEARDOWN")
            record["passed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            json.dump(record, receipt, indent=2)


if __name__ == "__main__":
    main()
