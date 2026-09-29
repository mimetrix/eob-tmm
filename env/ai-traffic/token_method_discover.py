#!/usr/bin/env python3
"""Pin the JSON token-cache observation point on the authoritative build box."""
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
    debug = Path("/home/starin/observability-20260925/debug/usr/lib/debug/usr/bin/tmm64.no_pgo.debug")
    record = {"completed": False, "files": {}, "commands": []}

    def run(*argv):
        row = subprocess.run(list(map(str, argv)), capture_output=True, text=True,
                             timeout=120, check=False)
        record["commands"].append(dict(argv=list(map(str, argv)), rc=row.returncode,
                                       stdout=row.stdout, stderr=row.stderr))
        row.check_returncode()
        return row.stdout

    with args.output.open("x") as output:
        try:
            paths = [tree / name for name in (
                "AGENTS.md", "src/modules/hudfilter/aimcp/aimcp.c",
                "src/modules/hudfilter/json/json_filter.c",
                "src/modules/hudfilter/json/json_parse.c",
                "src/modules/hudfilter/json/json_parse.h",
                "src/modules/hudfilter/json/jxmn.h",
                "src/modules/hudfilter/json/jxmn.c",
            )] + [package / "hook-index.tsv", package / "runtime-identity.json",
                  Path(__file__), Path(__file__).with_name("TOKEN-METHOD.md")]
            for path in paths:
                data = path.read_bytes()
                record["files"][str(path)] = dict(sha256=hashlib.sha256(data).hexdigest(), text=data.decode())
            record["tree_head"] = run("git", "-C", tree, "rev-parse", "HEAD").strip()
            status = run("git", "-C", tree, "status", "--porcelain", "src/modules/hudfilter/aimcp", "src/modules/hudfilter/json")
            assert not status
            with (package / "tmm64.no_pgo").open("rb") as stream:
                record["binary_sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
            runtime = json.loads((package / "runtime-identity.json").read_text())
            assert runtime["sha256"] == record["binary_sha256"]
            record["build_id"] = runtime["build_id"]
            assert "Build ID: " + runtime["build_id"] in run("readelf", "-n", debug)
            index = (package / "hook-index.tsv").read_text()
            row, = [line.split("\t") for line in index.splitlines() if line.startswith("json_filter_handle_json_complete\t")]
            assert row[2:] == ["pad", "0", "5"]
            address = int(row[1], 16)
            record["hook"] = dict(name=row[0], entry=hex(address), pad=0)
            run("objdump", "-d", "--start-address=" + hex(address),
                "--stop-address=" + hex(address + 704), package / "tmm64.no_pgo")
            run("objdump", "-d", "--start-address=0xd93800", "--stop-address=0xd94c00", package / "tmm64.no_pgo")
            record["layout"] = run("gdb", "-nx", "-batch", debug,
                "-ex", "ptype /o struct tmm_json_cache", "-ex", "ptype /o jxmntok_t",
                "-ex", "ptype /o struct xfrag", "-ex", "ptype /o struct json_scb",
                "-ex", "p/d JXMN_OBJECT", "-ex", "p/d JXMN_STRING")
            record["completed"] = True
        finally:
            json.dump(record, output, indent=2)
    print(json.dumps({k: record[k] for k in ("completed", "build_id", "hook")}))


if __name__ == "__main__":
    main()
