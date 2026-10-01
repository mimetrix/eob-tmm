#!/usr/bin/env python3
"""Capture JSON-filter scope evidence on the pinned build box without running TMM."""
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
    record = dict(completed=False, files={}, commands=[])

    def run(*argv):
        result = subprocess.run(list(map(str, argv)), capture_output=True, text=True,
                                timeout=120, check=False)
        record["commands"].append(dict(argv=list(map(str, argv)), rc=result.returncode,
                                       stdout=result.stdout, stderr=result.stderr))
        result.check_returncode()
        return result.stdout

    with args.output.open("x") as output:
        try:
            names = (
                "AGENTS.md", "src/modules/hudfilter/json/json_filter.c",
                "src/modules/hudfilter/json/json_parse.c",
                "src/modules/hudfilter/json/json_parse.h",
                "src/modules/hudfilter/hudfilter.h", "src/modules/hudchain.c",
                "src/modules/hudfilter/flow_stream.h",
                "src/modules/hudfilter/flow_stream.c", "src/modules/hudfilter/hudnode.c",
                "src/base/flow_table.h", "src/modules/hudfilter/http/http_api.h",
                "src/modules/hudfilter/aimcp/aimcp.c",
            )
            paths = [tree / name for name in names]
            paths += [package / "runtime-identity.json", package / "hook-index.tsv",
                      Path(__file__), Path(__file__).with_name("MESSAGE-SCOPE.md")]
            for path in paths:
                data = path.read_bytes()
                record["files"][str(path)] = dict(text=data.decode(), sha256=hashlib.sha256(data).hexdigest())
            record["tree_head"] = run("git", "-C", tree, "rev-parse", "HEAD").strip()
            assert not run("git", "-C", tree, "status", "--porcelain", *names[1:])
            runtime = json.loads((package / "runtime-identity.json").read_text())
            with (package / "tmm64.no_pgo").open("rb") as stream:
                record["binary_sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
            assert record["binary_sha256"] == runtime["sha256"] == "05d17517531d99b26eb9e8f00f5b5326f660b5bef492226c9555368b887a9611"
            assert runtime["build_id"] == "ca69b84f4f5c9e225813b2ed3997c59f18ba2a31"
            assert "Build ID: " + runtime["build_id"] in run("readelf", "-n", debug)
            assert "Build ID: " + runtime["build_id"] in run("readelf", "-n", package / "tmm64.no_pgo")
            record["runtime"] = runtime
            hooks = []
            for line in (package / "hook-index.tsv").read_text().splitlines():
                fields = line.split("\t")
                if fields[0].startswith(("json_filter_", "hud_json_", "json_http_")):
                    hooks.append(fields)
            record["hooks"] = hooks
            for name, address, *_ in hooks:
                run("objdump", "-d", "--start-address=" + address,
                    "--stop-address=" + hex(int(address, 16) + 1024), package / "tmm64.no_pgo")
            for start, stop in ((0xd94100, 0xd95680), (0xd93800, 0xd94100),
                                (0xd928c0, 0xd93000)):
                run("objdump", "-d", "--start-address=" + hex(start),
                    "--stop-address=" + hex(stop), package / "tmm64.no_pgo")
            record["layout"] = run("gdb", "-nx", "-batch", debug,
                "-ex", "ptype /o struct json_scb", "-ex", "ptype /o struct hudnode",
                "-ex", "ptype /o struct connflow", "-ex", "ptype /o struct tmm_json_cache",
                "-ex", "p/d &((struct hudnode *)0)->ctx",
                "-ex", "p/d &((struct hudnode *)0)->ctx_sz")
            record["completed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            json.dump(record, output, indent=2)
    print(json.dumps(dict(completed=True, hooks=len(record["hooks"]), runtime=record["runtime"])))


if __name__ == "__main__":
    main()
