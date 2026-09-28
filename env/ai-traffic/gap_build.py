#!/usr/bin/env python3
"""Recheck pinned signed programs and run four-VM gap/capacity/recovery tests."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path("/home/starin/eob-config-20260925")
BASE = Path("/home/starin/eob-tmm-staged/substrate")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir()
    record = {"passed": False, "sources": {}, "commands": []}

    def run(*argv):
        result = subprocess.run(list(map(str, argv)), capture_output=True, text=True,
                                timeout=180, check=False)
        record["commands"].append(dict(argv=list(map(str, argv)), rc=result.returncode,
                                       stdout=result.stdout, stderr=result.stderr))
        result.check_returncode()
        return result.stdout

    with (args.output / "lifetime-program-build.json").open("x") as receipt:
        try:
            previous = ROOT / "correlation-build-02"
            build = json.loads((previous / "lifetime-program-build.json").read_text())
            assert build["passed"]
            record.update(correlation_build=build, runtime=build["runtime"], programs=build["programs"])
            for path in (BASE / "check_correlation_gaps.c", BASE / "ls_map_glue.h",
                         BASE / "ls_map.h", BASE / "ls_config.h", ROOT / "GAPS.md",
                         ROOT / "gap_window.py", ROOT / "check_gap_window.py",
                         ROOT / "correlation_join.py", Path(__file__)):
                record["sources"][str(path)] = dict(text=path.read_text(),
                    sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            ubpf = Path("/home/starin/code/tmm/.ubpf")
            verifier = BASE.parent / "ebpf-verifier/bin/prevail"
            assert run("git", "-C", ubpf, "rev-parse", "HEAD").strip() == "c900ed9faf1d41358a7ea9217ccd0b64a4ee8d5d"
            assert run("git", "-C", verifier.parent.parent, "rev-parse", "HEAD").strip() == "06769f7b508214e63b97905d275920f7e90182fa"
            record["gcc"] = run("gcc", "--version")
            package = Path("/home/starin/observability-20260925/image-context/tmm64.no_pgo")
            assert hashlib.sha256(package.read_bytes()).hexdigest() == build["runtime"]["sha256"]
            for program in build["programs"].values():
                for suffix, field in ((".o", "sha256"), (".sig", "signature_sha256")):
                    path = (previous / program["object"]).with_suffix(suffix)
                    assert hashlib.sha256(path.read_bytes()).hexdigest() == program[field]
                    shutil.copyfile(path, args.output / path.name)
                assert run(verifier, args.output / program["object"], program["section"],
                           "--termination", "--strict", "--no-division-by-zero", "--stack-size", "256").startswith("PASS:")
            native = args.output / "native"
            run("gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-I" + str(ubpf / "vm/inc"),
                "-I" + str(ubpf / "build/vm"), BASE / "check_correlation_gaps.c",
                ubpf / "build/lib/libubpf.a", "-lm", "-o", native)
            text = run(native, *(args.output / build["programs"][name]["object"]
                                for name in ("init", "parse", "fini", "candidate")))
            trace = args.output / "native-trace.txt"
            with trace.open("x") as output:
                output.write(text)
            record["consumer"] = json.loads(run("python3", ROOT / "check_gap_window.py", trace))
            assert record["consumer"]["passed"]
            record["passed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            json.dump(record, receipt, indent=2)
    print(json.dumps({"passed": record["passed"], "output": str(args.output)}))


if __name__ == "__main__":
    main()
