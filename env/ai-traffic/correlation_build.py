#!/usr/bin/env python3
"""Build the fourth observer against the checked lifetime programs and image."""
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
        argv = list(map(str, argv))
        result = subprocess.run(argv, capture_output=True, text=True, timeout=240, check=False)
        record["commands"].append({"argv": argv, "rc": result.returncode,
                                   "stdout": result.stdout, "stderr": result.stderr})
        print(result.stdout, result.stderr, flush=True)
        result.check_returncode()
        return result.stdout

    with (args.output / "lifetime-program-build.json").open("x") as receipt:
        try:
            previous = ROOT / "lifetime-build-01"
            build = json.loads((previous / "lifetime-program-build.json").read_text())
            assert build["passed"]
            record.update(lifetime_build=build, runtime=build["runtime"], programs=build["programs"].copy())
            for p in (BASE / "surfaces/request_candidate.bpf.c", BASE / "check_request_candidate.c",
                      BASE / "ls_map_glue.h", BASE / "ls_map.h", BASE / "ls_config.h",
                      BASE / "config_snapshot.bpf.h", ROOT / "CORRELATION.md", Path(__file__)):
                record["sources"][str(p)] = {"sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "text": p.read_text()}
            for program in build["programs"].values():
                for suffix, field in ((".o", "sha256"), (".sig", "signature_sha256")):
                    path = (previous / program["object"]).with_suffix(suffix)
                    assert hashlib.sha256(path.read_bytes()).hexdigest() == program[field]
                    shutil.copyfile(path, args.output / path.name)
            assert "18.1.3" in run("clang-18", "--version")
            ubpf = Path("/home/starin/code/tmm/.ubpf")
            verifier = BASE.parent / "ebpf-verifier/bin/prevail"
            assert run("git", "-C", ubpf, "rev-parse", "HEAD").strip() == "c900ed9faf1d41358a7ea9217ccd0b64a4ee8d5d"
            assert run("git", "-C", verifier.parent.parent, "rev-parse", "HEAD").strip() == "06769f7b508214e63b97905d275920f7e90182fa"
            package = Path("/home/starin/observability-20260925/image-context")
            assert hashlib.sha256((package / "tmm64.no_pgo").read_bytes()).hexdigest() == build["runtime"]["sha256"]
            objcopy = "/usr/lib/llvm-18/bin/llvm-objcopy"
            obj = args.output / "lifetime-candidate.bpf.o"
            run("clang-18", "-target", "bpf", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
                "-c", BASE / "surfaces/request_candidate.bpf.c", "-o", obj)
            run(objcopy, "--remove-section=.BTF", "--remove-section=.BTF.ext", "--remove-section=.rel.BTF.ext", obj)
            binding = run("python3", BASE / "bind_target.py", "--prog", obj, "--binary", package / "tmm64.no_pgo",
                          "--index", package / "hook-index.tsv", "--objcopy", objcopy)
            assert run(verifier, obj, "fentry/http_parse_headers", "--termination", "--strict",
                       "--no-division-by-zero", "--stack-size", "256").startswith("PASS:")
            build_id = "0x" + build["runtime"]["build_id"][:8]
            run("python3", BASE / "sign_shield.py", "--prog", obj, "--key", Path.home() / ".ls-signing/shield_sk.pem",
                "--hook", "http_parse_headers", "--mode-ceiling", "monitor", "--build-min", build_id,
                "--build-max", build_id, "-o", obj.with_suffix(".sig"))
            record["programs"]["candidate"] = {"kind": 4, "slot": 8, "section": "fentry/http_parse_headers",
                "entry": binding.split(" -> ")[1].split()[0], "pad": 0, "object": obj.name,
                "sha256": hashlib.sha256(obj.read_bytes()).hexdigest(),
                "signature_sha256": hashlib.sha256(obj.with_suffix(".sig").read_bytes()).hexdigest()}
            native = args.output / "native"
            run("gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-I" + str(ubpf / "vm/inc"),
                "-I" + str(ubpf / "build/vm"), BASE / "check_request_candidate.c", ubpf / "build/lib/libubpf.a",
                "-lm", "-o", native)
            run(native, obj)
            record["passed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            json.dump(record, receipt, indent=2)


if __name__ == "__main__":
    main()
