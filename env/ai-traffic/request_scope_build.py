#!/usr/bin/env python3
"""Verify, execute, bind and sign the parser-scope probe on the build box."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new directory")
    args = parser.parse_args()
    args.output.mkdir()
    base = Path("/home/starin/eob-tmm-staged/substrate")
    ubpf = Path("/home/starin/code/tmm/.ubpf")
    verifier = base.parent / "ebpf-verifier/bin/prevail"
    context = Path("/home/starin/observability-20260925/image-context")
    debug = context.parent / "debug/usr/lib/debug/usr/bin/tmm64.no_pgo.debug"
    objcopy = "/usr/lib/llvm-18/bin/llvm-objcopy"
    record = {"passed": False, "commands": [], "sources": {}}

    def run(*command):
        command = [str(value) for value in command]
        result = subprocess.run(command, capture_output=True, text=True,
                                check=False, timeout=180)
        record["commands"].append({"command": command, "returncode": result.returncode,
                                   "stdout": result.stdout, "stderr": result.stderr})
        print(result.stdout, result.stderr, flush=True)
        result.check_returncode()
        return result.stdout

    with (args.output / "scope-program-build.json").open("x") as receipt:
        try:
            for name in ("surfaces/request_scope.bpf.c", "check_request_scope.c",
                         "config_snapshot.bpf.h", "ls_config.h", "ls_map.h",
                         "ls_map_glue.h", "bind_target.py", "exit_admit.py",
                         "ls_buildid.py", "sign_shield.py"):
                path = base / name
                record["sources"][name] = {"sha256": digest(path), "text": path.read_text()}
            record["driver"] = {"sha256": digest(Path(__file__)),
                                "text": Path(__file__).read_text()}
            assert "18.1.3" in run("clang-18", "--version")
            run("gcc", "--version")
            for path, wanted in ((ubpf, "c900ed9faf1d41358a7ea9217ccd0b64a4ee8d5d"),
                                 (verifier.parent.parent, "06769f7b508214e63b97905d275920f7e90182fa")):
                assert run("git", "-C", path, "rev-parse", "HEAD").strip() == wanted
            record["inputs"] = {str(path): digest(path) for path in
                                (verifier, ubpf / "build/lib/libubpf.a", debug,
                                 context / "tmm64.no_pgo", context / "hook-index.tsv")}
            identity = json.loads((context / "runtime-identity.json").read_text())
            assert digest(context / "tmm64.no_pgo") == identity["sha256"]
            record["runtime"] = identity
            obj = args.output / "request-scope.bpf.o"
            native = args.output / "native"
            run("clang-18", "-target", "bpf", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
                "-c", base / "surfaces/request_scope.bpf.c", "-o", obj)
            run(objcopy, "--remove-section=.BTF", "--remove-section=.BTF.ext",
                "--remove-section=.rel.BTF.ext", obj)
            binding = run("python3", base / "bind_target.py", "--prog", obj,
                          "--binary", context / "tmm64.no_pgo", "--index", context / "hook-index.tsv",
                          "--debug", debug, "--objcopy", objcopy)
            record["entry"] = binding.split(" -> ")[1].split()[0]
            verdict = run(verifier, obj, "fexit/http_parse_client_headers", "--termination",
                          "--strict", "--no-division-by-zero", "--stack-size", "256")
            assert verdict.startswith("PASS:")
            run("gcc", "-O2", "-Wall", "-Wextra", "-Werror",
                "-I" + str(ubpf / "vm/inc"), "-I" + str(ubpf / "build/vm"),
                base / "check_request_scope.c", ubpf / "build/lib/libubpf.a", "-lm", "-o", native)
            run(native, obj)
            signature = obj.with_suffix(".sig")
            build = "0x" + identity["build_id"][:8]
            run("python3", base / "sign_shield.py", "--key", Path.home() / ".ls-signing/shield_sk.pem",
                "--prog", obj, "--hook", "http_parse_client_headers", "--mode-ceiling", "monitor",
                "--build-min", build, "--build-max", build, "-o", signature)
            record["outputs"] = {p.name: digest(p) for p in (obj, signature, native)}
            record["passed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            json.dump(record, receipt, indent=2)


if __name__ == "__main__":
    main()
