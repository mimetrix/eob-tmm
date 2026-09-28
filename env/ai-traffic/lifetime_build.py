#!/usr/bin/env python3
"""Build, verify and sign three cooperating parser-lifetime programs."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir()
    base = Path("/home/starin/eob-tmm-staged/substrate")
    ubpf = Path("/home/starin/code/tmm/.ubpf")
    verifier = base.parent / "ebpf-verifier/bin/prevail"
    context = Path("/home/starin/observability-20260925/image-context")
    debug = context.parent / "debug/usr/lib/debug/usr/bin/tmm64.no_pgo.debug"
    objcopy = "/usr/lib/llvm-18/bin/llvm-objcopy"
    record = {"passed": False, "commands": [], "sources": {}, "programs": {}}

    def run(*argv):
        argv = list(map(str, argv))
        result = subprocess.run(argv, text=True, capture_output=True, timeout=180, check=False)
        record["commands"].append({"argv": argv, "rc": result.returncode,
                                   "stdout": result.stdout, "stderr": result.stderr})
        print(result.stdout, result.stderr, flush=True)
        result.check_returncode()
        return result.stdout

    with (args.output / "lifetime-program-build.json").open("x") as receipt:
        try:
            for name in ("surfaces/parser_lifetime.bpf.c", "check_parser_lifetime.c",
                         "ls_map_glue.h", "ls_map.h", "ls_config.h", "config_snapshot.bpf.h",
                         "bind_target.py", "exit_admit.py", "ls_buildid.py", "sign_shield.py"):
                path = base / name
                record["sources"][name] = {"sha256": digest(path), "text": path.read_text()}
            record["driver"] = {"sha256": digest(Path(__file__)), "text": Path(__file__).read_text()}
            gate = Path(__file__).parent / "LIFETIME.md"
            record["registered_gate"] = {"sha256": digest(gate), "text": gate.read_text()}
            assert "18.1.3" in run("clang-18", "--version")
            run("gcc", "--version")
            for path, expected in ((ubpf, "c900ed9faf1d41358a7ea9217ccd0b64a4ee8d5d"),
                                   (verifier.parent.parent, "06769f7b508214e63b97905d275920f7e90182fa")):
                assert run("git", "-C", path, "rev-parse", "HEAD").strip() == expected
            record["inputs"] = {str(p): digest(p) for p in (
                verifier, ubpf / "build/lib/libubpf.a", debug,
                context / "tmm64.no_pgo", context / "hook-index.tsv")}
            identity = json.loads((context / "runtime-identity.json").read_text())
            assert identity["sha256"] == digest(context / "tmm64.no_pgo")
            record["runtime"] = identity
            objects = []
            for kind, label, section, slot in (
                    (1, "init", "fentry/http_parse_ctx_init", 6),
                    (2, "parse", "fexit/http_parse_client_headers", 5),
                    (3, "fini", "fentry/http_parse_ctx_fini", 7)):
                obj = args.output / ("lifetime-" + label + ".bpf.o")
                objects.append(obj)
                run("clang-18", "-target", "bpf", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
                    "-DLIFE_KIND=" + str(kind), "-c", base / "surfaces/parser_lifetime.bpf.c", "-o", obj)
                run(objcopy, "--remove-section=.BTF", "--remove-section=.BTF.ext",
                    "--remove-section=.rel.BTF.ext", obj)
                binding = run("python3", base / "bind_target.py", "--prog", obj,
                              "--binary", context / "tmm64.no_pgo", "--index", context / "hook-index.tsv",
                              "--debug", debug, "--objcopy", objcopy)
                assert run(verifier, obj, section, "--termination", "--strict",
                           "--no-division-by-zero", "--stack-size", "256").startswith("PASS:")
                signature = obj.with_suffix(".sig")
                build = "0x" + identity["build_id"][:8]
                run("python3", base / "sign_shield.py", "--key", Path.home() / ".ls-signing/shield_sk.pem",
                    "--prog", obj, "--hook", section.split("/")[1], "--mode-ceiling", "monitor",
                    "--build-min", build, "--build-max", build, "-o", signature)
                record["programs"][label] = {"kind": kind, "slot": slot, "section": section,
                    "entry": binding.split(" -> ")[1].split()[0],
                    "object": obj.name, "sha256": digest(obj), "signature_sha256": digest(signature)}
            native = args.output / "native"
            run("gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-I" + str(ubpf / "vm/inc"),
                "-I" + str(ubpf / "build/vm"), base / "check_parser_lifetime.c",
                ubpf / "build/lib/libubpf.a", "-lm", "-o", native)
            run(native, *objects)
            record["native_sha256"] = digest(native)
            record["passed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            json.dump(record, receipt, indent=2)


if __name__ == "__main__":
    main()
