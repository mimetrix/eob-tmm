#!/usr/bin/env python3
"""Build, verify, sign and test the two handler-entry metadata programs."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from metadata_decode import decode


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--discovery", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir()
    base = Path("/home/starin/eob-tmm-staged/substrate")
    ubpf = Path("/home/starin/code/tmm/.ubpf")
    verifier = base.parent / "ebpf-verifier/bin/prevail"
    package = Path("/home/starin/observability-20260925/image-context")
    objcopy = "/usr/lib/llvm-18/bin/llvm-objcopy"
    record = {"passed": False, "commands": [], "sources": {}, "programs": {}}

    def run(*argv):
        argv = list(map(str, argv))
        result = subprocess.run(argv, capture_output=True, text=True,
                                timeout=240, check=False)
        record["commands"].append({"argv": argv, "rc": result.returncode,
                                   "stdout": result.stdout, "stderr": result.stderr})
        print(result.stdout, result.stderr, flush=True)
        result.check_returncode()
        return result.stdout

    with (args.output / "metadata-program-build.json").open("x", encoding="utf-8") as receipt:
        try:
            discovery = json.loads(args.discovery.read_text())
            assert discovery["completed"] and len(discovery["handler_arguments"]) == 2
            record["discovery_sha256"] = digest(args.discovery)
            record["handler_arguments"] = discovery["handler_arguments"]
            record["event_names"] = discovery["event_names"]
            paths = [base / name for name in (
                "surfaces/metadata_handler.bpf.c", "check_metadata_handler.c",
                "ls_map_glue.h", "ls_map.h", "ls_config.h", "config_snapshot.bpf.h",
                "bind_target.py", "ls_buildid.py", "sign_shield.py",
            )]
            paths += [Path(__file__), Path(__file__).with_name("metadata_decode.py"),
                      Path(__file__).with_name("METADATA.md")]
            for path in paths:
                record["sources"][str(path)] = {"sha256": digest(path), "text": path.read_text()}
            assert "18.1.3" in run("clang-18", "--version")
            run("gcc", "--version")
            assert run("git", "-C", ubpf, "rev-parse", "HEAD").strip() == "c900ed9faf1d41358a7ea9217ccd0b64a4ee8d5d"
            assert run("git", "-C", verifier.parent.parent, "rev-parse", "HEAD").strip() == "06769f7b508214e63b97905d275920f7e90182fa"
            record["tool_inputs"] = {str(p): digest(p) for p in
                                     (verifier, ubpf / "build/lib/libubpf.a")}
            runtime = json.loads((package / "runtime-identity.json").read_text())
            assert runtime["sha256"] == discovery["binary_sha256"] == digest(package / "tmm64.no_pgo")
            assert runtime["build_id"] == discovery["build_id"]
            assert digest(package / "hook-index.tsv") == discovery["files"][str(package / "hook-index.tsv")]["sha256"]
            record["runtime"] = runtime
            objects = []
            for kind, label, hook, slot in ((1, "a2a", "hud_a2a_handler", 5),
                                             (2, "aimcp", "hud_aimcp_handler", 6)):
                obj = args.output / ("metadata-" + label + ".bpf.o")
                objects.append(obj)
                section = "fentry/" + hook
                run("clang-18", "-target", "bpf", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
                    "-DMETA_KIND=" + str(kind), "-c", base / "surfaces/metadata_handler.bpf.c", "-o", obj)
                run(objcopy, "--remove-section=.BTF", "--remove-section=.BTF.ext",
                    "--remove-section=.rel.BTF.ext", obj)
                binding = run("python3", base / "bind_target.py", "--prog", obj,
                              "--binary", package / "tmm64.no_pgo", "--index", package / "hook-index.tsv",
                              "--objcopy", objcopy)
                assert run(verifier, obj, section, "--termination", "--strict",
                           "--no-division-by-zero", "--stack-size", "256").startswith("PASS:")
                build = "0x" + runtime["build_id"][:8]
                signature = obj.with_suffix(".sig")
                run("python3", base / "sign_shield.py", "--key", Path.home() / ".ls-signing/shield_sk.pem",
                    "--prog", obj, "--hook", hook, "--mode-ceiling", "monitor",
                    "--build-min", build, "--build-max", build, "-o", signature)
                record["programs"][label] = {"kind": kind, "slot": slot, "section": section,
                    "entry": binding.split(" -> ")[1].split()[0], "pad": 4,
                    "object": obj.name, "sha256": digest(obj), "signature_sha256": digest(signature)}
            native = args.output / "native"
            run("gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-I" + str(ubpf / "vm/inc"),
                "-I" + str(ubpf / "build/vm"), base / "check_metadata_handler.c",
                ubpf / "build/lib/libubpf.a", "-lm", "-o", native)
            output = run(native, *objects)
            events = [decode(bytes.fromhex(line[7:]), record["event_names"])
                      for line in output.splitlines() if line.startswith("RECORD ")]
            assert events and {e["kind"] for e in events} == {1, 2}
            assert any(e["code"] == 0xffffffff and e["event_name"] is None for e in events)
            assert any(e["event_name"] == "HUDEVT_REQUEST" for e in events)
            record["native_events"] = events
            record["native_sha256"] = digest(native)
            record["passed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            json.dump(record, receipt, indent=2)


if __name__ == "__main__":
    main()
