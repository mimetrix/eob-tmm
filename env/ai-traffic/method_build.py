#!/usr/bin/env python3
"""Build and check root-object method extraction on the pinned build box."""
import argparse
import json
from pathlib import Path
import subprocess

from metadata_build import digest
from method_decode import decode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--discovery", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir()
    base = Path("/home/starin/eob-tmm-staged/substrate")
    tree = Path("/home/starin/code/tmm")
    ubpf = tree / ".ubpf"
    verifier = base.parent / "ebpf-verifier/bin/prevail"
    package = Path("/home/starin/observability-20260925/image-context")
    debug = Path("/home/starin/observability-20260925/debug/usr/lib/debug/usr/bin/tmm64.no_pgo.debug")
    objcopy = "/usr/lib/llvm-18/bin/llvm-objcopy"
    record = {"passed": False, "commands": [], "sources": {}, "programs": {}}

    def run(*argv):
        argv = list(map(str, argv))
        result = subprocess.run(argv, capture_output=True, text=True, timeout=240, check=False)
        record["commands"].append({"argv": argv, "rc": result.returncode,
                                   "stdout": result.stdout, "stderr": result.stderr})
        if result.returncode:
            print(result.stdout, result.stderr, flush=True)
        result.check_returncode()
        return result.stdout

    with (args.output / "metadata-program-build.json").open("x") as receipt:
        try:
            discovery = json.loads(args.discovery.read_text())
            assert discovery["completed"]
            record["discovery_sha256"] = digest(args.discovery)
            record["event_names"] = discovery["event_names"]
            layout = " ".join(discovery["json_layout"].split())
            for expected in (
                "/* 40 | 8 */ struct tmm_json_value *owner;",
                "/* 24: 0 | 4 */ BOOL parsed : 1;",
                "/* 16 | 8 */ struct json_keyval *tlt_last;",
                "/* 20: 0 | 4 */ BOOL key_parsed : 1;",
                "/* 24 | 8 */ struct tmm_json_value *value;",
                "/* 32 | 8 */ struct json_keyval *tle_next;",
                "$1 = 1 $2 = 3",
            ):
                assert expected in layout, expected
            record["json_layout"] = discovery["json_layout"]
            paths = [base / name for name in (
                "surfaces/json_method.bpf.c", "surfaces/json_method_abi.h", "check_json_method.c",
                "ls_map_glue.h", "ls_map.h", "ls_config.h", "config_snapshot.bpf.h",
                "bind_target.py", "exit_admit.py", "ls_buildid.py", "sign_shield.py",
            )]
            paths += [Path(__file__), Path(__file__).with_name("method_decode.py"),
                      Path(__file__).with_name("metadata_build.py"),
                      Path(__file__).with_name("metadata_decode.py"),
                      Path(__file__).with_name("METADATA.md"), tree / "src/sys/queue.h"]
            for path in paths:
                record["sources"][str(path)] = {"sha256": digest(path), "text": path.read_text()}
            assert "18.1.3" in run("clang-18", "--version")
            assert "13.3.0" in run("gcc", "--version")
            assert run("git", "-C", ubpf, "rev-parse", "HEAD").strip() == "c900ed9faf1d41358a7ea9217ccd0b64a4ee8d5d"
            assert run("git", "-C", verifier.parent.parent, "rev-parse", "HEAD").strip() == "06769f7b508214e63b97905d275920f7e90182fa"
            record["tool_inputs"] = {str(p): digest(p) for p in (verifier, ubpf / "build/lib/libubpf.a", debug)}
            runtime = json.loads((package / "runtime-identity.json").read_text())
            assert runtime["sha256"] == discovery["binary_sha256"] == digest(package / "tmm64.no_pgo")
            assert runtime["build_id"] == discovery["build_id"]
            assert "Build ID: " + runtime["build_id"] in run("readelf", "-n", debug)
            assert digest(package / "hook-index.tsv") == discovery["files"][str(package / "hook-index.tsv")]["sha256"]
            record["runtime"] = runtime
            obj = args.output / "metadata-method.bpf.o"
            hook = "tmm_json_value_get_string"
            section = "fexit/" + hook
            run("clang-18", "-target", "bpf", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
                "-c", base / "surfaces/json_method.bpf.c", "-o", obj)
            run(objcopy, "--remove-section=.BTF", "--remove-section=.BTF.ext", "--remove-section=.rel.BTF.ext", obj)
            binding = run("python3", base / "bind_target.py", "--prog", obj,
                          "--binary", package / "tmm64.no_pgo", "--index", package / "hook-index.tsv",
                          "--debug", debug, "--objcopy", objcopy)
            assert run(verifier, obj, section, "--termination", "--strict",
                       "--no-division-by-zero", "--stack-size", "256").startswith("PASS:")
            build_id = "0x" + runtime["build_id"][:8]
            signature = obj.with_suffix(".sig")
            run("python3", base / "sign_shield.py", "--key", Path.home() / ".ls-signing/shield_sk.pem",
                "--prog", obj, "--hook", hook, "--mode-ceiling", "monitor",
                "--build-min", build_id, "--build-max", build_id, "-o", signature)
            record["programs"]["method"] = {"slot": 7, "section": section,
                "entry": binding.split(" -> ")[1].split()[0], "pad": 4,
                "object": obj.name, "sha256": digest(obj), "signature_sha256": digest(signature)}
            native = args.output / "native"
            run("gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-I" + str(ubpf / "vm/inc"),
                "-I" + str(ubpf / "build/vm"), base / "check_json_method.c",
                ubpf / "build/lib/libubpf.a", "-lm", "-o", native)
            output = run(native, obj)
            events = [decode(bytes.fromhex(line[7:])) for line in output.splitlines() if line.startswith("RECORD ")]
            assert {e["status"] for e in events} == set(range(1, 8))
            record["native_events"] = events
            record["native_sha256"] = digest(native)
            record["passed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            json.dump(record, receipt, indent=2)
    print(json.dumps({"passed": record["passed"], "events": len(events)}))


if __name__ == "__main__":
    main()
