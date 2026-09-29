#!/usr/bin/env python3
"""Build, verify and sign the token-cache method probe on the pinned build VM."""
import argparse
import json
from pathlib import Path
import subprocess
from metadata_build import digest
from token_method_decode import decode


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
    debug = Path("/home/starin/observability-20260925/debug/usr/lib/debug/usr/bin/tmm64.no_pgo.debug")
    objcopy = "/usr/lib/llvm-18/bin/llvm-objcopy"
    record = dict(passed=False, commands=[], sources={}, programs={}, event_names={})

    def run(*argv):
        row = subprocess.run(list(map(str, argv)), capture_output=True, text=True, timeout=240, check=False)
        record["commands"].append(dict(argv=list(map(str, argv)), rc=row.returncode, stdout=row.stdout, stderr=row.stderr))
        if row.returncode:
            print(row.stdout, row.stderr, flush=True)
        row.check_returncode()
        return row.stdout

    with (args.output / "metadata-program-build.json").open("x") as output:
        try:
            discovery = json.loads(args.discovery.read_text())
            assert discovery["completed"]
            record["discovery_sha256"] = digest(args.discovery)
            record["layout"] = discovery["layout"]
            layout = " ".join(discovery["layout"].split())
            for expected in ("/* 8 | 24 */ struct xbuf", "/* 40 | 8 */ jxmntok_t (*tokens)[];",
                             "/* 64 | 4 */ BOOL raw_valid;", "/* 16 | 4 */ int sibling;",
                             "/* 6 | 2 */ __arch_uint16_t doff;", "/* 8 | 8 */ __arch_uint8_t *base;",
                             "/* 24 | 8 */ struct tmm_json_cache *json;",
                             "/* 88: 5 | 4 */ BOOL f_valid_parse : 1;",
                             "/* 89: 4 | 4 */ BOOL f_ingress_msg_mode : 1;",
                             "$1 = 1 $2 = 3"):
                assert expected in layout, expected
            paths = [base / name for name in (
                "surfaces/token_method.bpf.c", "surfaces/token_method_abi.h", "surfaces/json_method_abi.h",
                "check_token_method.c", "ls_map_glue.h", "ls_map.h", "ls_config.h", "config_snapshot.bpf.h",
                "bind_target.py", "ls_buildid.py", "sign_shield.py")]
            paths += [Path(__file__), Path(__file__).with_name("token_method_decode.py"),
                      Path(__file__).with_name("TOKEN-METHOD.md")]
            for path in paths:
                record["sources"][str(path)] = dict(sha256=digest(path), text=path.read_text())
            assert "18.1.3" in run("clang-18", "--version")
            assert "13.3.0" in run("gcc", "--version")
            assert run("git", "-C", ubpf, "rev-parse", "HEAD").strip() == "c900ed9faf1d41358a7ea9217ccd0b64a4ee8d5d"
            assert run("git", "-C", verifier.parent.parent, "rev-parse", "HEAD").strip() == "06769f7b508214e63b97905d275920f7e90182fa"
            record["tool_inputs"] = {str(p): digest(p) for p in (verifier, ubpf / "build/lib/libubpf.a", debug)}
            runtime = json.loads((package / "runtime-identity.json").read_text())
            assert runtime["sha256"] == discovery["binary_sha256"] == digest(package / "tmm64.no_pgo")
            assert runtime["build_id"] == discovery["build_id"]
            assert digest(package / "hook-index.tsv") == discovery["files"][str(package / "hook-index.tsv")]["sha256"]
            record["runtime"] = runtime
            obj = args.output / "metadata-token.bpf.o"
            run("clang-18", "-target", "bpf", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
                "-c", base / "surfaces/token_method.bpf.c", "-o", obj)
            run(objcopy, "--remove-section=.BTF", "--remove-section=.BTF.ext", "--remove-section=.rel.BTF.ext", obj)
            run("python3", base / "bind_target.py", "--prog", obj, "--binary", package / "tmm64.no_pgo",
                "--index", package / "hook-index.tsv", "--debug", debug, "--objcopy", objcopy)
            section = "fentry/json_filter_handle_json_complete"
            assert run(verifier, obj, section, "--termination", "--strict", "--no-division-by-zero", "--stack-size", "256").startswith("PASS:")
            native = args.output / "native"
            run("gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-I" + str(ubpf / "vm/inc"),
                "-I" + str(ubpf / "build/vm"), base / "check_token_method.c", ubpf / "build/lib/libubpf.a", "-lm", "-o", native)
            text = run(native, obj)
            events = [decode(bytes.fromhex(line[7:])) for line in text.splitlines() if line.startswith("RECORD ")]
            record["native_events"] = events
            record["native_sha256"] = digest(native)
            build_id = "0x" + runtime["build_id"][:8]
            signature = obj.with_suffix(".sig")
            run("python3", base / "sign_shield.py", "--key", Path.home() / ".ls-signing/shield_sk.pem",
                "--prog", obj, "--hook", "json_filter_handle_json_complete", "--mode-ceiling", "monitor",
                "--build-min", build_id, "--build-max", build_id, "-o", signature)
            record["programs"]["token"] = dict(slot=7, section=section, entry=discovery["hook"]["entry"], pad=discovery["hook"]["pad"],
                object=obj.name, sha256=digest(obj), signature_sha256=digest(signature))
            record["passed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            json.dump(record, output, indent=2)
    print(json.dumps(dict(passed=True, events=len(events))))


if __name__ == "__main__":
    main()
