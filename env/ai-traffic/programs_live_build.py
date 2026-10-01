#!/usr/bin/env python3
"""Bind the native-qualified ownership test to the packaged TMM's entry hooks."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "package", "native", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir()
    base = args.source / "substrate"
    sys.path.insert(0, str(base))
    from bind_target import sections
    from bind_targets import bind
    record = dict(passed=False, commands=[], sources={})

    def run(*cmd):
        p = subprocess.run(list(map(str, cmd)), capture_output=True, text=True, timeout=240)
        record["commands"].append(dict(argv=list(map(str, cmd)), rc=p.returncode,
                                       stdout=p.stdout, stderr=p.stderr))
        p.check_returncode()
        return p.stdout

    with (args.output / "program-build.json").open("x") as receipt:
        try:
            package = json.loads((args.package / "package-result.json").read_text())
            assert package["passed"]
            record["package_sha256"] = sha(args.package / "package-result.json")
            native = json.loads((args.native / "result.json").read_text())
            assert sha(args.native / "result.json") == "7cce91bb5bc202352583f47aedd31b5955eb6d7d6007bc5f1063fb66f9c4d717"
            assert native["passed"]
            record["native_sha256"] = sha(args.native / "result.json")
            for path in [Path(__file__), base / "bind_target.py", base / "bind_targets.py",
                         base / "sign_shield.py", base / "check_programs.bpf.c",
                         base / "config_snapshot.bpf.h", args.source / "env/scripts/ls-load.py"]:
                record["sources"][path.name] = dict(sha256=sha(path), text=path.read_text())
            original = args.native / "check_programs.bpf.o"
            obj = args.output / "ownership.bpf.o"
            objcopy = "/usr/lib/llvm-18/bin/llvm-objcopy"
            assert sha(base / "check_programs.bpf.c") == native["sources"]["substrate/check_programs.bpf.c"]["sha256"]
            assert sha(base / "config_snapshot.bpf.h") == native["sources"]["substrate/config_snapshot.bpf.h"]["sha256"]
            assert "18.1.3" in run("clang-18", "--version")
            rebuilt = args.output / "native.bpf.o"
            run("clang-18", "-target", "bpf", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
                "-c", base / "check_programs.bpf.c", "-o", rebuilt)
            run(objcopy, "--strip-debug", "--remove-section=.BTF", "--remove-section=.BTF.ext",
                "--remove-section=.rel.BTF.ext", rebuilt)
            assert sha(rebuilt) == sha(original)
            record["native_object_sha256"] = sha(original)
            mapping = {"fentry/program_alpha": "fentry/json_filter_handle_json_complete",
                       "fentry/program_beta": "fentry/hud_aimcp_handler"}
            run(objcopy, *(arg for pair in mapping.items() for arg in ("--rename-section", "=".join(pair))), original, obj)

            def code(path, rename=False):
                blob = path.read_bytes()
                return {mapping.get(n, n) if rename else n: blob[h[4]:h[4] + h[5]]
                        for n, h in sections(blob) if h[2] & 4}

            assert code(original, True) == code(obj)
            binary = args.package / "image-context/tmm64.no_pgo"
            assert sha(binary) == package["runtime"]["sha256"]
            targets = bind(obj, binary, args.package / "image-context/hook-index.tsv", objcopy)
            assert code(original, True) == code(obj)
            record["native_executable_sections_unchanged"] = True
            prevail = Path("/home/starin/eob-tmm-staged/ebpf-verifier/bin/prevail")
            assert run("git", "-C", prevail.parent.parent, "rev-parse", "HEAD").strip() == "06769f7b508214e63b97905d275920f7e90182fa"
            for target in targets:
                assert run(prevail, obj, target["section"], "--termination", "--strict",
                           "--no-division-by-zero", "--stack-size", "256").startswith("PASS:")
            bid = package["runtime"]["build_id"]
            signature = args.output / "ownership.sig"
            run("python3", base / "sign_shield.py", "--key", Path.home() / ".ls-signing/shield_sk.pem",
                "--prog", obj, "--hook", "@program-v1", "--mode-ceiling", "monitor",
                "--build-min", "0x" + bid[:8], "--build-max", "0x" + bid[:8], "-o", signature)
            shutil.copy2(args.source / "env/scripts/ls-load.py", args.output / "ls-load.py")
            record.update(runtime=package["runtime"], tmm_image=package["image"],
                          artifact=dict(object=obj.name, sha256=sha(obj), signature=signature.name,
                                        signature_sha256=sha(signature), cli_sha256=sha(args.output / "ls-load.py")),
                          targets=targets, passed=True)
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            json.dump(record, receipt, indent=2)
    print(json.dumps(dict(passed=True, targets=targets)))


if __name__ == "__main__":
    main()
