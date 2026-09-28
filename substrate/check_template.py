#!/usr/bin/env python3
"""Check template.c on the pinned build box; retain every command and failure.

With --context and --debug, also emit target-bound, verified entry/exit objects.
These final objects are unsigned. No program is loaded or armed by this script.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess

from check_relo_baked import Btf, elf_sections, core_relos, baked_immediates

HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new directory")
    parser.add_argument("--context", type=Path, help="packaged build context")
    parser.add_argument("--debug", type=Path, help="matching debug ELF")
    args = parser.parse_args()
    if bool(args.context) != bool(args.debug):
        parser.error("--context and --debug must be supplied together")
    args.output.mkdir()  # Refuse an existing directory; preserve all attempts.
    record = {"passed": False, "scope": "pinned bench; no live TMM", "commands": []}
    clang = os.environ.get("CLANG", "clang-18")
    objcopy = os.environ.get("OBJCOPY", "/usr/lib/llvm-18/bin/llvm-objcopy")
    ubpf = Path(os.environ.get("UBPF", str(HERE.parent / "ubpf"))).resolve()
    prevail = Path(os.environ.get("PREVAIL", str(HERE.parent / "ebpf-verifier/bin/prevail"))).resolve()

    def run(*command, check=True, input_text=None):
        command = [str(value) for value in command]
        result = subprocess.run(command, capture_output=True, text=True, timeout=180,
                                check=False, input=input_text)
        record["commands"].append({"argv": command, "rc": result.returncode,
                                   "stdout": result.stdout, "stderr": result.stderr,
                                   "stdin": input_text})
        print(result.stdout, result.stderr, flush=True)
        if check:
            result.check_returncode()
        return result

    def strip(obj):
        run(objcopy, "--remove-section=.BTF", "--remove-section=.BTF.ext",
            "--remove-section=.rel.BTF.ext", obj)

    def verify(obj, kind):
        result = run(prevail, obj, kind + "/http_parse_client_headers",
                     "--termination", "--strict", "--no-division-by-zero", "--stack-size", "256")
        assert result.stdout.startswith("PASS:"), "missing verifier PASS"

    with (args.output / "receipt.json").open("x") as receipt:
        try:
            assert "18.1.3" in run(clang, "--version").stdout
            run("gcc", "--version")
            assert run("git", "-C", ubpf, "rev-parse", "HEAD").stdout.strip() == "c900ed9faf1d41358a7ea9217ccd0b64a4ee8d5d"
            assert run("git", "-C", prevail.parent.parent, "rev-parse", "HEAD").stdout.strip() == "06769f7b508214e63b97905d275920f7e90182fa"
            sources = ("template.c", "template_io.py", "check_template.c", "check_template.py", "check_relo_baked.py",
                       "ls_core_relo.c", "ls_core_relo.h", "ls_map_glue.h", "ls_map.h", "ls_config.h",
                       "config_snapshot.bpf.h", "ls_tp.h", "bind_target.py", "ls_buildid.py", "exit_admit.py")
            record["sources"] = {name: digest(HERE / name) for name in sources}
            record["tools"] = {str(path): digest(path) for path in (prevail, ubpf / "build/lib/libubpf.a")}
            native = args.output / "native"
            fixture_btf = args.output / "fixture.btf"
            relo = args.output / "relo"
            run("gcc", "-O2", "-g", "-gbtf", "-Wall", "-Wextra", "-Werror",
                "-I" + str(ubpf / "vm/inc"), "-I" + str(ubpf / "build/vm"),
                HERE / "check_template.c", ubpf / "build/lib/libubpf.a", "-lm", "-o", native)
            run(objcopy, "--dump-section=.BTF=" + str(fixture_btf), native)
            offsets = json.loads(run(native, "--offsets").stdout)
            run("gcc", "-O2", "-DLS_CORE_RELO_TEST", HERE / "ls_core_relo.c", "-o", relo)
            record["native_offsets"] = offsets
            record["objects"] = {}
            for name, flag, kind in (("entry", "0", "fentry"), ("exit", "1", "fexit")):
                original = args.output / (name + ".local.o")
                bench = args.output / (name + ".bench.o")
                run(clang, "-O2", "-g", "-target", "bpf", "-Wall", "-Wextra", "-Werror",
                    "-DTEMPLATE_EXIT=" + flag, "-c", HERE / "template.c", "-o", original)
                if name == "entry":
                    run(relo, original, fixture_btf, bench)
                    sections = elf_sections(original.read_bytes())
                    btf = Btf(sections[".BTF"][2])
                    relos = core_relos(sections[".BTF.ext"][2], btf)
                    actual = baked_immediates(bench.read_bytes(), relos)
                    assert len(relos) == 4, relos
                    for section, pos, tid, access, relo_kind in relos:
                        indices = [int(value) for value in access.split(":")]
                        assert relo_kind == 0 and indices[0] == 0 and len(indices) == 2
                        owner = btf.strip(tid)
                        field = btf.members(owner)[indices[1]][0]
                        assert actual[section, pos] == offsets[owner["name"]][field]
                    record["native_offset_checks"] = len(relos)
                else:
                    bench.write_bytes(original.read_bytes())
                strip(bench)
                verify(bench, kind)
                executed = run(native, bench, name)
                event = next(line[6:] for line in executed.stdout.splitlines() if line.startswith("EVENT "))
                decoded = run("python3", HERE / "template_io.py", "decode", input_text=event + "\n")
                value = json.loads(decoded.stdout)["tutorial"]
                assert value["kind"] == (1 if name == "entry" else 2) and value["observed"] == 123
                bad_event = json.loads(event)
                bad_event["len"] = 1
                refused = run("python3", HERE / "template_io.py", "decode", check=False,
                              input_text=json.dumps(bad_event) + "\n")
                assert refused.returncode == 1 and "unexpected tutorial event size" in refused.stderr
                if name == "entry":
                    wrong = args.output / "entry.unrelocated.o"
                    wrong.write_bytes(original.read_bytes())
                    strip(wrong)
                    result = run(native, wrong, name, check=False)
                    assert result.returncode == 1 and "MISMATCH native fields" in result.stdout
                    record["unrelocated_falsifier"] = "MISMATCH native fields"
                record["objects"][bench.name] = digest(bench)
                if args.context:
                    final = args.output / ("template-" + name + ".bpf.o")
                    if name == "entry":
                        run(relo, original, args.context / "tmm.btf", final)
                    else:
                        final.write_bytes(original.read_bytes())
                    strip(final)
                    run("python3", HERE / "bind_target.py", "--prog", final,
                        "--binary", args.context / "tmm64.no_pgo", "--index", args.context / "hook-index.tsv",
                        "--debug", args.debug, "--objcopy", objcopy)
                    verify(final, kind)
                    record["objects"][final.name] = digest(final)
            identity = args.output / "example-identity.json"
            identity.write_text(json.dumps({"revision": 7, "session": "000000000000002a",
                                            "instance": "8000000000000045", "program_sha256": "ab" * 32}))
            config = run("python3", HERE / "template_io.py", "policy", "--identity", identity,
                          "--threshold", "123", "--reset-token", "5",
                         "--request-safe-return")
            document = json.loads(config.stdout)
            assert document["expected_revision"] == 7 and document["revision"] == 8
            assert document["schema"] == 2
            assert struct.unpack("<QQQII", bytes.fromhex(document["rows"][0])) == (123, 0, 5, 3, 0)
            removed = run("python3", HERE / "template_io.py", "policy", "--identity", identity,
                          "--interval-ns", "99", check=False)
            assert removed.returncode == 2 and "unrecognized arguments" in removed.stderr
            if args.context:
                record["target_inputs"] = {str(path): digest(path) for path in
                                          (args.context / "tmm64.no_pgo", args.context / "tmm.btf",
                                           args.context / "hook-index.tsv", args.debug)}
                record["scope"] += "; packaged target relocation/binding and verification"
            record["passed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            json.dump(record, receipt, indent=2)
            receipt.write("\n")


if __name__ == "__main__":
    main()
