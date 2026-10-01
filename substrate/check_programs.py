#!/usr/bin/env python3
"""Pinned native program-ownership checks. No live TMM result."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir()
    source = Path(__file__).resolve().parent
    ubpf = Path("/home/starin/code/tmm/.ubpf")
    prevail = Path("/home/starin/eob-tmm-staged/ebpf-verifier/bin/prevail")
    record = dict(passed=False, scope="pinned native harness; no live TMM", commands=[], sources={})

    def run(*argv, **kwargs):
        argv = list(map(str, argv))
        row = subprocess.run(argv, capture_output=True, text=True, timeout=240, **kwargs)
        record["commands"].append(dict(argv=argv, rc=row.returncode, stdout=row.stdout, stderr=row.stderr))
        if row.returncode:
            print(row.stdout + row.stderr, flush=True)
        row.check_returncode()
        return row.stdout

    with (args.output / "result.json").open("x") as receipt:
        try:
            for path in sorted(source.parent.rglob("*")):
                if path.is_file() and "__pycache__" not in path.parts:
                    data = path.read_bytes()
                    record["sources"][str(path.relative_to(source.parent))] = dict(
                        sha256=hashlib.sha256(data).hexdigest(), text=data.decode())
            assert "13.3.0" in run("gcc", "--version")
            assert "18.1.3" in run("clang-18", "--version")
            assert run("git", "-C", ubpf, "rev-parse", "HEAD").strip() == "c900ed9faf1d41358a7ea9217ccd0b64a4ee8d5d"
            assert run("git", "-C", prevail.parent.parent, "rev-parse", "HEAD").strip() == "06769f7b508214e63b97905d275920f7e90182fa"
            obj = args.output / "check_programs.bpf.o"
            run("clang-18", "-target", "bpf", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
                "-c", source / "check_programs.bpf.c", "-o", obj)
            run("/usr/lib/llvm-18/bin/llvm-objcopy", "--strip-debug", "--remove-section=.BTF",
                "--remove-section=.BTF.ext", "--remove-section=.rel.BTF.ext", obj)
            for section in ("fentry/program_alpha", "fentry/program_beta"):
                assert run(prevail, obj, section, "--termination", "--strict",
                           "--no-division-by-zero", "--stack-size", "256").startswith("PASS:")
            # The deployed target uses GCC's five one-byte NOPs. Clang emits a
            # different pad. Check host C with both compilers against that target.
            targets = args.output / "targets.o"
            run("gcc", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-fcf-protection=branch",
                "-fno-pie", "-c", source / "check_programs_targets.c", "-o", targets)
            for cc in ("gcc", "clang-18"):
                common = [cc, "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-D_GNU_SOURCE=",
                          "-I" + str(source), "-I" + str(ubpf / "vm/inc"), "-I" + str(ubpf / "build/vm")]
                run(*common, "-fsyntax-only", source / "ls_vm.c", source / "ls_vm_load.c")
                # TMM does not supply the harness's GNU feature macro. The
                # loader must declare its socket peer-credential API itself.
                run(cc, "-O2", "-Wall", "-Wextra", "-Werror",
                    "-I" + str(source), "-I" + str(ubpf / "vm/inc"),
                    "-I" + str(ubpf / "build/vm"), "-fsyntax-only",
                    source / "ls_vm_load.c")
                binary = args.output / ("programs-" + cc)
                run(*common, "-fcf-protection=branch", "-fno-pie", "-no-pie",
                    "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
                    source / "check_programs.c", source / "ls_vm_config.c", source / "ls_tramp.c",
                    targets,
                    source / "ls_arm.c", source / "ls_core_relo.c", source / "trampoline_x86_64.S",
                    ubpf / "build/lib/libubpf.a", "-lm", "-lpthread", "-o", binary)
                for jit in (0, 1):
                    run(binary, obj, jit)
                if cc == "gcc":
                    sanitized = args.output / "programs-sanitized"
                    run(*common, "-fsanitize=address,undefined", "-fcf-protection=branch",
                        "-fno-pie", "-no-pie", "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
                        source / "check_programs.c", source / "ls_vm_config.c", source / "ls_tramp.c",
                        source / "ls_arm.c", source / "ls_core_relo.c", source / "trampoline_x86_64.S",
                        targets, ubpf / "build/lib/libubpf.a", "-lm", "-lpthread", "-o", sanitized)
                    for jit in (0, 1):
                        run(sanitized, obj, jit)
                activity = Path("/home/starin/eob-config-20260925/activity-group-check-06/agent_activity.bpf.o")
                assert hashlib.sha256(activity.read_bytes()).hexdigest() == "aeda57b92798f3ceac6aec6d7fba7b0aa42191d9037b252ebed5cdb8f118e1d7"
                activity_check = args.output / ("activity-" + cc)
                run(*common, source / "check_agent_activity.c", ubpf / "build/lib/libubpf.a",
                    "-lm", "-o", activity_check)
                run(activity_check, activity)
                for name, files in (
                    ("context", ("check_ctx_contract.c", "ls_tramp.c", "ls_fexit.c")),
                    ("trampoline", ("check_tramp.c", "ls_tramp.c", "ls_fexit.c", "trampoline_x86_64.S", "victim.S")),
                    ("fexit", ("check_fexit.c", "ls_tramp.c", "ls_fexit.c", "trampoline_x86_64.S", "fexit_victims.S")),
                ):
                    check = args.output / (name + "-" + cc)
                    run(*common, "-fcf-protection=branch", *(source / name for name in files), "-o", check)
                    run(check)
            run("python3", source / "check_ls_load.py", env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
            from check_program_socket import check
            check(source, args.output, obj, targets, common, ubpf, run, record)
            record["passed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            json.dump(record, receipt, indent=2)
    print(json.dumps(dict(passed=True, receipt=str(args.output / "result.json"))))


if __name__ == "__main__":
    main()
