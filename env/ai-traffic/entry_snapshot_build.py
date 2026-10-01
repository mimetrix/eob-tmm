#!/usr/bin/env python3
"""Capture production snapshot tests on the pinned x86-64 build box."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir()
    source = args.source.resolve()
    old = Path("/home/starin/eob-tmm-staged/substrate")
    ubpf = Path("/home/starin/code/tmm/.ubpf")
    verifier = Path("/home/starin/eob-tmm-staged/ebpf-verifier")
    result = dict(passed=False, scope="production_snapshot_native_vm",
                  sources={}, commands=[], artifacts={})

    def run(*argv, expected=0, env=None):
        argv = list(map(str, argv))
        row = subprocess.run(argv, capture_output=True, text=True, timeout=240,
                             check=False, env=env)
        result["commands"].append(dict(argv=argv, rc=row.returncode,
                                       stdout=row.stdout, stderr=row.stderr))
        print(row.stdout, row.stderr, end="", flush=True)
        assert row.returncode == expected, (argv, row.returncode, expected)
        return row.stdout

    with (args.output / "build.json").open("x") as receipt:
        try:
            for path in sorted(source.iterdir()):
                if path.is_file():
                    result["sources"][path.name] = dict(sha256=sha(path), text=path.read_text())
            result["driver"] = dict(sha256=sha(Path(__file__)), text=Path(__file__).read_text())
            for path in (old / "ls_target.h", old / "check_target.c",
                         ubpf / "build/lib/libubpf.a", verifier / "bin/prevail"):
                result["artifacts"][str(path)] = sha(path)
            assert run("uname", "-m").strip() == "x86_64"
            assert "13.3.0" in run("gcc", "--version")
            assert "18.1.3" in run("clang-18", "--version")
            pins = dict(line.split("=", 1) for line in (source / "vendor.pins").read_text().splitlines()
                        if line and not line.startswith("#"))
            assert run("git", "-C", ubpf, "rev-parse", "HEAD").strip() == pins["UBPF_PIN"]
            assert run("git", "-C", verifier, "rev-parse", "HEAD").strip() == pins["PREVAIL_PIN"]
            objects = []
            for owner in (1, 2):
                obj = args.output / f"snapshot-{owner}.o"
                run("clang-18", "-O2", "-Wall", "-Wextra", "-Werror", "-target", "bpf",
                    "-I" + str(source), f"-DOWNER={owner}", "-c",
                    source / "check_snapshot.bpf.c", "-o", obj)
                run(verifier / "bin/prevail", obj, "fexit/snapshot/snapshot_victim",
                    "--termination", "--strict", "--no-division-by-zero", "--stack-size", "256")
                objects.append(obj)
            for compiler in ("gcc", "clang-18"):
                executable = args.output / ("snapshot-" + compiler)
                run(compiler, "-O2", "-g", "-Wall", "-Wextra", "-Werror",
                    "-fcf-protection=branch", "-I" + str(source),
                    "-I" + str(ubpf / "vm/inc"), "-I" + str(ubpf / "build/vm"),
                    source / "check_snapshot.c", source / "ls_fexit.c",
                    source / "ls_tramp.c", source / "trampoline_x86_64.S",
                    source / "void_fexit_victim.S", source / "ls_vm_config.c",
                    source / "ls_core_relo.c",
                    ubpf / "build/lib/libubpf.a", "-lm", "-o", executable)
                for jit in (0, 1):
                    env = os.environ.copy()
                    env.update(LS_VM_JIT=str(jit), LS_VM_SELFTEST="0", LS_VM_REPORT_EVERY="0",
                               LS_VM_VERBOSE="0", LS_SHIELD_ENABLE="1")
                    text = run(executable, *objects, env=env)
                    for noise in (0, 1):
                        assert f"PASS snapshot jit={jit} noise={noise}" in text
            for name, extra in (("fexit", ["fexit_victims.S", "trampoline_x86_64.S"]),
                                ("ctx_contract", [])):
                executable = args.output / ("ordinary-" + name)
                run("gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-fcf-protection=branch",
                    "-I" + str(source), source / ("check_" + name + ".c"),
                    source / "ls_fexit.c", source / "ls_tramp.c",
                    *(source / value for value in extra), "-o", executable)
                run(executable)
            run("gcc", "-fsyntax-only", "-Wall", "-Wextra", "-Werror",
                "-I" + str(source), "-I" + str(ubpf / "vm/inc"),
                "-I" + str(ubpf / "build/vm"), source / "ls_vm_load.c")

            # Real ELF binding, with independent symbol lookup and both parsers.
            victim_c = args.output / "victim.c"
            victim_c.write_text("volatile int value;\n"
                                "__attribute__((noinline)) void snapshot_victim(void) { value++; }\n"
                                "__attribute__((noinline)) int integer_victim(void) { return value; }\n"
                                "int main(void) { snapshot_victim(); return 0; }\n")
            victim = args.output / "victim"
            run("gcc", "-O2", "-g", "-no-pie", "-fcf-protection=branch",
                "-fpatchable-function-entry=5,0", "-Wl,--build-id=sha1",
                victim_c, "-o", victim)
            sys.path.insert(0, str(source))
            from ls_buildid import build_id
            from bind_target import sections
            build = build_id(str(victim))
            symbols = run("nm", "-n", victim)
            entry = int(next(line.split()[0] for line in symbols.splitlines()
                             if line.endswith(" T snapshot_victim")), 16)
            index = args.output / "hooks.tsv"
            index.write_text(f"#build_id\t{build}\nsnapshot_victim\t{entry + 4:#x}\tpad\t4\t5\n")
            run(sys.executable, source / "bind_snapshot.py", "--prog", objects[0],
                "--index", index, "--binary", victim, "--debug", victim)
            run(verifier / "bin/prevail", objects[0], "fexit/snapshot/snapshot_victim",
                "--termination", "--strict", "--no-division-by-zero", "--stack-size", "256")
            run(sys.executable, source / "completion_admit.py", victim, victim,
                "integer_victim", expected=1)
            run(sys.executable, source / "exit_admit.py", victim, victim,
                "snapshot_victim", expected=1)
            for label, directory in (("current", source), ("old", old)):
                executable = args.output / ("parser-" + label)
                run("gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-I" + str(directory),
                    directory / "check_target.c", "-o", executable)
                run(executable, objects[0], "fexit/snapshot/snapshot_victim", build,
                    victim, expected=0 if label == "current" else 1)
            blob = objects[0].read_bytes()
            off = next(row[4] for name, row in sections(blob) if name == ".ls.target")
            for label, at, replacement_bytes in (
                    ("old_version", off + 6, b"1"), ("wrong_kind", off + 56, b"\0"),
                    ("unsupported_pad", off + 57, b"\2"), ("reserved", off + 58, b"\1"),
                    ("wrong_address", off + 48, struct.pack("<Q", 1))):
                changed = bytearray(blob)
                changed[at:at + len(replacement_bytes)] = replacement_bytes
                path = args.output / (label + ".o")
                path.write_bytes(changed)
                run(args.output / "parser-current", path, "fexit/snapshot/snapshot_victim",
                    build, victim, expected=1)
            result.update(passed=True, compilers=2, paths=["interpreter", "jit"],
                          cases_per_compiler=78, live_initialization_validated=False)
        except BaseException as error:
            result["error"] = repr(error)
            raise
        finally:
            json.dump(result, receipt, indent=2)


if __name__ == "__main__":
    main()
