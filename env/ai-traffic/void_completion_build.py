#!/usr/bin/env python3
"""Run the void-return native fixture against the pinned return-hook source."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--discovery", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir()
    base = Path("/home/starin/eob-tmm-staged/substrate")
    source = Path(__file__).resolve().parent
    result = dict(passed=False, scope="native_void_completion_adapter_only", sources={}, commands=[])

    def run(*argv):
        row = subprocess.run(list(map(str, argv)), capture_output=True, text=True,
                             timeout=120, check=False)
        result["commands"].append(dict(argv=list(map(str, argv)), rc=row.returncode,
                                       stdout=row.stdout, stderr=row.stderr))
        print(row.stdout, row.stderr, end="", flush=True)
        row.check_returncode()
        return row.stdout

    with (args.output / "void-completion-build.json").open("x") as receipt:
        try:
            assert sha(args.discovery) == "787a96e8d860640f509a4143ff380530ef2708ad3ee01e16c24c9699c7c6b2f0"
            old = json.loads(args.discovery.read_text())
            result["discovery_sha256"] = sha(args.discovery)
            for name in ("ls_fexit.c", "ls_fexit.h"):
                assert sha(base / name) == old["sources"]["/home/starin/code/tmm/src/base/" + name]["sha256"]
            assert run("uname", "-m").strip() == "x86_64"
            run("gcc", "--version")
            run("clang-18", "--version")
            paths = [source / n for n in ("void_completion_build.py", "VOID-COMPLETION.md",
                                           "check_void_fexit.c", "void_fexit_victim.S")]
            paths += [base / n for n in ("ls_fexit.c", "ls_fexit.h", "ls_tramp.c",
                                         "ls_vm.h", "trampoline_x86_64.S", "check_fexit.c",
                                         "fexit_victims.S", "check_ctx_contract.c")]
            for path in paths:
                result["sources"][str(path)] = dict(sha256=sha(path), text=path.read_text())
            for compiler in ("gcc", "clang-18"):
                output = args.output / ("void-" + compiler)
                run(compiler, "-O2", "-Wall", "-Wextra", "-Werror", "-fcf-protection=branch",
                    "-I" + str(base), "-o", output, source / "check_void_fexit.c",
                    source / "void_fexit_victim.S", base / "ls_fexit.c", base / "ls_tramp.c",
                    base / "trampoline_x86_64.S", "-Wl,--wrap=ls_fexit_enter")
                text = run(output)
                assert all(f"PASS noise={n} cases=12 observed_returns=550" in text for n in (0, 1))
            regression = args.output / "fexit-regression"
            run("gcc", "-O2", "-fcf-protection=branch", "-I" + str(base), "-o", regression,
                base / "check_fexit.c", base / "ls_fexit.c", base / "ls_tramp.c",
                base / "trampoline_x86_64.S", base / "fexit_victims.S")
            run(regression)
            regression = args.output / "context-regression"
            run("gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-I" + str(base), "-o", regression,
                base / "check_ctx_contract.c", base / "ls_tramp.c", base / "ls_fexit.c")
            run(regression)
            result.update(passed=True, compilers=2, cases_per_compiler=24,
                          observed_returns_per_compiler=1100,
                          production_entry_capture_implemented=False,
                          live_initialization_validated=False, lifecycle_validated=False)
        except BaseException as error:
            result["error"] = repr(error)
            raise
        finally:
            json.dump(result, receipt, indent=2)


if __name__ == "__main__":
    main()
