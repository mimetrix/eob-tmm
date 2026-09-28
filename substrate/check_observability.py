#!/usr/bin/env python3
"""Pinned host regressions for unsampled observability; retain each attempt."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir()
    here = Path(__file__).resolve().parent
    ubpf = Path("/home/starin/code/tmm/.ubpf")
    record = {"passed": False, "commands": [], "sources": {}}

    def run(*command):
        result = subprocess.run([str(v) for v in command], cwd=here,
                                capture_output=True, text=True, timeout=180, check=False)
        record["commands"].append({"argv": [str(v) for v in command], "rc": result.returncode,
                                   "stdout": result.stdout, "stderr": result.stderr})
        print(result.stdout, result.stderr, flush=True)
        result.check_returncode()
        return result

    with (args.output / "receipt.json").open("x") as receipt:
        try:
            assert run("git", "-C", ubpf, "rev-parse", "HEAD").stdout.strip() == "c900ed9faf1d41358a7ea9217ccd0b64a4ee8d5d"
            run("gcc", "--version")
            names = ("ls_map.h", "ls_map_glue.h", "ls_vm.c", "ls_vm_load.c", "ls_tp_emit.c",
                     "check_map.c", "check_map_reuse.c", "check_map_threads.c", "check_output_result.c",
                     "check_glue_owner.c", "check_glue_user.c", "check_glue_stubs.c")
            record["sources"] = {n: hashlib.sha256((here / n).read_bytes()).hexdigest() for n in names}
            flags = ("-O2", "-Wall", "-Wextra", "-Werror", "-pthread", "-I" + str(here),
                     "-I" + str(ubpf / "vm/inc"), "-I" + str(ubpf / "build/vm"))
            for source in ("check_map.c", "check_map_reuse.c", "check_map_threads.c", "check_output_result.c"):
                binary = args.output / Path(source).stem
                run("gcc", *flags, here / source, "-o", binary)
                run(binary)
            binary = args.output / "check_glue"
            run("gcc", *flags, here / "check_glue_owner.c", here / "check_glue_user.c",
                here / "check_glue_stubs.c", "-o", binary)
            run(binary)
            # Use the generated blob from this build tree. The legacy generator's
            # default source was retired; this regression does not rebuild it.
            blob = here / "ls_shield_blob.h"
            record["sources"][blob.name] = hashlib.sha256(blob.read_bytes()).hexdigest()
            run("make", "-o", "shield-blob", "check-vm", "check-ls-load",
                "check-ctx-contract", "check-ring", "check-tp-ring")
            record["passed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            json.dump(record, receipt, indent=2)


if __name__ == "__main__":
    main()
