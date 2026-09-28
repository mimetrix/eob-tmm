#!/usr/bin/env python3
"""Build/bind/verify/sign the ICAP probe on the authoritative x86 build box.

Uses the packaged runtime/debug pair retained by the P17 validation. Never
changes TMM source, the type catalog, or the signing key. Output is exclusive.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    """Preserve every command result, including failures, in a build receipt."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir()
    root = Path.home()
    substrate = root / "eob-tmm-staged/substrate"
    catalogs = root / "lstools"
    target = root / "embedded-p17-20260924/target"
    binary = target / "usr/bin/tmm64.no_pgo"
    debug, = target.rglob("tmm64.no_pgo.debug")
    source = Path(__file__).with_name("icap_state.bpf.c")
    obj = args.output / "icap-state.bpf.o"
    final = args.output / "icap-state.final.bpf.o"
    objcopy = "/usr/lib/llvm-18/bin/llvm-objcopy"
    records = []
    inputs = {}
    try:
        for path in (source, binary, debug, catalogs / "tmm.btf",
                     catalogs / "hook-index.tsv"):
            inputs[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        assert inputs[str(binary)] == (
            "a4b9e777a1daccd8c2b8c7f1aa7eba920b6040253f45f017605ea0a5f0a8afd7"
        )
        commands = [
            ["clang-18", "-target", "bpf", "-O2", "-g", "-c", source, "-o", obj],
            ["gcc", "-O2", "-DLS_CORE_RELO_TEST", substrate / "ls_core_relo.c",
             "-o", args.output / "relo"],
            [args.output / "relo", obj, catalogs / "tmm.btf", final],
            [objcopy, "--remove-section=.BTF", "--remove-section=.BTF.ext",
             "--remove-section=.rel.BTF.ext", final],
            ["python3", substrate / "bind_target.py", "--prog", final,
             "--binary", binary, "--debug", debug, "--index",
             catalogs / "hook-index.tsv", "--objcopy", objcopy],
            [root / "eob-tmm-staged/ebpf-verifier/bin/prevail", final,
             "fentry/adapt_set_state", "--termination", "--strict",
             "--no-division-by-zero", "--stack-size", "256"],
            ["python3", substrate / "sign_shield.py", "--key",
             root / ".ls-signing/shield_sk.pem", "--prog", final,
             "--hook", "adapt_set_state", "--mode-ceiling", "monitor",
             "--build-min", "0xc3b81927", "--build-max", "0xc3b81927",
             "-o", args.output / "icap-state.final.bpf.sig"],
        ]
        for command in commands:
            command = [str(value) for value in command]
            print("COMMAND", *command, flush=True)
            result = subprocess.run(command, capture_output=True, text=True, timeout=120)
            records.append({"command": command, "returncode": result.returncode,
                            "stdout": result.stdout, "stderr": result.stderr})
            print(result.stdout, result.stderr, flush=True)
            result.check_returncode()
    finally:
        receipt = {"inputs": inputs, "commands": records,
                   "outputs": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in args.output.iterdir() if p.is_file()}}
        (args.output / "build.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
