#!/usr/bin/env python3
"""Bind, verify and sign the P21 live probe against the newly packaged runtime."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def run_commands(commands, record, verifier):
    """Record subprocess results and require the pinned compiler/verifier verdict."""
    for command in commands:
        command = [str(value) for value in command]
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=120, check=False
        )
        record["commands"].append(
            {
                "command": command,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        )
        print(result.stdout, result.stderr, flush=True)
        result.check_returncode()
        if command[1:] == ["--version"]:
            assert "18.1.3" in result.stdout
        if command[0] == str(verifier):
            assert "PASS:" in result.stdout


def main():
    """Keep a complete receipt, including refusals; never overwrite a program."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--map-reuse", action="store_true")
    args = parser.parse_args()
    substrate = Path("/home/starin/eob-tmm-staged/substrate")
    verifier = Path("/home/starin/eob-tmm-staged/ebpf-verifier/bin/prevail")
    objcopy = "/usr/lib/llvm-18/bin/llvm-objcopy"
    binary = args.context / "tmm64.no_pgo"
    index = args.context / "hook-index.tsv"
    obj = args.output / "config-observe.bpf.o"
    signature = obj.with_suffix(".sig")
    assert not obj.exists() and not signature.exists()
    record = {
        "passed": False,
        "inputs": {},
        "commands": [],
        "map_reuse": args.map_reuse,
    }
    with (args.output / "config-program-build.json").open("x") as receipt:
        try:
            for path in (
                args.source,
                args.source.parent.parent / "config_snapshot.bpf.h",
                binary,
                index,
                verifier,
            ):
                record["inputs"][str(path)] = hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
            identity = json.loads((args.context / "runtime-identity.json").read_text())
            assert record["inputs"][str(binary)] == identity["sha256"]
            build = "0x" + identity["build_id"][:8]
            commands = [
                ["clang-18", "--version"],
                [
                    "clang-18",
                    "-target",
                    "bpf",
                    "-O2",
                    "-g",
                    *(["-DLS_MAP_REUSE_TEST=1"] if args.map_reuse else []),
                    "-c",
                    args.source,
                    "-o",
                    obj,
                ],
                [
                    objcopy,
                    "--remove-section=.BTF",
                    "--remove-section=.BTF.ext",
                    "--remove-section=.rel.BTF.ext",
                    obj,
                ],
                [
                    "python3",
                    substrate / "bind_target.py",
                    "--prog",
                    obj,
                    "--binary",
                    binary,
                    "--index",
                    index,
                    "--objcopy",
                    objcopy,
                ],
                [
                    verifier,
                    obj,
                    "fentry/http_parse_client_headers",
                    "--termination",
                    "--strict",
                    "--no-division-by-zero",
                    "--stack-size",
                    "256",
                ],
                [
                    "python3",
                    substrate / "sign_shield.py",
                    "--key",
                    Path.home() / ".ls-signing/shield_sk.pem",
                    "--prog",
                    obj,
                    "--hook",
                    "http_parse_client_headers",
                    "--mode-ceiling",
                    "monitor",
                    "--build-min",
                    build,
                    "--build-max",
                    build,
                    "-o",
                    signature,
                ],
            ]
            run_commands(commands, record, verifier)
            shutil.copyfile(args.context / "ls_drain", args.output / "ls_drain")
            (args.output / "ls_drain").chmod(0o755)
            record["outputs"] = {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in (obj, signature, args.output / "ls_drain")
            }
            record["runtime"] = identity
            record["passed"] = True
        finally:
            json.dump(record, receipt, indent=2)


if __name__ == "__main__":
    main()
