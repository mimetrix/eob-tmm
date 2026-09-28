#!/usr/bin/env python3
"""Sign the exact tutorial objects accepted by the pinned build checks."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def digest(path):
    """Hash an input or output without exporting the signing key."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():  # pylint: disable=too-many-locals
    """Refuse overwrite and retain the signing result, including failures."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    record = {"passed": False, "commands": [], "outputs": {}}
    with (args.output / "template-program-build.json").open("x") as receipt:
        try:
            checked = json.loads((args.build / "receipt.json").read_text())
            assert checked["passed"] is True
            record["bench_receipt_sha256"] = digest(args.build / "receipt.json")
            identity = json.loads((args.context / "runtime-identity.json").read_text())
            binary = args.context / "tmm64.no_pgo"
            assert digest(binary) == identity["sha256"] == checked["target_inputs"][str(binary)]
            record["runtime"] = identity
            for name in ("template.c", "template_io.py"):
                assert digest(args.output / name) == checked["sources"][name]
            for kind in ("entry", "exit"):
                name = "template-" + kind + ".bpf.o"
                source = args.build / name
                target = args.output / name
                signature = target.with_suffix(".sig")
                assert not target.exists() and not signature.exists()
                assert digest(source) == checked["objects"][name]
                shutil.copyfile(source, target)
                command = [
                    "python3", "/home/starin/eob-tmm-staged/substrate/sign_shield.py",
                    "--key", str(Path.home() / ".ls-signing/shield_sk.pem"),
                    "--prog", str(target), "--hook", "http_parse_client_headers",
                    "--mode-ceiling", "monitor", "--build-min", "0x" + identity["build_id"][:8],
                    "--build-max", "0x" + identity["build_id"][:8], "-o", str(signature),
                ]
                result = subprocess.run(
                    command, capture_output=True, text=True, check=False, timeout=60)
                record["commands"].append({"command": command, "returncode": result.returncode,
                                           "stdout": result.stdout, "stderr": result.stderr})
                result.check_returncode()
                assert digest(target) == checked["objects"][name]
                record["outputs"].update({path.name: digest(path) for path in (target, signature)})
            bindings = [row["stdout"] for row in checked["commands"]
                        if any(value.endswith("/bind_target.py") for value in row["argv"])]
            addresses = {text.split(" -> ")[1].split()[0] for text in bindings}
            assert len(bindings) == 2 and len(addresses) == 1
            record["entry"] = addresses.pop()
            record["passed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            json.dump(record, receipt, indent=2)
            receipt.write("\n")


if __name__ == "__main__":
    main()
