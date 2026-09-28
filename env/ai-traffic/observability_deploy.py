#!/usr/bin/env python3
"""Replace only the isolated tutorial fixture's TMM with the checked repair image."""
import argparse
import json
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path("/home/starin/eob-config-20260925")
    record = {"passed": False, "commands": []}

    def run(*command, check=True):
        result = subprocess.run(command, cwd=root, capture_output=True, text=True,
                                timeout=240, check=False)
        record["commands"].append({"argv": command, "rc": result.returncode,
                                   "stdout": result.stdout, "stderr": result.stderr})
        if check:
            result.check_returncode()
        return result

    with args.output.open("x") as receipt:
        try:
            package = json.loads(Path("/home/starin/observability-20260925/package-result.json").read_text())
            assert package["passed"]
            record["package"] = package
            for project in ("eob-config-20260925", "eob-template-20260925"):
                run("docker", "inspect", project + "-tmm-1", "--format",
                    "{{json .Id}} {{json .Image}} {{json .State}} {{.RestartCount}}")
            run("docker", "compose", "--env-file", "template-fixture.env",
                "--project-name", "eob-template-20260925", "-f", "icap-compose.yaml",
                "-f", "config-compose.yaml", "-f", "observability-compose.yaml",
                "up", "-d", "--no-deps", "--wait", "--wait-timeout", "180", "tmm")
            image = run("docker", "inspect", "eob-template-20260925-tmm-1",
                        "--format", "{{.Image}}")
            assert image.stdout.strip() == package["image"]
            for _ in range(60):
                ready = run("docker", "exec", "eob-template-20260925-fixture-1",
                            "python3", "/work/ls-load.py", "status", "5", check=False)
                if ready.returncode == 0 and ready.stdout.startswith("OK "):
                    break
                time.sleep(2)
            else:
                raise RuntimeError("isolated loader did not become ready")
            record["passed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            json.dump(record, receipt, indent=2)


if __name__ == "__main__":
    main()
