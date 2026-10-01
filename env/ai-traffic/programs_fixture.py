#!/usr/bin/env python3
"""Create only the two-container SSA ownership fixture, with its dedicated ring."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path("/home/starin/eob-config-20260925")
sys.path.insert(0, str(ROOT))
from lifetime_fixture import COMPOSE, PROJECT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    package = json.loads((args.package / "package-result.json").read_text())
    assert package["passed"] and package["image"].startswith("sha256:")
    record = dict(passed=False, commands=[], sources={}, package=package)
    environment = dict(os.environ, SNAPSHOT_IMAGE=package["image"])

    def run(*cmd, check=True):
        p = subprocess.run(list(map(str, cmd)), cwd=ROOT, env=environment,
                           capture_output=True, text=True, timeout=240)
        record["commands"].append(dict(argv=list(map(str, cmd)), rc=p.returncode, stdout=p.stdout, stderr=p.stderr))
        if check:
            p.check_returncode()
        return p.stdout

    def inventory():
        return [json.loads(run("docker", "inspect", identity, "--format",
                '{"id":{{json .Id}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
                '"state":{{json .State}},"restarts":{{.RestartCount}}}'))
                for identity in run("docker", "ps", "-aq").split()]

    with args.output.open("x") as receipt:
        try:
            for path in [Path(__file__)] + [ROOT / name for name in (
                    "lifetime_fixture.py", "icap-compose.yaml", "config-compose.yaml",
                    "observability-compose.yaml", "initialization-compose.yaml", "template-fixture.env")]:
                record["sources"][path.name] = dict(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), text=path.read_text())
            record["before"] = inventory()
            assert not any(row["project"] == PROJECT for row in record["before"])
            run(*COMPOSE, "-f", "initialization-compose.yaml", "up", "-d", "--wait", "--wait-timeout", "180", "fixture", "tmm")
            assert run("docker", "inspect", PROJECT + "-tmm-1", "--format", "{{.Image}}").strip() == package["image"]
            for _ in range(60):
                if run("docker", "exec", PROJECT + "-fixture-1", "python3", "/work/ls-load.py", "status", "11", check=False).startswith("OK "):
                    break
                time.sleep(2)
            else:
                raise RuntimeError("isolated loader did not become ready")
            record["after"] = inventory()
            assert record["before"] == [row for row in record["after"] if row["project"] != PROJECT]
            record["passed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            json.dump(record, receipt, indent=2)
    print(json.dumps(dict(passed=True, image=package["image"])))


if __name__ == "__main__":
    main()
