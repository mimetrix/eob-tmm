#!/usr/bin/env python3
"""Create or archive/remove only the isolated parser-lifetime Compose fixture."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import time

from config_live_run import WITNESS

ROOT = Path("/home/starin/eob-config-20260925")
PROJECT = "eob-template-20260925"
COMPOSE = ("docker", "compose", "--env-file", "template-fixture.env", "--project-name",
           PROJECT, "-f", "icap-compose.yaml", "-f", "config-compose.yaml",
           "-f", "observability-compose.yaml")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("create", "archive-cleanup"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--live", type=Path)
    parser.add_argument("--collector-image")
    parser.add_argument("--collector-source", type=Path)
    args = parser.parse_args()
    record = {"passed": False, "action": args.action, "commands": [], "sources": {}}
    compose = COMPOSE
    environment = os.environ.copy()
    if args.collector_image:
        assert args.collector_image.startswith("sha256:") and args.collector_source.is_dir()
        compose += ("-f", "collector-compose.yaml")
        environment.update(COLLECTOR_IMAGE=args.collector_image,
                           COLLECTOR_SOURCE_DIR=str(args.collector_source.resolve()))
        record["collector_image"] = args.collector_image

    def run(*argv, check=True):
        result = subprocess.run(argv, cwd=ROOT, env=environment, capture_output=True, text=True, timeout=240, check=False)
        record["commands"].append({"argv": argv, "rc": result.returncode,
                                   "stdout": result.stdout, "stderr": result.stderr})
        if check:
            result.check_returncode()
        return result.stdout

    def inventory():
        rows = []
        for identity in run("docker", "ps", "-aq").split():
            rows.append(json.loads(run("docker", "inspect", identity, "--format",
                '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},'
                '"status":{{json .State.Status}},"started":{{json .State.StartedAt}},'
                '"restarts":{{.RestartCount}},"project":{{json (index .Config.Labels "com.docker.compose.project")}}}')))
        return rows

    with args.output.open("x") as receipt:
        try:
            for name in ("lifetime_fixture.py", "icap-compose.yaml", "config-compose.yaml",
                         "observability-compose.yaml", "template-fixture.env"):
                path = ROOT / name
                record["sources"][name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                           "text": path.read_text()}
            record["before"] = inventory()
            if args.collector_image:
                path = ROOT / "collector-compose.yaml"
                record["sources"][path.name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "text": path.read_text()}
            owned = [row for row in record["before"] if row["project"] == PROJECT]
            if args.action == "create":
                assert not owned, owned
                run(*compose, "up", "-d", "--wait", "--wait-timeout", "180", "fixture", "tmm")
                image = run("docker", "inspect", PROJECT + "-tmm-1", "--format", "{{.Image}}")
                assert image.strip() == "sha256:e5bbcb5ef4a188f3417188d2672f5aeeaf558c626808f031e09ca28f74e10d3e"
                for _ in range(60):
                    status = run("docker", "exec", PROJECT + "-fixture-1", "python3",
                                 "/work/ls-load.py", "status", "5", check=False)
                    if status.startswith("OK "):
                        break
                    time.sleep(2)
                else:
                    raise RuntimeError("isolated loader did not become ready")
            else:
                assert len(owned) == (3 if args.collector_image else 2) and args.archive is not None and args.live is not None
                assert not args.archive.exists()
                live = json.loads(args.live.read_text())
                assert live["passed"]
                assert next(r["id"] for r in owned if r["name"].endswith("-tmm-1")) == json.loads(live["before"].split()[0])
                record["live_sha256"] = hashlib.sha256(args.live.read_bytes()).hexdigest()
                record["witness_script"] = WITNESS
                for label, program in live["program_build"]["programs"].items():
                    rows = [json.loads(line) for line in run(
                        "docker", "exec", PROJECT + "-tmm-1", "python3", "-u", "-c",
                        WITNESS, program["entry"]).splitlines()]
                    expected = live["witnesses"][label]["initial"]
                    assert rows[0]["sha256"] == expected["sha256"]
                    assert rows[0]["bytes"] == rows[-1]["bytes"] == expected["bytes"]
                    assert rows[0]["stat"].split()[21] == expected["stat"].split()[21]
                for slot in range(12):
                    text = run("docker", "exec", PROJECT + "-fixture-1", "python3",
                               "/work/ls-load.py", "status", str(slot))
                    assert text.startswith("OK ") and ("mode=0" in text or "armed=0" in text), text
                record["manifest"] = json.loads(run(
                    "docker", "exec", PROJECT + "-fixture-1", "python3", "-c",
                    'import hashlib,json,pathlib; root=pathlib.Path("/evidence"); '
                    'print(json.dumps({str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() '
                    'for p in root.rglob("*") if p.is_file()}))'))
                archive = subprocess.run(["docker", "exec", PROJECT + "-fixture-1", "tar", "czf", "-",
                                          "-C", "/evidence", "."], capture_output=True, timeout=60, check=True)
                members = {}
                with tarfile.open(fileobj=io.BytesIO(archive.stdout), mode="r:gz") as stream:
                    for member in stream.getmembers():
                        if member.isfile():
                            name = member.name.removeprefix("./")
                            assert not name.endswith((".pem", ".key", ".p12"))
                            assert name not in members
                            data = stream.extractfile(member).read()
                            assert b"PRIVATE KEY-----" not in data and b"BEGIN CERTIFICATE" not in data
                            members[name] = hashlib.sha256(data).hexdigest()
                        else:
                            assert member.isdir(), member.name
                assert members == record["manifest"] and members
                with args.archive.open("xb") as output:
                    output.write(archive.stdout)
                record["archive"] = {"path": str(args.archive), "files": len(members),
                                     "sha256": hashlib.sha256(archive.stdout).hexdigest()}
                run(*compose, "down", "--volumes", "--remove-orphans")
                for kind in ("container", "network", "volume"):
                    assert not run("docker", kind, "ls", "-q", "--filter",
                                   "label=com.docker.compose.project=" + PROJECT).strip()
            record["after"] = inventory()
            assert [r for r in record["before"] if r["project"] != PROJECT] == [
                r for r in record["after"] if r["project"] != PROJECT]
            record["passed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            json.dump(record, receipt, indent=2)
    print(json.dumps({"passed": record["passed"], "output": str(args.output)}))


if __name__ == "__main__":
    main()
