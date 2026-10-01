#!/usr/bin/env python3
"""Create the snapshot fixture or use the checked archive/removal procedure."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import time

import lifetime_fixture as fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    args, remaining = parser.parse_known_args()
    package = json.loads((args.package / "package-result.json").read_text())
    assert package["passed"] and package["image"].startswith("sha256:")
    os.environ["SNAPSHOT_IMAGE"] = package["image"]
    fixture.COMPOSE += ("-f", "initialization-compose.yaml")
    if remaining[0] == "archive-cleanup":
        sys.argv = [sys.argv[0]] + remaining
        fixture.main()
        return
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("create", "archive-blocked"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--collector-image", required=True)
    parser.add_argument("--collector-source", type=Path, required=True)
    parser.add_argument("--failed-build", type=Path)
    parser.add_argument("--create", type=Path)
    parser.add_argument("--archive", type=Path)
    options = parser.parse_args(remaining)
    assert options.collector_source.is_dir()
    environment = dict(os.environ, COLLECTOR_IMAGE=options.collector_image,
                       COLLECTOR_SOURCE_DIR=str(options.collector_source.resolve()))
    compose = fixture.COMPOSE + ("-f", "collector-compose.yaml")
    record = dict(passed=False, commands=[], package=package, sources={})

    def run(*argv, check=True):
        result = subprocess.run(argv, cwd=fixture.ROOT, env=environment, capture_output=True,
                                text=True, timeout=240, check=False)
        record["commands"].append(dict(argv=argv, rc=result.returncode,
                                       stdout=result.stdout, stderr=result.stderr))
        if check:
            result.check_returncode()
        return result.stdout

    def inventory():
        return [json.loads(run("docker", "inspect", identity, "--format",
                    '{"id":{{json .Id}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
                    '"state":{{json .State}},"restarts":{{.RestartCount}}}'))
                for identity in run("docker", "ps", "-aq").split()]

    with options.output.open("x") as receipt:
        try:
            for name in ("json_initialization_fixture.py", "lifetime_fixture.py", "initialization-compose.yaml",
                         "icap-compose.yaml", "config-compose.yaml", "observability-compose.yaml",
                         "collector-compose.yaml", "template-fixture.env"):
                path = fixture.ROOT / name
                record["sources"][name] = dict(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), text=path.read_text())
            record["before"] = inventory()
            if options.action == "archive-blocked":
                failed = json.loads(options.failed_build.read_text())
                created = json.loads(options.create.read_text())
                assert not failed["passed"] and "runtime imports an unwind initiator" in failed["error"]
                assert created["passed"] and created["package"] == package
                owned = [r for r in record["before"] if r["project"] == fixture.PROJECT]
                assert len(owned) == 2
                expected = {r["id"]: r for r in created["after"] if r["project"] == fixture.PROJECT}
                assert {r["id"] for r in owned} == set(expected)
                for row in owned:
                    assert row["restarts"] == expected[row["id"]]["restarts"]
                    assert all(row["state"][key] == expected[row["id"]]["state"][key]
                               for key in ("Pid", "StartedAt", "Status"))
                assert not (options.collector_source / "source.json").exists()
                tmm, peer = fixture.PROJECT + "-tmm-1", fixture.PROJECT + "-fixture-1"
                witness = run("docker", "exec", tmm, "python3", "-u", "-c", fixture.WITNESS,
                              failed["instruction_checks"]["entry"])
                record["witness"] = [json.loads(line) for line in witness.splitlines()]
                assert record["witness"][0]["sha256"] == package["runtime"]["sha256"]
                assert all(r["bytes"] == record["witness"][0]["bytes"]
                           and r["bytes"][8:].startswith("9090909090") for r in record["witness"])
                assert record["witness"][0]["stat"].split()[21] == record["witness"][-1]["stat"].split()[21]
                for slot in range(12):
                    text = run("docker", "exec", peer, "python3", "/work/ls-load.py", "status", str(slot))
                    assert text.startswith("OK ") and "armed=0" in text and "fired=0" in text, text
                summary = dict(passed=False, stage="admission", runtime=package["runtime"],
                               build_sha256=hashlib.sha256(options.failed_build.read_bytes()).hexdigest(),
                               error=failed["error"], live_program_loaded=False)
                run("docker", "exec", peer, "python3", "-c",
                    'import pathlib,sys; pathlib.Path("/evidence/admission-blocked.json").open("x").write(sys.argv[1])',
                    json.dumps(summary, indent=2))
                record["manifest"] = json.loads(run("docker", "exec", peer, "python3", "-c",
                    'import hashlib,json,pathlib; root=pathlib.Path("/evidence"); '
                    'print(json.dumps({str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() '
                    'for p in root.rglob("*") if p.is_file()}))'))
                archive = subprocess.run(["docker", "exec", peer, "tar", "czf", "-", "-C", "/evidence", "."],
                                         capture_output=True, timeout=60, check=True)
                members = {}
                with tarfile.open(fileobj=io.BytesIO(archive.stdout), mode="r:gz") as stream:
                    for member in stream.getmembers():
                        assert member.isdir() or member.isfile()
                        if member.isfile():
                            name = member.name.removeprefix("./")
                            assert name not in members and not Path(name).is_absolute() and ".." not in Path(name).parts
                            assert not name.endswith((".pem", ".key", ".p12", ".sig", ".bpf.o"))
                            data = stream.extractfile(member).read()
                            assert b"PRIVATE KEY-----" not in data and b"BEGIN CERTIFICATE" not in data
                            members[name] = hashlib.sha256(data).hexdigest()
                assert members == record["manifest"] and members
                with options.archive.open("xb") as output:
                    output.write(archive.stdout)
                record["archive"] = dict(files=len(members), sha256=hashlib.sha256(archive.stdout).hexdigest())
                run(*compose, "down", "--volumes", "--remove-orphans")
                record["after"] = inventory()
                assert [r for r in record["before"] if r["project"] != fixture.PROJECT] == record["after"]
                for kind in ("container", "network", "volume"):
                    assert not run("docker", kind, "ls", "-q", "--filter",
                                   "label=com.docker.compose.project=" + fixture.PROJECT).strip()
                record.update(passed=True, action="archive-blocked", blocked=summary)
                return
            assert not any(row["project"] == fixture.PROJECT for row in record["before"])
            run(*compose, "up", "-d", "--wait", "--wait-timeout", "180", "fixture", "tmm")
            assert run("docker", "inspect", fixture.PROJECT + "-tmm-1", "--format", "{{.Image}}").strip() == package["image"]
            for _ in range(60):
                if run("docker", "exec", fixture.PROJECT + "-fixture-1", "python3",
                       "/work/ls-load.py", "status", "11", check=False).startswith("OK "):
                    break
                time.sleep(2)
            else:
                raise RuntimeError("isolated loader did not become ready")
            record["after"] = inventory()
            assert record["before"] == [row for row in record["after"] if row["project"] != fixture.PROJECT]
            record["passed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            json.dump(record, receipt, indent=2)


if __name__ == "__main__":
    main()
