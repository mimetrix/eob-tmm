#!/usr/bin/env python3
"""Run the snapshot image with an isolated collector and kernel hook witness."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import traceback

from config_live_run import WITNESS
from lifetime_fixture import COMPOSE, PROJECT, ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--image-build", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--activity", action="store_true",
                        help="run the two-entry activity artifact")
    parser.add_argument("--combined", action="store_true")
    args = parser.parse_args()
    if args.combined:
        args.activity = True
    assert args.run.replace("-", "").isalnum()
    assert not args.artifact_dir.is_absolute() and ".." not in args.artifact_dir.parts
    record = dict(passed=False, commands=[], sources={}, witnesses={}, witness_script=WITNESS)
    image_build = json.loads(args.image_build.read_text())
    build = json.loads((ROOT / args.artifact_dir / "metadata-program-build.json").read_text())
    if not image_build["passed"] or not build["passed"]:
        record.update(stage="preflight", image_build_passed=image_build["passed"],
                      program_build_passed=build["passed"],
                      program_build_sha256=hashlib.sha256((ROOT / args.artifact_dir / "metadata-program-build.json").read_bytes()).hexdigest(),
                      error="image or program build refused; no live commands run")
        path = Path(__file__)
        record["sources"][path.name] = dict(text=path.read_text(), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        with args.output.open("x") as receipt:
            json.dump(record, receipt, indent=2)
        raise SystemExit(record["error"])
    image = image_build["image"]
    environment = dict(os.environ, COLLECTOR_IMAGE=image, COLLECTOR_SOURCE_DIR=str(args.source_dir.resolve()),
                       SNAPSHOT_IMAGE=build["tmm_image"])
    compose = COMPOSE + ("-f", "initialization-compose.yaml", "-f", "collector-compose.yaml")
    tmm, fixture, collector = (PROJECT + "-" + name + "-1" for name in ("tmm", "fixture", "collector"))
    monitors, started = {}, False

    def run(*argv, timeout=60):
        row = subprocess.run(list(map(str, argv)), cwd=ROOT, env=environment, capture_output=True,
                             text=True, timeout=timeout, check=False)
        record["commands"].append(dict(argv=list(map(str, argv)), rc=row.returncode,
                                       stdout=row.stdout, stderr=row.stderr))
        row.check_returncode()
        return row.stdout

    def state():
        return run("docker", "inspect", tmm, "--format", "{{json .Id}} {{json .Image}} {{json .State}} {{.RestartCount}}")

    with args.output.open("x") as receipt:
        try:
            names = ("json_initialization_live.py", "json_initialization_fixture.py",
                     "json_initialization_suite.py", "json_initialization_decode.py", "json-initialization-run.sh",
                     "initialization-compose.yaml", "ENTRY-SNAPSHOT.md", "json_lifecycle_suite.py",
                     "json_lifecycle_decode.py", "id_flow_suite.py", "id_flow_cases.py", "id_flow_decode.py",
                     "message_id_suite.py", "message_id_cases.py", "message_id_decode.py", "session_routing_suite.py",
                     "session_routing_client.py", "session_routing_decode.py", "metadata_suite.py", "config_suite.py",
                     "icap_suite.py", "collector_client.py", "collector_container.py", "stream_collector.py",
                      "collector-compose.yaml", "icap_check_result.py", "lifetime_fixture.py")
            if args.activity:
                names += ("activity_program_suite.py", "activity-program-run.sh", "activity_export.py",
                          "activity_group_decode.py",
                          "operation_target_decode.py", "reply_metadata_decode.py", "response_metadata_decode.py",
                           "token_method_decode.py", "method_decode.py", "ls-load.py")
            if args.combined:
                names += ("activity_combined_suite.py", "activity_combine.py")
            for name in names:
                path = ROOT / name
                record["sources"][name] = dict(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), text=path.read_text())
            for name in ("collector_container.py", "stream_collector.py", "collector-compose.yaml", "collector_client.py"):
                assert record["sources"][name]["sha256"] == image_build["sources"][name]["sha256"]
            record.update(image_build=image_build, program_build=build, before=state())
            assert json.loads(record["before"].split()[1]) == build["tmm_image"]
            run("docker", "exec", fixture, "mkdir", "/evidence/" + args.run)
            record["fixture_mounts"] = json.loads(run("docker", "inspect", fixture, "--format", "{{json .Mounts}}"))
            assert any(m["Destination"] == "/collector-api" and not m["RW"] for m in record["fixture_mounts"])
            suite = "activity_combined_suite.py" if args.combined else "activity_program_suite.py" if args.activity else "json_initialization_suite.py"
            run("docker", "exec", fixture, "python3", "-m", "black", "--check", "/work/" + suite, "/work/metadata_suite.py")
            run("docker", "exec", fixture, "python3", "-m", "pylint", "--disable=C,R,broad-exception-caught", "/work/" + suite, "/work/metadata_suite.py")
            for label, program in build["programs"].items():
                obj = ROOT / args.artifact_dir / program["object"]
                assert hashlib.sha256(obj.read_bytes()).hexdigest() == program["sha256"]
                signature = ROOT / args.artifact_dir / program["signature"] if program.get("signature") else obj.with_suffix(".sig")
                assert hashlib.sha256(signature.read_bytes()).hexdigest() == program["signature_sha256"]
                monitor = subprocess.Popen(["docker", "exec", "-i", tmm, "python3", "-u", "-c", WITNESS, program["entry"]],
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                monitors[label] = monitor
                witness = json.loads(monitor.stdout.readline())
                record["witnesses"][label] = dict(initial=witness)
                assert witness["sha256"] == build["runtime"]["sha256"]
                assert witness["bytes"][program["pad"] * 2:].startswith("9090909090")
            source = json.loads(run("docker", "exec", tmm, "python3", "-c",
                'import json,pathlib; print(json.dumps({"boot":pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip(),'
                '"pid_namespace":str(pathlib.Path("/proc/self/ns/pid").stat().st_ino)}))'))
            source.update(pid=witness["pid"], start=witness["stat"].split()[21], sha256=witness["sha256"])
            record["source_binding"] = source
            with (args.source_dir / "source.json").open("x") as output:
                json.dump(source, output)
            run(*compose, "up", "-d", "--no-deps", "collector")
            started = True
            record["collector"] = json.loads(run("docker", "inspect", collector, "--format",
                '{"id":{{json .Id}},"image":{{json .Image}},"host":{{json .HostConfig}},"mounts":{{json .Mounts}}}'))
            assert record["collector"]["image"] == image
            ready = '''import sys,time,json
sys.path.insert(0,"/work")
from session_routing_client import page
for i in range(100):
 try: print(json.dumps(page("/collector-api/events.sock"))); break
 except (OSError,ValueError): time.sleep(.1)
else: raise RuntimeError("collector socket not ready")
'''
            record["api_initial"] = json.loads(run("docker", "exec", fixture, "python3", "-c", ready, timeout=20))
            run("docker", "exec", "-e", "ACTIVITY_COMBINED=" + ("1" if args.combined else "0"),
                "-e", "TEMPLATE_PROGRAM_DIR=" + str(Path("/work") / args.artifact_dir), fixture,
                "bash", "/work/" + ("activity-program-run.sh" if args.activity else "json-initialization-run.sh"), args.run, timeout=300)
            record["passed"] = True
        except BaseException as error:
            record.update(error=repr(error), traceback=traceback.format_exc())
        finally:
            errors = []
            if started:
                try:
                    record["collector_logs"] = run("docker", "logs", collector)
                    run(*compose, "stop", "collector")
                    journal = args.source_dir / "events.sqlite"
                    assert not journal.exists()
                    run("docker", "cp", collector + ":/journal/events.sqlite", journal)
                    run("docker", "cp", journal, fixture + ":/evidence/" + args.run + "/events.sqlite")
                    record["journal_sha256"] = hashlib.sha256(journal.read_bytes()).hexdigest()
                except BaseException as error:
                    errors.append("collector: " + repr(error))
            for label, monitor in monitors.items():
                try:
                    stdout, stderr = monitor.communicate("stop\n", timeout=20)
                    row = record["witnesses"][label]
                    program = build["programs"][label]
                    row.update(changes=[json.loads(line) for line in stdout.splitlines()], stderr=stderr, returncode=monitor.returncode)
                    assert monitor.returncode == 0
                    final = row["changes"][-1]
                    assert final["final"] and final["bytes"] == row["initial"]["bytes"]
                    assert final["stat"].split()[21] == row["initial"]["stat"].split()[21]
                    if record["passed"]:
                        assert len([e for e in row["changes"] if e["bytes"][program["pad"] * 2:].startswith("e8")]) == 1
                except BaseException as error:
                    errors.append("witness: " + repr(error))
            try:
                record["after"] = state()
                assert record["after"] == record["before"]
                record["files"] = json.loads(run("docker", "exec", fixture, "python3", "-c",
                    'import json,pathlib,sys; root=pathlib.Path("/evidence")/sys.argv[1]; '
                    'print(json.dumps({p.name:p.read_text() for p in root.iterdir() if p.is_file() and p.suffix!=".sqlite"}))', args.run))
                for program in build["programs"].values():
                    assert "mode=0" in run("docker", "exec", fixture, "python3", "/work/ls-load.py", "status", str(program["slot"]))
            except BaseException as error:
                errors.append("final: " + repr(error))
            if errors:
                record.update(passed=False, collection_errors=errors)
            json.dump(record, receipt, indent=2)
    print(json.dumps(dict(passed=record["passed"], error=record.get("error"), collection_errors=record.get("collection_errors"))))
    raise SystemExit(0 if record["passed"] else 1)


if __name__ == "__main__":
    main()
