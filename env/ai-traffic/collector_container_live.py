#!/usr/bin/env python3
"""Run the isolated separate-container gate with source and restart witnesses."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import traceback

from config_live_run import WITNESS
from lifetime_fixture import COMPOSE, PROJECT, ROOT

INSPECT = ('{"id":{{json .Id}},"image":{{json .Image}},"state":{{json .State}},'
           '"restarts":{{.RestartCount}},"host":{{json .HostConfig}},"mounts":{{json .Mounts}}}')
RING = '''import json,pathlib,struct
p=pathlib.Path("/run/ls-stream/ls_tp_ring")
if not p.exists(): print("null")
else:
 b=p.read_bytes(); stride=struct.unpack_from("<I",b,16)[0]; claimed=struct.unpack_from("<I",b,24)[0]
 assert claimed<=16
 print(json.dumps([dict(zip(("producer","consumer","drops","drop_bytes"),struct.unpack_from("<4Q",b,32+i*stride+24))) for i in range(claimed)]))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True)
    parser.add_argument("--image-build", required=True, type=Path)
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    assert args.run.replace("-", "").isalnum()
    record = {"passed": False, "commands": [], "sources": {}, "witnesses": {}, "controls": []}
    environment = os.environ.copy()
    image_build = json.loads(args.image_build.read_text())
    assert image_build["passed"]
    image = image_build["image"]
    record["image_build"] = image_build
    environment.update(COLLECTOR_IMAGE=image, COLLECTOR_SOURCE_DIR=str(args.source_dir.resolve()))
    compose = COMPOSE + ("-f", "collector-compose.yaml")
    tmm, fixture, collector = (PROJECT + "-" + name + "-1" for name in ("tmm", "fixture", "collector"))
    monitor = None
    suite = None
    consumers = []
    consumer_cursor = None

    def run(*command, check=True, timeout=60, retain=True):
        row = subprocess.run(list(map(str, command)), cwd=ROOT, env=environment,
                             capture_output=True, text=True, timeout=timeout, check=False)
        if retain:
            record["commands"].append({"argv": list(map(str, command)), "rc": row.returncode,
                                       "stdout": row.stdout, "stderr": row.stderr})
        if check:
            row.check_returncode()
        return row

    def state():
        return run("docker", "inspect", tmm, "--format",
                   "{{json .Id}} {{json .Image}} {{json .State}} {{.RestartCount}}").stdout

    def inspection():
        row = json.loads(run("docker", "inspect", collector, "--format", INSPECT).stdout)
        host = row["host"]
        assert row["image"] == image
        assert not host["Privileged"] and host["ReadonlyRootfs"]
        assert host["Memory"] == 128 * 1024 * 1024 and host["NanoCpus"] == 500000000
        assert host["MemorySwap"] == host["Memory"]
        assert host["Tmpfs"] == {"/tmp": "size=8m,noexec,nosuid,nodev"}
        assert host["PidsLimit"] == 32 and host["NetworkMode"] == "none"
        assert host["CapAdd"] == ["CAP_SYS_PTRACE"] and host["CapDrop"] == ["ALL"]
        assert host["PidMode"] == "container:" + json.loads(record["before"].split()[0])
        mounts = {m["Destination"]: m for m in row["mounts"]}
        assert set(mounts) == {"/run/ls-stream", "/journal", "/api", "/source"}
        assert not mounts["/source"]["RW"]
        return row

    def ready():
        script = '''import sys,time
sys.path.insert(0,"/work")
from collector_client import page
for i in range(100):
 try: print(__import__("json").dumps(page("/collector-api/events.sock"))); break
 except (OSError,ValueError): time.sleep(.1)
else: raise RuntimeError("collector socket not ready")
'''
        return json.loads(run("docker", "exec", fixture, "python3", "-c", script, timeout=20).stdout)

    def ring():
        return json.loads(run("docker", "exec", fixture, "python3", "-c", RING).stdout)

    def consume(name, cursor=None):
        return json.loads(run("docker", "exec", name, "python3", "-c",
            'import json,sys; from collector_client import page; '
            'print(json.dumps(page("/api/events.sock",sys.argv[1] or None)))', cursor or "").stdout)

    with args.output.open("x") as receipt:
        try:
            for name in ("collector_container_live.py", "collector_container_suite.py", "collector_container.py",
                         "collector_client.py", "stream_collector.py", "collector-compose.yaml",
                         "collector_suite.py", "method_suite.py", "method_decode.py", "metadata_suite.py",
                         "icap-run-suite.sh", "COLLECTOR-CONTAINER.md", "lifetime_fixture.py"):
                path = ROOT / name
                record["sources"][name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "text": path.read_text()}
            for name in ("collector_container.py", "collector_client.py", "stream_collector.py", "collector-compose.yaml"):
                assert record["sources"][name]["sha256"] == image_build["sources"][name]["sha256"]
            build = json.loads((ROOT / "method-build-02/metadata-program-build.json").read_text())
            record["program_build"] = build
            assert build["passed"]
            for program in build["programs"].values():
                obj = ROOT / "method-build-02" / program["object"]
                assert hashlib.sha256(obj.read_bytes()).hexdigest() == program["sha256"]
                assert hashlib.sha256(obj.with_suffix(".sig").read_bytes()).hexdigest() == program["signature_sha256"]
            record["before"] = state()
            run("docker", "exec", fixture, "python3", "-m", "black", "--check", "/work/collector_container_suite.py")
            run("docker", "exec", fixture, "python3", "-m", "pylint", "--disable=C,R,broad-exception-caught",
                "/work/collector_container_suite.py")
            monitor = subprocess.Popen(["docker", "exec", "-i", tmm, "python3", "-u", "-c", WITNESS,
                                        build["programs"]["method"]["entry"]], stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            witness = json.loads(monitor.stdout.readline())
            record["witnesses"]["method"] = {"initial": witness}
            assert witness["sha256"] == build["runtime"]["sha256"]
            assert witness["bytes"].startswith("f30f1efa9090909090")
            source = json.loads(run("docker", "exec", tmm, "python3", "-c",
                'import json,pathlib; print(json.dumps({"boot":pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip(),'
                '"pid_namespace":str(pathlib.Path("/proc/self/ns/pid").stat().st_ino)}))').stdout)
            source.update(pid=witness["pid"], start=witness["stat"].split()[21], sha256=witness["sha256"])
            record["source_binding"] = source
            with (args.source_dir / "source.json").open("x") as output:
                json.dump(source, output)
            with (args.source_dir / "wrong-start.json").open("x") as output:
                json.dump(dict(source, start=str(int(source["start"]) + 1)), output)
            negative = ["docker", "run", "--rm", "--network", "none", "--pid", "container:" + tmm,
                        "--cap-drop", "ALL", "--security-opt", "apparmor=unconfined",
                        "--security-opt", "no-new-privileges", "-v", str(args.source_dir.resolve()) + ":/source:ro"]
            denied = run(*negative, image, "--check-source", check=False)
            assert denied.returncode != 0 and "PermissionError" in denied.stderr
            wrong = run(*negative, "--cap-add", "SYS_PTRACE", image, "--source", "/source/wrong-start.json",
                        "--check-source", check=False)
            assert wrong.returncode != 0 and "source binding mismatch" in wrong.stderr
            run(*compose, "up", "-d", "--no-deps", "collector")
            record["collector_initial"] = inspection()
            record["api_initial"] = ready()
            api_volume = next(m["Name"] for m in record["collector_initial"]["mounts"] if m["Destination"] == "/api")
            record["consumers"] = {}
            for label in ("a", "b"):
                name = PROJECT + "-consumer-" + label
                run("docker", "run", "-d", "--name", name, "--network", "none", "--read-only",
                    "--cap-drop", "ALL", "--memory", "64m", "--cpus", "0.25", "--pids-limit", "16",
                    "--label", "com.docker.compose.project=" + PROJECT, "--entrypoint", "python3",
                    "-v", api_volume + ":/api:ro", image, "-c", "import time; time.sleep(600)")
                consumers.append(name)
                details = json.loads(run("docker", "inspect", name, "--format", INSPECT).stdout)
                assert len(details["mounts"]) == 1 and details["mounts"][0]["Destination"] == "/api"
                assert not details["mounts"][0]["RW"]
                assert details["host"]["CapDrop"] == ["ALL"] and not details["host"]["CapAdd"]
                assert not details["host"]["PidMode"] and details["host"]["NetworkMode"] == "none"
                record["consumers"][label] = details
            record["consumer_a_pages"] = [consume(consumers[0])]
            consumer_cursor = record["consumer_a_pages"][0]["next_cursor"]
            record["placement"] = {name: run("docker", "top", name, "-eo", "pid,comm,args").stdout
                                   for name in (tmm, collector)}
            assert "stream_collector.py" not in record["placement"][tmm]
            assert "stream_collector.py" in record["placement"][collector]
            command = ["docker", "exec", "-e", "TEMPLATE_PROGRAM_DIR=/work/method-build-02", fixture,
                       "bash", "/work/icap-run-suite.sh", args.run, "collector-container"]
            suite = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            handled = 0
            stopped = None
            old_id = record["collector_initial"]["id"]
            deadline = time.monotonic() + 300
            while suite.poll() is None:
                if time.monotonic() > deadline:
                    raise TimeoutError("container suite deadline")
                request = json.loads(run("docker", "exec", fixture, "python3", "-c",
                    'import pathlib; p=pathlib.Path("/evidence")/"' + args.run + '"/"control-request.json"; '
                    'print(p.read_text() if p.exists() else "{}")', retain=False).stdout)
                if request and request["sequence"] > handled:
                    handled = request["sequence"]
                    action = request["action"]
                    event = dict(request)
                    if action in ("stop", "kill"):
                        current = consume(consumers[0], consumer_cursor)
                        record["consumer_a_pages"].append(current)
                        consumer_cursor = current["next_cursor"]
                        logs = run("docker", "logs", collector)
                        record.setdefault("collector_logs", []).append({"stdout": logs.stdout, "stderr": logs.stderr})
                        if action == "stop":
                            run(*compose, "stop", "collector")
                        else:
                            run("docker", "kill", "--signal", "KILL", collector)
                        stopped = ring()
                        event["stopped_ring"] = stopped
                    elif action == "resume":
                        queued = ring()
                        assert len(queued) == len(stopped) == 1
                        assert queued[0]["consumer"] == stopped[0]["consumer"]
                        assert queued[0]["producer"] > stopped[0]["producer"]
                        assert queued[0]["drops"] == stopped[0]["drops"] == 0
                        event["queued_ring"] = queued
                        run(*compose, "up", "-d", "--no-deps", "--force-recreate", "collector")
                        event["container"] = inspection()
                        assert event["container"]["id"] != old_id
                        old_id = event["container"]["id"]
                        event["api"] = ready()
                        assert event["api"]["journal_id"] == record["api_initial"]["journal_id"]
                    else:
                        raise ValueError(action)
                    assert state() == record["before"]
                    event["passed"] = True
                    record["controls"].append(event)
                    run("docker", "exec", fixture, "python3", "-c",
                        'import pathlib,sys; p=pathlib.Path("/evidence")/sys.argv[1]; '
                        't=p/"control-response.tmp"; t.write_text(sys.argv[2]); t.replace(p/"control-response.json")',
                        args.run, json.dumps({"sequence": handled, "action": action, "passed": True}))
                time.sleep(0.1)
            stdout, stderr = suite.communicate(timeout=10)
            record["suite"] = {"command": command, "returncode": suite.returncode, "stdout": stdout, "stderr": stderr}
            assert suite.returncode == 0 and handled == 4
            record["consumer_a_pages"].append(consume(consumers[0], consumer_cursor))
            record["consumer_b_page"] = consume(consumers[1], record["consumer_a_pages"][0]["oldest_cursor"])
            a_events = [row for page in record["consumer_a_pages"] for row in page["events"]]
            assert a_events == record["consumer_b_page"]["events"]
            assert len([row for row in a_events if row["event"]["type"] == "record"]) == 8
            assert len({row["cursor"] for row in a_events}) == len(a_events)
            identities = [row["event"]["event_id"] for row in a_events if row["event"]["type"] == "record"]
            assert len(set(identities)) == len(identities)
            record["passed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            record["traceback"] = traceback.format_exc()
        finally:
            errors = []
            if suite is not None and suite.poll() is None:
                try:
                    suite.communicate(timeout=55)  # The fixture's control timeout runs hook cleanup.
                except subprocess.TimeoutExpired:
                    errors.append("suite still running; retain fixture for recovery")
            try:
                logs = run("docker", "logs", collector, check=False)
                record["collector_final_log"] = {"stdout": logs.stdout, "stderr": logs.stderr}
                run(*compose, "stop", "collector", check=False)
                if record["passed"]:
                    # The controller archives the stopped journal. Consumers never mount it.
                    run("docker", "cp", collector + ":/journal/events.sqlite", args.source_dir / "events.sqlite")
                    run("docker", "cp", args.source_dir / "events.sqlite", fixture + ":/evidence/" + args.run + "/journal.sqlite")
                    record["journal_sha256"] = hashlib.sha256((args.source_dir / "events.sqlite").read_bytes()).hexdigest()
                    record["files"] = json.loads(run("docker", "exec", fixture, "python3", "-c",
                        'import pathlib,json,sys; p=pathlib.Path("/evidence")/sys.argv[1]; '
                        'print(json.dumps({f.name:f.read_text() for f in p.iterdir() if f.is_file() and f.suffix!=".sqlite"}))', args.run).stdout)
                    result = json.loads(record["files"]["result.json"])
                    assert result["passed"] and len(result["events"]) == 8
            except BaseException as error:
                errors.append(repr(error))
            for name in consumers:
                try:
                    run("docker", "rm", "-f", name)
                except BaseException as error:
                    errors.append(repr(error))
            if monitor is not None:
                try:
                    stdout, stderr = monitor.communicate("stop\n", timeout=20)
                    changes = [json.loads(line) for line in stdout.splitlines()]
                    record["witnesses"]["method"].update(changes=changes, stderr=stderr, returncode=monitor.returncode)
                    assert monitor.returncode == 0
                    assert changes[-1]["bytes"] == witness["bytes"]
                    assert changes[-1]["stat"].split()[21] == witness["stat"].split()[21]
                    if record["passed"]:
                        assert len([r for r in changes if r["bytes"].startswith("f30f1efae8")]) == 1
                except BaseException as error:
                    errors.append(repr(error))
            try:
                record["after"] = state()
                assert record["after"] == record["before"]
            except BaseException as error:
                errors.append(repr(error))
            if errors:
                record.update(passed=False, collection_errors=errors)
            json.dump(record, receipt, indent=2)
    print(json.dumps({"passed": record["passed"], "output": str(args.output)}))
    raise SystemExit(0 if record["passed"] else 1)


if __name__ == "__main__":
    main()
