#!/usr/bin/env python3
"""Retain one live attempt and kernel byte witnesses for all three targets."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

from config_live_run import WITNESS

ROOT = Path("/home/starin/eob-config-20260925")
PROJECT = "eob-template-20260925"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--artifact-dir", required=True, type=Path)
    parser.add_argument("--suite", choices=("parser-lifetime", "correlation", "gaps", "metadata", "method", "collector"), default="parser-lifetime")
    parser.add_argument("--collector-dir", type=Path)
    args = parser.parse_args()
    assert args.run.replace("-", "").isalnum()
    assert not args.artifact_dir.is_absolute() and ".." not in args.artifact_dir.parts
    record = {"passed": False, "commands": [], "witnesses": {}, "sources": {},
              "started": time.time(), "witness_script": WITNESS}
    monitors = {}
    collector = None
    collector_directory = "/run/ls-stream/" + args.run

    def run(*argv, timeout=60):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        record["commands"].append({"argv": argv, "rc": result.returncode,
                                   "stdout": result.stdout, "stderr": result.stderr})
        result.check_returncode()
        return result.stdout

    def state():
        return run("docker", "inspect", PROJECT + "-tmm-1", "--format",
                   "{{json .Id}} {{json .Image}} {{json .State}} {{.RestartCount}}")

    with args.output.open("x") as receipt:
        try:
            names = ("lifetime_suite.py", "lifetime_live_run.py", "config_live_run.py",
                         "request_scope_suite.py", "config_suite.py", "attribution.py",
                         "attribution_suite.py", "attribution_join.py", "icap_suite.py",
                         "icap-run-suite.sh", "icap_check_result.py", "LIFETIME.md")
            if args.suite in ("correlation", "gaps"):
                names += ("correlation_suite.py", "correlation_join.py", "CORRELATION.md")
            if args.suite == "gaps":
                names += ("gap_suite.py", "gap_window.py", "GAPS.md")
            if args.suite in ("metadata", "method", "collector"):
                names += ("metadata_suite.py", "metadata_decode.py", "METADATA.md",
                          "metadata_preflight.py", "icap-compose.yaml", "config-compose.yaml",
                           "observability-compose.yaml", "template-fixture.env")
            if args.suite in ("method", "collector"):
                names += ("method_suite.py", "method_decode.py")
            if args.suite == "collector":
                names += ("collector_suite.py", "collector_session.py", "stream_collector.py", "COLLECTOR.md")
            for name in names:
                path = ROOT / name
                record["sources"][name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                           "text": path.read_text()}
            build_name = "metadata-program-build.json" if args.suite in ("metadata", "method", "collector") else "lifetime-program-build.json"
            build = json.loads((ROOT / args.artifact_dir / build_name).read_text())
            assert build["passed"]
            record["program_build"] = build
            for program in build["programs"].values():
                obj = ROOT / args.artifact_dir / program["object"]
                assert hashlib.sha256(obj.read_bytes()).hexdigest() == program["sha256"]
                assert hashlib.sha256(obj.with_suffix(".sig").read_bytes()).hexdigest() == program["signature_sha256"]
            record["before"] = state()
            if args.suite in ("method", "collector"):
                run("docker", "exec", PROJECT + "-fixture-1", "python3", "-m", "black", "--check",
                    "/work/method_suite.py", "/work/method_decode.py", "/work/metadata_suite.py")
                run("docker", "exec", PROJECT + "-fixture-1", "python3", "-m", "pylint",
                    "--disable=C,R,broad-exception-caught", "/work/method_suite.py", "/work/method_decode.py", "/work/metadata_suite.py")
            if args.suite == "collector":
                run("docker", "exec", PROJECT + "-fixture-1", "python3", "-m", "black", "--check", "/work/collector_suite.py")
                run("docker", "exec", PROJECT + "-fixture-1", "python3", "-m", "pylint",
                    "--disable=C,R,broad-exception-caught", "/work/collector_suite.py")
            if args.suite == "metadata":
                run("docker", "exec", PROJECT + "-fixture-1", "python3", "-m", "black", "--check",
                    "/work/metadata_suite.py", "/work/metadata_decode.py")
                run("docker", "exec", PROJECT + "-fixture-1", "python3", "-m", "pylint",
                    "--disable=C,R,broad-exception-caught", "/work/metadata_suite.py", "/work/metadata_decode.py")
            if args.suite == "correlation":
                run("docker", "exec", PROJECT + "-fixture-1", "python3", "-m", "black", "--check",
                    "/work/correlation_suite.py", "/work/correlation_join.py")
            if args.suite == "gaps":
                run("docker", "exec", PROJECT + "-fixture-1", "python3", "-m", "black", "--check",
                    "/work/gap_suite.py", "/work/gap_window.py")
                run("docker", "exec", PROJECT + "-fixture-1", "python3", "-m", "pylint", "--disable=C,R,broad-exception-caught",
                    "/work/gap_suite.py", "/work/gap_window.py")
                run("docker", "exec", PROJECT + "-fixture-1", "python3", "-m", "pylint", "--disable=C,R",
                    "/work/correlation_suite.py", "/work/correlation_join.py")
            for label, program in build["programs"].items():
                monitor = subprocess.Popen(
                    ["docker", "exec", "-i", PROJECT + "-tmm-1", "python3", "-u", "-c",
                     WITNESS, program["entry"]], stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                monitors[label] = monitor
                row = {"initial": json.loads(monitor.stdout.readline())}
                record["witnesses"][label] = row
                assert row["initial"]["sha256"] == build["runtime"]["sha256"]
                prefix = "f30f1efa" if program.get("pad", 4) else ""
                assert row["initial"]["bytes"].startswith(prefix + "9090909090")
            if args.suite == "collector":
                assert args.collector_dir and not args.collector_dir.is_absolute() and ".." not in args.collector_dir.parts
                collector_build = json.loads((ROOT / args.collector_dir / "collector-build.json").read_text())
                assert collector_build["passed"]
                record["collector_build"] = collector_build
                reader = ROOT / args.collector_dir / "ls_stream"
                assert hashlib.sha256(reader.read_bytes()).hexdigest() == collector_build["ls_stream_sha256"]
                for name in ("stream_collector.py", "method_decode.py"):
                    assert record["sources"][name]["sha256"] == collector_build["sources"][str(ROOT / name)]["sha256"]
                code = "/tmp/" + args.run + "-collector"
                run("docker", "exec", PROJECT + "-tmm-1", "ls", "-d", "/tmp", "/run/ls-stream")
                run("docker", "exec", PROJECT + "-tmm-1", "mkdir", code)
                for path in (reader, ROOT / "stream_collector.py", ROOT / "method_decode.py", ROOT / "collector_session.py"):
                    run("docker", "cp", str(path), PROJECT + "-tmm-1:" + code + "/" + path.name)
                source = record["witnesses"]["method"]["initial"]
                command = ["docker", "exec", "-i", PROJECT + "-tmm-1", "python3", code + "/collector_session.py",
                           "--directory", collector_directory, "--reader", code + "/ls_stream",
                           "--pid", source["pid"], "--start", source["stat"].split()[21]]
                collector = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                record["collector_command"] = command
                record["collector_ready"] = json.loads(collector.stdout.readline())
                assert record["collector_ready"]["ready"]
            print(run("docker", "exec", "-e", "TEMPLATE_PROGRAM_DIR=" + str(Path("/work") / args.artifact_dir),
                       "-e", "COLLECTOR_DIRECTORY=" + collector_directory,
                      PROJECT + "-fixture-1", "bash", "/work/icap-run-suite.sh",
                       args.run, args.suite, timeout=600 if args.suite == "gaps" else 300), flush=True)
            record["passed"] = True
        except Exception as error:
            record["error"] = repr(error)
        finally:
            errors = []
            if collector is not None:
                try:
                    stdout, stderr = collector.communicate("stop\n", timeout=20)
                    record["collector_stop"] = {"stdout": stdout, "stderr": stderr, "returncode": collector.returncode}
                    assert collector.returncode == 0
                    record["journal"] = json.loads(run(
                        "docker", "exec", PROJECT + "-fixture-1", "python3", "-c",
                        'import hashlib,json,pathlib,shutil,sqlite3,sys; source=pathlib.Path(sys.argv[1]); '
                        'dest=pathlib.Path("/evidence")/sys.argv[2]; '
                        'shutil.copyfile(source/"journal.sqlite",dest/"journal.sqlite"); '
                        'shutil.copyfile(source/"collector.log",dest/"collector.log"); '
                        'db=sqlite3.connect(source/"journal.sqlite"); '
                        'print(json.dumps({"sha256":hashlib.sha256((dest/"journal.sqlite").read_bytes()).hexdigest(),'
                        '"integrity":db.execute("PRAGMA integrity_check").fetchone()[0],'
                        '"events":db.execute("SELECT count(*) FROM events").fetchone()[0]}))',
                        collector_directory, args.run))
                    assert record["journal"]["integrity"] == "ok"
                except Exception as error:
                    errors.append("collector: " + repr(error))
            for label, monitor in monitors.items():
                try:
                    stdout, stderr = monitor.communicate("stop\n", timeout=20)
                    row = record["witnesses"].setdefault(label, {})
                    row.update(changes=[json.loads(line) for line in stdout.splitlines()],
                               stderr=stderr, returncode=monitor.returncode)
                    assert monitor.returncode == 0, stderr
                    final = row["changes"][-1]
                    assert final["final"] and final["bytes"] == row["initial"]["bytes"]
                    assert final["stat"].split()[21] == row["initial"]["stat"].split()[21]
                    if record["passed"]:
                        prefix = "f30f1efa" if build["programs"][label].get("pad", 4) else ""
                        calls = [e for e in row["changes"] if e["bytes"].startswith(prefix + "e8")]
                        expected = (7 if label in ("init", "fini") else 6) if args.suite == "gaps" else (2 if label == "init" else 1)
                        assert len(calls) == expected, row
                except Exception as error:
                    errors.append(label + ": " + repr(error))
            try:
                record["after"] = state()
                assert record["before"] == record["after"]
                record["files"] = json.loads(run(
                    "docker", "exec", PROJECT + "-fixture-1", "python3", "-c",
                    'import json,pathlib,sys; root=pathlib.Path("/evidence")/sys.argv[1]; '
                    'print(json.dumps({p.name:p.read_text() for p in root.iterdir() if p.is_file() and p.suffix!=".sqlite"}))', args.run))
                for slot in (p["slot"] for p in build["programs"].values()):
                    text = run("docker", "exec", PROJECT + "-fixture-1", "python3",
                               "/work/ls-load.py", "status", str(slot))
                    assert "mode=0" in text, text
            except Exception as error:
                errors.append(repr(error))
            if errors:
                record.update(passed=False, collection_errors=errors)
            record["finished"] = time.time()
            json.dump(record, receipt, indent=2)
    print(json.dumps({"passed": record["passed"], "output": str(args.output)}))
    raise SystemExit(0 if record["passed"] else 1)


if __name__ == "__main__":
    main()
