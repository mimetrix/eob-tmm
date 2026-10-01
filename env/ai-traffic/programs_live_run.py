#!/usr/bin/env python3
"""Run the ownership SSA test with independent binary, process and patch checks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback

ROOT = Path("/home/starin/eob-config-20260925")
sys.path.insert(0, str(ROOT))
from config_live_run import WITNESS
from lifetime_fixture import PROJECT


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True)
    for name in ("source", "artifacts", "package", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    assert args.run.replace("-", "").isalnum()
    tmm, fixture = PROJECT + "-tmm-1", PROJECT + "-fixture-1"
    record = dict(passed=False, commands=[], sources={}, witnesses={}, witness_script=WITNESS)
    monitors = {}

    def run(*cmd, timeout=120):
        p = subprocess.run(list(map(str, cmd)), cwd=ROOT, capture_output=True, text=True,
                           timeout=timeout, check=False)
        record["commands"].append(dict(argv=list(map(str, cmd)), rc=p.returncode, stdout=p.stdout, stderr=p.stderr))
        p.check_returncode()
        return p.stdout

    def state():
        return run("docker", "inspect", tmm, "--format", "{{json .Id}} {{json .Image}} {{json .State}} {{.RestartCount}}")

    with args.output.open("x") as receipt:
        try:
            build = json.loads((args.artifacts / "program-build.json").read_text())
            package = json.loads((args.package / "package-result.json").read_text())
            assert build["passed"] and package["passed"] and build["tmm_image"] == package["image"]
            assert build["package_sha256"] == sha(args.package / "package-result.json")
            record["program_build"] = build
            build["programs"] = {row["section"]: dict(entry=hex(row["entry"]), pad=row["pad"])
                                 for row in build["targets"]}
            record["before"] = state()
            assert json.loads(record["before"].split()[1]) == package["image"]
            assert record["before"].strip().endswith(" 0")
            for name in ("config_suite.py", "session_routing_suite.py", "metadata_suite.py", "icap_suite.py",
                         "config_live_run.py", "lifetime_fixture.py", "icap_check_result.py"):
                path = ROOT / name
                record["sources"][name] = dict(sha256=sha(path), text=path.read_text())
            for name in ("programs_live_suite.py", "programs_live_run.py"):
                path = args.source / "env/ai-traffic" / name
                record["sources"][name] = dict(sha256=sha(path), text=path.read_text())
            suite = Path("/work") / args.source.relative_to(ROOT) / "env/ai-traffic/programs_live_suite.py"
            directory = Path("/work") / args.artifacts.relative_to(ROOT)
            cli = directory / "ls-load.py"
            artifact = build["artifact"]
            for filename, digest in ((artifact["object"], artifact["sha256"]),
                                     (artifact["signature"], artifact["signature_sha256"]),
                                     ("ls-load.py", artifact["cli_sha256"])):
                assert sha(args.artifacts / filename) == digest
            run("docker", "exec", fixture, "python3", "-m", "black", "--check", suite)
            run("docker", "exec", "-e", "PYTHONPATH=/work", fixture, "python3", "-m", "pylint", "--disable=C,R,broad-exception-caught", suite)
            for owner in range(8):
                assert "instance=0" in run("docker", "exec", fixture, "python3", cli, "program-status", owner)
            for label, target in build["programs"].items():
                monitor = subprocess.Popen(["docker", "exec", "-i", tmm, "python3", "-u", "-c", WITNESS, target["entry"]],
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                monitors[label] = monitor
                initial = json.loads(monitor.stdout.readline())
                record["witnesses"][label] = dict(initial=initial)
                assert initial["sha256"] == package["runtime"]["sha256"]
                assert initial["bytes"][2 * target["pad"]:].startswith("9090909090")
            run("docker", "exec", fixture, "mkdir", "/evidence/" + args.run)
            shell = '''set -euo pipefail
export ICAP_RESULT="/evidence/$1/result.json"
export TAO_OUTPUT_FILE="/evidence/$1/tao.xml"
export TAO_TIME_OUT=240 TAO_LOG_DISPLAY=all TAO_LOG_LEVEL=INFO
export CONFIG_SERVER_DPC_RAISE_ON_ERROR=false
export PYTHONPATH="/work:${PYTHONPATH:-}"
set +e
tao_runner >"/evidence/$1/tao.log" 2>&1
status=$?
printf '%s\\n' "$status" >"/evidence/$1/exit-status"
if [ "$status" = 0 ]; then
 python3 /work/icap_check_result.py "/evidence/$1"
 status=$?
fi
printf '%s\\n' "$status" >"/evidence/$1/checked-exit-status"
exit "$status"
'''
            record["runner"] = shell
            drain = Path("/work") / args.package.relative_to(ROOT) / "image-context/ls_drain"
            run("docker", "exec", "-e", "TAO_TEST_PATH=" + str(suite),
                "-e", "TEMPLATE_PROGRAM_DIR=" + str(directory), "-e", "PROGRAMS_DRAIN=" + str(drain),
                fixture, "bash", "-c", shell, "programs", args.run, timeout=300)
            record["passed"] = True
        except BaseException as error:
            record.update(error=repr(error), traceback=traceback.format_exc())
        finally:
            errors = []
            for label, monitor in monitors.items():
                try:
                    stdout, stderr = monitor.communicate("stop\n", timeout=20)
                    row = record["witnesses"][label]
                    row.update(changes=[json.loads(line) for line in stdout.splitlines()], stderr=stderr, returncode=monitor.returncode)
                    assert monitor.returncode == 0
                    final = row["changes"][-1]
                    assert final["final"] and final["bytes"] == row["initial"]["bytes"]
                    assert final["stat"].split()[21] == row["initial"]["stat"].split()[21]
                    if record["passed"]:
                        pad = build["programs"][label]["pad"]
                        assert sum(r["bytes"][2 * pad:].startswith("e8") for r in row["changes"]) == 1
                except BaseException as error:
                    errors.append("witness: " + repr(error))
            try:
                record["after"] = state()
                assert record["after"] == record["before"]
                for owner in range(8):
                    assert "instance=0" in run("docker", "exec", fixture, "python3", cli, "program-status", owner)
                record["files"] = json.loads(run("docker", "exec", fixture, "python3", "-c",
                    'import json,pathlib,sys; p=pathlib.Path("/evidence")/sys.argv[1]; print(json.dumps({f.name:f.read_text() for f in p.iterdir() if f.is_file()}))', args.run))
                if record["passed"]:
                    assert json.loads(record["files"]["result.json"])["passed"]
            except BaseException as error:
                errors.append("final: " + repr(error))
            if errors:
                record.update(passed=False, collection_errors=errors)
            json.dump(record, receipt, indent=2)
    print(json.dumps({k: record.get(k) for k in ("passed", "error", "collection_errors")}))
    raise SystemExit(0 if record["passed"] else 1)


if __name__ == "__main__":
    main()
