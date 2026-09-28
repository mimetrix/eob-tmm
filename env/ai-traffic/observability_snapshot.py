#!/usr/bin/env python3
"""Collect repair receipts, exact sources and final isolated-fixture state."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", default="check-07")
    parser.add_argument("--live", default="observability-live-01.json")
    args = parser.parse_args()
    build = Path("/home/starin/observability-20260925")
    bench = Path("/home/starin/template-20260925")
    fixture = Path("/home/starin/eob-config-20260925")
    stage = Path("/home/starin/eob-tmm-staged/substrate")
    tree = Path("/home/starin/code/tmm/src/base")
    record = {"completed": False, "records": {}, "sources": {}, "commands": []}

    def capture(path, table):
        data = path.read_bytes()
        record[table][str(path)] = {
            "sha256": hashlib.sha256(data).hexdigest(), "text": data.decode()
        }

    def run(*command, expected=0):
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=120, check=False)
        row = {"argv": command, "rc": result.returncode,
               "stdout": result.stdout, "stderr": result.stderr}
        record["commands"].append(row)
        assert result.returncode == expected, row

    with args.output.open("x") as output:
        try:
            receipts = [build / name for name in (
                "preflight.json", "build-result.json", "package-result.json",
                "config-regression.json", "package-step-0.log", "package-step-1.log")]
            receipts += [bench / f"host-check-{i:02d}/receipt.json" for i in range(1, 4)]
            receipts += [bench / "check-06/receipt.json", bench / args.check / "receipt.json"]
            receipts += [fixture / "observability-01" / name for name in (
                "template-program-build.json", "config-program-build.json")]
            receipts += [fixture / args.live, fixture / "observability-deploy-01.json"]
            for path in receipts:
                capture(path, "records")
            for path in fixture.glob("observability-live-*.json"):
                capture(path, "records")
            native = json.loads((bench / "host-check-03/receipt.json").read_text())
            built = json.loads((build / "build-result.json").read_text())
            checked = json.loads((bench / args.check / "receipt.json").read_text())
            live = json.loads((fixture / args.live).read_text())
            assert native["passed"] and built["passed"] and checked["passed"] and live["passed"]
            for name in ("ls_map.h", "ls_map_glue.h", "ls_vm.c", "ls_vm_load.c", "ls_tp_emit.c"):
                capture(stage / name, "sources")
                digest = record["sources"][str(stage / name)]["sha256"]
                assert digest == native["sources"][name] == built["sources"][name]
                assert (stage / name).read_bytes() == (tree / name).read_bytes()
            for name in ("check_map.c", "check_map_reuse.c", "check_map_threads.c",
                         "check_output_result.c", "check_observability.py", "check_glue_owner.c",
                         "ls_tp_ring.h", "ls_ring.h", "map-registry-globals.patch"):
                capture(stage / name, "sources")
            for name in ("template.c", "template_io.py", "check_template.c", "check_template.py"):
                capture(bench / name, "sources")
                assert record["sources"][str(bench / name)]["sha256"] == checked["sources"][name]
            capture(stage / "surfaces/config_observe.bpf.c", "sources")
            for name in ("template_suite.py", "template_prepare.py", "config_build_probe.py",
                         "config_live_run.py", "observability_snapshot.py", "observability_deploy.py", "config_suite.py",
                         "icap_suite.py", "icap-run-suite.sh", "template-fixture.env",
                         "observability-compose.yaml"):
                capture(fixture / name, "sources")
            test_fixture = "eob-template-20260925-fixture-1"
            run("docker", "exec", test_fixture, "python3", "-m", "black", "--check",
                "/work/template_suite.py", "/work/config_build_probe.py")
            run("docker", "exec", "-e", "PYTHONDONTWRITEBYTECODE=1", test_fixture,
                "python3", "-m", "pylint", "/work/template_suite.py", "/work/config_build_probe.py")
            run("docker", "exec", test_fixture, "bash", "-n", "/work/icap-run-suite.sh")
            for project in ("eob-config-20260925", "eob-template-20260925"):
                for slot in (("5", "6") if "template" in project else ("5",)):
                    run("docker", "exec", project + "-fixture-1", "python3",
                        "/work/ls-load.py", "status", slot)
                    run("docker", "exec", project + "-fixture-1", "python3",
                        "/work/ls-load.py", "config-status", slot, expected=1)
                run("docker", "inspect", project + "-tmm-1", "--format",
                    "{{json .Id}} {{json .Image}} {{json .State}} {{.RestartCount}}")
            record["completed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            json.dump(record, output, indent=2)


if __name__ == "__main__":
    main()
