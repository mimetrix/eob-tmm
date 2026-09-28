#!/usr/bin/env python3
"""Retain tutorial sources, final state and the real output-result falsifier."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    """A successful collection does not mean the tutorial passed."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path("/home/starin/eob-config-20260925")
    staged = Path("/home/starin/eob-tmm-staged/substrate")
    record = {"completed": False, "commands": [], "sources": {}}

    def run(*command, expected=0):
        result = subprocess.run([str(item) for item in command], capture_output=True,
                                text=True, timeout=90, check=False)
        record["commands"].append({"command": [str(item) for item in command],
                                   "returncode": result.returncode,
                                   "stdout": result.stdout, "stderr": result.stderr})
        assert result.returncode == expected, record["commands"][-1]
        return result

    with args.output.open("x") as output:
        try:
            names = ("template.c", "template_io.py", "template_suite.py", "template_prepare.py",
                     "template_fixture.py", "template_snapshot.py", "config_live_run.py",
                     "config_suite.py", "icap_suite.py", "icap-run-suite.sh", "check_map_reuse.c",
                     "check_output_result.c", "template-fixture.env")
            for name in names:
                path = root / name
                record["sources"][name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                           "text": path.read_text()}
            for name in ("ls_tp_emit.c", "ls_tp_ring.h", "ls_ring.h"):
                path = staged / name
                source = path.read_bytes()
                assert source == (Path("/home/starin/code/tmm/src/base") / name).read_bytes()
                record["sources"][name] = {"sha256": hashlib.sha256(source).hexdigest(),
                                           "text": source.decode()}
            binary = root / "check-output-result"
            assert not binary.exists()
            run("gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-I" + str(staged),
                root / "check_output_result.c", "-o", binary)
            record["output_falsifier"] = json.loads(run(binary, expected=1).stdout)
            assert record["output_falsifier"] == {"delivered_result": -1, "consumed_bytes": 8,
                                                   "dropped_result": 0, "drops": 1, "passed": False}
            fixture = "eob-template-20260925-fixture-1"
            run("docker", "exec", fixture, "python3", "-m", "pylint",
                "/work/template_suite.py", "/work/template_prepare.py")
            run("docker", "exec", fixture, "bash", "-n", "/work/icap-run-suite.sh")
            for project in ("eob-config-20260925", "eob-template-20260925"):
                run("docker", "exec", project + "-fixture-1", "python3", "/work/ls-load.py", "status", "5")
                run("docker", "exec", project + "-fixture-1", "python3", "/work/ls-load.py",
                    "config-status", "5", expected=1)
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
