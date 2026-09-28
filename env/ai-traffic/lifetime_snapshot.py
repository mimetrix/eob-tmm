#!/usr/bin/env python3
"""Check receipt/source consistency and final disabled state before cleanup."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path("/home/starin/eob-config-20260925")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    record = {"passed": False, "commands": [], "sources": {}}
    with args.output.open("x") as receipt:
        try:
            live = json.loads(args.live.read_text())
            assert live["passed"]
            record["live_sha256"] = hashlib.sha256(args.live.read_bytes()).hexdigest()
            test = json.loads(live["files"]["result.json"])
            record["summary"] = test["summary"]
            gaps = test.get("controlled_gap_guard_validated") is True
            if gaps:
                assert test["request_scope_validated"] is False
                record["windows"] = [{"name": w["name"], "summary": w["data"]["summary"],
                                      "coverage": w["data"]["coverage"]} for w in test["windows"]]
            else:
                record["flags"] = dict(Counter(e["flags"] for e in test["events"]))
                record["reuse_pairs"] = len(test["address_reuse"])
            correlation = "candidate" in live["program_build"]["programs"]
            if correlation and not gaps:
                assert test["bounded_join_validated"]
                assert test["request_scope_validated"] is False
                record["candidate_flags"] = dict(Counter(e["flags"] for e in test["candidates"]))
                record["join_negative_checks"] = test["join_negative_checks"]
            for name, saved in live["sources"].items():
                path = ROOT / name
                assert hashlib.sha256(path.read_bytes()).hexdigest() == saved["sha256"], name
                assert hashlib.sha256(saved["text"].encode()).hexdigest() == saved["sha256"], name
            sources = ("lifetime_snapshot.py", "lifetime_fixture.py", "lifetime_build.py", "lifetime_discover.py")
            if correlation:
                sources += ("correlation_build.py", "correlation_discover.py")
            if gaps:
                sources += ("gap_build.py", "check_gap_window.py")
            for name in sources:
                path = ROOT / name
                record["sources"][name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                           "text": path.read_text()}
            for name in set(sources) | {n for n in live["sources"] if n.endswith(".py")}:
                compile((ROOT / name).read_text(), name, "exec")
            fixture = "eob-template-20260925-fixture-1"
            # stop() must attempt every detach/revoke after any cleanup exception.
            # It saves each error and raises after the remaining actions finish.
            record["lint_scope"] = "Errors/warnings, except intentional broad cleanup catches; convention/refactor rules excluded."
            commands = [["bash", "-n", str(ROOT / "icap-run-suite.sh")],
                        ["docker", "exec", fixture, "python3", "-m", "pylint", "--disable=C,R,broad-exception-caught", "/work/lifetime_suite.py"]]
            for slot in (p["slot"] for p in live["program_build"]["programs"].values()):
                for operation in ("status", "config-status"):
                    commands.append(["docker", "exec", fixture, "python3", "/work/ls-load.py", operation, str(slot)])
            for argv in commands:
                result = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
                record["commands"].append({"argv": argv, "rc": result.returncode,
                                           "stdout": result.stdout, "stderr": result.stderr})
                if "config-status" in argv:
                    assert result.returncode != 0
                else:
                    result.check_returncode()
                if "status" in argv:
                    assert "mode=0" in result.stdout
            record["passed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            json.dump(record, receipt, indent=2)
    print(json.dumps({"passed": record["passed"], "output": str(args.output)}))


if __name__ == "__main__":
    main()
