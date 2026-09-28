#!/usr/bin/env python3
"""Finish evidence capture after live 03's final source-boundary key assertion."""
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess

from config_live_run import WITNESS
from lifetime_fixture import PROJECT, ROOT
from method_decode import decode


def main():
    previous = ROOT / "collector-container-live-03.json"
    record = json.loads(previous.read_text())
    assert not record["passed"] and record["error"] == "KeyError('event_id')"
    assert not record.get("collection_errors") and record["suite"]["returncode"] == 0
    record["retained_failure"] = {
        "path": str(previous), "sha256": hashlib.sha256(previous.read_bytes()).hexdigest(),
        "passed": False, "error": record.pop("error"), "traceback": record.pop("traceback"),
        "correction": "Check cursor uniqueness for all events; event_id uniqueness for records. Source boundaries have source_id.",
    }
    record["recovery_commands"] = []
    path = Path(__file__)
    record["sources"][path.name] = {"text": path.read_text(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    fixture, tmm, collector = (PROJECT + "-" + name + "-1" for name in ("fixture", "tmm", "collector"))

    def run(*command):
        row = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=30, check=False)
        record["recovery_commands"].append({"argv": list(map(str, command)), "rc": row.returncode,
                                            "stdout": row.stdout, "stderr": row.stderr})
        row.check_returncode()
        return row.stdout

    with (ROOT / "collector-container-recovery-01.json").open("x") as receipt:
        try:
            assert [row["action"] for row in record["controls"]] == ["stop", "resume", "kill", "resume"]
            assert all(row["passed"] for row in record["controls"])
            events = [row for page in record["consumer_a_pages"] for row in page["events"]]
            assert events == record["consumer_b_page"]["events"] and len(events) == 10
            assert len({row["cursor"] for row in events}) == 10
            values = [row for row in events if row["event"]["type"] == "record"]
            assert len(values) == len({row["event"]["event_id"] for row in values}) == 8
            assert not any(row["event"]["type"] == "observation_gap" for row in events)
            assert run("docker", "inspect", collector, "--format", "{{.State.Running}} {{.State.ExitCode}}").strip() == "false 0"
            run("docker", "exec", fixture, "python3", "/work/icap_check_result.py", "/evidence/collector-container-live-03")
            database = ROOT / "collector-source-03/events.sqlite"
            assert not database.exists()
            run("docker", "cp", collector + ":/journal/events.sqlite", database)
            db = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
            try:
                assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
                archived = [json.loads(row[0]) for row in db.execute("SELECT body FROM events ORDER BY id")]
                assert archived == [row["event"] for row in events]
                assert db.execute("SELECT count(DISTINCT event_key) FROM events").fetchone()[0] == 10
                record["journal"] = {"integrity": "ok", "events": 10, "sha256": hashlib.sha256(database.read_bytes()).hexdigest()}
            finally:
                db.close()
            run("docker", "cp", database, fixture + ":/evidence/collector-container-live-03/journal.sqlite")
            record["files"] = json.loads(run("docker", "exec", fixture, "python3", "-c",
                'import pathlib,json; p=pathlib.Path("/evidence/collector-container-live-03"); '
                'print(json.dumps({f.name:f.read_text() for f in p.iterdir() if f.is_file() and f.suffix!=".sqlite"}))'))
            result = json.loads(record["files"]["result.json"])
            decoded = [decode(bytes.fromhex(row["event"]["raw"]["data"])) for row in values]
            assert decoded == result["events"] and result["passed"]
            assert [row["sequence"] for row in decoded] == list(range(1, 9))
            assert not any(row["output_failures"] for row in decoded)
            assert len(result["clients"]) == 10 and len(result["container_controls"]) == 4
            assert result["counter_end"]["method"]["fired"] - result["counter_start"]["method"]["fired"] == 8
            witness = record["witnesses"]["method"]
            assert len([row for row in witness["changes"] if row["bytes"].startswith("f30f1efae8")]) == 1
            check = [json.loads(line) for line in run("docker", "exec", tmm, "python3", "-u", "-c",
                WITNESS, record["program_build"]["programs"]["method"]["entry"]).splitlines()]
            assert check[0]["sha256"] == witness["initial"]["sha256"]
            assert check[0]["bytes"] == check[-1]["bytes"] == witness["initial"]["bytes"]
            assert check[0]["stat"].split()[21] == witness["initial"]["stat"].split()[21]
            record["recovery_witness"] = check
            record["after"] = run("docker", "inspect", tmm, "--format",
                                   "{{json .Id}} {{json .Image}} {{json .State}} {{.RestartCount}}")
            assert record["after"] == record["before"]
            record["passed"] = True
        except BaseException as error:
            record["recovery_error"] = repr(error)
            raise
        finally:
            json.dump(record, receipt, indent=2)
    print(json.dumps({"passed": True, "journal_events": 10, "method_records": 8, "new_traffic": 0}))


if __name__ == "__main__":
    main()
