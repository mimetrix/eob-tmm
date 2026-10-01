#!/usr/bin/env python3
"""Check activity export against saved live journals and the replay API."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import select
import subprocess
import sys
import tarfile
import tempfile
import unittest

from activity_export import project_event, project_page
from method_decode import RECORD
from stream_collector import Journal, replay

HERE = Path(__file__).resolve().parent
CACHE = HERE.parents[1] / "evidence/cache"
ARCHIVES = (
    "token-method-evidence-01.tar.gz", "operation-target-evidence-01.tar.gz",
    "reply-metadata-evidence-01.tar.gz", "response-metadata-evidence-01.tar.gz",
    "id-flow-evidence-01.tar.gz",
)
RESULTS = {"archives": {}, "examples": {}}


def method(value=b"tools/call", **changes):
    metadata = dict(magic=0x544D4554, abi=1, instance=(1 << 63) + 1, revision=1,
                    run=99, monotonic_ns=123456, sequence=1, output_failures=0,
                    status=1, root=1, original_length=len(value), copied_length=len(value),
                    flags=0, reads=1, source_bytes=len(value), value=value.ljust(64, b"\0"))
    metadata.update(changes)
    return {"type": "record", "event_id": "source:record:0:1", "source_id": "source",
            "raw": {"schema": 100, "data": RECORD.pack(*metadata.values()).hex()}}


class ActivityExport(unittest.TestCase):
    def test_saved_live_journals(self):
        manifest = {line.split()[1]: line.split()[0] for line in (CACHE / "MANIFEST.sha256").read_text().splitlines()
                    if line and not line.startswith("#")}
        counts = Counter()
        with tempfile.TemporaryDirectory(dir=HERE) as temporary:
            for name in ARCHIVES:
                archive = CACHE / name
                self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), manifest[name])
                with tarfile.open(archive, "r:gz") as stream:
                    journals = [m for m in stream.getmembers() if m.isfile() and m.name.endswith("events.sqlite")
                                and json.loads(stream.extractfile(m.name.rsplit("/", 1)[0] + "/result.json").read())["passed"]]
                    self.assertEqual(len(journals), 1)
                    path = Path(temporary) / name.replace(".tar.gz", ".sqlite")
                    path.write_bytes(stream.extractfile(journals[0]).read())
                cursor, rows = None, 0
                while True:
                    status, page = replay(path, cursor, 128)
                    self.assertEqual(status, 200)
                    output = project_page(page)
                    self.assertEqual(output["next_cursor"], page["next_cursor"])
                    self.assertEqual([r["cursor"] for r in output["events"]], [r["cursor"] for r in page["events"]])
                    self.assertEqual(project_page(page), output)
                    for old, new in zip(page["events"], output["events"]):
                        event = new["event"]
                        self.assertEqual(event["identity_binding"], "unknown")
                        self.assertIsNone(event["identity"])
                        self.assertEqual(event["correlation"], {"status": "unknown"})
                        self.assertEqual(event["evidence"]["continuity"], "not_established")
                        if old["event"]["type"] == "record":
                            self.assertEqual(event["event_type"], "agent.activity")
                            self.assertEqual(event["evidence"]["raw"], old["event"]["raw"])
                            kind = event["evidence"]["observation"]
                            counts[kind] += 1
                            record = event["evidence"]["record"]
                            self.assertIsInstance(record["instance"], str)
                            if kind == "operation_target" and record["status"] == 1:
                                RESULTS["examples"].setdefault(kind, event)
                            self.assertNotIn("success", event["reported_outcome"])
                        else:
                            self.assertEqual(event["evidence"]["diagnostic"], old["event"])
                        rows += 1
                    cursor = page["next_cursor"]
                    if not page["events"]:
                        break
                RESULTS["archives"][name] = dict(sha256=manifest[name], journal_rows=rows)
        self.assertEqual(set(counts), {"method", "operation_target", "reply", "http_response", "message_id"})
        RESULTS["observations"] = dict(counts)

    def test_raw_strings_and_truncation(self):
        event = project_event(method(b'tools/\\u0063all'))
        self.assertEqual(event["activity"]["method"]["value"], "tools/call")
        self.assertEqual(event["activity"]["method"]["raw_hex"], b'tools/\\u0063all'.hex())
        for raw in (b"bad\nvalue", b"\xff"):
            value = project_event(method(raw))["activity"]["method"]
            self.assertNotIn("value", value)
            self.assertIn("text_error", value)
        value = project_event(method(b"x" * 64, original_length=70, status=2))["activity"]["method"]
        self.assertEqual(value["status"], "truncated")
        self.assertNotIn("value", value)

    def test_identity_claims_do_not_become_binding(self):
        original = method()
        original.update(identity_binding="verified", identity={"subject": "admin"}, trace_id="claimed")
        original["raw"].update(identity={"subject": "admin"}, trace_id="claimed")
        result = project_event(original)
        self.assertEqual(result["identity_binding"], "unknown")
        self.assertIsNone(result["identity"])
        self.assertEqual(result["correlation"], {"status": "unknown"})
        self.assertEqual(project_page({"next_cursor": "j:2", "events": [
            {"cursor": "j:1", "event": original}, {"cursor": "j:2", "event": original}
        ]})["events"][0]["event"], result)

    def test_gaps_and_bad_records_are_retained(self):
        for kind in ("source_boundary", "observation_gap", "discard", "ring_health"):
            original = {"type": kind, "dropped_since_checkpoint": 3}
            output = project_event(original)
            self.assertEqual(output["event_type"], "agent." + kind)
            self.assertEqual(output["evidence"]["diagnostic"], original)
        for data in ("not hex", "00", "00" * 513):
            original = method()
            original["raw"]["data"] = data
            result = project_event(original)
            self.assertEqual(result["event_type"], "agent.observation")
            self.assertEqual(result["activity"], {})
            self.assertIn(result["evidence"]["status"], ("malformed_record", "unsupported_schema"))
        self.assertEqual(project_event(method(flags=1))["evidence"]["status"], "unqualified_record")
        self.assertEqual(project_event(method(instance=0))["evidence"]["status"], "unqualified_record")
        self.assertTrue(project_event(method(output_failures=1))["evidence"]["output_loss_reported"])

    def test_ids_keep_numeric_spelling(self):
        original = method(b"900719925474099312345", magic=0x4D534749, root=2)
        value = project_event(original)["activity"]["message_id"]
        self.assertEqual(value["value"], "900719925474099312345")
        self.assertEqual(value["kind"], "number")

    def test_cli_over_socket_and_retention(self):
        with tempfile.TemporaryDirectory(dir=HERE) as temporary:
            directory = Path(temporary)
            path, socket = directory / "events.sqlite", directory / "api.sock"
            journal = Journal(path, retain=2)
            try:
                journal.accept({"kind": "source", "pid": 1, "start": "1"})
                for index in range(3):
                    raw = dict(method()["raw"], kind="record", ring=0, begin=index, end=index + 1)
                    journal.accept(raw)
            finally:
                journal.close()
            server = subprocess.Popen([sys.executable, HERE / "stream_collector.py", "serve", "--journal", path,
                                       "--unix-socket", socket], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.assertTrue(select.select([server.stdout], [], [], 10)[0], "replay server startup")
                ready = server.stdout.readline()
                self.assertIn("listening", ready, server.stderr.read() if not ready else ready)
                command = [sys.executable, HERE / "activity_export.py", "--socket", socket, "--limit", "1"]
                first = subprocess.run(command, capture_output=True, text=True, timeout=15, check=True)
                page = json.loads(first.stdout)
                self.assertEqual(len(page["events"]), 1)
                self.assertEqual(page["events"][0]["event"]["activity"]["method"]["value"], "tools/call")
                next_page = json.loads(subprocess.run(command + ["--after", page["next_cursor"]],
                    capture_output=True, text=True, timeout=15, check=True).stdout)
                self.assertNotEqual(page["next_cursor"], next_page["next_cursor"])
                expired = page["journal_id"] + ":0"
                failure = subprocess.run(command + ["--after", expired], capture_output=True, text=True, timeout=15)
                self.assertEqual(failure.returncode, 1)
                self.assertEqual(failure.stdout, "")
                self.assertIn("retention_gap", failure.stderr)
                local = subprocess.run([sys.executable, HERE / "activity_export.py", "--journal", path,
                    "--after", expired], capture_output=True, text=True, timeout=15)
                self.assertEqual(local.returncode, 1)
                self.assertEqual(json.loads(local.stdout)["error"], "retention_gap")
            finally:
                server.terminate()
                server.communicate(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ActivityExport)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if args.report:
        report = dict(passed=result.wasSuccessful(), tests=result.testsRun, results=RESULTS,
                      failures=[text for _, text in result.failures + result.errors],
                      scope="saved live journal replay and local collector API; no new TMM run",
                      witness="SELF: exporter and tests", sources={})
        for name in ("activity_export.py", "check_activity_export.py", "id_flow_decode.py", "message_id_decode.py",
                     "activity_group_decode.py",
                     "method_decode.py", "operation_target_decode.py", "reply_metadata_decode.py",
                     "response_metadata_decode.py", "token_method_decode.py", "collector_client.py", "stream_collector.py"):
            path = HERE / name
            report["sources"][name] = dict(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), text=path.read_text())
        with args.report.open("x") as output:
            json.dump(report, output, indent=2)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
