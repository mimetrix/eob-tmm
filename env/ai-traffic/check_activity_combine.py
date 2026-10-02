#!/usr/bin/env python3
"""Replay live exchange frames and attack incomplete or ambiguous joins."""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import select
import struct
import subprocess
import sys
import tempfile
import unittest

from activity_combine import ActivityCombiner
from activity_export import project_event

HERE = Path(__file__).resolve().parent
ROWS = []
REPORT = {}


def combined(rows, size=128, **limits):
    combiner, result = ActivityCombiner(**limits), []
    for offset in range(0, len(rows), size):
        chunk = rows[offset:offset + size]
        result.extend(combiner.feed(dict(events=chunk, next_cursor=chunk[-1]["cursor"])))
    result.extend(combiner.flush("end_of_input"))
    return [r for r in result if r["event_type"] == "agent.activity.combined"]


def complete(rows, **limits):
    return [r for r in combined(rows, **limits) if r["correlation"]["status"] == "observed_exchange"]


def project_rows(rows):
    from activity_export import project_page  # pylint: disable=import-outside-toplevel
    return project_page(dict(events=rows, next_cursor=rows[-1]["cursor"]))["events"] if len(rows) <= 128 else \
        [r for i in range(0, len(rows), 128) for r in project_rows(rows[i:i + 128])]


def edit(row, offset, value, fmt="<Q"):
    payload = bytearray.fromhex(row["event"]["raw"]["data"])
    struct.pack_into(fmt, payload, offset, value)
    row["event"]["raw"]["data"] = payload.hex()


class CombinedTests(unittest.TestCase):
    def test_live_values_and_page_boundaries(self):
        baseline = combined(ROWS)
        self.assertEqual(len(baseline), 10)
        self.assertTrue(all(r["correlation"]["status"] == "observed_exchange" for r in baseline))
        self.assertEqual(len({r["activity_id"] for r in baseline}), 10)
        for size in (1, 2, 3, 7, 17, 127):
            self.assertEqual(combined(ROWS, size), baseline)
        values = {r["activity"]["target"]["value"]: r for r in baseline}
        for i in range(4):
            row = values["concurrent-" + str(i)]
            self.assertEqual(row["activity"]["message_id"]["value"], "same")
            self.assertEqual(row["reported_outcome"]["tool_error"]["value"], bool(i % 2))
        self.assertEqual(values["file:///one"]["activity"]["message_id"]["value"], "9007199254740993")
        self.assertEqual(values["file:///one"]["reported_outcome"]["error_code"]["value"], -32601)
        REPORT["combined"] = baseline

    def test_each_missing_record_and_discard(self):
        # Delete every record of the first exchange. Also replace it with a
        # DISCARD while retaining its cursor, to test sequence/field checks.
        reference = complete(ROWS)[0]
        first = next(i for i, r in enumerate(ROWS) if r["cursor"] == reference["evidence"]["first_cursor"])
        last = next(i for i, r in enumerate(ROWS) if r["cursor"] == reference["evidence"]["last_cursor"])
        tested = 0
        for i in range(first, last + 1):
            if ROWS[i]["event"]["type"] != "record":
                continue
            for discard in (False, True):
                rows = copy.deepcopy(ROWS)
                if discard:
                    rows[i]["event"] = dict(type="discard", source_id=rows[i]["event"]["source_id"], raw={})
                else:
                    del rows[i]
                self.assertNotIn(reference["activity_id"], {r["activity_id"] for r in complete(rows)})
                tested += 1
        REPORT["missing_record_mutations"] = tested

    def test_source_timestamps_and_clock_adjustment(self):
        by_cursor = {row["cursor"]: row for row in ROWS}

        def epoch_ns(value):
            seconds, fraction = value.removesuffix("Z").split(".")
            self.assertEqual(len(fraction), 9)
            date = datetime.strptime(seconds, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
            delta = date - datetime(1970, 1, 1, tzinfo=timezone.utc)
            return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + int(fraction)

        for row in complete(ROWS):
            first = by_cursor[row["evidence"]["first_cursor"]]
            last = by_cursor[row["evidence"]["last_cursor"]]
            timing = row["timing"]
            self.assertEqual(timing["status"], "complete")
            self.assertEqual(epoch_ns(timing["started_at"]), int(first["event"]["raw"]["ts_ns"]))
            self.assertEqual(epoch_ns(timing["ended_at"]), int(last["event"]["raw"]["ts_ns"]))
            self.assertEqual(timing["last_observed_at"], timing["ended_at"])
            start = int(project_event(first["event"])["evidence"]["record"]["monotonic_ns"])
            end = int(project_event(last["event"])["evidence"]["record"]["monotonic_ns"])
            self.assertEqual(timing["duration_ns"], str(end - start))

        reference = complete(ROWS)[0]
        first_cursor, last_cursor = [reference["evidence"][k] for k in ("first_cursor", "last_cursor")]
        rows = copy.deepcopy(ROWS)
        first = next(r for r in rows if r["cursor"] == first_cursor)
        last = next(r for r in rows if r["cursor"] == last_cursor)
        last["event"]["raw"]["ts_ns"] = str(int(first["event"]["raw"]["ts_ns"]) - 1_000_000_001)
        changed = complete(rows)[0]["timing"]
        self.assertLess(changed["ended_at"], changed["started_at"])
        self.assertEqual(changed["duration_ns"], reference["timing"]["duration_ns"])
        self.assertEqual(changed["status"], "complete")

        start = int(project_event(first["event"])["evidence"]["record"]["monotonic_ns"])
        edit(last, 48 + 32, start - 1)
        invalid = complete(rows)[0]["timing"]
        self.assertEqual(invalid["status"], "invalid")
        self.assertIsNone(invalid["duration_ns"])

    def test_unfinished_and_missing_timestamps(self):
        reference = complete(ROWS)[0]
        first = next(i for i, r in enumerate(ROWS) if r["cursor"] == reference["evidence"]["first_cursor"])
        last = next(i for i, r in enumerate(ROWS) if r["cursor"] == reference["evidence"]["last_cursor"])
        unfinished = combined(ROWS[first:last])[0]["timing"]
        self.assertEqual(unfinished["status"], "incomplete")
        self.assertIsNone(unfinished["ended_at"])
        self.assertIsNone(unfinished["duration_ns"])
        self.assertIsNotNone(unfinished["last_observed_at"])
        for bad in (None, "", "bad", "-1", "0", str(1 << 64), 1.5, True):
            rows = copy.deepcopy(ROWS)
            rows[first]["event"]["raw"]["ts_ns"] = bad
            timing = complete(rows)[0]["timing"]
            self.assertIsNone(timing["started_at"])
            self.assertEqual(timing["status"], "incomplete")
        rows = copy.deepcopy(ROWS)
        del rows[last]["event"]["raw"]["ts_ns"]
        edit(rows[first], 48 + 32, 0)
        timing = complete(rows)[0]["timing"]
        self.assertIsNone(timing["ended_at"])
        self.assertIsNone(timing["duration_ns"])
        self.assertEqual(timing["status"], "incomplete")

    def test_binding_and_payload_mutations(self):
        first = complete(ROWS)[0]
        field_cursor = first["evidence"]["field_sources"]
        mutations = [(field_cursor["target"], 16, 999, "<Q"),
                     (field_cursor["reply"], 48 + 8, 999, "<Q"),
                     (field_cursor["http_status"], 48 + 8, 999, "<Q"),
                     (field_cursor["reply"], 48 + 24, 999, "<Q"),
                     (field_cursor["reply"], 40, 999, "<Q"),
                     (field_cursor["reply"], 48 + 48, 1, "<Q"),
                     (field_cursor["target"], 4, 1, "<I"),
                     (field_cursor["target"], 12, 2, "<I")]
        for cursor, offset, value, fmt in mutations:
            rows = copy.deepcopy(ROWS)
            row = next(r for r in rows if r["cursor"] == cursor)
            edit(row, offset, value, fmt)
            self.assertNotIn(first["activity_id"], {r["activity_id"] for r in complete(rows)})
        rows = copy.deepcopy(ROWS)
        row = next(r for r in rows if r["cursor"] == field_cursor["target"])
        edit(row, 48 + 56, 2, "<I")
        edit(row, 48 + 64, 65, "<I")
        edit(row, 48 + 68, 64, "<I")
        data = bytearray.fromhex(row["event"]["raw"]["data"])
        data[128:] = b"x" * 64
        row["event"]["raw"]["data"] = data.hex()
        self.assertEqual(project_event(row["event"])["activity"]["target"]["status"], "truncated")
        self.assertNotIn(first["activity_id"], {r["activity_id"] for r in complete(rows)})

    def test_duplicate_start_and_capacity(self):
        rows = copy.deepcopy(ROWS)
        first = complete(rows)[0]
        index = next(i for i, r in enumerate(rows) if r["cursor"] == first["evidence"]["first_cursor"])
        rows.insert(index, copy.deepcopy(rows[index]))
        for i, row in enumerate(rows):
            row["cursor"] = "test:" + str(i + 1)
        self.assertNotIn(first["activity_id"], {r["activity_id"] for r in complete(rows)})
        self.assertLess(len(complete(ROWS, capacity=2)), 10)
        self.assertFalse(complete(ROWS, max_records=3))
        self.assertFalse(complete(ROWS[:index + 3]))

    def test_id_mismatch_and_explicit_gap(self):
        first = complete(ROWS)[0]
        rows = copy.deepcopy(ROWS)
        for row in rows:
            event = project_event(row["event"])
            evidence = event["evidence"]
            if (evidence.get("group", {}).get("exchange") == first["evidence"]["exchange"]
                    and evidence.get("observation") == "message_id" and evidence["group"]["side"] == 2):
                payload = bytearray.fromhex(row["event"]["raw"]["data"])
                payload[128:131] = b"two"
                row["event"]["raw"]["data"] = payload.hex()
        result = combined(rows)[0]
        self.assertIn("reply_id_mismatch", result["correlation"]["issues"])
        for kind in ("observation_gap", "source_boundary"):
            rows = copy.deepcopy(ROWS)
            index = next(i for i, r in enumerate(rows) if r["cursor"] == first["evidence"]["first_cursor"])
            rows.insert(index + 1, dict(cursor="", event=dict(type=kind)))
            for i, row in enumerate(rows):
                row["cursor"] = "test:" + str(i + 1)
            self.assertNotIn(first["activity_id"], {r["activity_id"] for r in complete(rows)})

    def test_measured_journal_has_no_tls_reading(self):
        # The measured journal predates ABI 2: no TLS claim may appear.
        for row in combined(ROWS):
            self.assertEqual(row["transport"], {"client_tls": {"status": "not_observed"}})
            self.assertEqual(row["identity_binding"], "unknown")

    def test_client_tls_block_and_derivation(self):
        from response_metadata_decode import FORMAT, TLS, decode
        base = bytearray(FORMAT.size)
        struct.pack_into("<II6Q10I", base, 0, 0x5253504D, 2, 1, 1, 1, 1, 1, 0,
                         142, 7, 0, 1, 1, 0, 0, 0, 0, 0)

        def reading(*fields):
            return decode(bytes(base) + TLS.pack(*fields))["client_tls"]

        HSOK, PASS, CHAIN, SCERT, RETAIN = 1, 2, 4, 8, 16
        self.assertEqual(reading(3, 0, 3, 0, 0, 0, 0, 0), dict(mode="no_ssl_filter", filter_nodes=3))
        cases = [  # (pcm, vfy, bits, expected)
            (0, 0, HSOK, "not_requested"),
            (2, 0, HSOK | SCERT | RETAIN, "verified"),
            (2, 0, HSOK | CHAIN, "verified"),
            (2, 20, HSOK | CHAIN | RETAIN, "failed"),
            (2, 0, HSOK | RETAIN, "none_observed"),
            (2, 0, HSOK, "unknown"),  # freed chain, nothing retained
            (1, 0, HSOK, "unknown"),
        ]
        for pcm, vfy, bits, expected in cases:
            value = reading(1, 0, 3, bits, 6, 0x1302, pcm, vfy)
            self.assertEqual(value["client_certificate"], expected, (pcm, vfy, bits))
            self.assertEqual((value["protocol"], value["cipher_suite_id"]), ("TLSv1.3", 0x1302))
        self.assertEqual(reading(2, 0, 3, PASS | HSOK, 5, 0xc02f, 0, 0)["mode"], "ssl_filter_not_decrypting")
        self.assertEqual(reading(4, 3, 4, 0, 0, 0, 0, 0)["reason"], "multiple_ssl_filters")
        refused = [
            (1, 0, 3, PASS | HSOK, 6, 1, 0, 0),   # terminated but passthru
            (1, 0, 3, 0, 6, 1, 0, 0),             # terminated without handshake
            (2, 0, 3, HSOK, 6, 1, 0, 0),          # not-decrypting with handshake
            (3, 0, 3, HSOK, 0, 0, 0, 0),          # values without an SSL filter
            (4, 0, 1, 0, 0, 0, 0, 0),             # unknown without reason
            (3, 2, 1, 0, 0, 0, 0, 0),             # reason on a class
            (0, 0, 2, 0, 0, 0, 0, 0),             # walk on inapplicable event
            (5, 0, 0, 0, 0, 0, 0, 0), (1, 0, 17, HSOK, 6, 1, 0, 0),
            (1, 0, 3, HSOK | 256, 6, 1, 0, 0), (1, 0, 3, HSOK, 10, 1, 0, 0),
            (1, 0, 3, HSOK, 6, 1, 3, 0), (1, 0, 3, HSOK, 6, 1, 0, 128),
        ]
        for fields in refused:
            with self.assertRaises(ValueError, msg=fields):
                reading(*fields)
        other = bytearray(base)
        struct.pack_into("<I", other, 56, 144)
        struct.pack_into("<I", other, 76, 7)
        with self.assertRaises(ValueError):  # TLS reading on the wrong event
            decode(bytes(other) + TLS.pack(3, 0, 1, 0, 0, 0, 0, 0))
        with self.assertRaises(ValueError):  # ABI 1 with a TLS block
            one = bytearray(base)
            struct.pack_into("<I", one, 4, 1)
            decode(bytes(one) + TLS.pack(*[0] * 8))
        REPORT["tls_decoder_cases"] = len(cases) + len(refused) + 4

    def test_client_tls_conflict_is_reported(self):
        # Two confirming readings that disagree must not be resolved.
        rows = copy.deepcopy(ROWS)
        reference = complete(rows)[0]
        group = [r for r in rows if r["event"]["type"] == "record"
                 and reference["evidence"]["first_cursor"] <= r["cursor"] <= reference["evidence"]["last_cursor"]]
        self.assertTrue(group)
        combiner = ActivityCombiner()
        key = (reference["evidence"]["source_id"], reference["evidence"]["ring"], reference["evidence"]["run"],
               reference["evidence"]["owner_instance"], reference["evidence"]["exchange"])
        projected = [r for r in project_rows(rows) if r["cursor"] in {g["cursor"] for g in group}]
        readings = [p for p in projected if p["event"]["evidence"]["observation"] == "http_response"
                    and p["event"]["evidence"]["group"]["side"] == 1]
        self.assertGreaterEqual(len(readings), 2)
        readings[0]["event"]["activity"]["client_tls"] = dict(mode="no_ssl_filter", filter_nodes=2)
        readings[1]["event"]["activity"]["client_tls"] = dict(mode="unknown", filter_nodes=1, reason="read_failed")
        combiner.pending[key] = dict(first=projected[0]["cursor"], rows=projected, issues=[], confirmed=True)
        row = combiner.finish(key)
        self.assertEqual(row["transport"]["client_tls"]["status"], "conflicting")
        self.assertIn("conflicting_client_tls", row["correlation"]["issues"])
        self.assertEqual(row["correlation"]["status"], "incomplete")

    def test_cli_journal_socket_and_errors(self):
        command = [sys.executable, HERE / "activity_combine.py"]
        expected = complete(ROWS)
        args = ["--journal", REPORT["journal"], "--after", REPORT["after"]]
        direct = subprocess.run(command + args, capture_output=True, text=True, timeout=30, check=True)
        rows = [json.loads(line) for line in direct.stdout.splitlines()]
        self.assertEqual([r for r in rows if r["event_type"] == "agent.activity.combined"], expected)
        with tempfile.TemporaryDirectory(dir=HERE) as temporary:
            socket = Path(temporary) / "api.sock"
            server = subprocess.Popen([sys.executable, HERE / "stream_collector.py", "serve", "--journal",
                                       REPORT["journal"], "--unix-socket", socket],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.assertTrue(select.select([server.stdout], [], [], 10)[0])
                self.assertIn("listening", server.stdout.readline())
                result = subprocess.run(command + ["--socket", socket, "--after", REPORT["after"]],
                                        capture_output=True, text=True, timeout=30, check=True)
                self.assertEqual(result.stdout, direct.stdout)
                failed = subprocess.run(command + ["--socket", socket, "--after", "wrong:0"],
                                        capture_output=True, text=True, timeout=30)
                self.assertNotEqual(failed.returncode, 0)
                self.assertEqual(failed.stdout, "")
                self.assertIn("wrong_journal", failed.stderr)
            finally:
                server.terminate()
                server.communicate(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", type=Path, required=True)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    record = json.loads(args.live.read_text())
    result = json.loads(record["files"]["result.json"])
    ROWS.extend(result["replay_consumer"]["events"])
    REPORT.update(live_sha256=hashlib.sha256(args.live.read_bytes()).hexdigest(),
                  journal=str(args.journal), journal_sha256=hashlib.sha256(args.journal.read_bytes()).hexdigest(),
                  after=result["initial_cursor"], sources={})
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CombinedTests)
    outcome = unittest.TextTestRunner(verbosity=2).run(suite)
    REPORT.update(passed=outcome.wasSuccessful(), tests=outcome.testsRun,
                  failures=[text for _, text in outcome.errors + outcome.failures])
    for path in [HERE / name for name in ("check_activity_combine.py", "activity_combine.py", "activity_export.py",
                                         "collector_client.py", "stream_collector.py")] + list(HERE.glob("*decode.py")):
        REPORT["sources"][path.name] = dict(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), text=path.read_text())
    with args.report.open("x") as output:
        json.dump(REPORT, output, indent=2)
    return 0 if outcome.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
