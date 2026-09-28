#!/usr/bin/env python3
"""Process-level collector gates, using the real shared-ring implementation."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import select
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen

from method_decode import RECORD
from collector_client import page as unix_page
from stream_collector import Journal, replay

ARGS = None
PAYLOAD = RECORD.pack(0x4A4D4554, 1, 2**63 + 79, 1, 2**63 + 31, 123, 1, 0,
                      1, 0, 11, 11, 0, 7, 120, b"SendMessage")


def line(process):
    if not select.select([process.stdout], [], [], 5)[0]:
        raise AssertionError("subprocess output timeout")
    return process.stdout.readline()


def stop(process):
    if process.poll() is None:
        process.kill()
    process.wait(timeout=5)
    for pipe in (process.stdin, process.stdout, process.stderr):
        if pipe:
            pipe.close()


class StreamTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ARGS.work)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.segment = self.root / "ring"
        self.source = self.spawn([ARGS.source, self.segment])
        self.assertEqual(json.loads(line(self.source)), {"ready": True})
        stat = Path(f"/proc/{self.source.pid}/stat").read_text()
        self.start = stat.rsplit(")", 1)[1].split()[19]
        self.reader_args = [ARGS.reader, self.segment, str(self.source.pid), self.start]

    def spawn(self, command):
        proc = subprocess.Popen(list(map(str, command)), stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        self.addCleanup(stop, proc)
        return proc

    def command(self, text):
        self.source.stdin.write((text + "\n").encode())
        return json.loads(line(self.source))

    def emit(self, count=1):
        return self.command(f"emit {count} {PAYLOAD.hex()}")

    def reader(self, journal=None):
        proc = self.spawn(self.reader_args)
        for kind in ("source", "ring_health"):
            frame = json.loads(line(proc))
            self.assertEqual(frame["kind"], kind)
            if journal:
                journal.accept(frame)
            self.ack(proc, frame)
        return proc

    @staticmethod
    def ack(proc, frame):
        proc.stdin.write(("ACK " + frame["token"] + "\n").encode())

    def journal(self, name="journal", **kwargs):
        value = Journal(self.root / name, **kwargs)
        self.addCleanup(value.close)
        return value

    def test_old_consume_precedes_downstream_acceptance(self):
        before = self.emit()
        after = self.command("consume")
        self.assertEqual(before["consumer"], "0")
        self.assertEqual(after["consumed"], len(PAYLOAD))
        self.assertEqual(after["consumer"], after["producer"])

    def test_legacy_drain_failed_output_has_already_consumed(self):
        self.emit()
        with open("/dev/full", "wb", buffering=0) as sink:
            result = subprocess.run([str(ARGS.legacy), "--segment", str(self.segment), "--once"],
                                    stdout=sink, stderr=subprocess.PIPE, timeout=5, check=False)
        state = self.command("status")
        self.assertEqual(state["consumer"], state["producer"])
        self.assertNotEqual(state["consumer"], "0")
        print(json.dumps({"legacy_failed_output": {"rc": result.returncode,
              "stderr": result.stderr.decode(), "state": state}}), flush=True)

    def test_crash_before_ack_and_after_commit(self):
        self.emit()
        reader = self.reader()
        first = json.loads(line(reader))
        self.assertEqual(self.command("status")["consumer"], "0")
        stop(reader)
        journal = self.journal()
        reader = self.reader(journal)
        second = json.loads(line(reader))
        self.assertEqual(first, second)
        journal.accept(second)
        self.assertEqual(journal.db.execute("SELECT count(*) FROM events").fetchone()[0], 3)
        stop(reader)  # Committed; the ring cursor has not been acknowledged.
        self.assertEqual(self.command("status")["consumer"], "0")
        journal.close()
        journal = self.journal()
        reader = self.reader(journal)
        duplicate = json.loads(line(reader))
        journal.accept(duplicate)
        self.assertEqual(journal.db.execute("SELECT count(*) FROM events").fetchone()[0], 3)
        self.ack(reader, duplicate)
        for _ in range(100):
            if self.command("status")["consumer"] == duplicate["end"]:
                break
            time.sleep(0.01)
        self.assertEqual(self.command("status")["consumer"], duplicate["end"])
        _, body = replay(self.root / "journal", None)
        decoded = body["events"][-1]["event"]["decoded"]["record"]
        self.assertEqual(decoded["value_hex"], b"SendMessage".hex())
        self.assertEqual(decoded["instance"], str(2**63 + 79))

    def test_reader_lock_bad_ack_and_source_binding(self):
        self.emit()
        reader = self.reader()
        frame = json.loads(line(reader))
        competitor = self.spawn(self.reader_args)
        self.assertNotEqual(competitor.wait(timeout=5), 0)
        self.assertIn(b"another cooperative reader", competitor.stderr.read())
        reader.stdin.write(b"ACK wrong\n")
        self.assertNotEqual(reader.wait(timeout=5), 0)
        self.assertEqual(self.command("status")["consumer"], frame["begin"])
        self.command("corrupt")
        invalid = self.spawn(self.reader_args)
        self.assertNotEqual(invalid.wait(timeout=5), 0)
        self.assertIn(b"invalid segment geometry", invalid.stderr.read())

    def test_source_replacement_and_unmapped_source(self):
        self.emit()
        reader = self.reader()
        frame = json.loads(line(reader))
        self.segment.rename(self.root / "old")
        self.segment.write_bytes((self.root / "old").read_bytes())
        self.ack(reader, frame)
        self.assertNotEqual(reader.wait(timeout=5), 0)
        self.assertIn(b"source identity changed", reader.stderr.read())
        self.assertEqual(self.command("status")["consumer"], "0")
        invalid = self.spawn(self.reader_args)
        self.assertNotEqual(invalid.wait(timeout=5), 0)
        self.assertIn(b"producer does not map", invalid.stderr.read())

    def test_full_ring_returns_and_reports_drops(self):
        self.emit()
        reader = self.reader()
        frame = json.loads(line(reader))
        filled = self.emit(2000)
        self.assertGreater(int(filled["drops"]), 0)
        self.assertLess(filled["emitted"], 2000)
        self.assertEqual(filled["consumer"], "0")
        self.ack(reader, frame)
        health = json.loads(line(reader))
        self.assertEqual(health["kind"], "ring_health")
        self.assertEqual(health["drops"], filled["drops"])

    def test_retention_conflicts_foreign_cursor_and_writer_lock(self):
        self.emit()
        journal = self.journal(retain=3)
        with self.assertRaises(BlockingIOError):
            Journal(self.root / "journal")
        reader = self.reader(journal)
        frame = json.loads(line(reader))
        journal.accept(frame)
        status, page = replay(self.root / "journal", None, 1)
        self.assertEqual(status, 200)
        old = page["next_cursor"]
        for count in range(1, 8):
            journal.accept({"kind": "ring_health", "ring": 0, "drops": str(count)})
        journal.accept(frame)  # Checkpoint still deduplicates an expired event.
        self.assertEqual(journal.db.execute("SELECT count(*) FROM events").fetchone()[0], 3)
        self.assertEqual(replay(self.root / "journal", old)[1]["error"], "retention_gap")
        self.assertEqual(replay(self.root / "journal", "wrong:1")[1]["error"], "wrong_journal")
        with self.assertRaisesRegex(ValueError, "conflicting replay"):
            journal.accept(dict(frame, data="00" * len(PAYLOAD)))
        with self.assertRaisesRegex(ValueError, "regressed"):
            journal.accept(dict(frame, end="8"))
        with self.assertRaisesRegex(ValueError, "position gap"):
            journal.accept(dict(frame, begin="999", end="1000"))
        previous_source = journal.source
        journal.accept({"kind": "source", "pid": "new"})
        self.assertNotEqual(journal.source, previous_source)
        self.assertEqual(replay(self.root / "journal", None)[1]["events"][-1]["event"]["type"], "source_boundary")

    def test_page_limit_rolls_back_without_ack(self):
        self.emit()
        journal = self.journal(retain=10000, max_pages=32)
        reader = self.reader(journal)
        frame = json.loads(line(reader))
        failed = False
        for index in range(1000):
            raw = dict(frame, begin=str(index * 184), end=str((index + 1) * 184))
            try:
                journal.accept(raw)
            except sqlite3.OperationalError as error:
                self.assertIn("full", str(error))
                failed = True
                break
        self.assertTrue(failed)
        self.assertFalse(journal.db.in_transaction)
        self.assertEqual(self.command("status")["consumer"], "0")
        self.assertLessEqual(journal.db.execute("PRAGMA page_count").fetchone()[0], 32)
        self.assertEqual(journal.db.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_continuous_collection_http_consumers_and_parent_death(self):
        collector = self.spawn([
            sys.executable, Path(__file__).with_name("stream_collector.py"), "collect",
            "--reader", ARGS.reader, "--segment", self.segment,
            "--pid", self.source.pid, "--start", self.start,
            "--journal", self.root / "journal",
        ])
        self.emit()
        for _ in range(300):
            if self.command("status")["consumer"] != "0":
                break
            self.assertIsNone(collector.poll())
            time.sleep(0.01)
        self.assertNotEqual(self.command("status")["consumer"], "0")
        server = self.spawn([sys.executable, Path(__file__).with_name("stream_collector.py"),
                             "serve", "--journal", self.root / "journal", "--port", "0"])
        port = json.loads(line(server))["listening"][1]

        def fetch(query=""):
            try:
                with urlopen(f"http://127.0.0.1:{port}/events{query}", timeout=5) as response:
                    return response.status, json.load(response)
            except HTTPError as error:
                return error.code, json.load(error)

        first = fetch()[1]
        cursor = first["next_cursor"]
        with ThreadPoolExecutor(max_workers=1) as pool:
            slow = pool.submit(fetch, f"?after={cursor}&wait_ms=1000")
            self.assertEqual(fetch()[1]["events"], first["events"])
            self.emit()
            second = slow.result(timeout=5)[1]
            self.assertEqual(len(second["events"]), 1)
            self.assertNotEqual(second["next_cursor"], cursor)
        # Consumer one can reconnect with its old cursor and obtain the same event.
        self.assertEqual(fetch(f"?after={cursor}")[1]["events"], second["events"])
        self.assertEqual(fetch("?after=foreign:0")[0], 409)
        stop(collector)  # Reader must not keep its cooperative lock after parent death.
        time.sleep(0.1)
        restarted = self.reader()
        self.assertIsNone(restarted.poll())

    def test_lazy_segment_start_and_deadline(self):
        late = self.root / "late"
        command = [sys.executable, Path(__file__).with_name("stream_collector.py"), "collect",
                   "--reader", ARGS.reader, "--segment", late, "--pid", self.source.pid,
                   "--start", self.start, "--journal", self.root / "lazy", "--once",
                   "--wait-segment", "2"]
        collector = self.spawn(command)
        time.sleep(0.1)
        self.assertIsNone(collector.poll())
        self.segment.rename(late)
        self.emit()
        self.assertEqual(collector.wait(timeout=5), 0)
        self.assertEqual(self.command("status")["consumer"], self.command("status")["producer"])
        command[command.index("--segment") + 1] = self.root / "never"
        command[command.index("--journal") + 1] = self.root / "timeout"
        command[-1] = "0.1"
        timed = self.spawn(command)
        self.assertNotEqual(timed.wait(timeout=5), 0)
        self.assertIn(b"startup deadline", timed.stderr.read())

    def test_unix_api_replay_and_socket_ownership(self):
        journal = self.journal()
        self.reader(journal)
        path = self.root / "events.sock"
        command = [sys.executable, Path(__file__).with_name("stream_collector.py"),
                   "serve", "--journal", self.root / "journal", "--unix-socket", path]
        server = self.spawn(command)
        self.assertEqual(json.loads(line(server))["listening"], str(path))
        first = unix_page(path)
        self.assertEqual(len(first["events"]), 2)
        self.assertEqual(unix_page(path, first["next_cursor"])["events"], [])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        other = self.spawn(command)
        self.assertNotEqual(other.wait(timeout=5), 0)
        self.assertEqual(unix_page(path)["events"], first["events"])
        stop(server)
        replacement = self.spawn(command)
        self.assertEqual(json.loads(line(replacement))["listening"], str(path))
        self.assertEqual(unix_page(path)["events"], first["events"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--reader", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--legacy", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    ARGS = parser.parse_args()
    unittest.main(argv=[sys.argv[0]], verbosity=2)
