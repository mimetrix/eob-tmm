#!/usr/bin/env python3
"""Continuous acknowledged collection, bounded SQLite journal and HTTP replay.

The C reader retains its ring cursor until this process commits and sends ACK.
Replay clients own their cursors; they never acknowledge the producer ring.
"""
import argparse
import fcntl
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import socketserver
import sqlite3
import stat
import subprocess
import threading
import time
from urllib.parse import parse_qs, urlsplit
import uuid

from method_decode import decode

MAX_FRAME = 8192


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class Journal:
    """One writer; retained event bodies and source checkpoints share a transaction."""

    def __init__(self, path, retain=10000, max_pages=32768):
        if retain < 2 or max_pages < 32:
            raise ValueError("retain >= 2 and max_pages >= 32 required")
        path = Path(path).resolve()
        self.lock = Path(str(path) + ".lock").open("a+b")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.db = sqlite3.connect(path, timeout=1, isolation_level=None)
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA synchronous=FULL")
            actual = self.db.execute(f"PRAGMA max_page_count={max_pages}").fetchone()[0]
            if actual > max_pages:
                raise ValueError("existing journal exceeds the requested page limit")
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_key TEXT UNIQUE NOT NULL,
                    fingerprint TEXT NOT NULL,
                    body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            """)
            self.db.execute("INSERT OR IGNORE INTO state VALUES ('journal_id', ?)", (uuid.uuid4().hex,))
            self.retain = retain
            self.source = None
            self.source_frame = None
        except BaseException:
            if hasattr(self, "db"):
                self.db.close()
            self.lock.close()
            raise

    def close(self):
        self.db.close()
        self.lock.close()

    def get(self, key):
        row = self.db.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO state VALUES (?,?)", (key, canonical(value)))

    def insert(self, key, fingerprint, body):
        row = self.db.execute("SELECT id,fingerprint FROM events WHERE event_key=?", (key,)).fetchone()
        if row:
            if row[1] != fingerprint:
                raise ValueError("conflicting bytes for an existing event identity")
            return row[0]
        # Delete before insert. SQLite reuses freed pages; the page limit also
        # bounds high-water storage if event sizes change. No WAL grows behind readers.
        self.db.execute(
            "DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)",
            (self.retain - 1,),
        )
        return self.db.execute(
            "INSERT INTO events(event_key,fingerprint,body) VALUES (?,?,?)",
            (key, fingerprint, canonical(body)),
        ).lastrowid

    def accept(self, frame):
        raw = {k: v for k, v in frame.items() if k != "token"}
        if len(canonical(raw)) > MAX_FRAME:
            raise ValueError("oversize reader frame")
        kind = raw["kind"]
        if kind == "source":
            source = hashlib.sha256(canonical(raw).encode()).hexdigest()
            self.db.execute("BEGIN IMMEDIATE")
            try:
                if self.get("source_id") != source:
                    self.db.execute("DELETE FROM state WHERE key LIKE 'ring:%' OR key LIKE 'drops:%'")
                    self.put("source_id", source)
                    epoch = uuid.uuid4().hex
                    self.put("source_epoch", epoch)
                    self.insert("source:" + epoch, source, {
                        "type": "source_boundary", "source_id": epoch, "source": raw,
                        "history": "unknown_before_first_collection",
                    })
                self.db.execute("COMMIT")
            except BaseException:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                raise
            self.source = self.get("source_epoch")
            self.source_frame = raw
            return
        if not self.source or kind not in ("record", "discard", "ring_health"):
            raise ValueError("record without a registered source or unknown frame kind")
        ring = raw["ring"]
        if not isinstance(ring, int) or not 0 <= ring < 16:
            raise ValueError("invalid ring index")
        progress_key = ("drops:" if kind == "ring_health" else "ring:") + str(ring)
        if kind == "ring_health":
            position = int(raw["drops"])
            if position < 0:
                raise ValueError("invalid drop count")
            # Drop count and byte count are separately sampled. Only count is
            # used as the health event identity; it is not an atomic pair.
            raw.pop("drop_bytes", None)
            key = f"{self.source}:drops:{ring}:{position}"
        else:
            begin, position = int(raw["begin"]), int(raw["end"])
            if begin < 0 or position <= begin:
                raise ValueError("invalid ring interval")
            key = f"{self.source}:record:{ring}:{begin}"
        fingerprint = hashlib.sha256(canonical(raw).encode()).hexdigest()
        body = {"type": kind, "source_id": self.source, "source": self.source_frame,
                "event_id": key, "raw": raw, "schema": "application_stream/v1"}
        if kind == "record":
            payload = bytes.fromhex(raw["data"])
            if len(payload) > 512:
                raise ValueError("oversize record")
            if raw["schema"] == 100 and len(payload) == 144 and payload[:4] == b"TEMJ":
                try:
                    body["decoded"] = {
                        "schema": "method/v1", "binding": "not_verified_by_collector",
                        "record": {k: str(v) if k in (
                            "instance", "revision", "run", "monotonic_ns", "sequence",
                            "output_failures") else v for k, v in decode(payload).items()},
                    }
                except ValueError as error:
                    body["decode_error"] = str(error)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            previous = self.get(progress_key)
            if previous:
                if position < previous["position"]:
                    raise ValueError("source position regressed")
                if position == previous["position"]:
                    if previous["fingerprint"] != fingerprint:
                        raise ValueError("conflicting replay at checkpoint")
                    self.db.execute("COMMIT")
                    return
                if kind != "ring_health" and begin != previous["position"]:
                    raise ValueError("unaccounted source position gap")
            if kind == "ring_health":
                body["type"] = "ring_health" if position == 0 else "observation_gap"
                body["dropped_since_checkpoint"] = (
                    position - previous["position"] if previous else None
                )
            self.insert(key, fingerprint, body)
            self.put(progress_key, {"position": position, "fingerprint": fingerprint})
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise


def collect(args):
    journal = Journal(args.journal, args.retain, args.max_pages)
    child = None
    try:
        deadline = time.monotonic() + args.wait_segment
        while args.wait_segment:
            try:
                with args.segment.open("rb") as stream:
                    magic = int.from_bytes(stream.read(8), "little")
                if magic == 0x4C53534547303031:
                    break
            except FileNotFoundError:
                pass
            if time.monotonic() >= deadline:
                raise TimeoutError("source segment was not published before startup deadline")
            time.sleep(0.05)
        command = [str(args.reader), str(args.segment), str(args.pid), str(args.start)]
        if args.once:
            command.append("--once")
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        while True:
            line = child.stdout.readline(MAX_FRAME + 1)
            if not line:
                break
            if len(line) > MAX_FRAME or not line.endswith(b"\n"):
                raise ValueError("incomplete or oversize reader frame; no ACK")
            frame = json.loads(line)
            journal.accept(frame)
            child.stdin.write(("ACK " + frame["token"] + "\n").encode())
            child.stdin.flush()
        if child.wait() != 0:
            raise RuntimeError("reader stopped with an error; source continuity is unknown")
    finally:
        if child:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            child.stdin.close()
            child.stdout.close()
        journal.close()


def replay(path, cursor, limit=100):
    if not 1 <= limit <= 128:
        raise ValueError("limit must be 1..128")
    db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=1, isolation_level=None)
    try:
        db.execute("BEGIN")
        identity = db.execute("SELECT value FROM state WHERE key='journal_id'").fetchone()[0]
        oldest, newest = db.execute("SELECT min(id),max(id) FROM events").fetchone()
        oldest, newest = oldest or 1, newest or 0
        boundary = {"journal_id": identity, "oldest_cursor": f"{identity}:{oldest - 1}",
                    "latest_cursor": f"{identity}:{newest}"}
        if cursor is None:
            after = oldest - 1
            boundary["start"] = "oldest_retained; earlier history not requested"
        else:
            journal_id, offset = cursor.split(":", 1)
            if journal_id != identity:
                return 409, dict(boundary, error="wrong_journal")
            after = int(offset)
            if after < oldest - 1:
                return 409, dict(boundary, error="retention_gap", requested_cursor=cursor)
            if after > newest:
                return 409, dict(boundary, error="future_cursor")
        rows = db.execute("SELECT id,body FROM events WHERE id>? ORDER BY id LIMIT ?", (after, limit)).fetchall()
        events = [{"cursor": f"{identity}:{row[0]}", "event": json.loads(row[1])} for row in rows]
        return 200, dict(boundary, events=events, next_cursor=f"{identity}:{rows[-1][0] if rows else after}")
    finally:
        db.close()


def serve(args):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def do_GET(self):
            try:
                url = urlsplit(self.path)
                if url.path != "/events":
                    self.send_error(404)
                    return
                query = parse_qs(url.query, strict_parsing=True)
                cursor = query.get("after", [None])[0]
                limit = int(query.get("limit", ["100"])[0])
                wait = int(query.get("wait_ms", ["0"])[0])
                if not 0 <= wait <= 10000:
                    raise ValueError("wait_ms must be 0..10000")
                deadline = time.monotonic() + wait / 1000
                while True:
                    status, body = replay(args.journal, cursor, limit)
                    if status != 200 or body["events"] or time.monotonic() >= deadline:
                        break
                    time.sleep(0.05)
                data = canonical(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(data)
                self.close_connection = True
            except (ValueError, KeyError) as error:
                self.send_error(400, str(error))
            except sqlite3.Error:
                self.send_error(503, "journal unavailable; no cursor advanced")

        def log_message(self, *_args):
            pass

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        gate = threading.BoundedSemaphore(8)

        def process_request(self, request, client_address):
            if not self.gate.acquire(blocking=False):
                request.close()
                return
            try:
                super().process_request(request, client_address)
            except BaseException:
                self.gate.release()
                raise

        def process_request_thread(self, request, client_address):
            try:
                super().process_request_thread(request, client_address)
            finally:
                self.gate.release()

    class UnixServer(Server):
        address_family = socket.AF_UNIX

        def server_bind(self):
            socketserver.TCPServer.server_bind(self)
            self.server_name, self.server_port = "localhost", 0

    lock = None
    try:
        if args.unix_socket:
            path = args.unix_socket
            lock = Path(str(path) + ".lock").open("a+b")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if path.exists():
                if not stat.S_ISSOCK(path.lstat().st_mode):
                    raise ValueError("API path exists and is not a socket")
                path.unlink()
            server = UnixServer(str(path), Handler)
            os.chmod(path, 0o600)
        else:
            server = Server((args.host, args.port), Handler)
        with server:
            print(canonical({"listening": server.server_address}), flush=True)
            server.serve_forever()
    finally:
        if lock:
            lock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    writer = commands.add_parser("collect")
    writer.add_argument("--journal", required=True, type=Path)
    writer.add_argument("--reader", required=True, type=Path)
    writer.add_argument("--segment", required=True, type=Path)
    writer.add_argument("--pid", required=True, type=int)
    writer.add_argument("--start", required=True, type=int)
    writer.add_argument("--retain", type=int, default=10000)
    writer.add_argument("--max-pages", type=int, default=32768)
    writer.add_argument("--once", action="store_true")
    writer.add_argument("--wait-segment", type=float, default=0,
                        help="startup wait in seconds for a lazily created source segment")
    reader = commands.add_parser("serve")
    reader.add_argument("--journal", required=True, type=Path)
    reader.add_argument("--host", default="127.0.0.1", choices=("127.0.0.1",))
    reader.add_argument("--port", default=18096, type=int)
    reader.add_argument("--unix-socket", type=Path)
    args = parser.parse_args()
    if args.command == "collect" and not 0 <= args.wait_segment <= 120:
        parser.error("--wait-segment must be 0..120")
    try:
        (collect if args.command == "collect" else serve)(args)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
