#!/usr/bin/env python3
"""Own one isolated live collector until its controller closes stdin."""
import argparse
import json
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--reader", required=True, type=Path)
    parser.add_argument("--pid", required=True)
    parser.add_argument("--start", required=True)
    args = parser.parse_args()
    args.directory.mkdir()
    journal = args.directory / "journal.sqlite"
    segment_exists = Path("/run/ls-stream/ls_tp_ring").exists()
    with (args.directory / "collector.log").open("xb") as log:
        child = subprocess.Popen([
            sys.executable, str(Path(__file__).with_name("stream_collector.py")), "collect",
            "--journal", str(journal), "--reader", str(args.reader),
            "--segment", "/run/ls-stream/ls_tp_ring", "--pid", args.pid,
            "--start", args.start,
            "--wait-segment", "120",
        ], stdout=log, stderr=log)
        try:
            for _ in range(100):
                assert child.poll() is None, "collector exited before ready"
                if journal.exists():
                    try:
                        with sqlite3.connect(journal.as_uri() + "?mode=ro", uri=True) as db:
                            if db.execute("SELECT count(*) FROM state WHERE key='journal_id'").fetchone()[0]:
                                break
                    except sqlite3.OperationalError:
                        pass
                time.sleep(0.05)
            else:
                raise RuntimeError("collector did not open its journal")
            print(json.dumps({"ready": True, "pid": child.pid,
                              "segment_exists_at_start": segment_exists}), flush=True)
            sys.stdin.readline()
        finally:
            if child.poll() is None:
                child.send_signal(signal.SIGINT)
            try:
                status = child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
                raise
            print(json.dumps({"stopped": True, "returncode": status}), flush=True)
            assert status == 0


if __name__ == "__main__":
    main()
