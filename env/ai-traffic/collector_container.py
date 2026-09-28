#!/usr/bin/env python3
"""Run the collector writer and Unix replay service in their own container."""
import argparse
import hashlib
import json
from pathlib import Path
import signal
import subprocess
import sys
import time


def source_check(path):
    expected = json.loads(path.read_text())
    process = Path("/proc") / str(int(expected["pid"]))
    start = process.joinpath("stat").read_text().rsplit(")", 1)[1].split()[19]
    with process.joinpath("exe").open("rb") as executable:
        executable_hash = hashlib.file_digest(executable, "sha256").hexdigest()
    actual = {
        "pid": str(int(expected["pid"])), "start": start,
        "boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "pid_namespace": str(Path("/proc/self/ns/pid").stat().st_ino),
        "sha256": executable_hash,
    }
    if actual != expected:
        raise ValueError("source binding mismatch")
    return actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("/source/source.json"))
    parser.add_argument("--check-source", action="store_true")
    args = parser.parse_args()
    source = source_check(args.source)
    print(json.dumps({"source_checked": source}), flush=True)
    if args.check_source:
        return
    children = []
    stopping = False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    script = str(Path(__file__).with_name("stream_collector.py"))
    try:
        children.append(subprocess.Popen([
            sys.executable, script, "collect", "--reader", "/app/ls_stream",
            "--segment", "/run/ls-stream/ls_tp_ring", "--pid", source["pid"],
            "--start", source["start"], "--journal", "/journal/events.sqlite",
            "--wait-segment", "120", "--retain", "10000", "--max-pages", "32768",
        ]))
        children.append(subprocess.Popen([
            sys.executable, script, "serve", "--journal", "/journal/events.sqlite",
            "--unix-socket", "/api/events.sock",
        ]))
        while not stopping:
            if any(child.poll() is not None for child in children):
                raise RuntimeError("collector component exited; stopping API and writer")
            time.sleep(0.1)
    finally:
        for child in children:
            if child.poll() is None:
                child.send_signal(signal.SIGINT)
        for child in children:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


if __name__ == "__main__":
    main()
