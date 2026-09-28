#!/usr/bin/env python3
"""Exercise the jig itself over loopback before using the proxy. Not a TMM test."""
from contextlib import redirect_stdout
import hashlib
import io
from pathlib import Path
import subprocess
import sys
import threading

import backend


def main():
    here = Path(__file__).resolve().parent
    for name in ("backend.py", "client.py", "check.py"):
        print("SHA256", hashlib.sha256((here / name).read_bytes()).hexdigest(), name)
    server = backend.ThreadingHTTPServer(("127.0.0.1", 0), backend.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    logs = io.StringIO()
    try:
        with redirect_stdout(logs):
            thread.start()
            result = subprocess.run([sys.executable, str(here / "client.py"), "--base-url",
                f"http://127.0.0.1:{server.server_port}", "--workers", "3"], text=True, capture_output=True, timeout=30)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    if result.returncode:
        print(logs.getvalue(), result.stdout, result.stderr)
        result.check_returncode()
    print(result.stdout.splitlines()[-1])
    print("PASS loopback fixture only; no TMM/proxy evidence")


if __name__ == "__main__":
    main()
