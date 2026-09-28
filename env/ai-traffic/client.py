#!/usr/bin/env python3
"""Generate correlated AI-shaped flows and check the independent origin ledger."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
import threading
import time
from urllib.parse import urlsplit
import uuid

PRINT_LOCK = threading.Lock()


def emit(row):
    with PRINT_LOCK:
        print(json.dumps(row, sort_keys=True), flush=True)


class Client:
    def __init__(self, base, run, worker):
        self.base, self.run, self.worker = urlsplit(base), run, worker
        self.seq = 0
        self.records = []

    def request(self, path, data=None, session=None, stream=False, status=200, operation=None):
        self.seq += 1
        rid = f"{self.run}-{self.worker}-{self.seq}"
        operation = operation or rid
        raw = None if data is None else json.dumps(data, separators=(",", ":")).encode()
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "X-Run-Id": self.run, "X-Request-Id": rid, "X-Operation-Id": operation}
        if session:
            headers["Mcp-Session-Id"] = session
            headers["MCP-Protocol-Version"] = "2025-03-26"
        conn = http.client.HTTPConnection(self.base.hostname, self.base.port or 80, timeout=10)
        started, wall = time.monotonic_ns(), time.time_ns()
        chunks, arrivals = [], []
        try:
            conn.request("GET" if data is None else "POST", path, body=raw, headers=headers)
            response = conn.getresponse()
            assert response.status == status, (rid, response.status, response.read())
            assert response.getheader("X-Request-Id") == rid
            if stream:
                assert response.getheader("Content-Type").startswith("text/event-stream")
                body = bytearray()
                while True:
                    line = response.readline()
                    if not line:
                        break
                    body.extend(line)
                    if line.startswith(b"data: "):
                        text = line[6:].strip()
                        chunks.append(text.decode() if text == b"[DONE]" else json.loads(text))
                        arrivals.append(time.monotonic_ns() - started)
                assert len(arrivals) >= 3
                # Catch whole-response buffering for this deliberately paced fixture.
                assert arrivals[-1] - arrivals[0] >= 150_000_000, ("SSE arrived buffered", arrivals)
                value = chunks
                body = bytes(body)
            else:
                body = response.read()
                value = json.loads(body) if body else None
            row = dict(witness="client", event="response_received", run_id=self.run,
                       request_id=rid, operation_id=operation, path=path, time_ns=wall,
                       elapsed_ns=time.monotonic_ns() - started, status=response.status,
                       request_bytes=len(raw or b""), request_sha256=hashlib.sha256(raw or b"").hexdigest(),
                       response_bytes=len(body), response_sha256=hashlib.sha256(body).hexdigest(),
                       stream_events=len(chunks), event_arrival_ns=arrivals)
            emit(row)
            if data is not None:
                self.records.append(row)
            return value, response.getheader("Mcp-Session-Id")
        finally:
            conn.close()

    def rpc(self, path, method, params=None, **kw):
        data = {"jsonrpc": "2.0", "id": self.seq + 1, "method": method, "params": params or {}}
        result, session = self.request(path, data, **kw)
        if not kw.get("stream"):
            assert result["id"] == data["id"] and result["jsonrpc"] == "2.0"
        else:
            assert all(e["id"] == data["id"] for e in result)
        return result, session

    def suite(self):
        init, sid = self.rpc("/mcp", "initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                                                  "clientInfo": {"name": "traffic-jig", "version": "1"}})
        assert sid and init["result"]["serverInfo"]["name"] == "traffic-jig"
        self.request("/mcp", {"jsonrpc": "2.0", "method": "notifications/initialized"}, session=sid, status=202)
        tools, _ = self.rpc("/mcp", "tools/list", session=sid)
        assert tools["result"]["tools"][0]["name"] == "echo"
        text = f"synthetic input worker {self.worker}"
        tool, _ = self.rpc("/mcp", "tools/call", {"name": "echo", "arguments": {"text": text}}, session=sid)
        assert tool["result"]["content"][0]["text"] == text and not tool["result"]["isError"]
        resource, _ = self.rpc("/mcp", "resources/read", {"uri": "fixture://context"}, session=sid)
        assert resource["result"]["contents"][0]["text"] == "synthetic context"
        tool, _ = self.rpc("/mcp", "tools/call", {"name": "missing"}, session=sid)
        assert tool["result"]["isError"]
        error, _ = self.rpc("/mcp", "unknown/method", session=sid)
        assert error["error"]["code"] == -32601
        error, _ = self.rpc("/mcp", "tools/list", session="invalid", status=404)
        assert error["error"]["code"] == -32001

        message = {"message": {"messageId": uuid.uuid4().hex, "role": "user", "parts": [{"text": text}]}}
        result, _ = self.rpc("/a2a", "SendMessage", message)
        task = result["result"]["task"]
        assert task["status"]["state"] == "working"
        result, _ = self.rpc("/a2a", "GetTask", {"id": task["id"]})
        assert result["result"]["contextId"] == task["contextId"]
        result, _ = self.rpc("/a2a", "CancelTask", {"id": task["id"]})
        assert result["result"]["status"]["state"] == "canceled"
        result, _ = self.rpc("/a2a", "GetTask", {"id": task["id"]})
        assert result["result"]["status"]["state"] == "canceled"
        events, _ = self.rpc("/a2a", "SendStreamingMessage", message, stream=True)
        assert len(events) == 3 and events[-1]["result"]["statusUpdate"]["final"]
        assert events[1]["result"]["artifactUpdate"]["artifact"]["parts"][0]["text"] == "synthetic answer"
        assert events[0]["result"]["task"]["id"] == events[-1]["result"]["statusUpdate"]["taskId"]

        chat = {"model": "fixture-model", "messages": [{"role": "user", "content": text}]}
        result, _ = self.request("/v1/chat/completions", chat)
        assert result["choices"][0]["message"]["content"] == "synthetic answer"
        events, _ = self.request("/v1/chat/completions", {**chat, "stream": True}, stream=True)
        assert len(events) == 4 and events[-1] == "[DONE]"
        assert "".join(e["choices"][0]["delta"].get("content", "") for e in events[:-1]) == "synthetic answer"
        operation = f"{self.run}-{self.worker}-retry"
        result, _ = self.request("/v1/chat/completions", {**chat, "fixture_fail_once": True}, status=503, operation=operation)
        assert result["error"]["type"] == "fixture_overload"
        result, _ = self.request("/v1/chat/completions", {**chat, "fixture_fail_once": True}, operation=operation)
        assert result["choices"][0]["finish_reason"] == "stop"
        assert len(self.records) == 17
        return self.records


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-url", default="http://11.11.11.99:18090")
    ap.add_argument("--workers", type=int, choices=range(1, 9), default=3)
    ap.add_argument("--rounds", type=int, choices=range(1, 21), default=1)
    ap.add_argument("--run-id", default="ai-" + uuid.uuid4().hex[:12])
    args = ap.parse_args()
    assert urlsplit(args.base_url).scheme == "http", "fixture supports cleartext HTTP/1 only"
    records = []
    for turn in range(args.rounds):
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            clients = [Client(args.base_url, args.run_id, f"{turn}-{i}") for i in range(args.workers)]
            for rows in pool.map(lambda c: c.suite(), clients):
                records.extend(rows)
    checker = Client(args.base_url, args.run_id, "ledger")
    # Response bytes can arrive just before the backend logs completion.
    for _ in range(20):
        ledger, _ = checker.request("/_fixture/events?run=" + args.run_id)
        completed = [r for r in ledger["events"] if r["event"] == "response_complete"]
        if len(completed) >= len(records):
            break
        time.sleep(0.1)
    starts = [r for r in ledger["events"] if r["event"] == "request_received"]
    assert len(starts) == len(completed) == len(records), (len(starts), len(completed), len(records))
    received = {r["request_id"]: r for r in starts}
    finished = {r["request_id"]: r for r in completed}
    assert len(received) == len(finished) == len(records), "duplicate request IDs"
    for row in records:
        start, end = received[row["request_id"]], finished[row["request_id"]]
        for key in ("operation_id", "path", "request_bytes", "request_sha256"):
            assert row[key] == start[key], (row["request_id"], key)
        for key in ("status", "response_bytes", "response_sha256"):
            assert row[key] == end[key], (row["request_id"], key)
    for row in ledger["events"]:
        emit(row)
    emit(dict(witness="fixture-checker", event="PASS", run_id=args.run_id,
              requests=len(records), workers=args.workers, rounds=args.rounds,
              streams=sum(bool(r["stream_events"]) for r in records),
              backend_peer_ips=sorted({r["peer_ip"] for r in starts}),
              checks="17 exchanges/worker; payload hashes, RPC IDs, session/task state, errors/retry, paced SSE"))


if __name__ == "__main__":
    main()
