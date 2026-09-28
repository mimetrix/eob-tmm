#!/usr/bin/env python3
"""Synthetic MCP/A2A/inference origin. A traffic jig, not a conformance server."""
import argparse
from collections import deque
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time
from urllib.parse import parse_qs, urlsplit
import uuid

LOCK = threading.RLock()
EVENTS = deque(maxlen=20000)
SESSIONS = {}
TASKS = {}
ATTEMPTS = {}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def event(self, name, **fields):
        row = dict(witness="backend", event=name, time_ns=time.time_ns(),
                   monotonic_ns=time.monotonic_ns(), run_id=self.headers.get("X-Run-Id", ""),
                   request_id=self.headers.get("X-Request-Id", ""),
                   operation_id=self.headers.get("X-Operation-Id", ""), path=self.path,
                   peer_ip=self.client_address[0], **fields)
        with LOCK:
            EVENTS.append(row)
            print(json.dumps(row, sort_keys=True), flush=True)

    def reply(self, status, value, headers=None):
        body = b"" if value is None else json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Request-Id", self.headers.get("X-Request-Id", ""))
        self.send_header("Connection", "close")
        for key, val in (headers or {}).items():
            self.send_header(key, val)
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        self.close_connection = True
        if self.command == "POST":
            self.event("response_complete", status=status, response_bytes=len(body),
                       response_sha256=hashlib.sha256(body).hexdigest())

    def rpc(self, data, result=None, error=None, headers=None, status=200):
        value = {"jsonrpc": "2.0", "id": data.get("id")}
        value["error" if error else "result"] = error if error else result
        self.reply(status, value, headers)

    def stream(self, values):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("X-Request-Id", self.headers.get("X-Request-Id", ""))
        self.end_headers()
        total, digest = 0, hashlib.sha256()
        for index, value in enumerate(values):
            if index:
                time.sleep(0.20)
            text = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
            body = ("data: " + text + "\n\n").encode()
            self.wfile.write(("%x\r\n" % len(body)).encode() + body + b"\r\n")
            self.wfile.flush()
            total += len(body)
            digest.update(body)
            self.event("stream_event_sent", index=index, bytes=len(body))
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()
        self.event("response_complete", status=200, response_bytes=total,
                   response_sha256=digest.hexdigest())

    def do_GET(self):
        url = urlsplit(self.path)
        if url.path == "/health":
            self.reply(200, {"fixture": "ai-traffic", "ok": True})
        elif url.path == "/_fixture/events":
            run = parse_qs(url.query).get("run", [""])[0]
            with LOCK:
                rows = [e for e in EVENTS if e["run_id"] == run]
            self.reply(200, {"events": rows})
        else:
            self.reply(404, {"error": "unknown fixture path"})

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "-1"))
            if not 0 <= length <= 65536:
                self.reply(413, {"error": "fixture requires Content-Length <= 65536"})
                return
            raw = self.rfile.read(length)
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("expected JSON object")
            self.event("request_received", method=data.get("method", "chat.completions"),
                       request_bytes=len(raw), request_sha256=hashlib.sha256(raw).hexdigest())
            if self.path == "/mcp":
                self.mcp(data)
            elif self.path == "/a2a":
                self.a2a(data)
            elif self.path == "/v1/chat/completions":
                self.inference(data)
            else:
                self.reply(404, {"error": "unknown fixture path"})
        except (BrokenPipeError, ConnectionResetError):
            self.event("peer_disconnected")
            self.close_connection = True
        except (ValueError, KeyError, TypeError) as exc:
            self.reply(400, {"error": str(exc)})

    def mcp(self, data):
        method = data.get("method")
        session = self.headers.get("Mcp-Session-Id")
        run = self.headers.get("X-Run-Id", "")
        if method == "initialize":
            session = "fixture-" + uuid.uuid4().hex
            with LOCK:
                SESSIONS[session] = run
            self.rpc(data, {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}, "resources": {}},
                            "serverInfo": {"name": "traffic-jig", "version": "1"}},
                     headers={"Mcp-Session-Id": session})
            return
        with LOCK:
            valid = session in SESSIONS and SESSIONS[session] == run
        if not valid:
            self.rpc(data, error={"code": -32001, "message": "invalid session"}, status=404)
        elif method == "notifications/initialized":
            self.reply(202, None)
        elif method == "tools/list":
            self.rpc(data, {"tools": [{"name": "echo", "description": "Synthetic echo",
                                       "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}}]})
        elif method == "tools/call":
            time.sleep(0.05)
            params = data["params"]
            failed = params["name"] != "echo"
            text = "unknown tool" if failed else params.get("arguments", {}).get("text", "")
            self.rpc(data, {"content": [{"type": "text", "text": text}], "isError": failed})
        elif method == "resources/read":
            self.rpc(data, {"contents": [{"uri": data["params"]["uri"], "mimeType": "text/plain",
                                         "text": "synthetic context"}]})
        else:
            self.rpc(data, error={"code": -32601, "message": "method not found"})

    def a2a(self, data):
        method, params = data.get("method"), data.get("params", {})
        run = self.headers.get("X-Run-Id", "")
        if method in ("SendMessage", "SendStreamingMessage"):
            task_id, context = "task-" + uuid.uuid4().hex, "ctx-" + uuid.uuid4().hex
            task = {"id": task_id, "contextId": context, "status": {"state": "working"}}
            with LOCK:
                TASKS[run, task_id] = task
            if method == "SendMessage":
                self.rpc(data, {"task": task})
            else:
                values = [{"jsonrpc": "2.0", "id": data["id"], "result": {"task": task}},
                          {"jsonrpc": "2.0", "id": data["id"], "result": {"artifactUpdate": {
                              "taskId": task_id, "contextId": context, "artifact": {
                                  "artifactId": "output", "parts": [{"text": "synthetic answer"}]}}}},
                          {"jsonrpc": "2.0", "id": data["id"], "result": {"statusUpdate": {
                              "taskId": task_id, "contextId": context,
                              "status": {"state": "completed"}, "final": True}}}]
                self.stream(values)
                with LOCK:
                    TASKS[run, task_id] = {**task, "status": {"state": "completed"}}
        elif method in ("GetTask", "CancelTask"):
            with LOCK:
                task = TASKS.get((run, params.get("id")))
                if task and method == "CancelTask":
                    task = {**task, "status": {"state": "canceled"}}
                    TASKS[run, params["id"]] = task
            if task:
                self.rpc(data, task)
            else:
                self.rpc(data, error={"code": -32001, "message": "task not found"})
        else:
            self.rpc(data, error={"code": -32601, "message": "method not found"})

    def inference(self, data):
        key = (self.headers.get("X-Run-Id", ""), self.headers.get("X-Operation-Id", ""))
        with LOCK:
            attempt = ATTEMPTS.get(key, 0) + 1
            ATTEMPTS[key] = attempt
        if data.get("fixture_fail_once") and attempt == 1:
            self.reply(503, {"error": {"type": "fixture_overload", "message": "retry this synthetic attempt"}},
                       {"Retry-After": "0"})
            return
        common = {"id": "chatcmpl-fixture", "model": "fixture-model"}
        if data.get("stream"):
            values = [{**common, "object": "chat.completion.chunk", "choices": [{"index": 0,
                       "delta": {"content": text}, "finish_reason": None}]} for text in ("synthetic ", "answer")]
            values.append({**common, "object": "chat.completion.chunk", "choices": [{"index": 0,
                           "delta": {}, "finish_reason": "stop"}]})
            self.stream(values + ["[DONE]"])
        else:
            time.sleep(0.05)
            self.reply(200, {**common, "object": "chat.completion", "choices": [{"index": 0,
                            "message": {"role": "assistant", "content": "synthetic answer"},
                            "finish_reason": "stop"}],
                            "usage": {"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6}})


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=18090)
    args = ap.parse_args()
    ThreadingHTTPServer(("0.0.0.0", args.port), Handler).serve_forever()
