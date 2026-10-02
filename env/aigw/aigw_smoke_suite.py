"""Smoke test the unmodified MR !21165 AI gateway in an isolated TMM.

One virtual server carries an ai_gateway profile whose library_config names a
single plain-HTTP OpenAI-format provider: a mock in this container. RBAC,
budget, rate limit, routing and translation are off, so no Redis or router is
used. A second virtual server carries an ai_gateway profile with an empty
library_config, which the library must refuse.

Checks: the library writes the provider key and forwards to the mock; the
model listing is answered by TMM; an unknown model is refused; an empty
library_config yields the host's 503 without dialing the mock.
"""

import asyncio
import hashlib
import json
import os
from pathlib import Path
import secrets
import time
import uuid

from google.protobuf.json_format import MessageToDict
import tao
import tao.test_types
import pru_ssa_config_builder as builder
import pru_ssa_config_server
import profile_ai_gateway_pb2

VIP = os.environ.get("AIGW_VIP", "10.203.82.50")
BACKEND = os.environ.get("AIGW_BACKEND", "10.203.82.11")
GATEWAY, REFUSED, MOCK = 18101, 18102, 18110
MODEL = "smoke-model"
REPLY = {
    "id": "chatcmpl-smoke",
    "object": "chat.completion",
    "model": MODEL,
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "pong"},
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4},
}


def library_config(pool):
    """One plain-HTTP OpenAI provider; every capability off."""
    return {
        "kind": "aigw.profile",
        "version": 1,
        "requires": [],
        "source": {"profile": "eob/aigw-smoke", "generation": 1},
        "features": {
            name: False
            for name in (
                "rbac",
                "rate_limit",
                "budget",
                "model_routing",
                "prompt_cache",
                "param_governance",
                "translation",
                "dlp",
                "guardrail",
            )
        }
        | {"observability": os.environ.get("AIGW_OBSERVE") == "1"},
        "providers": [
            {
                "name": "mock-openai",
                "usable": True,
                "pool": pool,
                "serverssl": "",
                "format": "openai",
                "dialect": "openai",
                "hosting": "compatible",
                "host": "mock-provider.local",
                "path_template": "/v1/{op}",
                "auth": {"kind": "bearer", "key_slot": 0},
                "models": [MODEL],
                "model_map": [],
                "weight": 1,
                "priority": 1,
            }
        ],
    }


def redact(rows, key):
    """Configuration evidence without the provider key."""
    recorded = []
    for row in rows:
        value = MessageToDict(row)
        if "providerSecrets" in value:
            value["providerSecrets"] = [
                "<omitted sha256=%s>" % hashlib.sha256(s.encode()).hexdigest()
                for s in value["providerSecrets"]
            ]
        recorded.append({"type": row.DESCRIPTOR.full_name, "value": value})
    assert key not in json.dumps(recorded)
    return recorded


async def configure(log, key):
    pru_ssa_config_server.tmm_count = 1
    server = await asyncio.wait_for(pru_ssa_config_server.get_conf_svr(), 120)
    client = server.tmm_clients[0]
    heartbeat = client.nats_client.watch_subject(client.HEART_BEAT_SUBJECT)
    rows = []
    for port, label in ((GATEWAY, "gateway"), (REFUSED, "refused")):
        vs = builder.create_vs_msgs(f"aigw-smoke-{label}", (VIP, port))
        vs += builder.add_pool_member(vs, (BACKEND, MOCK))
        (pool,) = [row for row in vs if row.DESCRIPTOR.name == "pool"]
        for profile in (
            builder.create_default_tcp_profile(),
            builder.create_default_http_profile(),
            builder.create_default_httprouter_profile(),
            builder.create_default_json_profile(),
            builder.create_default_sse_profile(),
        ):
            vs += builder.add_profile(vs, profile)
        gateway = profile_ai_gateway_pb2.profile_ai_gateway()
        gateway.id = gateway.name = str(uuid.uuid4())
        if label == "gateway":
            gateway.library_config = json.dumps(library_config(pool.id))
            gateway.provider_secrets.append(key)
        vs += builder.add_profile(vs, gateway)
        rows += vs
    recorded = redact(rows, key)
    log.info("Configuring the isolated AI gateway virtual servers")
    await asyncio.wait_for(server.send_create_msgs(rows), 60)
    acks = []
    while True:
        message = await asyncio.wait_for(heartbeat.get(), 10)
        ack = await client.unpack_dpc_msg(message.body)
        acks.append(
            {
                "generation": ack.generation,
                "sequence": ack.seq_start,
                "status": ack.status,
                "description": ack.description,
            }
        )
        assert ack.status == 0, str(ack)
        if (
            ack.generation == server.generation
            and ack.seq_start >= server.current_sequence
        ):
            break
    return recorded, acks


class Mock:
    """An OpenAI-shaped provider that records what reached it."""

    def __init__(self, key):
        self.key = key
        self.requests = []

    async def serve(self, reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            lines = head.decode("latin-1").split("\r\n")
            headers = {}
            for line in lines[1:]:
                if ": " in line:
                    name, value = line.split(": ", 1)
                    headers.setdefault(name.lower(), []).append(value)
            length = int(headers.get("content-length", ["0"])[0])
            body = await asyncio.wait_for(reader.readexactly(length), 10)
            auth = headers.get("authorization", [])
            self.requests.append(
                {
                    "request_line": lines[0],
                    "host": headers.get("host"),
                    "authorization_count": len(auth),
                    "authorization_is_provider_key": auth == ["Bearer " + self.key],
                    "client_credential_reached_mock": any(
                        "client-token" in v for v in auth
                    ),
                    "header_names": sorted(headers),
                    "body_sha256": hashlib.sha256(body).hexdigest(),
                }
            )
            reply = json.dumps(REPLY).encode()
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Connection: close\r\nContent-Length: "
                + str(len(reply)).encode()
                + b"\r\n\r\n"
                + reply
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()


async def http(port, method, path, body=None):
    """One request on its own connection; returns status, headers, body."""
    data = b"" if body is None else json.dumps(body).encode()
    reader, writer = await asyncio.wait_for(asyncio.open_connection(VIP, port), 10)
    try:
        writer.write(
            (
                f"{method} {path} HTTP/1.1\r\nHost: gateway.local\r\n"
                "Authorization: Bearer client-token\r\n"
                "Content-Type: application/json\r\nConnection: close\r\n"
                f"Content-Length: {len(data)}\r\n\r\n"
            ).encode()
            + data
        )
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), 15)
    finally:
        writer.close()
        await writer.wait_closed()
    head, _, payload = response.partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1]) if head else 0
    return status, head.decode("latin-1"), payload


async def smoke_test(log, _config):
    output = Path(os.environ["AIGW_RESULT"])
    key = "sk-smoke-" + secrets.token_hex(16)
    mock = Mock(key)
    result = {"passed": False, "cases": [], "started_ns": time.time_ns()}
    with output.open("x", encoding="utf-8") as receipt:
        try:
            result["configuration"], result["acknowledgements"] = await configure(
                log, key
            )
            async with await asyncio.start_server(mock.serve, BACKEND, MOCK):
                chat = {
                    "model": MODEL,
                    "messages": [{"role": "user", "content": "ping"}],
                }
                cases = (
                    ("chat", GATEWAY, "POST", "/v1/chat/completions", chat),
                    ("models", GATEWAY, "GET", "/v1/models", None),
                    (
                        "unknown-model",
                        GATEWAY,
                        "POST",
                        "/v1/chat/completions",
                        dict(chat, model="no-such-model"),
                    ),
                    ("empty-config", REFUSED, "POST", "/v1/chat/completions", chat),
                )
                for name, port, method, path, body in cases:
                    before = len(mock.requests)
                    status, head, payload = await http(port, method, path, body)
                    result["cases"].append(
                        {
                            "case": name,
                            "status": status,
                            "head": head,
                            "body": payload.decode("utf-8", "replace")[:2000],
                            "mock_requests": mock.requests[before:],
                        }
                    )
            by = {c["case"]: c for c in result["cases"]}
            chat_case = by["chat"]
            assert chat_case["status"] == 200, chat_case
            assert json.loads(chat_case["body"])["choices"][0]["message"][
                "content"
            ] == ("pong"), chat_case
            (seen,) = chat_case["mock_requests"]
            assert seen["authorization_count"] == 1, seen
            assert seen["authorization_is_provider_key"], seen
            assert not seen["client_credential_reached_mock"], seen
            assert seen["request_line"].startswith("POST /v1/chat/completions"), seen
            models = by["models"]
            assert models["status"] == 200 and not models["mock_requests"], models
            assert MODEL in models["body"], models
            unknown = by["unknown-model"]
            assert unknown["status"] == 404, unknown
            assert (
                "model_not_found" in unknown["body"] and not unknown["mock_requests"]
            ), unknown
            refused = by["empty-config"]
            assert refused["status"] == 503 and not refused["mock_requests"], refused
            result["passed"] = True
            return tao.Result.PASS
        except Exception as error:
            result["error"] = repr(error)
            raise
        finally:
            result["finished_ns"] = time.time_ns()
            text = json.dumps(result, indent=2, sort_keys=True)
            assert key not in text
            receipt.write(text + "\n")


def publish_tests():
    return [tao.test_types.DockerBaseTest2("aigw smoke", smoke_test)]
