"""The AI gateway with its session store: virtual keys, model scope and a
rate limit, observed live by two eBPF probes.

Redis runs in the fixture network. The test seeds it with the records the
gateway reads (`vk:resolved:<sha256(key)>`, the owner rate-limit index and a
rate-limit definition), using fixture identities only.

Probes (both monitor-only, signed for this build):
- aigw_record at aigw_host_obs_publish: every per-request record;
(Admission timing and outcome per stage are covered by aigw_timing_suite.py.)

Cases, each with an independently stated expected outcome:
  valid key, allowed model            200, provider called once
  no key                              401
  unknown key                         401
  revoked key (active=0)              401
  key scoped to another model         403
  rate limit: 2 requests per hour     third request 429
"""

import asyncio
import hashlib
import json
import os
from pathlib import Path
import secrets
import time
import uuid

import tao
import tao.test_types
import pru_ssa_config_builder as builder
import pru_ssa_config_server
import profile_ai_gateway_pb2

import aigw_smoke_suite as smoke
from aigw_ebpf_suite import cli, drain, records

REDIS = os.environ.get("AIGW_REDIS", "10.203.82.20")
PREFIX = "eob:"
HOOKS = {
    "record": ("4", "aigw_host_obs_publish", "aigw_record"),
}


async def redis(*args):
    """Minimal RESP client; one command per connection; returns the reply."""
    reader, writer = await asyncio.wait_for(asyncio.open_connection(REDIS, 6379), 10)
    try:
        payload = b"*%d\r\n" % len(args)
        for arg in args:
            data = arg if isinstance(arg, bytes) else str(arg).encode()
            payload += b"$%d\r\n%s\r\n" % (len(data), data)
        writer.write(payload)
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), 10)
        if line[:1] == b"$" and int(line[1:]) >= 0:
            data = await reader.readexactly(int(line[1:]) + 2)
            return data[:-2]
        return line.strip()
    finally:
        writer.close()
        await writer.wait_closed()


def vk_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


async def seed(keys):
    """Fixture governance records, with the gateway's own key names."""
    assert await redis("PING") == b"+PONG"
    await redis("FLUSHALL")
    for name, (token, fields) in keys.items():
        await redis(
            "HSET",
            PREFIX + "vk:resolved:" + vk_hash(token),
            *sum(([k, v] for k, v in fields.items()), []),
        )
    # The live-scope script reads principal:, team: and org: (unprefixed) and
    # treats a MISSING record as deny-all (a deleted team or org must not read
    # as unrestricted). Seed each owner with an empty, i.e. unrestricted, scope.
    for name, (_token, fields) in keys.items():
        await redis(
            "HSET",
            "principal:" + fields["principal_id"],
            "name",
            name,
            "team_ref",
            fields["team_id"],
            "model_scope",
            "",
        )
    await redis(
        "HSET", "team:team-a", "name", "team-a", "org_ref", "org-a", "model_scope", ""
    )
    await redis("HSET", "org:org-a", "name", "org-a", "model_scope", "")
    await redis("SADD", PREFIX + "owner:vk:vk-limited:ratelimits", "rl-two")
    await redis(
        "HSET",
        PREFIX + "ratelimit:rl-two",
        "max_requests",
        "2",
        "request_window",
        "hourly",
    )


def library_config(pool):
    doc = smoke.library_config(pool)
    doc["features"].update(rbac=True, rate_limit=True, observability=True)
    doc["store"] = {"key_prefix": PREFIX}
    return doc


async def configure(log, provider_key):
    pru_ssa_config_server.tmm_count = 1
    server = await asyncio.wait_for(pru_ssa_config_server.get_conf_svr(), 120)
    client = server.tmm_clients[0]
    heartbeat = client.nats_client.watch_subject(client.HEART_BEAT_SUBJECT)
    rows = builder.create_vs_msgs("aigw-rbac", (smoke.VIP, smoke.GATEWAY))
    rows += builder.add_pool_member(rows, (smoke.BACKEND, smoke.MOCK))
    (pool,) = [row for row in rows if row.DESCRIPTOR.name == "pool"]
    for profile in (
        builder.create_default_tcp_profile(),
        builder.create_default_http_profile(),
        builder.create_default_httprouter_profile(),
        builder.create_default_json_profile(),
        builder.create_default_sse_profile(),
    ):
        rows += builder.add_profile(rows, profile)
    gateway = profile_ai_gateway_pb2.profile_ai_gateway()
    gateway.id = gateway.name = str(uuid.uuid4())
    gateway.library_config = json.dumps(library_config(pool.id))
    gateway.provider_secrets.append(provider_key)
    rows += builder.add_profile(rows, gateway)
    recorded = smoke.redact(rows, provider_key)
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


async def request(token, model):
    data = json.dumps(
        {"model": model, "messages": [{"role": "user", "content": "ping"}]}
    ).encode()
    auth = "" if token is None else f"Authorization: Bearer {token}\r\n"
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(smoke.VIP, smoke.GATEWAY), 10
    )
    try:
        writer.write(
            (
                "POST /v1/chat/completions HTTP/1.1\r\nHost: gateway.local\r\n"
                f"{auth}Content-Type: application/json\r\nConnection: close\r\n"
                f"Content-Length: {len(data)}\r\n\r\n"
            ).encode()
            + data
        )
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), 15)
    finally:
        writer.close()
        await writer.wait_closed()
    head, _, body = response.partition(b"\r\n\r\n")
    return int(head.split(b" ", 2)[1]), body.decode("utf-8", "replace")


async def load_probe(result, directory, label, config_path):
    slot, _hook, obj = HOOKS[label]
    text = await cli(
        result,
        "load-signed",
        slot,
        str(directory / f"{obj}.bpf.o"),
        str(directory / f"{obj}.sig"),
        "1",
    )
    assert "signature=verified" in text, text
    identity = json.loads(await cli(result, "config-status", slot))
    doc = dict(identity)
    doc["expected_revision"] = doc.pop("revision")
    doc["revision"] = doc["expected_revision"] + 1
    doc["schema"] = 1
    doc.pop("entries")
    doc["rows"] = []
    config_path.write_text(json.dumps(doc))
    await cli(result, "config-publish", slot, str(config_path))


async def rbac_test(log, _config):
    output = Path(os.environ["AIGW_RESULT"])
    directory = Path(os.environ["AIGW_PROBE_DIR"])
    provider_key = "sk-rbac-" + secrets.token_hex(16)
    tokens = {
        name: "vk-fixture-" + secrets.token_hex(12)
        for name in ("alice", "revoked", "scoped", "limited", "unknown")
    }
    base = {
        "active": "1",
        "team_id": "team-a",
        "org_id": "org-a",
        "model_scope": "",
        "vk_model_scope": "",
    }
    keys = {
        "alice": (tokens["alice"], dict(base, vkid="vk-alice", principal_id="alice")),
        "revoked": (
            tokens["revoked"],
            dict(base, vkid="vk-revoked", principal_id="bob", active="0"),
        ),
        "scoped": (
            tokens["scoped"],
            dict(
                base,
                vkid="vk-scoped",
                principal_id="carol",
                vk_model_scope="other-model",
            ),
        ),
        "limited": (
            tokens["limited"],
            dict(base, vkid="vk-limited", principal_id="dave"),
        ),
    }
    mock = smoke.Mock(provider_key)
    result = {
        "passed": False,
        "commands": [],
        "drains": [],
        "cases": [],
        "started_ns": time.time_ns(),
    }
    loaded, armed = set(), set()
    secrets_in_run = [provider_key] + list(tokens.values())
    with output.open("x", encoding="utf-8") as receipt:
        try:
            await seed(keys)
            result["configuration"], result["acknowledgements"] = await configure(
                log, provider_key
            )
            for label in HOOKS:
                await load_probe(
                    result, directory, label, output.parent / f"{label}-config.json"
                )
                loaded.add(label)
            start = {
                label: await cli(result, "status", HOOKS[label][0]) for label in HOOKS
            }
            for label in HOOKS:
                await cli(result, "arm", HOOKS[label][0])
                armed.add(label)
            plan = [
                ("valid", tokens["alice"], smoke.MODEL, 200, 1),
                ("no-key", None, smoke.MODEL, 401, 0),
                ("unknown-key", tokens["unknown"], smoke.MODEL, 401, 0),
                ("revoked-key", tokens["revoked"], smoke.MODEL, 401, 0),
                ("out-of-scope", tokens["scoped"], smoke.MODEL, 403, 0),
                ("limit-1", tokens["limited"], smoke.MODEL, 200, 1),
                ("limit-2", tokens["limited"], smoke.MODEL, 200, 1),
                ("limit-3", tokens["limited"], smoke.MODEL, 429, 0),
            ]
            async with await asyncio.start_server(
                mock.serve, smoke.BACKEND, smoke.MOCK
            ):
                for name, token, model, want, calls in plan:
                    before = len(mock.requests)
                    status, body = await request(token, model)
                    row = {
                        "case": name,
                        "status": status,
                        "expected": want,
                        "provider_calls": len(mock.requests) - before,
                        "expected_provider_calls": calls,
                        "body_prefix": body[:200],
                    }
                    if mock.requests[before:]:
                        row["provider_saw_only_provider_key"] = all(
                            r["authorization_is_provider_key"]
                            and not any(t in json.dumps(r) for t in tokens.values())
                            for r in mock.requests[before:]
                        )
                    result["cases"].append(row)
                frames = await drain(result)
            end = {
                label: await cli(result, "status", HOOKS[label][0]) for label in HOOKS
            }
            for label in list(armed):
                await cli(result, "disarm", HOOKS[label][1])
                armed.discard(label)
            for label in list(loaded):
                await cli(result, "revoke", HOOKS[label][0])
                loaded.discard(label)
            result["counter"] = (
                await redis(
                    "GET",
                    PREFIX
                    + "counter:rl:req:vk:vk-limited:"
                    + time.strftime("%Y-%m-%dT%H", time.gmtime()),
                )
            ).decode()
            by_slot = {}
            for item in frames:
                by_slot.setdefault(item["slot"], []).append(item)
            result["records"] = records(by_slot.get(int(HOOKS["record"][0]), []))
            result["status_start"], result["status_end"] = start, end
            for row in result["cases"]:
                assert row["status"] == row["expected"], row
                assert row["provider_calls"] == row["expected_provider_calls"], row
                assert row.get("provider_saw_only_provider_key", True), row
            assert result["counter"] == "2", result["counter"]
            result["passed"] = True
            return tao.Result.PASS
        except Exception as error:
            result["error"] = repr(error)
            raise
        finally:
            for label in list(armed):
                try:
                    await cli(result, "disarm", HOOKS[label][1])
                except Exception as error:
                    result.setdefault("cleanup_errors", []).append(repr(error))
            for label in list(loaded):
                try:
                    await cli(result, "revoke", HOOKS[label][0])
                except Exception as error:
                    result.setdefault("cleanup_errors", []).append(repr(error))
            result["finished_ns"] = time.time_ns()
            text = json.dumps(result, indent=2, sort_keys=True)
            for value in secrets_in_run:
                assert value not in text
            receipt.write(text + "\n")


def publish_tests():
    return [tao.test_types.DockerBaseTest2("aigw rbac and limits", rbac_test)]
