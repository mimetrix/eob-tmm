"""Compare observed session headers and selected routes through the collector."""

import asyncio
import json
import os
from pathlib import Path
import uuid

from google.protobuf.json_format import MessageToDict
import tao
import tao.test_types
import pru_ssa_config_builder as builder
import pru_ssa_config_server
import profile_aimcp_pb2

from session_routing_client import page, ReplayUnavailable
from icap_suite import BACKEND, VIP
from metadata_suite import Metadata
from session_routing_decode import decode

PROGRAMS = {
    "session": (7, 1, "aimcp_decrypt_and_parse_sessionid.constprop.0", 18095),
    "route": (8, 2, "hud_aimcp_add_persist.isra.0", 18095),
}


async def configure(log):
    """Record the selected configuration input and wait for positive ACKs."""
    pru_ssa_config_server.tmm_count = 1
    server = await asyncio.wait_for(pru_ssa_config_server.get_conf_svr(), 120)
    client = server.tmm_clients[0]
    heartbeat = client.nats_client.watch_subject(client.HEART_BEAT_SUBJECT)
    rows = builder.create_vs_msgs("session-routing", (VIP, 18095))
    rows += builder.add_pool_member(rows, (BACKEND, 18095))
    (pool,) = [row for row in rows if row.DESCRIPTOR.name == "pool"]
    expected_pool = pool.id
    for profile in (
        builder.create_default_tcp_profile(),
        builder.create_default_http_profile(),
        builder.create_default_httprouter_profile(),
        builder.create_default_json_profile(),
        builder.create_default_sse_profile(),
    ):
        rows += builder.add_profile(rows, profile)
    native = profile_aimcp_pb2.profile_aimcp()
    native.id = native.name = str(uuid.uuid4())
    rows += builder.add_profile(rows, native)
    config = [
        {"type": row.DESCRIPTOR.full_name, "value": MessageToDict(row)} for row in rows
    ]
    log.info("Enabling the isolated session/routing AIMCP fixture")
    await asyncio.wait_for(server.send_create_msgs(rows), 60)
    acknowledgements = []
    while True:
        message = await asyncio.wait_for(heartbeat.get(), 10)
        ack = await client.unpack_dpc_msg(message.body)
        acknowledgements.append(
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
    return config, expected_pool, acknowledgements


class SessionRouting(Metadata):
    """Keep hook observations distinct from fixture request intervals."""

    def __init__(self, output):
        super().__init__(output, PROGRAMS)
        self.continuous_collector = True
        self.cursor = None
        self.initial_cursor = None
        self.result.update(stream_pages=[], comparisons=[], replay_retries=[])

    async def page(self, cursor=None):
        """Read the existing Unix replay API outside the event loop."""
        for attempt in range(5):
            try:
                return await asyncio.to_thread(
                    page, "/collector-api/events.sock", cursor
                )
            except ReplayUnavailable as error:
                self.result["replay_retries"].append(
                    {"cursor": cursor, "attempt": attempt, "error": repr(error)}
                )
                if attempt == 4:
                    raise
                await asyncio.sleep(0.25)
        raise AssertionError("unreachable replay retry exit")

    async def start(self):
        self.result["pre_run_pages"] = []
        for _ in range(10):
            first = await self.page(self.cursor)
            self.result["pre_run_pages"].append(first)
            self.cursor = first["next_cursor"]
            if not first["events"]:
                break
        else:
            raise RuntimeError("pre-run journal exceeds the fixture page limit")
        self.initial_cursor = self.cursor
        self.result["initial_cursor"] = self.initial_cursor
        await super().start()

    async def drain(self, label):
        current = await self.counters()
        targets = {
            name: value["fired"] - self.result["counter_start"][name]["fired"]
            for name, value in current.items()
        }
        transport = []
        for _ in range(100):
            current = await self.page(self.cursor)
            self.result["stream_pages"].append(current)
            self.cursor = current["next_cursor"]
            for row in current["events"]:
                event = row["event"]
                assert event["type"] != "observation_gap", event
                if event["type"] != "record":
                    continue
                raw = event["raw"]
                value = decode(bytes.fromhex(raw["data"]))
                name = "session" if value["kind"] == 1 else "route"
                identity = self.identities[name]
                assert raw["slot"] == PROGRAMS[name][0]
                assert raw["hook_id"] == raw["schema"] == 100
                assert value["instance"] == int(identity["instance"], 16)
                assert value["revision"] == identity["revision"]
                assert value["run"] == self.run_token and not value["flags"]
                assert not value["output_failures"] and value["monotonic_ns"]
                assert value["sequence"] == 1 + sum(
                    previous["kind"] == value["kind"] for previous in self.events
                )
                self.events.append(value)
                transport.append(raw)
            if len(self.events) >= sum(targets.values()):
                break
            await asyncio.sleep(0.05)
        for name, (_, kind, _, _) in PROGRAMS.items():
            assert sum(e["kind"] == kind for e in self.events) == targets[name]
        self.result["batches"].append({"label": label, "transport": transport})
        return transport

    async def compare(self, label, session, fragmented=False, header="Mcp-Session-Id"):
        """Compare only fields emitted during this isolated test interval."""
        start = len(self.events)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(VIP, 18095), 10)
        body = b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
        extra = b"" if session is None else header.encode() + b": " + session + b"\r\n"
        data = (
            (
                f"POST /{label} HTTP/1.1\r\nHost: metadata\r\n"
                "Content-Type: application/json\r\nConnection: close\r\n"
                f"Content-Length: {len(body)}\r\n"
            ).encode()
            + extra
            + b"\r\n"
            + body
        )
        try:
            if fragmented:
                for fragment in (data[:23], data[23:-5], data[-5:]):
                    writer.write(fragment)
                    await writer.drain()
                    await asyncio.sleep(0.05)
            else:
                writer.write(data)
                await writer.drain()
            response = await asyncio.wait_for(reader.read(), 15)
            assert response.startswith(b"HTTP/1.1 200 "), response
            assert b'"observed":true' in response, response
            self.result["clients"].append(
                {"case": label, "response_hex": response.hex()}
            )
        finally:
            writer.close()
            await writer.wait_closed()
        await self.drain(label)
        events = self.events[start:]
        values = [e for e in events if e["kind"] == 1]
        routes = [e for e in events if e["kind"] == 2]
        expected = session if header.lower() == "mcp-session-id" else None
        comparison = {
            "case": label,
            "expected_session_hex": None if expected is None else expected.hex(),
            "events": events,
        }
        self.result["comparisons"].append(comparison)
        assert len(values) == (0 if expected is None else 1), comparison
        if expected is not None:
            value = values[0]
            assert value["value_hex"] == expected[:64].hex(), comparison
            assert value["original_length"] == len(expected), comparison
            assert value["status_name"] == (
                "truncated" if len(expected) > 64 else "complete"
            ), comparison
        assert len(routes) == 1, comparison
        route = routes[0]
        assert (
            route["status_name"] == route["endpoint_status_name"] == "complete"
        ), comparison
        assert (
            route["value_hex"] == self.result["expected_pool"].encode().hex()
        ), comparison
        assert route["address"] == BACKEND and route["port"] == 18095, comparison
        assert route["domain"] == 0, comparison

    async def finish(self):
        await self.drain("settle")
        for name in list(self.armed_labels):
            await self.cli("disarm", PROGRAMS[name][2])
            self.armed_labels.remove(name)
        await self.drain("final")
        self.result["counter_end"] = await self.counters()
        for name in PROGRAMS:
            before = self.result["counter_start"][name]
            after = self.result["counter_end"][name]
            assert after["fired"] > before["fired"]
            for key in ("errors", "safe_returns", "gen"):
                assert before[key] == after[key]
        replay = await self.page(self.initial_cursor)
        rows = [
            row for current in self.result["stream_pages"] for row in current["events"]
        ]
        assert [r for r in rows if r["event"]["type"] == "record"] == [
            r for r in replay["events"] if r["event"]["type"] == "record"
        ]
        self.result["replay_consumer"] = replay


async def session_routing_test(log, _config):
    """Keep exact fields, scope exclusions and independent replay checks."""
    test = SessionRouting(Path(os.environ["ICAP_RESULT"]))
    with test.output.open("x", encoding="utf-8") as output:
        try:
            config, pool, acknowledgements = await configure(log)
            test.result.update(
                configuration=config,
                expected_pool=pool,
                acknowledgements=acknowledgements,
            )
            origin = await asyncio.start_server(test.origin, BACKEND, 18095)
            async with origin:
                await test.start()
                for name, value in (
                    ("missing", None),
                    ("known", b"fixture-session-01"),
                    ("unfamiliar", b"future.session:v7+alpha"),
                    ("limit", b"x" * 64),
                    ("truncated", b"y" * 65),
                ):
                    await test.compare(name, value, fragmented=name == "unfamiliar")
                await test.compare(
                    "mixed-case", b"case-sensitive-VALUE", header="mCp-SeSsIoN-Id"
                )
                await test.compare(
                    "unrelated", b"must-not-export", header="X-Other-Header"
                )
                await test.finish()
            assert len(test.result["origin"]) == len(test.result["clients"]) == 7
            assert not test.result["backend_errors"]
            test.result["passed"] = True
            return tao.Result.PASS
        except Exception as error:
            test.result["error"] = repr(error)
            raise
        finally:
            try:
                await test.cleanup()
            finally:
                json.dump(test.result, output, indent=2)


def publish_tests():
    """Expose the bounded session/routing test to Tao."""
    return [
        tao.test_types.DockerBaseTest2(
            "session routing extraction", session_routing_test
        )
    ]
