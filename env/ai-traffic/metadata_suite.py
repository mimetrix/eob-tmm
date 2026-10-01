"""Exercise native-filter handler metadata in the isolated SSA fixture."""

import asyncio
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import struct
import uuid

import tao
import tao.runner
import tao.test_types
import pru_ssa_config_builder as builder
import pru_ssa_config_server
import profile_a2a_pb2
import profile_aimcp_pb2

from config_suite import Lifecycle
from icap_suite import BACKEND, VIP
from metadata_decode import decode

PROGRAMS = {
    "a2a": (5, 1, "hud_a2a_handler", 18094),
    "aimcp": (6, 2, "hud_aimcp_handler", 18095),
}


async def configure(log):
    """Enable the actual protocol filters and retain positive configuration ACKs."""
    pru_ssa_config_server.tmm_count = 1
    server = await asyncio.wait_for(pru_ssa_config_server.get_conf_svr(), 120)
    client = server.tmm_clients[0]
    heartbeat = client.nats_client.watch_subject(client.HEART_BEAT_SUBJECT)
    messages = []
    for label, (_, _, _, port) in PROGRAMS.items():
        rows = builder.create_vs_msgs("metadata-" + label, (VIP, port))
        rows += builder.add_pool_member(rows, (BACKEND, port))
        for profile in (
            builder.create_default_tcp_profile(),
            builder.create_default_http_profile(),
            builder.create_default_httprouter_profile(),
            builder.create_default_json_profile(),
            builder.create_default_sse_profile(),
        ):
            rows += builder.add_profile(rows, profile)
        native = (
            profile_a2a_pb2.profile_a2a()
            if label == "a2a"
            else profile_aimcp_pb2.profile_aimcp()
        )
        native.id = native.name = str(uuid.uuid4())
        rows += builder.add_profile(rows, native)
        messages += rows
    log.info("Enabling isolated A2A and AIMCP profiles with JSON/SSE")
    await asyncio.wait_for(server.send_create_msgs(messages), 60)
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
    return acknowledgements


class Metadata(Lifecycle):
    """Capture raw events independently of method names or request matching."""

    def __init__(self, output, programs=None):
        super().__init__(output)
        self.programs = PROGRAMS if programs is None else programs
        directory = Path(os.environ["TEMPLATE_PROGRAM_DIR"])
        self.build = json.loads((directory / "metadata-program-build.json").read_text())
        self.run_token = uuid.uuid4().int & ((1 << 64) - 1)
        self.events = []
        self.loaded_slots = set()
        self.armed_labels = set()
        self.identities = {}
        self.result.update(
            events=self.events,
            batches=[],
            clients=[],
            backend_errors=[],
            scope="one-worker native-filter handler invocations",
            run_token=self.run_token,
            event_names=self.build["event_names"],
        )

    async def counters(self):
        """Read only the two slots owned by this fixture."""
        result = {}
        for label, (slot, _, _, _) in self.programs.items():
            text = await self.cli("status", str(slot))
            result[label] = {
                k: int(v) for k, v in (word.split("=") for word in text.split()[1:])
            }
        return result

    async def start(self):
        """Load and configure both monitor programs before attaching either."""
        directory = Path(os.environ["TEMPLATE_PROGRAM_DIR"])
        if (
            not getattr(self, "continuous_collector", False)
            and Path("/run/ls-stream/ls_tp_ring").exists()
        ):
            self.result["initial_drain"] = await self.run(
                "/work/ls_drain", "--segment", "/run/ls-stream/ls_tp_ring", "--once"
            )
        for label, (slot, _, _, _) in self.programs.items():
            program = self.build["programs"][label]
            load = [
                "load",
                str(slot),
                str(directory / program.get("object", "metadata-" + label + ".bpf.o")),
                "1",
            ]
            if program.get("signature"):
                load = [
                    "load-signed",
                    str(slot),
                    str(directory / program["object"]),
                    str(directory / program["signature"]),
                    "1",
                ]
            text = await self.cli(
                *load,
            )
            assert "signature=verified" in text, text
            self.loaded_slots.add(slot)
            identity = json.loads(await self.cli("config-status", str(slot)))
            document = dict(identity)
            document["expected_revision"] = document.pop("revision")
            document["revision"] = document["expected_revision"] + 1
            document["schema"] = 1
            document.pop("entries")
            document["rows"] = [struct.pack("<4Q", self.run_token, 0, 0, 0).hex()]
            path = self.output.parent / (label + "-config.json")
            with path.open("x", encoding="utf-8") as stream:
                json.dump(document, stream, indent=2)
            await self.cli("config-publish", str(slot), str(path))
            self.identities[label] = json.loads(
                await self.cli("config-status", str(slot))
            )
        self.result["instances"] = self.identities
        self.result["counter_start"] = await self.counters()
        for label, (slot, _, _, _) in self.programs.items():
            await self.cli("arm", str(slot))
            self.armed_labels.add(label)

    async def drain(self, label):
        """Keep all invocation records; no protocol or event-code filtering."""
        row = await self.run(
            "/work/ls_drain", "--segment", "/run/ls-stream/ls_tp_ring", "--once"
        )
        transport = [json.loads(line) for line in row["stdout"].splitlines()]
        self.result["batches"].append({"label": label, "transport": transport})
        assert "0 drop(s) seen" in row["stderr"], row
        for item in transport:
            assert item["hook"] == "prog" and item["len"] == 72, item
            event = decode(bytes.fromhex(item["data"]), self.build["event_names"])
            source = {1: "a2a", 2: "aimcp"}[event["kind"]]
            identity = self.identities[source]
            assert item["slot"] == self.programs[source][0]
            assert event["instance"] == int(identity["instance"], 16)
            assert event["revision"] == identity["revision"]
            assert event["run"] == self.run_token and not event["flags"]
            assert not event["output_failures"] and event["monotonic_ns"]
            assert event["sequence"] == 1 + sum(
                e["kind"] == event["kind"] for e in self.events
            )
            self.events.append(event)
        return transport

    async def origin(self, reader, writer):
        """Serve metadata-neutral test content; preserve only fixture facts."""
        try:
            headers = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            lines = headers.decode().split("\r\n")
            fields = dict(line.split(": ", 1) for line in lines[1:] if ": " in line)
            length = next(
                (int(v) for k, v in fields.items() if k.lower() == "content-length"), 0
            )
            body = await asyncio.wait_for(reader.readexactly(length), 10)
            path = lines[0].split()[1]
            self.result["origin"].append(
                {
                    "path": path,
                    "body_sha256": hashlib.sha256(body).hexdigest(),
                    "peer": writer.get_extra_info("peername"),
                }
            )
            if path == "/stream":
                chunks = [
                    b'data: {"jsonrpc":"2.0","result":{"status":"working"}}\n\n',
                    b'data: {"jsonrpc":"2.0","result":{"status":"done"}}\n\n',
                ]
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                    b"Connection: close\r\n\r\n"
                )
                for chunk in chunks:
                    writer.write(chunk)
                    await writer.drain()
                    await asyncio.sleep(0.05)
            else:
                response = b'{"jsonrpc":"2.0","id":1,"result":{"observed":true}}'
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    b"Connection: close\r\nContent-Length: "
                    + str(len(response)).encode()
                    + b"\r\n\r\n"
                    + response
                )
                await writer.drain()
        except Exception as error:
            self.result["backend_errors"].append(repr(error))
        finally:
            writer.close()
            await writer.wait_closed()

    async def request(
        self, label, path, body, mime="application/json", fragmented=False
    ):
        """Send known, unfamiliar and non-JSON inputs without fixture markers."""
        port = PROGRAMS[label][3]
        reader, writer = await asyncio.wait_for(asyncio.open_connection(VIP, port), 10)
        data = (
            f"POST {path} HTTP/1.1\r\nHost: metadata\r\nContent-Type: {mime}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        ).encode() + body
        response = b""
        try:
            if fragmented:
                for fragment in (data[:19], data[19:-3], data[-3:]):
                    writer.write(fragment)
                    await writer.drain()
                    await asyncio.sleep(0.05)
            else:
                writer.write(data)
                await writer.drain()
            response = await asyncio.wait_for(reader.read(), 15)
            assert response.startswith(b"HTTP/1.1 200 "), response
            if path == "/stream":
                assert b'"working"' in response and b'"done"' in response, response
            else:
                assert b'"observed":true' in response, response
        finally:
            self.result["clients"].append(
                {
                    "filter": label,
                    "path": path,
                    "mime": mime,
                    "fragmented": fragmented,
                    "request_body_sha256": hashlib.sha256(body).hexdigest(),
                    "response_hex": response.hex(),
                }
            )
            writer.close()
            await writer.wait_closed()

    async def finish(self):
        """Stop output, reconcile every invocation, and preserve unknown codes."""
        for _ in range(5):
            await self.drain("settle")
            await asyncio.sleep(0.1)
        for label in list(self.armed_labels):
            await self.cli("disarm", self.programs[label][2])
            self.armed_labels.remove(label)
        await self.drain("final")
        self.result["counter_end"] = await self.counters()
        summary = {}
        for label, (_, kind, _, _) in self.programs.items():
            before = self.result["counter_start"][label]
            after = self.result["counter_end"][label]
            events = [e for e in self.events if e["kind"] == kind]
            assert after["fired"] - before["fired"] == len(events) > 0
            assert after["errors"] == before["errors"]
            assert after["safe_returns"] == before["safe_returns"]
            assert after["gen"] == before["gen"]
            counts = Counter(e["event_name"] or str(e["code"]) for e in events)
            assert (
                counts["HUDEVT_REQUEST"] > 0 and counts["HUDCTL_RESPONSE"] > 0
            ), counts
            summary[label] = {"records": len(events), "event_counts": dict(counts)}
        self.result["summary"] = summary

    async def cleanup(self):
        """Attempt each owned disarm and revoke, retaining every failure."""
        errors = []
        for label in list(self.armed_labels):
            try:
                await self.cli("disarm", self.programs[label][2])
                self.armed_labels.remove(label)
            except Exception as error:
                errors.append(repr(error))
        for slot in list(self.loaded_slots):
            try:
                await self.cli("revoke", str(slot))
                self.loaded_slots.remove(slot)
            except Exception as error:
                errors.append(repr(error))
        self.result["cleanup_errors"] = errors
        if errors:
            self.result["passed"] = False
            raise RuntimeError(str(errors))


async def metadata_test(log, _config):
    """Establish native reachability and extraction, not agent-workflow coverage."""
    test = Metadata(Path(os.environ["ICAP_RESULT"]))
    with test.output.open("x", encoding="utf-8") as output:
        try:
            test.result["acknowledgements"] = await configure(log)
            left = await asyncio.start_server(test.origin, BACKEND, 18094)
            right = await asyncio.start_server(test.origin, BACKEND, 18095)
            async with left, right:
                await test.start()
                for label in PROGRAMS:
                    for path, body, mime, fragmented in (
                        (
                            "/known",
                            b'{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{}}',
                            "application/json",
                            True,
                        ),
                        (
                            "/unfamiliar",
                            b'{"jsonrpc":"2.0","id":1,"method":"future.variant","params":{}}',
                            "application/json",
                            False,
                        ),
                        (
                            "/stream",
                            b'{"jsonrpc":"2.0","id":1,"method":"SendStreamingMessage","params":{}}',
                            "application/json",
                            False,
                        ),
                        ("/plain", b"unfamiliar non-JSON input", "text/plain", False),
                    ):
                        await test.request(label, path, body, mime, fragmented)
                        await test.drain(label + path)
                await test.finish()
            assert len(test.result["origin"]) == len(test.result["clients"]) == 8
            assert not test.result["backend_errors"]
            assert sorted(r["body_sha256"] for r in test.result["origin"]) == sorted(
                r["request_body_sha256"] for r in test.result["clients"]
            )
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
    """Expose only the native handler-metadata test."""
    return [tao.test_types.DockerBaseTest2("native handler metadata", metadata_test)]
