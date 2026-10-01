"""Compare observed ID type and bytes through the isolated AIMCP/JSON path."""
import asyncio
import hashlib
import json
import os
from pathlib import Path

import tao
import tao.test_types

from icap_suite import BACKEND, VIP
from session_routing_suite import SessionRouting, configure
from message_id_decode import decode
from message_id_cases import cases

HOOK = "json_filter_handle_json_complete"


class MessageId(SessionRouting):
    """Keep each observation separate; do not join on caller-supplied IDs."""

    def __init__(self, output):
        super().__init__(output)
        self.programs = {"id": (11, 6, HOOK, 18095)}
        self.result["scope"] = "bounded literal message ID type and bytes"
        self.bodies = {c[0]: (c[1], c[2]) for c in cases()}

    async def drain(self, label):
        target = (await self.counters())["id"]["fired"] - self.result["counter_start"][
            "id"
        ]["fired"]
        transport = []
        for _ in range(100):
            current = await self.page(self.cursor)
            self.result["stream_pages"].append(current)
            self.cursor = current["next_cursor"]
            for row in current["events"]:
                envelope = row["event"]
                assert envelope["type"] != "observation_gap", envelope
                if envelope["type"] != "record":
                    continue
                raw = envelope["raw"]
                assert raw["slot"] == 11 and raw["hook_id"] == raw["schema"] == 100
                event = decode(bytes.fromhex(raw["data"]))
                identity = self.identities["id"]
                assert event["instance"] == int(identity["instance"], 16)
                assert event["revision"] == identity["revision"]
                assert event["run"] == self.run_token and not event["flags"]
                assert event["monotonic_ns"] and not event["output_failures"]
                assert event["sequence"] == len(self.events) + 1
                self.events.append(event)
                transport.append(raw)
            if len(self.events) >= target:
                break
            await asyncio.sleep(0.05)
        assert len(self.events) == target
        self.result["batches"].append({"label": label, "transport": transport})
        return transport

    async def origin(self, reader, writer):
        try:
            headers = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            lines = headers.decode().split("\r\n")
            fields = dict(line.split(": ", 1) for line in lines[1:] if ": " in line)
            length = next(
                (int(v) for k, v in fields.items() if k.lower() == "content-length"), 0
            )
            request = await asyncio.wait_for(reader.readexactly(length), 10)
            name = lines[0].split()[1].lstrip("/")
            expected_request, body = self.bodies[name]
            assert request == expected_request
            self.result["origin"].append(
                {
                    "case": name,
                    "request_sha256": hashlib.sha256(request).hexdigest(),
                    "response_sha256": hashlib.sha256(body).hexdigest(),
                }
            )
            writer.write(
                (
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                ).encode()
            )
            if name in ("large-integer", "escaped-value"):
                for chunk in (body[:5], body[5:-2], body[-2:]):
                    writer.write(chunk)
                    await writer.drain()
                    await asyncio.sleep(0.05)
            else:
                writer.write(body)
                await writer.drain()
        except Exception as error:
            self.result["backend_errors"].append(repr(error))
        finally:
            writer.close()
            await writer.wait_closed()

    async def compare_id(self, name, request, body, request_expected, reply_expected):
        start = len(self.events)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(VIP, 18095), 10)
        response = b""
        try:
            data = (
                f"POST /{name} HTTP/1.1\r\nHost: metadata\r\n"
                f"Content-Type: application/json\r\nContent-Length: {len(request)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode() + request
            if name == "string-64":
                for chunk in (data[:-9], data[-9:]):
                    writer.write(chunk)
                    await writer.drain()
                    await asyncio.sleep(0.05)
            else:
                writer.write(data)
                await writer.drain()
            response = await asyncio.wait_for(reader.read(), 15)
            assert response.startswith(b"HTTP/1.1 200 "), response
            assert response.split(b"\r\n\r\n", 1)[1] == body, response
        finally:
            self.result["clients"].append(
                {"case": name, "response_hex": response.hex()}
            )
            writer.close()
            await writer.wait_closed()
        await self.drain(name)
        events = self.events[start:]
        comparison = {"case": name, "expected": [], "events": events}
        self.result["comparisons"].append(comparison)
        assert len(events) == 2, comparison
        for event, expected in zip(events, (request_expected, reply_expected)):
            status, kind, value = expected
            comparison["expected"].append(
                [status, kind, None if value is None else value.hex()]
            )
            assert event["status"] == status and event["id_kind"] == kind, comparison
            if value is None:
                assert not event["value_hex"], comparison
            else:
                assert event["original_length"] == len(value), comparison
                assert event["value_hex"] == value[:64].hex(), comparison

    async def finish(self):
        await self.cli("disarm", HOOK)
        self.armed_labels.remove("id")
        await self.drain("final")
        self.result["counter_end"] = await self.counters()
        before = self.result["counter_start"]["id"]
        after = self.result["counter_end"]["id"]
        assert after["fired"] - before["fired"] == len(self.events)
        assert all(before[k] == after[k] for k in ("errors", "safe_returns", "gen"))
        cursor, replay = self.initial_cursor, []
        for _ in range(20):
            current = await self.page(cursor)
            replay.extend(current["events"])
            cursor = current["next_cursor"]
            if not current["events"]:
                break
        else:
            raise RuntimeError("replay page limit")
        self.result["replay_consumer"] = {"events": replay, "next_cursor": cursor}
        rows = [r for p in self.result["stream_pages"] for r in p["events"]]
        assert [r for r in rows if r["event"]["type"] == "record"] == [
            r for r in replay if r["event"]["type"] == "record"
        ]


async def message_id_test(log, _config):
    """Retain exact comparisons and failures before disarm and revoke."""
    test = MessageId(Path(os.environ["ICAP_RESULT"]))
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
                for case in cases():
                    await test.compare_id(*case)
                await test.finish()
            assert (
                len(test.result["origin"])
                == len(test.result["clients"])
                == len(cases())
            )
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
    """Publish the isolated ID-field gate."""
    return [tao.test_types.DockerBaseTest2("message ID extraction", message_id_test)]
