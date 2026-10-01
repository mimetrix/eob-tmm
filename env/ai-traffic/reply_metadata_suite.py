"""Compare reported reply fields through the isolated native AIMCP/JSON path."""
import asyncio
import hashlib
import json
import os
from pathlib import Path

import tao
import tao.test_types

from icap_suite import BACKEND, VIP
from session_routing_suite import SessionRouting, configure
from reply_metadata_decode import decode, FIELDS
from reply_metadata_cases import CASES

HOOK = "json_filter_handle_json_complete"
REQUEST = b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'


class ReplyMetadata(SessionRouting):
    """Keep reported outcomes separate from transport and caller identity."""

    def __init__(self, output):
        super().__init__(output)
        self.programs = {"reply": (11, 5, HOOK, 18095)}
        self.result["scope"] = "bounded reported fields in JSON caches"
        self.bodies = {name: body.encode() for name, body, _ in CASES}

    async def drain(self, label):
        target = (await self.counters())["reply"]["fired"] - self.result[
            "counter_start"
        ]["reply"]["fired"]
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
                identity = self.identities["reply"]
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
            body = self.bodies[name]
            assert request == REQUEST
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
            if name in ("tool-true", "error-unfamiliar"):
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

    async def compare_reply(self, name, body, expected):
        start = len(self.events)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(VIP, 18095), 10)
        response = b""
        try:
            writer.write(
                (
                    f"POST /{name} HTTP/1.1\r\nHost: metadata\r\n"
                    f"Content-Type: application/json\r\nContent-Length: {len(REQUEST)}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode()
                + REQUEST
            )
            await writer.drain()
            response = await asyncio.wait_for(reader.read(), 15)
            assert response.startswith(b"HTTP/1.1 200 "), response
            assert response.split(b"\r\n\r\n", 1)[1] == body.encode(), response
        finally:
            self.result["clients"].append(
                {"case": name, "response_hex": response.hex()}
            )
            writer.close()
            await writer.wait_closed()
        await self.drain(name)
        events = self.events[start:]
        comparison = {"case": name, "expected": expected, "events": events}
        self.result["comparisons"].append(comparison)
        assert len(events) == 2, comparison
        assert tuple(events[0][k] for k in FIELDS) == (0,) * 7, comparison
        assert tuple(events[1][k] for k in FIELDS) == expected, comparison

    async def finish(self):
        await self.cli("disarm", HOOK)
        self.armed_labels.remove("reply")
        await self.drain("final")
        self.result["counter_end"] = await self.counters()
        before = self.result["counter_start"]["reply"]
        after = self.result["counter_end"]["reply"]
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


async def reply_metadata_test(log, _config):
    """Retain exact comparisons and all failures before disarm and revoke."""
    test = ReplyMetadata(Path(os.environ["ICAP_RESULT"]))
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
                for case in CASES:
                    await test.compare_reply(*case)
                await test.finish()
            assert (
                len(test.result["origin"]) == len(test.result["clients"]) == len(CASES)
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
    """Publish the isolated reply-field gate."""
    return [
        tao.test_types.DockerBaseTest2("reply metadata extraction", reply_metadata_test)
    ]
