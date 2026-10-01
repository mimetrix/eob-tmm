"""Compare same-record IDs and flow sides without assigning request identity."""
import asyncio
from collections import Counter
import hashlib
import json
import os
from pathlib import Path

import tao
import tao.test_types

from icap_suite import BACKEND, VIP
from session_routing_suite import configure
from message_id_suite import MessageId
from id_flow_decode import decode
from id_flow_cases import all_cases, cases, repeated


def fields(event):
    """Use only independently checked field values for multiset comparison."""
    return (
        event["flow_side"],
        event["status"],
        event["id_kind"],
        event["value_hex"],
    )


class IdFlow(MessageId):
    """Reuse loader, accounting and replay checks with a new schema decoder."""

    def __init__(self, output):
        super().__init__(output)
        self.result["scope"] = "same-invocation ID and connection-flow side"
        self.bodies = {c[0]: (c[1], c[2]) for c in all_cases()}
        self.connection_serial = 0
        self.concurrent_arrivals = 0
        self.concurrent_ready = asyncio.Event()

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
                assert event["flow_status"] == 1
                self.events.append(event)
                transport.append(raw)
            if len(self.events) >= target:
                break
            await asyncio.sleep(0.05)
        assert len(self.events) == target
        self.result["batches"].append({"label": label, "transport": transport})
        return transport

    async def origin(self, reader, writer):
        self.connection_serial += 1
        connection = self.connection_serial
        try:
            while True:
                headers = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
                lines = headers.decode().split("\r\n")
                values = dict(line.split(": ", 1) for line in lines[1:] if ": " in line)
                length = next(
                    (
                        int(v)
                        for k, v in values.items()
                        if k.lower() == "content-length"
                    ),
                    0,
                )
                request = await asyncio.wait_for(reader.readexactly(length), 10)
                name = lines[0].split()[1].lstrip("/")
                expected_request, body = self.bodies[name]
                assert request == expected_request
                self.result["origin"].append(
                    {
                        "case": name,
                        "fixture_connection": connection,
                        "request_sha256": hashlib.sha256(request).hexdigest(),
                        "response_sha256": hashlib.sha256(body).hexdigest(),
                    }
                )
                if name.startswith("concurrent-"):
                    self.concurrent_arrivals += 1
                    if self.concurrent_arrivals == 4:
                        self.concurrent_ready.set()
                    await asyncio.wait_for(self.concurrent_ready.wait(), 10)
                keep = name in ("keep-0", "keep-1")
                connection_header = "keep-alive" if keep else "close"
                writer.write(
                    (
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"Connection: {connection_header}\r\n\r\n"
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
                if not keep:
                    break
        except asyncio.IncompleteReadError as error:
            if error.partial:
                self.result["backend_errors"].append(repr(error))
        except Exception as error:
            self.result["backend_errors"].append(repr(error))
        finally:
            writer.close()
            await writer.wait_closed()

    async def compare_id(self, name, request, body, request_expected, reply_expected):
        await super().compare_id(name, request, body, request_expected, reply_expected)
        assert [e["flow_side"] for e in self.result["comparisons"][-1]["events"]] == [
            1,
            2,
        ]

    async def exchange(self, case, reader, writer, keep):
        """Read exactly one HTTP response without requiring connection closure."""
        name, request, body, _, _ = case
        connection = "keep-alive" if keep else "close"
        writer.write(
            (
                f"POST /{name} HTTP/1.1\r\nHost: metadata\r\n"
                f"Content-Type: application/json\r\nContent-Length: {len(request)}\r\n"
                f"Connection: {connection}\r\n\r\n"
            ).encode()
            + request
        )
        await writer.drain()
        headers = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
        assert headers.startswith(b"HTTP/1.1 200 ")
        values = dict(
            line.lower().split(b": ", 1)
            for line in headers.split(b"\r\n")[1:]
            if b": " in line
        )
        length = int(values[b"content-length"])
        actual = await asyncio.wait_for(reader.readexactly(length), 10)
        assert actual == body
        self.result["clients"].append(
            {"case": name, "response_hex": (headers + actual).hex()}
        )

    async def compare_group(self, name, group, start):
        """Keep equal-ID observations as a multiset, without cross-record joins."""
        await self.drain(name)
        events = self.events[start:]
        expected = [
            (side, status, kind, "" if value is None else value[:64].hex())
            for case in group
            for side, (status, kind, value) in enumerate(case[3:], 1)
        ]
        assert Counter(map(fields, events)) == Counter(expected)
        self.result["comparisons"].append(
            {
                "case": name,
                "cases": [c[0] for c in group],
                "comparison_mode": "multiset",
                "events": events,
                "expected": expected,
            }
        )

    async def keep_alive(self):
        start = len(self.events)
        group = repeated("keep", 3)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(VIP, 18095), 10)
        try:
            for i, case in enumerate(group):
                await self.exchange(case, reader, writer, i < 2)
        finally:
            writer.close()
            await writer.wait_closed()
        self.result["keep_alive_client_connections"] = 1
        await self.compare_group("keep-alive", group, start)

    async def concurrent(self):
        async def client(case):
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(VIP, 18095), 10
            )
            try:
                await self.exchange(case, reader, writer, False)
            finally:
                writer.close()
                await writer.wait_closed()

        start = len(self.events)
        group = repeated("concurrent", 4)
        await asyncio.gather(*(client(case) for case in group))
        assert self.concurrent_arrivals == 4
        self.result["concurrent_requests_before_replies"] = self.concurrent_arrivals
        await self.compare_group("concurrent", group, start)


async def id_flow_test(log, _config):
    """Retain exact field checks, known fixture boundaries and cleanup evidence."""
    test = IdFlow(Path(os.environ["ICAP_RESULT"]))
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
                await test.keep_alive()
                await test.concurrent()
                await test.finish()
            assert (
                len(test.result["origin"])
                == len(test.result["clients"])
                == len(all_cases())
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
    """Publish the combined-field gate."""
    return [tao.test_types.DockerBaseTest2("ID and flow side", id_flow_test)]
