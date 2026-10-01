"""Compare response fields and local transfer boundaries through the collector."""
import asyncio
import hashlib
import json
import os
from pathlib import Path

import tao
import tao.test_types

from icap_suite import BACKEND, VIP
from session_routing_suite import SessionRouting, configure
from response_metadata_decode import decode

PROGRAMS = {"response": (9, 3, "hud_aimcp_handler", 18095)}
CASES = {
    "ok": (200, b"observed", "fixed"),
    "bodyless": (204, b"", "fixed"),
    "not-found": (404, b"missing", "fixed"),
    "unavailable": (503, b"retry", "fixed"),
    "unfamiliar": (777, b"unfamiliar", "fixed"),
    "paced": (200, b"first-second", "paced"),
    "chunked": (200, b"first-second", "chunked"),
    "stream": (200, b'data: {"part":1}\n\ndata: {"part":2}\n\n', "stream"),
    "interrupted": (200, b"short", "interrupted"),
}


class ResponseMetadata(SessionRouting):
    """Reuse replay boundaries; interpret only this probe's response schema."""

    def __init__(self, output):
        super().__init__(output)
        self.programs = PROGRAMS
        self.continuous_collector = True
        self.cursor = self.initial_cursor = None
        self.release_body = asyncio.Event()
        self.result.update(
            stream_pages=[],
            comparisons=[],
            replay_retries=[],
            scope="one-worker AIMCP response fields and local done arguments",
        )

    async def drain(self, label):
        current = await self.counters()
        target = (
            current["response"]["fired"]
            - self.result["counter_start"]["response"]["fired"]
        )
        transport = []
        for _ in range(100):
            page = await self.page(self.cursor)
            self.result["stream_pages"].append(page)
            self.cursor = page["next_cursor"]
            for row in page["events"]:
                event = row["event"]
                assert event["type"] != "observation_gap", event
                if event["type"] != "record":
                    continue
                raw = event["raw"]
                value = decode(bytes.fromhex(raw["data"]))
                identity = self.identities["response"]
                assert raw["slot"] == 9 and raw["hook_id"] == raw["schema"] == 100
                assert value["instance"] == int(identity["instance"], 16)
                assert value["revision"] == identity["revision"]
                assert value["run"] == self.run_token and not value["flags"]
                assert value["monotonic_ns"] and not value["output_failures"]
                assert value["sequence"] == len(self.events) + 1
                self.events.append(value)
                transport.append(raw)
            if len(self.events) >= target:
                break
            await asyncio.sleep(0.05)
        assert len(self.events) >= target
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
            status, body, mode = CASES[name]
            self.result["origin"].append(
                {
                    "case": name,
                    "status": status,
                    "mode": mode,
                    "body_sha256": hashlib.sha256(request).hexdigest(),
                    "response_body_sha256": hashlib.sha256(body).hexdigest(),
                    "peer": writer.get_extra_info("peername"),
                }
            )
            mime = "text/event-stream" if mode == "stream" else "text/plain"
            header = f"HTTP/1.1 {status} Fixture\r\nContent-Type: {mime}\r\nConnection: close\r\n"
            if mode == "chunked":
                header += "Transfer-Encoding: chunked\r\n"
            elif mode != "stream":
                header += f"Content-Length: {len(body) + (20 if mode == 'interrupted' else 0)}\r\n"
            writer.write(header.encode() + b"\r\n")
            if mode == "paced":
                writer.write(body[:5])
                await writer.drain()
                await asyncio.wait_for(self.release_body.wait(), 30)
                writer.write(body[5:])
            elif mode == "chunked":
                for chunk in (body[:5], body[5:]):
                    writer.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                    await writer.drain()
                    await asyncio.sleep(0.05)
                writer.write(b"0\r\n\r\n")
            elif mode == "stream":
                for chunk in body.splitlines(keepends=True):
                    writer.write(chunk)
                    await writer.drain()
                    await asyncio.sleep(0.02)
            else:
                writer.write(body)
            await writer.drain()
        except Exception as error:
            self.result["backend_errors"].append(repr(error))
        finally:
            writer.close()
            await writer.wait_closed()

    async def compare_response(self, name):
        start = len(self.events)
        status, body, mode = CASES[name]
        if mode == "paced":
            self.release_body.clear()
        reader, writer = await asyncio.wait_for(asyncio.open_connection(VIP, 18095), 10)
        request = b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
        writer.write(
            (
                f"POST /{name} HTTP/1.1\r\nHost: metadata\r\n"
                f"Content-Type: application/json\r\nContent-Length: {len(request)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode()
            + request
        )
        await writer.drain()
        response = b""
        read_error = None
        try:
            if mode == "paced":
                response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
                await self.drain("paced-before-release")
                prefix = self.events[start:]
                self.result["paced_before_release"] = list(prefix)
                assert any(e["http_status"] == status for e in prefix), prefix
                assert not any(e["completion_state"] == 1 for e in prefix), prefix
                self.release_body.set()
            while True:
                try:
                    data = await asyncio.wait_for(reader.read(65536), 15)
                except ConnectionResetError as error:
                    if mode != "interrupted":
                        raise
                    read_error = repr(error)
                    break
                if not data:
                    break
                response += data
            assert response.startswith(f"HTTP/1.1 {status} ".encode()), response
            if mode not in ("chunked", "stream", "interrupted"):
                assert response.split(b"\r\n\r\n", 1)[1] == body, response
            if mode == "stream":
                assert b'"part":1' in response and b'"part":2' in response, response
            if mode == "chunked":
                assert b"first" in response and b"-second" in response, response
        finally:
            self.release_body.set()
            self.result["clients"].append(
                {"case": name, "response_hex": response.hex(), "read_error": read_error}
            )
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionResetError:
                if mode != "interrupted":
                    raise
        await asyncio.sleep(0.1)
        await self.drain(name)
        events = self.events[start:]
        status_events = [e for e in events if e["http_status_state"]]
        done_events = [e for e in events if e["completion_state"]]
        comparison = {
            "case": name,
            "expected_status": status,
            "mode": mode,
            "events": events,
        }
        self.result["comparisons"].append(comparison)
        assert status_events and all(
            e["http_status_state"] == 1 and e["http_status"] == status
            for e in status_events
        ), comparison
        assert done_events and all(
            e["completion_state"] == 1 for e in done_events
        ), comparison
        expected_complete = int(mode != "interrupted")
        assert all(
            e["transfer_complete"] == expected_complete for e in done_events
        ), comparison

    async def finish(self):
        await self.cli("disarm", "hud_aimcp_handler")
        self.armed_labels.remove("response")
        await self.drain("final")
        self.result["counter_end"] = await self.counters()
        before, after = (
            self.result["counter_start"]["response"],
            self.result["counter_end"]["response"],
        )
        assert after["fired"] - before["fired"] == len(self.events)
        assert all(
            before[key] == after[key] for key in ("errors", "safe_returns", "gen")
        )
        cursor, replay = self.initial_cursor, []
        for _ in range(20):
            page = await self.page(cursor)
            replay.extend(page["events"])
            cursor = page["next_cursor"]
            if not page["events"]:
                break
        else:
            raise RuntimeError("replay page limit")
        self.result["replay_consumer"] = {"events": replay, "next_cursor": cursor}
        rows = [row for page in self.result["stream_pages"] for row in page["events"]]
        assert [r for r in rows if r["event"]["type"] == "record"] == [
            r for r in replay if r["event"]["type"] == "record"
        ]


async def response_metadata_test(log, _config):
    """Compare exact fields and retain every failure before fixture cleanup."""
    test = ResponseMetadata(Path(os.environ["ICAP_RESULT"]))
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
                for name in CASES:
                    await test.compare_response(name)
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
            test.release_body.set()
            try:
                await test.cleanup()
            finally:
                json.dump(test.result, output, indent=2)


def publish_tests():
    """Publish the isolated response-field gate."""
    return [
        tao.test_types.DockerBaseTest2(
            "response metadata extraction", response_metadata_test
        )
    ]
