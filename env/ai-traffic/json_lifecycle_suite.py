"""Observe local JSON boundaries without asserting a completed lifecycle."""
import asyncio
from collections import Counter
import json
import os
from pathlib import Path

import tao
import tao.test_types
from icap_suite import BACKEND, VIP
from session_routing_suite import configure
from id_flow_suite import IdFlow
from json_lifecycle_decode import decode, window

PROGRAMS = {
    "handler": (8, 1, "hud_json_handler", 18095),
    "complete": (9, 2, "json_filter_handle_json_complete", 18095),
    "reset": (10, 3, "json_filter_reset_ingress_for_reuse", 18095),
}


class Boundaries(IdFlow):
    """Reuse exact HTTP peers, configuration and collector transport."""

    def __init__(self, output):
        super().__init__(output)
        self.programs = PROGRAMS
        self.result["scope"] = "entry observations; lifecycle unknown"
        self.bodies["late"] = (b'{"id":1}', b'{"id":1,"result":{}}')
        self.bodies["parse-error"] = (b'{"id":bad}', b'{"id":1,"result":{}}')
        self.bodies["paced"] = (b'{"id":1}', b'{"id":1,"result":{}}')

    async def drain(self, label):
        current = await self.counters()
        targets = {
            key: row["fired"] - self.result["counter_start"][key]["fired"]
            for key, row in current.items()
        }
        transport = []
        for _ in range(100):
            page = await self.page(self.cursor)
            self.result["stream_pages"].append(page)
            self.cursor = page["next_cursor"]
            for row in page["events"]:
                envelope = row["event"]
                assert envelope["type"] != "observation_gap"
                if envelope["type"] != "record":
                    continue
                raw = envelope["raw"]
                event = decode(bytes.fromhex(raw["data"]))
                name = next(k for k, p in PROGRAMS.items() if p[1] == event["kind"])
                identity = self.identities[name]
                assert raw["slot"] == PROGRAMS[name][0]
                assert raw["schema"] == raw["hook_id"] == 100
                assert event["instance"] == int(identity["instance"], 16)
                assert event["revision"] == identity["revision"]
                assert event["run"] == self.run_token
                assert event["sequence"] == len(self.events) + 1
                assert not event["flags"] and not event["output_failures"]
                assert event["status"] in (0, 1, 2, 3, 5), event
                if event["status"] == 0:
                    assert not any(
                        event[k]
                        for k in ("context_tag", "flow_side", "reads", "source_bytes")
                    ), event
                self.events.append(event)
                transport.append(raw)
            if len(self.events) >= sum(targets.values()):
                break
            await asyncio.sleep(0.05)
        for key, (_, kind, _, _) in PROGRAMS.items():
            assert sum(e["kind"] == kind for e in self.events) == targets[key]
        self.result["batches"].append({"label": label, "transport": transport})
        return transport

    async def response(self, name, reader):
        headers = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
        assert headers.startswith(b"HTTP/1.1 200 ")
        values = dict(
            line.lower().split(b": ", 1)
            for line in headers.split(b"\r\n")[1:]
            if b": " in line
        )
        body = await asyncio.wait_for(
            reader.readexactly(int(values[b"content-length"])), 10
        )
        assert body == self.bodies[name][1]
        self.result["clients"].append(
            {"case": name, "response_hex": (headers + body).hex()}
        )

    def request_bytes(self, name):
        body = self.bodies[name][0]
        return (
            f"POST /{name} HTTP/1.1\r\nHost: metadata\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode() + body

    async def one(self, name, paced=False):
        start = len(self.events)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(VIP, 18095), 10)
        try:
            request = self.request_bytes(name)
            if paced:
                writer.write(request[:-2])
                await writer.drain()
                await asyncio.sleep(0.1)
                writer.write(request[-2:])
            else:
                writer.write(request)
            await writer.drain()
            await self.response(name, reader)
        finally:
            writer.close()
            await writer.wait_closed()
        await asyncio.sleep(0.1)
        await self.drain(name)
        events = self.events[start:]
        counts = Counter(e["kind"] for e in events)
        assert counts[1] and counts[3]
        if name != "parse-error":
            assert counts[2] == 2
        self.result["comparisons"].append({"case": name, "events": events})

    async def compare_group(self, name, group, start):
        await asyncio.sleep(0.1)
        await self.drain(name)
        events = self.events[start:]
        complete = [e for e in events if e["kind"] == 2]
        assert len(complete) == len(group) * 2
        assert Counter(e["flow_side"] for e in complete) == {
            1: len(group),
            2: len(group),
        }
        self.result["comparisons"].append(
            {"case": name, "cases": [c[0] for c in group], "events": events}
        )

    async def finish(self):
        await asyncio.sleep(0.2)
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
            assert all(before[k] == after[k] for k in ("errors", "safe_returns", "gen"))
        replay, cursor = [], self.initial_cursor
        for _ in range(100):
            page = await self.page(cursor)
            replay += page["events"]
            cursor = page["next_cursor"]
            if not page["events"]:
                break
        else:
            raise AssertionError("replay page limit")
        records = [
            r
            for p in self.result["stream_pages"]
            for r in p["events"]
            if r["event"]["type"] == "record"
        ]
        assert records == [r for r in replay if r["event"]["type"] == "record"]
        self.result["replay_consumer"] = {"events": replay}
        self.result["boundary_window"] = window(self.events)
        self.result["known_gap_window"] = window(
            self.events, ["controller_reported_detach"]
        )
        assert not self.result["known_gap_window"]["boundaries_usable"]


async def boundary_test(log, _config):
    test = Boundaries(Path(os.environ["ICAP_RESULT"]))
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
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(VIP, 18095), 10
                )
                request = test.request_bytes("late")
                try:
                    writer.write(request[:-2])
                    await writer.drain()
                    await asyncio.sleep(0.2)
                    await test.start()
                    writer.write(request[-2:])
                    await writer.drain()
                    await test.response("late", reader)
                finally:
                    writer.close()
                    await writer.wait_closed()
                await asyncio.sleep(0.1)
                await test.drain("late")
                late = [
                    e for e in test.events if e["kind"] == 2 and e["flow_side"] == 1
                ]
                assert len(late) == 1 and not (late[0]["seen_mask"] & 1)
                test.result["late_client_completion"] = late[0]
                for name in (
                    "number",
                    "large-integer",
                    "escaped-value",
                    "parse-error",
                    "paced",
                ):
                    await test.one(name, paced=name == "paced")
                await test.keep_alive()
                await test.concurrent()
                await test.finish()
            assert not test.result["backend_errors"]
            assert len(test.result["clients"]) == len(test.result["origin"]) == 13
            test.result["unvalidated_challenges"] = [
                "interrupted transfer",
                "live disabled path",
                "deferred rule completion",
                "live omitted boundaries",
                "live capacity",
                "live reload",
            ]
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
    return [tao.test_types.DockerBaseTest2("JSON boundary observations", boundary_test)]
