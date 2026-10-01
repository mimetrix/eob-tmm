"""Check matched initialization returns with exact HTTP peers and replay."""
import asyncio
from collections import Counter
import json
import os
from pathlib import Path

import tao
import tao.test_types
from icap_suite import BACKEND, VIP
from session_routing_suite import configure
from json_lifecycle_suite import Boundaries
from json_initialization_decode import decode

PROGRAMS = {"initialization": (11, 1, "hud_json_handler", 18095)}


class Initialization(Boundaries):
    """Use the existing peers with a separate completion-only record schema."""

    def __init__(self, output):
        super().__init__(output)
        self.programs = PROGRAMS
        self.result["scope"] = "past initialization action; storage lifetime unknown"

    async def drain(self, label):
        current = (await self.counters())["initialization"]
        before = self.result["counter_start"]["initialization"]
        fired = current["fired"] - before["fired"]
        assert fired % 2 == 0, current
        target = fired // 2
        transport = []
        for _ in range(100):
            page = await self.page(self.cursor)
            self.result["stream_pages"].append(page)
            self.cursor = page["next_cursor"]
            for row in page["events"]:
                envelope = row["event"]
                assert envelope["type"] != "observation_gap", envelope
                if envelope["type"] != "record":
                    continue
                raw = envelope["raw"]
                assert raw["slot"] == 11 and raw["schema"] == raw["hook_id"] == 100
                event = decode(bytes.fromhex(raw["data"]))
                identity = self.identities["initialization"]
                assert event["instance"] == int(identity["instance"], 16)
                assert event["revision"] == identity["revision"]
                assert event["run"] == self.run_token
                assert event["sequence"] == len(self.events) + 1
                assert not event["flags"] and not event["output_failures"]
                assert event["invocation"] and event["monotonic_ns"]
                assert event["status"] in (0, 1, 2, 3, 5), event
                assert event["initialization_completed"] == (event["status"] == 1)
                self.events.append(event)
                transport.append(raw)
            if len(self.events) >= target:
                break
            await asyncio.sleep(0.05)
        assert len(self.events) == target
        self.result["batches"].append({"label": label, "transport": transport})

    async def one(self, name, paced=False):
        start = len(self.events)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(VIP, 18095), 10)
        try:
            request = self.request_bytes(name)
            writer.write(request[:-2] if paced else request)
            await writer.drain()
            if paced:
                await asyncio.sleep(0.1)
                writer.write(request[-2:])
                await writer.drain()
            await self.response(name, reader)
        finally:
            writer.close()
            await writer.wait_closed()
        await self.compare_group(name, [(name,)], start)

    async def compare_group(self, name, group, start):
        await asyncio.sleep(0.1)
        await self.drain(name)
        events = self.events[start:]
        complete = [e for e in events if e["initialization_completed"]]
        assert {e["flow_side"] for e in complete} == {1, 2}, complete
        self.result["comparisons"].append(
            {"case": name, "cases": [c[0] for c in group], "events": events}
        )

    async def finish(self):
        await asyncio.sleep(0.2)
        await self.drain("settle")
        await self.cli("disarm", "hud_json_handler")
        self.armed_labels.remove("initialization")
        await self.drain("final")
        self.result["counter_end"] = await self.counters()
        before = self.result["counter_start"]["initialization"]
        after = self.result["counter_end"]["initialization"]
        assert after["fired"] - before["fired"] == 2 * len(self.events) > 0
        for key in (
            "errors",
            "safe_returns",
            "gen",
            "snapshot_entry_errors",
            "snapshot_return_errors",
        ):
            assert before[key] == after[key], (key, before, after)
        assert len({e["invocation"] for e in self.events}) == len(self.events)
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
        self.result["summary"] = {
            "records": len(self.events),
            "status_counts": dict(Counter(e["status"] for e in self.events)),
            "initialized_sides": dict(
                Counter(
                    e["flow_side"] for e in self.events if e["initialization_completed"]
                )
            ),
            "lifecycle_validated": False,
        }


async def initialization_test(log, _config):
    test = Initialization(Path(os.environ["ICAP_RESULT"]))
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
                try:
                    request = test.request_bytes("late")
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
                assert not any(
                    e["initialization_completed"] and e["flow_side"] == 1
                    for e in test.events
                )
                test.result["late_attachment"] = list(test.events)
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
    return [
        tao.test_types.DockerBaseTest2(
            "JSON initialization completion", initialization_test
        )
    ]
