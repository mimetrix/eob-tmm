"""Compare requested target bytes through the native AIMCP/JSON path."""
import asyncio
import json
import os
from pathlib import Path

import tao
import tao.test_types

from icap_suite import BACKEND
from session_routing_suite import SessionRouting, configure
from operation_target_decode import decode
from operation_target_cases import cases

HOOK = "json_filter_handle_json_complete"


class OperationTarget(SessionRouting):
    """Reuse bounded replay and lifecycle checks for a private target program."""

    def __init__(self, output):
        super().__init__(output)
        self.programs = {"target": (10, 4, HOOK, 18095)}
        self.result["scope"] = "bounded literal requested targets in JSON caches"

    async def drain(self, label):
        target = (await self.counters())["target"]["fired"] - self.result[
            "counter_start"
        ]["target"]["fired"]
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
                assert raw["slot"] == 10 and raw["hook_id"] == raw["schema"] == 100
                event = decode(bytes.fromhex(raw["data"]))
                identity = self.identities["target"]
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

    async def compare_target(self, name, body, status, kind, value):
        start = len(self.events)
        await self.request("aimcp", "/" + name, body, fragmented="unfamiliar" in name)
        await self.drain(name)
        events = self.events[start:]
        comparison = {
            "case": name,
            "expected_status": status,
            "expected_kind": kind,
            "expected_value_hex": None if value is None else value.hex(),
            "events": events,
        }
        self.result["comparisons"].append(comparison)
        assert len(events) == 2, comparison
        assert [e["status"] for e in events] == [status, 8], comparison
        assert [e["target_kind"] for e in events] == [kind, 0], comparison
        if value is not None:
            assert events[0]["original_length"] == len(value), comparison
            assert events[0]["value_hex"] == value[:64].hex(), comparison

    async def finish(self):
        await self.cli("disarm", HOOK)
        self.armed_labels.remove("target")
        await self.drain("final")
        self.result["counter_end"] = await self.counters()
        before = self.result["counter_start"]["target"]
        after = self.result["counter_end"]["target"]
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


async def operation_target_test(log, _config):
    """Retain exact comparisons and all failures before disarm and revoke."""
    test = OperationTarget(Path(os.environ["ICAP_RESULT"]))
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
                    await test.compare_target(*case)
                await test.finish()
            assert (
                len(test.result["origin"])
                == len(test.result["clients"])
                == len(cases())
            )
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
    """Publish the isolated requested-target gate."""
    return [
        tao.test_types.DockerBaseTest2(
            "operation target extraction", operation_target_test
        )
    ]
