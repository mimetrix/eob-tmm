"""Compare bytecode-keyed groups on concurrent and reused HTTP connections."""
import asyncio
import json
import os
from pathlib import Path

import tao
import tao.test_types

from activity_combine import ActivityCombiner
from activity_program_suite import ActivityProgram, CASES, wire
from icap_suite import BACKEND, VIP
from id_flow_suite import IdFlow
from session_routing_suite import configure


def cases():
    """Use distinct operation targets but deliberately reuse the same ID."""
    result = [
        ("single-" + str(i), request, reply) for i, (request, reply) in enumerate(CASES)
    ]
    for prefix, count in (("keep", 3), ("concurrent", 4)):
        for i in range(count):
            name = f"{prefix}-{i}"
            result.append(
                (
                    name,
                    dict(
                        jsonrpc="2.0",
                        id="same",
                        method="tools/call",
                        params=dict(name=name),
                    ),
                    dict(jsonrpc="2.0", id="same", result=dict(isError=bool(i % 2))),
                )
            )
    return result


class CombinedActivity(ActivityProgram):
    """Replay page boundaries do not close an open exchange."""

    origin = IdFlow.origin
    exchange = IdFlow.exchange

    def __init__(self, output):
        super().__init__(output)
        self.combiner = ActivityCombiner()
        self.result["combined"] = []
        self.bodies = {
            name: (wire(request), wire(reply)) for name, request, reply in cases()
        }
        self.connection_serial = self.concurrent_arrivals = 0
        self.concurrent_ready = asyncio.Event()

    async def drain(self, label):
        start = len(self.result["stream_pages"])
        await super().drain(label)
        for page in self.result["stream_pages"][start:]:
            self.result["combined"].extend(self.combiner.feed(page))

    async def client(self, names):
        reader, writer = await asyncio.wait_for(asyncio.open_connection(VIP, 18095), 10)
        try:
            for i, name in enumerate(names):
                request, reply = self.bodies[name]
                await self.exchange(
                    (name, request, reply, None, None),
                    reader,
                    writer,
                    i < len(names) - 1,
                )
        finally:
            writer.close()
            await writer.wait_closed()

    async def finish(self):
        await super().finish()
        self.result["combined"].extend(self.combiner.flush("end_of_input"))
        combined = [
            r
            for r in self.result["combined"]
            if r["event_type"] == "agent.activity.combined"
        ]
        assert len(combined) == len(cases()), combined
        assert len({r["activity_id"] for r in combined}) == len(combined)
        expected = {
            next(iter(request["params"].values())): (request, reply)
            for _, request, reply in cases()
        }
        for row in combined:
            assert row["correlation"]["status"] == "observed_exchange", row
            request, reply = expected.pop(row["activity"]["target"]["value"])
            assert row["activity"]["method"]["value"] == request["method"]
            assert row["activity"]["message_id"]["value"] == str(request["id"])
            outcome = row["reported_outcome"]
            assert outcome["http_status"]["value"] == 200
            assert outcome["local_transfer_complete"]["value"] is True
            if "error" in reply:
                assert outcome["error_code"]["value"] == reply["error"]["code"]
            else:
                assert outcome["tool_error"]["value"] == reply["result"]["isError"]
            assert row["identity"] is None and row["identity_binding"] == "unknown"
        assert not expected
        replay = ActivityCombiner()
        split = []
        for row in self.result["replay_consumer"]["events"]:
            split.extend(replay.feed(dict(events=[row], next_cursor=row["cursor"])))
        split.extend(replay.flush("end_of_input"))
        assert [
            r for r in split if r["event_type"] == "agent.activity.combined"
        ] == combined
        self.result["single_row_page_replay"] = True


async def activity_combined_test(log, _config):
    """Keep client/backend receipts and restore both hooks after failure."""
    test = CombinedActivity(Path(os.environ["ICAP_RESULT"]))
    with test.output.open("x", encoding="utf-8") as output:
        try:
            config, pool, acks = await configure(log)
            test.result.update(
                configuration=config, expected_pool=pool, acknowledgements=acks
            )
            origin = await asyncio.start_server(test.origin, BACKEND, 18095)
            async with origin:
                await test.start()
                for i in range(len(CASES)):
                    await test.client(["single-" + str(i)])
                    await test.drain("single-" + str(i))
                await test.client(["keep-" + str(i) for i in range(3)])
                await test.drain("keep-alive")
                await asyncio.gather(
                    *(test.client(["concurrent-" + str(i)]) for i in range(4))
                )
                assert test.concurrent_arrivals == 4
                test.result["concurrent_requests_before_replies"] = 4
                test.result["keep_alive_client_connections"] = 1
                await test.finish()
            assert (
                len(test.result["clients"])
                == len(test.result["origin"])
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
    """Publish the combined activity fixture."""
    return [
        tao.test_types.DockerBaseTest2(
            "combined activity records", activity_combined_test
        )
    ]
