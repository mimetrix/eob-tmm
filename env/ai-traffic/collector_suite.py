"""Compare live method values received through a continuous journal collector."""
import asyncio
import json
import os
from pathlib import Path
from urllib.request import urlopen

import tao.test_types

from method_decode import decode
from method_suite import Method, method_test


class StreamingMethod(Method):
    """One continuous ring reader; two independent HTTP replay consumers."""

    def __init__(self, output):
        super().__init__(output)
        self.continuous_collector = True
        self.server = None
        self.cursor = None
        self.initial_cursor = None
        self.port = None
        self.result["stream_pages"] = []

    async def page(self, cursor=None):
        """Read a bounded HTTP page without blocking Tao's traffic loop."""

        def fetch():
            query = "?limit=128" + ("&after=" + cursor if cursor else "")
            with urlopen(
                f"http://127.0.0.1:{self.port}/events{query}", timeout=5
            ) as response:
                assert response.status == 200
                return json.load(response)

        return await asyncio.to_thread(fetch)

    async def start(self):
        """Start replay before traffic. The outer runner owns the writer."""
        self.server = await asyncio.create_subprocess_exec(
            "python3",
            "/work/stream_collector.py",
            "serve",
            "--journal",
            str(Path(os.environ["COLLECTOR_DIRECTORY"]) / "journal.sqlite"),
            "--port",
            "0",
            stdout=asyncio.subprocess.PIPE,
        )
        ready = json.loads(await asyncio.wait_for(self.server.stdout.readline(), 5))
        self.port = ready["listening"][1]
        first = await self.page()
        self.result["stream_pages"].append(first)
        self.cursor = first["next_cursor"]
        self.initial_cursor = first["oldest_cursor"]
        self.result["source_pending_at_start"] = not first["events"]
        assert not any(row["event"]["type"] == "record" for row in first["events"])
        await super().start()

    async def drain(self, label):
        """Read committed values through HTTP; never consume the TMM ring here."""
        target = (await self.counters())["method"]["fired"] - self.result[
            "counter_start"
        ]["method"]["fired"]
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
                assert raw["hook_id"] == raw["schema"] == 100 and raw["slot"] == 7
                event = decode(bytes.fromhex(raw["data"]))
                identity = self.identities["method"]
                assert event["instance"] == int(identity["instance"], 16)
                assert event["revision"] == identity["revision"]
                assert event["run"] == self.run_token and not event["flags"]
                assert not event["output_failures"] and event["monotonic_ns"]
                assert event["sequence"] == len(self.events) + 1
                assert envelope["decoded"]["record"]["value_hex"] == event["value_hex"]
                self.events.append(event)
                transport.append(raw)
            if len(self.events) >= target:
                break
            await asyncio.sleep(0.05)
        assert len(self.events) == target
        self.result["batches"].append({"label": label, "transport": transport})
        return transport

    async def finish(self):
        await super().finish()
        # Consumer two did not read while consumer one advanced. Replay must
        # return the same exact bytes and event identities from its old cursor.
        second = await self.page(self.initial_cursor)
        self.result["second_consumer"] = second
        events = [row for row in second["events"] if row["event"]["type"] == "record"]
        first = [
            row
            for page in self.result["stream_pages"]
            for row in page["events"]
            if row["event"]["type"] == "record"
        ]
        assert events == first and len(events) == 8

    async def cleanup(self):
        try:
            await super().cleanup()
        finally:
            if self.server is not None and self.server.returncode is None:
                self.server.terminate()
                await asyncio.wait_for(self.server.wait(), 5)


async def collector_test(log, config):
    """Reuse the exact value, truncation and status cases from the method test."""
    return await method_test(log, config, test_class=StreamingMethod)


def publish_tests():
    """Expose the continuous collection test to Tao."""
    return [
        tao.test_types.DockerBaseTest2("continuous method collection", collector_test)
    ]
