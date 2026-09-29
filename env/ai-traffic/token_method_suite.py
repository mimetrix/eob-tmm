"""Compare token-cache method bytes on the native AIMCP fixture path."""
import asyncio
import json
import os
from pathlib import Path

import tao
import tao.test_types

from collector_client import page
from icap_suite import BACKEND
from metadata_suite import Metadata, configure
from token_method_decode import decode

HOOK = "json_filter_handle_json_complete"


class TokenMethod(Metadata):
    """Read committed raw records from the separate collector's Unix socket."""

    def __init__(self, output):
        super().__init__(output, {"token": (7, 4, HOOK, 18095)})
        self.continuous_collector = True
        self.cursor = None
        self.initial_cursor = None
        self.result.update(
            stream_pages=[],
            comparisons=[],
            scope="literal root method in JSON caches on an isolated AIMCP path",
        )

    async def page(self, cursor=None):
        """Keep socket I/O outside the traffic event loop."""
        return await asyncio.to_thread(page, "/collector-api/events.sock", cursor)

    async def start(self):
        first = await self.page()
        self.result["stream_pages"].append(first)
        self.cursor = first["next_cursor"]
        self.initial_cursor = first["oldest_cursor"]
        assert not any(row["event"]["type"] == "record" for row in first["events"])
        await super().start()

    async def drain(self, label):
        """Retain each cache observation, including status-only records."""
        target = (await self.counters())["token"]["fired"] - self.result[
            "counter_start"
        ]["token"]["fired"]
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
                assert raw["hook_id"] == raw["schema"] == 100 and raw["slot"] == 7
                event = decode(bytes.fromhex(raw["data"]))
                identity = self.identities["token"]
                assert event["instance"] == int(identity["instance"], 16)
                assert event["revision"] == identity["revision"]
                assert event["run"] == self.run_token and not event["flags"]
                assert not event["output_failures"] and event["monotonic_ns"]
                assert event["sequence"] == len(self.events) + 1
                self.events.append(event)
                transport.append(raw)
            if len(self.events) >= target:
                break
            await asyncio.sleep(0.05)
        assert len(self.events) == target
        self.result["batches"].append({"label": label, "transport": transport})
        return transport

    async def compare(self, name, body, status, value=None, fragmented=False):
        """The isolated request interval is a test boundary, not an identity."""
        start = len(self.events)
        await self.request("aimcp", "/" + name, body, fragmented=fragmented)
        await self.drain(name)
        events = self.events[start:]
        comparison = {
            "case": name,
            "expected_status": status,
            "expected_value_hex": None if value is None else value.hex(),
            "events": events,
        }
        self.result["comparisons"].append(comparison)
        assert len(events) == 2, comparison
        assert [e["status_name"] for e in events] == [
            status,
            "no_literal_method",
        ], comparison
        if value is not None:
            assert events[0]["original_length"] == len(value)
            assert events[0]["copied_length"] == min(len(value), 64)
            assert events[0]["value_hex"] == value[:64].hex()

    async def finish(self):
        """Restore the hook and compare a replay reader with the first reader."""
        await self.drain("settle")
        await self.cli("disarm", HOOK)
        self.armed_labels.remove("token")
        await self.drain("final")
        self.result["counter_end"] = await self.counters()
        before = self.result["counter_start"]["token"]
        after = self.result["counter_end"]["token"]
        assert after["fired"] - before["fired"] == len(self.events) > 0
        for key in ("errors", "safe_returns", "gen"):
            assert before[key] == after[key]
        replay = await self.page(self.initial_cursor)
        first = [
            row
            for current in self.result["stream_pages"]
            for row in current["events"]
            if row["event"]["type"] == "record"
        ]
        assert first == [
            row for row in replay["events"] if row["event"]["type"] == "record"
        ]
        self.result["replay_consumer"] = replay


async def token_test(log, _config):
    """Exercise real fields and explicit exclusions through the native filters."""
    test = TokenMethod(Path(os.environ["ICAP_RESULT"]))
    with test.output.open("x", encoding="utf-8") as output:
        try:
            test.result["acknowledgements"] = await configure(log)
            origin = await asyncio.start_server(test.origin, BACKEND, 18095)
            async with origin:
                await test.start()
                for name, value in (
                    ("known", b"tools/list"),
                    ("unfamiliar", b"future.variant"),
                    ("empty", b""),
                    ("escaped", b"future\\u002evariant"),
                    ("limit", b"x" * 64),
                    ("truncated", b"y" * 65),
                ):
                    body = (
                        b'{"jsonrpc":"2.0","id":1,"method":"'
                        + value
                        + b'","params":{}}'
                    )
                    await test.compare(
                        name,
                        body,
                        "truncated" if len(value) > 64 else "complete",
                        value,
                        fragmented=name == "unfamiliar",
                    )
                for name, body, status, value in (
                    ("nonstring", b'{"method":7}', "nonstring", None),
                    (
                        "member-limit",
                        b'{"a":0,"b":0,"c":0,"d":0,"method":"late"}',
                        "budget_exhausted",
                        None,
                    ),
                    (
                        "nested-only",
                        b'{"params":{"method":"private"}}',
                        "no_literal_method",
                        None,
                    ),
                    (
                        "nested-and-root",
                        b'{"params":{"method":"private"},"method":"tools/list"}',
                        "complete",
                        b"tools/list",
                    ),
                    (
                        "escaped-key",
                        b'{"m\\u0065thod":"private"}',
                        "no_literal_method",
                        None,
                    ),
                    (
                        "duplicate-key",
                        b'{"method":"first","method":"second"}',
                        "complete",
                        b"first",
                    ),
                    (
                        "root-array",
                        b'[{"method":"private"}]',
                        "out_of_scope",
                        None,
                    ),
                ):
                    await test.compare(name, body, status, value)
                await test.finish()
            assert len(test.result["origin"]) == len(test.result["clients"]) == 13
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
    """Expose the token-cache extraction test to Tao."""
    return [tao.test_types.DockerBaseTest2("token method extraction", token_test)]
