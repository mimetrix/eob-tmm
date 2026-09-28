"""Compare actual getter-return metadata with authored requests through TMM."""
import asyncio
import json
import os
from pathlib import Path

import tao
import tao.test_types

from icap_suite import BACKEND
from metadata_suite import Metadata, configure
from method_decode import decode

HOOK = "tmm_json_value_get_string"


class Method(Metadata):
    """Read the selected field without a cross-invocation pointer association."""

    def __init__(self, output):
        super().__init__(output, {"method": (7, 3, HOOK, 18094)})
        self.result["scope"] = "root-object method values consumed by the JSON getter"
        self.result["comparisons"] = []

    async def drain(self, label):
        """Keep status-only records as well as complete and truncated values."""
        row = await self.run(
            "/work/ls_drain", "--segment", "/run/ls-stream/ls_tp_ring", "--once"
        )
        transport = [json.loads(line) for line in row["stdout"].splitlines()]
        self.result["batches"].append({"label": label, "transport": transport})
        assert "0 drop(s) seen" in row["stderr"], row
        identity = self.identities["method"]
        for item in transport:
            assert item["hook"] == "prog" and item["slot"] == 7, item
            event = decode(bytes.fromhex(item["data"]))
            assert item["len"] == 144
            assert event["instance"] == int(identity["instance"], 16)
            assert event["revision"] == identity["revision"]
            assert event["run"] == self.run_token and not event["flags"]
            assert not event["output_failures"] and event["monotonic_ns"]
            assert event["sequence"] == len(self.events) + 1
            self.events.append(event)
        return transport

    async def finish(self):
        """Reconcile getter invocations, then leave the hook restored."""
        for _ in range(3):
            await self.drain("settle")
            await asyncio.sleep(0.1)
        await self.cli("disarm", HOOK)
        self.armed_labels.remove("method")
        await self.drain("final")
        self.result["counter_end"] = await self.counters()
        before = self.result["counter_start"]["method"]
        after = self.result["counter_end"]["method"]
        assert after["fired"] - before["fired"] == len(self.events) > 0
        for key in ("errors", "safe_returns", "gen"):
            assert before[key] == after[key]

    async def compare(self, label, name, body, status, value=None, fragmented=False):
        """Compare an isolated test interval, not a production request identity."""
        start = len(self.events)
        await self.request(label, "/" + name, body, fragmented=fragmented)
        await self.drain(name)
        events = self.events[start:]
        comparison = {
            "case": name,
            "filter": label,
            "expected_status": status,
            "expected_value_hex": None if value is None else value.hex(),
            "events": events,
        }
        self.result["comparisons"].append(comparison)
        if status is None:
            assert not events, comparison
            return
        assert len(events) == 1 and events[0]["status_name"] == status, comparison
        event = events[0]
        if value is not None:
            assert event["original_length"] == len(value), comparison
            assert event["copied_length"] == min(len(value), 64), comparison
            assert event["value_hex"] == value[:64].hex(), comparison


async def method_test(log, _config, test_class=Method):
    """Test exact extraction, representation and explicit coverage limits."""
    test = test_class(Path(os.environ["ICAP_RESULT"]))
    with test.output.open("x", encoding="utf-8") as output:
        try:
            test.result["acknowledgements"] = await configure(log)
            left = await asyncio.start_server(test.origin, BACKEND, 18094)
            right = await asyncio.start_server(test.origin, BACKEND, 18095)
            async with left, right:
                await test.start()
                for name, value in (
                    ("known", b"SendMessage"),
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
                        "a2a",
                        name,
                        body,
                        "truncated" if len(value) > 64 else "complete",
                        value,
                        fragmented=name == "unfamiliar",
                    )
                await test.compare(
                    "a2a",
                    "nonstring",
                    b'{"jsonrpc":"2.0","id":1,"method":7,"params":{}}',
                    "getter_error",
                )
                await test.compare(
                    "a2a",
                    "budget",
                    b'{"jsonrpc":"2.0","id":1,"a":0,"b":0,"method":"late","params":{}}',
                    "budget_exhausted",
                )
                await test.compare(
                    "a2a",
                    "nested",
                    b'{"jsonrpc":"2.0","id":1,"params":{"method":"not-root"}}',
                    None,
                )
                await test.compare(
                    "aimcp",
                    "mcp-not-consumed",
                    b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}',
                    None,
                )
                await test.finish()
            assert len(test.result["origin"]) == len(test.result["clients"]) == 10
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
    """Expose the field-extraction test to Tao."""
    return [tao.test_types.DockerBaseTest2("root method extraction", method_test)]
