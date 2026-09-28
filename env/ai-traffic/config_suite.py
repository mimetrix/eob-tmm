"""SSA lifecycle proof for P21 input snapshots and existing event output."""

import asyncio
import json
import os
from pathlib import Path
import struct

import tao
import tao.runner
import tao.test_types

from icap_suite import BACKEND, VIP, configure, write_http_response

PORT = 18093
HOOK = "http_parse_client_headers"
SLOT = "5"
BODY = b"configuration-lifecycle\n"


class Lifecycle:
    """Keep command receipts, independent HTTP checks and per-phase events."""

    def __init__(self, output):
        self.output = output
        self.result = {"passed": False, "commands": [], "phases": [], "origin": []}
        self.armed = False
        self.loaded = False

    async def run(self, *command, refuse=False):
        """Capture stdout and exit status independently; enforce both."""
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), 35)
        except BaseException:
            process.kill()
            await process.wait()
            raise
        row = {
            "command": command,
            "returncode": process.returncode,
            "stdout": stdout.decode(),
            "stderr": stderr.decode(),
        }
        self.result["commands"].append(row)
        if refuse:
            assert process.returncode != 0, row
        else:
            assert process.returncode == 0, row
        return row

    async def cli(self, *args, refuse=False):
        """Legacy control commands need positive ACKs, not just exit zero."""
        row = await self.run("python3", "/work/ls-load.py", *args, refuse=refuse)
        if not refuse and args[0] != "config-status":
            assert row["stdout"].startswith("OK "), row
        return row["stdout"]

    async def identity(self):
        """Read the actual loaded-instance identity."""
        return json.loads(await self.cli("config-status", SLOT))

    async def load(self):
        """Only a signature-verified monitor load qualifies."""
        reply = await self.cli("load", SLOT, "/work/config-observe.bpf.o", "1")
        assert "signature=verified" in reply, reply
        self.loaded = True
        return await self.identity()

    async def arm(self):
        """Use the authenticated target; no manually supplied address."""
        await self.cli("arm", SLOT)
        self.armed = True

    async def disarm(self):
        """Restore only this test's attached target."""
        await self.cli("disarm", HOOK)
        self.armed = False

    async def publish(self, identity, tag, label, empty=False, refuse=False):
        """Keep the exact publisher document alongside each result."""
        document = dict(identity)
        document["expected_revision"] = document.pop("revision")
        document["revision"] = document["expected_revision"] + 1
        document["schema"] = 1
        document.pop("entries")
        document["rows"] = [] if empty else [struct.pack("<QQQQ", tag, 0, 0, 0).hex()]
        path = self.output.parent / (label + ".json")
        with path.open("x", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2)
        await self.cli("config-publish", SLOT, str(path), refuse=refuse)

    async def origin(self, reader, writer):
        """Serve independent fixed HTTP responses; never read configuration."""
        try:
            request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            self.result["origin"].append(
                {"request": request.decode(), "peer": writer.get_extra_info("peername")}
            )
            await write_http_response(writer, BODY)
        finally:
            writer.close()
            await writer.wait_closed()

    async def traffic(self, label, count=8):
        """Every request must reach the fixture and retain its exact response."""
        for index in range(count):
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(VIP, PORT), 10
            )
            try:
                writer.write(
                    (
                        f"GET /{label}/{index} HTTP/1.1\r\nHost: fixture\r\n"
                        "Connection: close\r\n\r\n"
                    ).encode()
                )
                await writer.drain()
                response = await asyncio.wait_for(reader.read(), 10)
                headers, body = response.split(b"\r\n\r\n", 1)
                assert headers.startswith(b"HTTP/1.1 200 ") and body == BODY, response
            finally:
                writer.close()
                await writer.wait_closed()

    async def stats(self):
        """Host counters are compared with client and collected record counts."""
        reply = await self.cli("status", SLOT)
        return {
            key: int(value)
            for key, value in (item.split("=") for item in reply.split()[1:])
        }

    async def phase(self, label, expected):
        """Drain only this isolated ring; exact count and zero drops are required."""
        before = await self.stats()
        await self.traffic(label)
        after = await self.stats()
        row = await self.run(
            "/work/ls_drain", "--segment", "/run/ls-stream/ls_tp_ring", "--once"
        )
        events = [json.loads(line) for line in row["stdout"].splitlines()]
        self.result["phases"].append(
            {"name": label, "before": before, "after": after, "events": events}
        )
        assert after["fired"] - before["fired"] == len(events) == 8
        assert after["errors"] == before["errors"] == 0
        assert after["safe_returns"] == before["safe_returns"] == 0
        assert "0 drop(s) seen" in row["stderr"], row
        for event in events:
            assert event["slot"] == 5 and event["len"] == 32, event
            decoded = struct.unpack("<QQQII", bytes.fromhex(event["data"]))
            assert decoded == expected, decoded

    async def exercise(self):
        """Prove missing-input, updates, withdrawal, reload identity and revoke."""
        await self.cli("config-status", SLOT, refuse=True)
        first = await self.load()
        assert first["revision"] == 0
        await self.arm()
        await self.phase("no-input", (0, 0, 0, 0, 0))
        await self.publish(first, 101, "publish-first")
        current = await self.identity()
        token = int(current["instance"], 16)
        await self.phase("first", (token, 1, 101, 1, 1))
        await self.publish(first, 999, "stale-revision", refuse=True)
        for field, value in (
            ("session", "0000000000000001"),
            ("instance", "8000000000000005"),
            ("program_sha256", "00" * 32),
        ):
            stale = dict(current, **{field: value})
            await self.publish(stale, 999, "stale-" + field, refuse=True)
        assert await self.identity() == current
        await self.publish(current, 202, "publish-second")
        current = await self.identity()
        await self.phase("second", (token, 2, 202, 1, 1))
        await self.publish(current, 0, "withdraw", empty=True)
        current = await self.identity()
        await self.phase("empty", (token, 3, 0, 1, 0))
        await self.disarm()
        replacement = await self.load()
        assert (
            replacement["instance"] != first["instance"]
            and replacement["revision"] == 0
        )
        await self.publish(current, 999, "previous-instance", refuse=True)
        await self.arm()
        await self.phase("reload-no-input", (0, 0, 0, 0, 0))
        await self.publish(replacement, 303, "replacement-policy")
        await self.phase(
            "replacement", (int(replacement["instance"], 16), 1, 303, 1, 1)
        )
        await self.disarm()
        before = await self.stats()
        await self.traffic("disarmed", count=2)
        assert (await self.stats())["fired"] == before["fired"]
        await self.cli("revoke", SLOT)
        self.loaded = False
        await self.cli("config-status", SLOT, refuse=True)


async def configuration_test(log, _config):
    """Run and preserve cleanup failures instead of reporting a false success."""
    test = Lifecycle(Path(os.environ["ICAP_RESULT"]))
    with test.output.open("x", encoding="utf-8") as output:
        try:
            test.result["acknowledgements"] = await configure(log, port=PORT)
            async with await asyncio.start_server(test.origin, BACKEND, PORT):
                await test.traffic("baseline", count=2)
                await test.exercise()
            assert len(test.result["origin"]) == 52
            assert {row["peer"][0] for row in test.result["origin"]} == {"10.203.74.10"}
            test.result["passed"] = True
        except Exception as error:
            test.result["error"] = repr(error)
            raise
        finally:
            try:
                if test.armed:
                    await test.disarm()
                if test.loaded:
                    await test.cli("revoke", SLOT)
            except Exception as error:
                test.result.update(passed=False, cleanup_error=repr(error))
                raise
            finally:
                json.dump(test.result, output, indent=2, sort_keys=True)
                output.write("\n")
    assert test.result["passed"], test.result
    return tao.Result.PASS


def publish_tests():
    """Only the explicitly selected lifecycle test is exposed."""
    return [
        tao.test_types.DockerBaseTest2("configuration lifecycle", configuration_test)
    ]
