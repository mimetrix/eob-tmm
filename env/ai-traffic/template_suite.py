"""Run both tutorial variants on the isolated SSA HTTP listener."""
import asyncio
import ipaddress
import json
import os
from pathlib import Path

import tao
import tao.runner
import tao.test_types

from config_suite import Lifecycle, PORT, SLOT
from icap_suite import BACKEND, configure


class Tutorial(Lifecycle):
    """Check live inputs, observations, state and monitor-only selection."""

    def __init__(self, output):
        super().__init__(output)
        self.kind = "entry"
        self.current = None

    async def load(self):
        directory = Path(os.environ.get("TEMPLATE_PROGRAM_DIR", "/work"))
        reply = await self.cli(
            "load", SLOT, str(directory / ("template-" + self.kind + ".bpf.o")), "1"
        )
        assert "signature=verified" in reply, reply
        self.loaded = True
        self.current = await self.identity()
        assert self.current["revision"] == 0

    async def policy(self, label, *options):
        """Exercise the shipped policy CLI, not a test-only row encoder."""
        identity = self.output.parent / (label + "-identity.json")
        identity.write_text(json.dumps(await self.identity()))
        generated = await self.run(
            "python3",
            "/work/template_io.py",
            "policy",
            "--identity",
            str(identity),
            *options
        )
        policy = self.output.parent / (label + "-policy.json")
        with policy.open("x") as output:
            output.write(generated["stdout"])
        await self.cli("config-publish", SLOT, str(policy))
        self.current = await self.identity()

    # Keep explicit expectations beside each phase and retain its full receipt.
    # pylint: disable=too-many-arguments,too-many-locals
    async def observe(self, label, *, flags=0, matched=0, verdict=0, seen=None):
        """Require exact hook counts, decode real output, and check HTTP results."""
        label = self.kind + "-" + label
        before = await self.stats()
        await self.traffic(label)
        after = await self.stats()
        drained = await self.run(
            "/work/ls_drain", "--segment", "/run/ls-stream/ls_tp_ring", "--once"
        )
        raw = self.output.parent / (label + "-events.jsonl")
        raw.write_text(drained["stdout"])
        # Use the real decoder with a file as stdin; retain both forms.
        decoded = await self.run(
            "python3",
            "-c",
            "import subprocess,sys; "
            "f=open(sys.argv[1]); "
            "raise SystemExit(subprocess.call([sys.executable,"
            "'/work/template_io.py','decode'],stdin=f))",
            str(raw),
        )
        events = [json.loads(line) for line in decoded["stdout"].splitlines()]
        transport = [json.loads(line) for line in drained["stdout"].splitlines()]
        self.result["phases"].append(
            {
                "name": label,
                "before": before,
                "after": after,
                "events": events,
                "transport": transport,
            }
        )
        assert after["mode"] == before["mode"] == 1
        assert after["fired"] - before["fired"] == 8
        assert after["errors"] == before["errors"] == 0
        assert after["safe_returns"] - before["safe_returns"] == 8 * verdict
        assert "0 drop(s) seen" in drained["stderr"], drained
        assert len(events) == 8, events
        if flags == 0 and self.kind == "entry":
            assert [event["tutorial"]["observed"] for event in events] == [
                len(row["request"].encode()) for row in self.result["origin"][-8:]
            ]
        if seen is not None:
            counts = [event["tutorial"]["seen"] for event in events]
            assert counts == list(range(seen, seen + 8)), events
        for event in events:
            value = event["tutorial"]
            assert event["transport"]["slot"] == 5
            assert value["kind"] == (1 if self.kind == "entry" else 2)
            assert value["flags"] == flags and value["matched"] == matched
            assert value["verdict"] == verdict and value["monotonic_ns"] > 0
            assert value["revision"] == self.current["revision"]
            expected_instance = 0 if flags == 1 else int(self.current["instance"], 16)
            assert value["instance"] == expected_instance
            if flags == 0 and self.kind == "entry":
                assert value["observed"] > 0 and value["header_count"] > 0, value
            if self.kind == "exit":
                assert value["observed"] == value["result"]
                assert value["version"] == value["header_count"] == 0

    async def prime_maps(self):
        """Use both output-map indices before the tutorial replaces them."""
        await self.cli("config-status", SLOT, refuse=True)
        segment = Path("/run/ls-stream/ls_tp_ring")
        if segment.exists():
            stale = await self.run(
                "/work/ls_drain", "--segment", str(segment), "--once"
            )
            self.result["initial_drain"] = stale
        else:
            self.result["initial_drain"] = {"segment_exists": False}
        # Allocate output-map storage, then replace that registry with the
        # tutorial's HASH at the reused index. A fresh process hid this defect.
        directory = Path(os.environ.get("TEMPLATE_PROGRAM_DIR", "/work"))
        reply = await self.cli(
            "load", SLOT, str(directory / "config-observe.bpf.o"), "1"
        )
        assert "signature=verified" in reply, reply
        self.loaded = True
        await self.arm()
        before = await self.stats()
        await self.traffic("output-map-precursor")
        after = await self.stats()
        drained = await self.run("/work/ls_drain", "--segment", str(segment), "--once")
        events = [json.loads(line) for line in drained["stdout"].splitlines()]
        self.result["precursor"] = {"before": before, "after": after, "events": events}
        assert after["fired"] - before["fired"] == 8
        assert after["errors"] == before["errors"] == 0
        assert after["safe_returns"] == before["safe_returns"] == 0
        assert len(events) == 16 and "0 drop(s) seen" in drained["stderr"]
        assert all(
            event["slot"] == 5
            and event["len"] == 32
            and bytes.fromhex(event["data"]) == bytes(32)
            for event in events
        )
        await self.disarm()
        await self.cli("revoke", SLOT)
        self.loaded = False
        await self.cli("config-status", SLOT, refuse=True)

    async def exercise(self):
        """Run sequential variants so their same-name maps cannot interfere."""
        await self.prime_maps()
        directory = Path(os.environ.get("TEMPLATE_PROGRAM_DIR", "/work"))
        for kind in ("entry", "exit"):
            self.kind = kind
            await self.load()
            await self.arm()
            await self.observe("missing", flags=1)
            await self.policy(kind + "-high", "--threshold", str((1 << 64) - 1))
            await self.observe("high", seen=1)
            # Revoking a second loaded slot must preserve this active slot's
            # map references and count. The next phase must start at nine.
            try:
                reply = await self.cli(
                    "load", "6", str(directory / ("template-" + kind + ".bpf.o")), "1"
                )
                assert "signature=verified" in reply, reply
            finally:
                await self.cli("revoke", "6")
            await self.cli("config-status", "6", refuse=True)
            await self.policy(
                kind + "-low", "--threshold", "0", "--request-safe-return"
            )
            verdict = int(kind == "entry")
            await self.observe("low", matched=1, verdict=verdict, seen=9)
            await self.policy(
                kind + "-continuous", "--threshold", "0", "--request-safe-return"
            )
            await self.observe("continuous", matched=1, verdict=verdict, seen=17)
            await self.policy(kind + "-reset", "--threshold", "0", "--reset-token", "2")
            await self.observe("reset", matched=1, seen=1)
            await self.policy(kind + "-disable", "--enabled", "0", "--reset-token", "2")
            await self.observe("disabled", flags=32)
            await self.policy(
                kind + "-enable", "--threshold", "0", "--reset-token", "2"
            )
            await self.observe("enabled", matched=1, seen=1)
            await self.disarm()
            before = await self.stats()
            await self.traffic(kind + "-disarmed", count=2)
            assert (await self.stats())["fired"] == before["fired"]
            await self.cli("revoke", SLOT)
            self.loaded = False
            await self.cli("config-status", SLOT, refuse=True)


async def tutorial_test(log, _config):
    """Keep result JSON even when a check or cleanup fails."""
    test = Tutorial(Path(os.environ["ICAP_RESULT"]))
    with test.output.open("x") as output:
        try:
            test.result["acknowledgements"] = await configure(log, port=PORT)
            async with await asyncio.start_server(test.origin, BACKEND, PORT):
                await test.traffic("tutorial-baseline", count=2)
                await test.exercise()
            assert len(test.result["origin"]) == 126
            # These isolated fixtures assign backend .11 and TMM .10.
            expected_peer = str(ipaddress.ip_address(BACKEND) - 1)
            assert {row["peer"][0] for row in test.result["origin"]} == {expected_peer}
            test.result["completed"] = True
            test.result["passed"] = True
        except BaseException as error:
            test.result["error"] = repr(error)
            raise
        finally:
            try:
                if test.armed:
                    await test.disarm()
                if test.loaded:
                    await test.cli("revoke", SLOT)
            except BaseException as error:
                test.result.update(passed=False, cleanup_error=repr(error))
                raise
            finally:
                json.dump(test.result, output, indent=2)
    return tao.Result.PASS if test.result["passed"] else tao.Result.FAIL


def publish_tests():
    """Expose only the selected tutorial test."""
    return [tao.test_types.DockerBaseTest2("tutorial lifecycle", tutorial_test)]
