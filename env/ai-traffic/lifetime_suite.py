"""Observe parser birth/end intervals; do not enable authenticated attribution."""
import asyncio
from collections import Counter
import ipaddress
import json
import os
from pathlib import Path
import struct
import uuid

import tao
import tao.runner
import tao.test_types

from attribution_suite import concurrent
from config_suite import PORT
from icap_suite import BACKEND, VIP, configure
from request_scope_suite import Scope

PROGRAMS = {"init": (6, 1, "http_parse_ctx_init"),
            "parse": (5, 2, "http_parse_client_headers"),
            "fini": (7, 3, "http_parse_ctx_fini")}
FIELDS = ("magic", "abi", "run", "sequence", "lifetime", "attempt", "value",
          "failures", "kind", "flags")


class ParserLifetime(Scope):
    """Track all three hooks and retain deliberate missing-boundary diagnostics."""

    def __init__(self, output):
        super().__init__(output)
        self.run_token = uuid.uuid4().int & ((1 << 64) - 1)
        self.loaded_slots = set()
        self.armed_hooks = set()
        self.expect_unknown = False
        self.events = []
        self.active = set()
        self.result.update(events=self.events, run_token=self.run_token,
                           scope="observed parser intervals in one HTTP/1 worker",
                           batches=[], request_scope_validated=False)

    async def cli(self, *args, refuse=False):
        """Convert numeric slot values to process arguments."""
        return await super().cli(*(str(value) for value in args), refuse=refuse)

    async def all_stats(self):
        """Read the three slot counters without using lifetime totals as deltas."""
        result = {}
        for label, (slot, _, _) in PROGRAMS.items():
            text = await self.cli("status", str(slot))
            result[label] = {key: int(value) for key, value in
                             (word.split("=") for word in text.split()[1:])}
        return result

    async def start(self):
        """Load all programs before attaching; publish the same unique run token."""
        directory = Path(os.environ["TEMPLATE_PROGRAM_DIR"])
        if Path("/run/ls-stream/ls_tp_ring").exists():
            self.result["initial_drain"] = await self.run(
                "/work/ls_drain", "--segment", "/run/ls-stream/ls_tp_ring", "--once")
        for label, (slot, _, _) in PROGRAMS.items():
            reply = await self.cli("load", str(slot),
                                   str(directory / ("lifetime-" + label + ".bpf.o")), "1")
            assert "signature=verified" in reply
            self.loaded_slots.add(slot)
            identity = json.loads(await self.cli("config-status", str(slot)))
            document = dict(identity)
            document["expected_revision"] = document.pop("revision")
            document["revision"] = document["expected_revision"] + 1
            document["schema"] = 1
            document.pop("entries")
            document["rows"] = [struct.pack("<4Q", self.run_token, 0, 0, 0).hex()]
            path = self.output.parent / ("lifetime-config-" + label + ".json")
            with path.open("x") as stream:
                json.dump(document, stream, indent=2)
            await self.cli("config-publish", str(slot), str(path))
        self.result["counter_start"] = await self.all_stats()
        for label in ("init", "fini", "parse"):
            await self.attach(label)

    async def attach(self, label):
        """Attach only the signed target for this slot."""
        await self.cli("arm", str(PROGRAMS[label][0]))
        self.armed_hooks.add(label)

    async def detach(self, label):
        """Restore this experiment's target bytes."""
        await self.cli("disarm", PROGRAMS[label][2])
        self.armed_hooks.remove(label)

    async def drain(self, label):
        """Keep every record, including negative-case diagnostics."""
        row = await self.run("/work/ls_drain", "--segment",
                             "/run/ls-stream/ls_tp_ring", "--once")
        transport = [json.loads(line) for line in row["stdout"].splitlines()]
        values = []
        self.result["batches"].append({"label": label, "transport": transport})
        assert "0 drop(s) seen" in row["stderr"], row
        for item in transport:
            assert item["hook"] == "prog" and item["len"] == 64, item
            event = dict(zip(FIELDS, struct.unpack("<II6QII", bytes.fromhex(item["data"]))))
            self.events.append(event)
            values.append(event)
            assert event["magic"] == 0x4C494645 and event["abi"] == 1
            assert event["run"] == self.run_token and not event["failures"]
            assert event["sequence"] == len(self.events), event
            assert item["slot"] == {1: 6, 2: 5, 3: 7}[event["kind"]]
            assert event["flags"] in (0, 32, 256), event
            if event["kind"] == 1:
                assert not event["flags"] and event["lifetime"] not in self.active
                self.active.add(event["lifetime"])
            elif event["kind"] == 3 and event["lifetime"]:
                assert event["lifetime"] in self.active, event
                self.active.remove(event["lifetime"])
        return values

    async def collect(self, name, before, complete, calls, **details):
        """Associate a controlled test window with parser calls, not an identity."""
        after = await self.stats()
        events = await self.drain(name)
        parsed = [e for e in events if e["kind"] == 2]
        phase = {"name": name, "before": before, "after": after,
                 "events": events, "complete_headers": complete,
                 "expect_unknown": self.expect_unknown, **details}
        self.result["phases"].append(phase)
        assert before["mode"] == after["mode"] == 1
        assert before["gen"] == after["gen"]
        assert after["fired"] - before["fired"] == len(parsed) == calls, phase
        assert after["errors"] == before["errors"]
        assert after["safe_returns"] == before["safe_returns"]
        assert sum(e["value"] == 0 for e in parsed) == complete
        for event in parsed:
            assert event["value"] in (0, 17)
            assert event["flags"] == (32 if self.expect_unknown else 0), event
            assert bool(event["lifetime"]) != self.expect_unknown
        return events

    async def settle(self, label, unknown_end=False):
        """Wait for observed ends after all clients in the window have closed."""
        quiet = 0
        seen_unknown = not unknown_end
        for _ in range(80):
            events = await self.drain(label)
            seen_unknown |= any(e["kind"] == 3 and e["flags"] == 32 for e in events)
            quiet = 0 if events else quiet + 1
            if not self.active and seen_unknown and quiet >= 5:
                return
            await asyncio.sleep(0.1)
        raise AssertionError(f"parser cleanup did not settle: {sorted(self.active)}")

    async def exercise(self):
        """Test complete, partial and absent boundaries on real proxy traffic."""
        late = await self.client(False)
        await late.request("before-attach", "agent-A", "/mcp", "tools/call", "agent-A")
        await self.start()
        self.expect_unknown = True
        before = await self.stats()
        await late.request("late-attach", "agent-B", "/mcp", "tools/call", "agent-B")
        await self.collect("late-attach", before, 1, 1)
        await late.close()
        await self.settle("late-close", unknown_end=True)
        await self.detach("init")
        missed = await self.client()
        await missed.request("missing-init", "agent-A", "/mcp", "tools/call", "agent-A")
        await self.attach("init")
        await missed.request("init-restored-existing-connection", "agent-B", "/mcp", "tools/call", "agent-B")
        await missed.close()
        await self.settle("missing-init-close", unknown_end=True)
        self.expect_unknown = False
        shared = await self.client()
        for index in range(4):
            actor = "agent-A" if index % 2 == 0 else "agent-B"
            await shared.request(f"keepalive-{index}", actor, "/mcp", "tools/call", actor)
        nonce = uuid.uuid4().hex
        shared.pacing = "headers"
        for label, actor, status in (("A", "agent-A", 200), ("B", "agent-B", 200),
                                     ("replay-A", "agent-A", 403)):
            await shared.request("fragmented-" + label, actor, "/mcp", "tools/call",
                                 actor, nonce=nonce, status=status)
        shared.pacing = "body"
        await shared.request("paced-body", "agent-A", "/mcp", "tools/call", "agent-A")
        await shared.close()
        await self.settle("shared-close")
        left, right = await self.client(False), await self.client(False)
        before = await self.stats()
        await asyncio.gather(concurrent(left, "agent-A"), concurrent(right, "agent-B"))
        await self.collect("concurrent", before, 8, 8)
        await asyncio.gather(left.close(), right.close())
        await self.settle("concurrent-close")
        before = await self.stats()
        _, writer = await asyncio.open_connection(VIP, PORT)
        try:
            writer.write(b"POST /mcp HT")
            await writer.drain()
            await self.wait_fired(before["fired"] + 1)
        finally:
            writer.close()
            await writer.wait_closed()
        await self.collect("aborted-header", before, 0, 1)
        await self.settle("abort-close")
        for index in range(32):
            client = await self.client()
            actor = "agent-A" if index % 2 == 0 else "agent-B"
            await client.request(f"new-connection-{index}", actor, "/mcp", "tools/call", actor)
            await client.close()
            await self.settle(f"new-close-{index}")
        self.result["counter_end"] = await self.all_stats()
        await self.stop()
        before = await self.all_stats()
        final = await self.client(False)
        await final.request("after-disarm", "agent-A", "/mcp", "tools/call", "agent-A")
        await final.close()
        assert before == await self.all_stats()

    async def stop(self):
        """Attempt every cleanup action, even when one action fails."""
        errors = []
        for label in tuple(self.armed_hooks):
            try:
                await self.detach(label)
            except BaseException as error:
                errors.append(repr(error))
        for slot in tuple(self.loaded_slots):
            try:
                await self.cli("revoke", str(slot))
                self.loaded_slots.remove(slot)
                await self.cli("config-status", str(slot), refuse=True)
            except BaseException as error:
                errors.append(repr(error))
        if errors:
            self.result["cleanup_errors"] = errors
            raise AssertionError(errors)

    def reconcile(self):
        """Validate observed intervals; keep the authentication join closed."""
        counts = Counter(e["kind"] for e in self.events)
        for label, (_, kind, _) in PROGRAMS.items():
            before, after = self.result["counter_start"][label], self.result["counter_end"][label]
            assert after["fired"] - before["fired"] == counts[kind]
            assert after["errors"] == before["errors"]
            assert after["safe_returns"] == before["safe_returns"]
            assert after["gen"] == before["gen"]
        born, ended, pending, attempts = {}, set(), {}, Counter()
        reused, complete, unknown = [], [], []
        for event in self.events:
            life = event["lifetime"]
            if event["kind"] == 1:
                assert life not in born
                if event["value"]:
                    assert event["value"] in ended
                    reused.append({"old": event["value"], "new": life})
                born[life] = event
            elif event["flags"] == 32:
                assert not life and not event["attempt"]
                if event["kind"] == 2:
                    unknown.append(event)
            elif event["kind"] == 2:
                assert life in born and life not in ended
                if not pending.get(life):
                    attempts[life] += 1
                assert event["attempt"] == attempts[life]
                pending[life] = event["value"] == 17
                if not pending[life]:
                    complete.append(event)
            else:
                assert life in born and life not in ended
                assert event["flags"] == (256 if pending.get(life) else 0)
                assert event["attempt"] == attempts[life]
                ended.add(life)
        assert set(born) == ended and not self.active
        assert reused, "no address reuse witnessed"
        assert len(complete) == 48 and len(unknown) == 3
        assert counts[2] == 58
        assert sum(e["flags"] == 256 for e in self.events) == 1
        shared = [p for p in self.result["phases"] if p["name"].startswith(("keepalive-", "fragmented-", "paced-body"))]
        assert len(shared) == 8
        assert len({e["lifetime"] for p in shared for e in p["events"] if e["kind"] == 2}) == 1
        clients, ledger = self.result["clients"], self.authority.ledger
        assert len(clients) == len(ledger) == 53
        assert not self.authority.errors
        by_attempt = {row["attempt"]: row for row in ledger}
        assert len(by_attempt) == len(ledger)
        for row in clients:
            assert row["result"] == by_attempt[row["result"]["attempt"]]
            assert row["body_sha256"] == row["result"]["body_sha256"]
        assert {r["peer"][0] for r in ledger} == {str(ipaddress.ip_address(BACKEND) - 1)}
        self.result.update(observed_parser_intervals_validated=True, address_reuse=reused,
                           summary={"events": len(self.events), "hook_counts": dict(counts),
                                    "closed_lifetimes": len(born), "known_header_attempts": len(complete),
                                    "unknown_header_attempts": len(unknown), "http_responses": len(clients),
                                    "accepted": sum(r["accepted"] for r in ledger),
                                    "request_scope_validated": False})


async def parser_lifetime_test(log, _config):
    """Keep the test result and all cleanup failures."""
    test = ParserLifetime(Path(os.environ["ICAP_RESULT"]))
    with test.output.open("x") as output:
        try:
            test.result["acknowledgements"] = await configure(log, port=PORT)
            async with await asyncio.start_server(test.authority.serve, BACKEND, PORT):
                await test.exercise()
                test.reconcile()
            test.result["passed"] = True
        except BaseException as error:
            test.result["error"] = repr(error)
            raise
        finally:
            try:
                await asyncio.gather(*(c.close() for c in test.clients))
                await test.stop()
            except BaseException as error:
                test.result.update(passed=False, cleanup_error=repr(error))
                raise
            finally:
                json.dump(test.result, output, indent=2)
    return tao.Result.PASS


def publish_tests():
    """Expose only the registered parser-lifetime experiment."""
    return [tao.test_types.DockerBaseTest2("parser lifetime gate", parser_lifetime_test)]
