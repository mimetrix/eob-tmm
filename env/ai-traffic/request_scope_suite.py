"""Challenge parser-call scope with live, destination-authenticated traffic."""
import asyncio
from collections import Counter, defaultdict
import ipaddress
import json
import os
from pathlib import Path
import struct
import uuid

import tao
import tao.runner
import tao.test_types

from attribution import Authority, Client, read_message
from attribution_join import join
from attribution_suite import exercise, concurrent
from config_suite import Lifecycle, PORT, SLOT
from icap_suite import BACKEND, VIP, configure


FIELDS = (
    "magic",
    "abi",
    "instance",
    "call_seq",
    "context_tag",
    "completions",
    "result",
    "output_failures",
    "flags",
    "reserved",
)


class ScopeClient(Client):
    """Pace fragments without writing proofs or request bodies to the receipt."""

    def __init__(self, reader, writer, test):
        super().__init__(reader, writer, test.authority.keys, test.result["clients"])
        self.test = test
        self.connection_label = uuid.uuid4().hex
        self.pacing = "plain"
        self.checkpoints = []

    async def checkpoint(self, fired, completed=False):
        """Wait for observed execution before sending the next fragment."""
        row = await self.test.wait_fired(fired)
        row["body_sent"] = False
        row["header_complete"] = completed
        row["ledger_attempts"] = len(self.test.authority.ledger)
        self.checkpoints.append(row)

    async def exchange(self, headers, body):
        block = headers.encode() + b"\r\n"
        if self.pacing == "plain":
            return await super().exchange(headers, body)
        before = await self.test.stats()
        ledger_before = len(self.test.authority.ledger)
        if self.pacing == "headers":
            # Split the request line and the final header terminator. Each
            # fragment must reach the parser before the next write starts.
            parts = (block[:7], block[7:-1], block[-1:] + body)
            for index, part in enumerate(parts):
                self.writer.write(part)
                await self.writer.drain()
                if index < 2:
                    await self.checkpoint(before["fired"] + index + 1)
                    assert len(self.test.authority.ledger) == ledger_before
        else:
            assert self.pacing == "body"
            self.writer.write(block)
            await self.writer.drain()
            await self.checkpoint(before["fired"] + 1, completed=True)
            assert len(self.test.authority.ledger) == ledger_before
            halfway = len(body) // 2
            self.writer.write(body[:halfway])
            await self.writer.drain()
            await asyncio.sleep(0.05)
            assert len(self.test.authority.ledger) == ledger_before
            self.writer.write(body[halfway:])
            await self.writer.drain()
        first, _, raw = await read_message(self.reader)
        return int(first.split()[1]), json.loads(raw)

    async def request(self, name, *args, **kwargs):
        before = await self.test.stats()
        self.checkpoints = []
        response = await super().request(name, *args, **kwargs)
        await self.test.collect(
            name,
            before,
            1,
            3 if self.pacing == "headers" else 1,
            connection=self.connection_label,
            attempt=response["attempt"],
            checkpoints=self.checkpoints,
        )
        return response


class Scope(Lifecycle):
    """Use exact windows for diagnostic counts; keep the identity gate closed."""

    def __init__(self, output):
        super().__init__(output)
        self.authority = Authority()
        self.clients = []
        self.current = None
        self.result.update(
            clients=[],
            server=self.authority.ledger,
            server_errors=self.authority.errors,
            request_scope_validated=False,
            scope="HTTP/1.1 parser exits; address equality is not object lifetime",
        )

    async def client(self, observed=True):
        """Open a real client connection and keep its cleanup handle."""
        reader, writer = await asyncio.open_connection(VIP, PORT)
        value = (
            ScopeClient(reader, writer, self)
            if observed
            else Client(reader, writer, self.authority.keys, self.result["clients"])
        )
        self.clients.append(value)
        return value

    async def wait_fired(self, minimum):
        """Require the exact call count before the next fragment is sent."""
        for _ in range(40):
            value = await self.stats()
            if value["fired"] >= minimum:
                assert value["fired"] == minimum, value
                return value
            await asyncio.sleep(0.025)
        raise AssertionError("parser did not observe the paced fragment")

    async def collect(self, name, before, complete, calls, **details):
        """Retain all records and require exact call, result and loss counts."""
        after = await self.stats()
        drained = await self.run(
            "/work/ls_drain", "--segment", "/run/ls-stream/ls_tp_ring", "--once"
        )
        transport = [json.loads(line) for line in drained["stdout"].splitlines()]
        events = []
        phase = {
            "name": name,
            "before": before,
            "after": after,
            "transport": transport,
            "events": events,
            "complete_headers": complete,
            **details,
        }
        self.result["phases"].append(phase)
        for row in transport:
            assert row["hook"] == "prog" and row["slot"] == 5 and row["len"] == 64, row
            events.append(
                dict(zip(FIELDS, struct.unpack("<II6QII", bytes.fromhex(row["data"]))))
            )
        assert "0 drop(s) seen" in drained["stderr"], drained
        assert after["mode"] == before["mode"] == 1
        assert after["gen"] == before["gen"]
        assert after["fired"] - before["fired"] == len(events) == calls, phase
        # Slot counters survive earlier programs. Require zero new errors or
        # selections in this window, not zero over the slot's entire history.
        assert after["errors"] == before["errors"]
        assert after["safe_returns"] == before["safe_returns"]
        assert sum(event["result"] == 0 for event in events) == complete, phase
        for event in events:
            assert event["magic"] == 0x53434F50 and event["abi"] == 1
            assert event["instance"] == int(self.current["instance"], 16)
            assert not (event["flags"] or event["reserved"] or event["output_failures"])
            assert event["context_tag"] > 0 and event["call_seq"] > 0
            assert event["result"] in (0, 17), event
        return events

    async def exercise(self):  # pylint: disable=too-many-locals
        """Challenge parser calls while the signed observer runs in monitor mode."""
        directory = Path(os.environ["TEMPLATE_PROGRAM_DIR"])
        await self.cli("config-status", SLOT, refuse=True)
        if Path("/run/ls-stream/ls_tp_ring").exists():
            self.result["initial_drain"] = await self.run(
                "/work/ls_drain", "--segment", "/run/ls-stream/ls_tp_ring", "--once"
            )
        reply = await self.cli(
            "load", SLOT, str(directory / "request-scope.bpf.o"), "1"
        )
        assert "signature=verified" in reply, reply
        self.loaded = True
        self.current = await self.identity()
        await self.publish(self.current, 0, "scope-metadata")
        self.current = await self.identity()
        await self.arm()
        first = await self.stats()
        shared = await self.client()
        await exercise(shared)
        # Two independently verified actors deliberately reuse the same nonce.
        nonce = uuid.uuid4().hex
        shared.pacing = "headers"
        for label, actor, status in (
            ("A", "agent-A", 200),
            ("B", "agent-B", 200),
            ("replay-A", "agent-A", 403),
        ):
            await shared.request(
                "fragmented-" + label,
                actor,
                "/mcp",
                "tools/call",
                actor,
                nonce=nonce,
                status=status,
            )
        shared.pacing = "body"
        await shared.request("paced-body", "agent-A", "/mcp", "tools/call", "agent-A")
        await shared.close()
        # Concurrent windows are reconciled as a set, never paired by time.
        left, right = await self.client(False), await self.client(False)
        before = await self.stats()
        await asyncio.gather(concurrent(left, "agent-A"), concurrent(right, "agent-B"))
        await self.collect("concurrent", before, 8, 8)
        await left.close()
        await right.close()
        before = await self.stats()
        reader, writer = await asyncio.open_connection(VIP, PORT)
        del reader
        try:
            writer.write(b"POST /mcp HT")
            await writer.drain()
            await self.wait_fired(before["fired"] + 1)
        finally:
            writer.close()
            await writer.wait_closed()
        await self.collect("aborted-header", before, 0, 1)
        for index in range(32):
            client = await self.client()
            actor = "agent-A" if index % 2 == 0 else "agent-B"
            await client.request(
                f"new-connection-{index}", actor, "/mcp", "tools/call", actor
            )
            await client.close()
        last = await self.stats()
        self.result["armed_accounting"] = {"before": first, "after": last}
        await self.disarm()
        await self.cli("revoke", SLOT)
        self.loaded = False
        await self.cli("config-status", SLOT, refuse=True)

    def reconcile(self):  # pylint: disable=too-many-locals
        """Check independent ledgers and refuse attribution for these call records."""
        phases = self.result["phases"]
        events = [event for phase in phases for event in phase["events"]]
        completed = [event for event in events if event["result"] == 0]
        clients, ledger = self.result["clients"], self.authority.ledger
        assert len(clients) == len(ledger) == 61
        assert len(events) == 66 and len(completed) == 59
        first = self.result["armed_accounting"]["before"]
        last = self.result["armed_accounting"]["after"]
        assert last["fired"] - first["fired"] == len(events)
        assert last["errors"] == first["errors"]
        assert last["safe_returns"] == first["safe_returns"]
        assert not self.authority.errors, self.authority.errors
        expected_peer = str(ipaddress.ip_address(BACKEND) - 1)
        assert {row["peer"][0] for row in ledger} == {expected_peer}
        by_attempt = {row["attempt"]: row for row in ledger}
        assert len(by_attempt) == len(ledger)
        for row in clients:
            observed = by_attempt[row["result"]["attempt"]]
            assert (
                observed == row["result"]
                and observed["body_sha256"] == row["body_sha256"]
            )
        assert [row["call_seq"] for row in events] == list(range(1, 67))
        counts = Counter()
        for event in events:
            counts[event["context_tag"]] += int(event["result"] == 0)
            assert event["completions"] == counts[event["context_tag"]]
        shared = [phase for phase in phases if "connection" in phase][:19]
        assert len({phase["connection"] for phase in shared}) == 1
        assert (
            len({by_attempt[phase["attempt"]]["connection"] for phase in shared}) == 1
        )
        assert (
            len({event["context_tag"] for phase in shared for event in phase["events"]})
            == 1
        )
        tagged_connections = defaultdict(set)
        for phase in phases:
            if "connection" in phase:
                for event in phase["events"]:
                    tagged_connections[event["context_tag"]].add(phase["connection"])
        reuse = {
            str(tag): sorted(values)
            for tag, values in tagged_connections.items()
            if len(values) > 1
        }
        # No nonce or request identity is invented from the call or address tag.
        armed_ledger = [
            row
            for row in ledger
            if row["attempt"]
            not in {clients[0]["result"]["attempt"], clients[-1]["result"]["attempt"]}
        ]
        accounting = {
            "requests": 59,
            "fired": 66,
            "events": 66,
            "ledger_attempts": 59,
            "drops": 0,
            "errors": 0,
        }
        result = join(
            completed,
            armed_ledger,
            accounting=accounting,
            request_scope_validated=False,
        )
        assert len(result) == 59
        assert all(
            row["status"] == "unknown" and row["reason"] == "unvalidated_request_scope"
            for row in result
        )
        self.result.update(
            join=result,
            address_tag_reuse=reuse,
            summary={
                "http_responses": 61,
                "armed_complete_headers": 59,
                "parser_calls": 66,
                "partial_header_returns": 7,
                "accepted": sum(row["accepted"] for row in ledger),
                "rejected": sum(not row["accepted"] for row in ledger),
                "unknown_joins": 59,
                "distinct_address_tags": len(counts),
            },
        )


async def request_scope_test(log, _config):
    """Keep both successful and failed test/cleanup records."""
    test = Scope(Path(os.environ["ICAP_RESULT"]))
    with test.output.open("x") as output:
        try:
            test.result["acknowledgements"] = await configure(log, port=PORT)
            async with await asyncio.start_server(test.authority.serve, BACKEND, PORT):
                baseline = await test.client(False)
                await baseline.request(
                    "unarmed-baseline", "agent-A", "/mcp", "tools/call", "agent-A"
                )
                await baseline.close()
                await test.exercise()
                after = await test.stats()
                final = await test.client(False)
                await final.request(
                    "disarmed-check", "agent-B", "/mcp", "tools/call", "agent-B"
                )
                await final.close()
                assert (await test.stats())["fired"] == after["fired"]
                await asyncio.sleep(0.1)
                test.reconcile()
            test.result["passed"] = True
        except BaseException as error:
            test.result["error"] = repr(error)
            raise
        finally:
            try:
                closed = await asyncio.gather(
                    *(client.close() for client in test.clients), return_exceptions=True
                )
                if test.armed:
                    await test.disarm()
                if test.loaded:
                    await test.cli("revoke", SLOT)
                errors = [
                    repr(value) for value in closed if isinstance(value, BaseException)
                ]
                assert not errors, errors
            except BaseException as error:
                test.result.update(passed=False, cleanup_error=repr(error))
                raise
            finally:
                json.dump(test.result, output, indent=2)
    return tao.Result.PASS


def publish_tests():
    """Expose only the selected scope experiment."""
    return [
        tao.test_types.DockerBaseTest2("parser request-scope gate", request_scope_test)
    ]
