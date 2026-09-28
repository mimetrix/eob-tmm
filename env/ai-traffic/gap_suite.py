"""Exercise controlled observation gaps, bounded storage and fresh recovery."""
import asyncio
from collections import Counter
import json
import os
from pathlib import Path
import struct

import tao
import tao.runner
import tao.test_types

from attribution import Authority, Client
from correlation_join import join
from correlation_suite import RAW_FIELDS
from gap_window import ObservationWindow
from icap_suite import BACKEND, VIP, configure
from lifetime_suite import FIELDS, PROGRAMS, ParserLifetime
from config_suite import PORT


class GapSession(ParserLifetime):
    """Each session owns a closed result window and a fresh four-program load."""

    def __init__(self, directory, authority):
        directory.mkdir()
        super().__init__(directory / "result.json")
        self.authority = authority
        self.ledger_start = len(authority.ledger)
        self.candidates = []
        self.sequence = 0
        self.coverage = None
        self.result.update(candidates=self.candidates, server=[])

    async def identities(self):
        """Read all loaded instance identities from the configuration interface."""
        values = {}
        for name, (slot, _, _) in PROGRAMS.items():
            values[name] = json.loads(await self.cli("config-status", slot))["instance"]
        return values

    async def start(self):
        await super().start()
        await self.attach("candidate")
        identities = await self.identities()
        self.coverage = ObservationWindow(self.run_token, identities, fresh=True)
        self.result["instances"] = identities

    async def detach(self, label):
        if self.coverage is not None and not self.coverage.closed:
            self.coverage.invalidate("hook_detached:" + label)
        await super().detach(label)

    async def client(self, observed=True):
        del observed
        reader, writer = await asyncio.open_connection(VIP, PORT)
        client = Client(reader, writer, self.authority.keys, self.result["clients"])
        self.clients.append(client)
        return client

    async def drain(self, label):
        row = await self.run(
            "/work/ls_drain", "--segment", "/run/ls-stream/ls_tp_ring", "--once"
        )
        assert "0 drop(s) seen" in row["stderr"]
        transport = [json.loads(line) for line in row["stdout"].splitlines()]
        self.result["batches"].append(dict(label=label, transport=transport))
        values = []
        for item in transport:
            assert item["hook"] == "prog"
            raw = item["slot"] == 8
            assert item["len"] == (96 if raw else 64)
            event = dict(
                zip(
                    RAW_FIELDS if raw else FIELDS,
                    struct.unpack(
                        "<II5Q4I32s" if raw else "<II6QII", bytes.fromhex(item["data"])
                    ),
                )
            )
            self.sequence += 1
            assert event["magic"] == (0x43414E44 if raw else 0x4C494645)
            assert event["abi"] == 1 and event["run"] == self.run_token
            assert event["sequence"] == self.sequence and not event["failures"]
            if raw:
                event["nonce"] = event.pop("nonce_bytes").decode("ascii").rstrip("\0")
                event["path"] = {1: "/mcp", 2: "/a2a", 3: "/delegate"}.get(
                    event["path_code"]
                )
                assert event["flags"] in (0, 1, 4, 8, 64, 256)
                if event["flags"] != 1:
                    assert not event["nonce"] and event["path"] is None
                self.candidates.append(event)
            else:
                assert item["slot"] == {1: 6, 2: 5, 3: 7}[event["kind"]]
                assert not event["flags"] & ~(4 | 32 | 64 | 128 | 256)
                self.events.append(event)
                values.append(event)
        return values

    async def quiet(self, label):
        """Wait for five empty drains after the controlled traffic stops."""
        empty = 0
        for _ in range(80):
            before = self.sequence
            await self.drain(label)
            empty = empty + 1 if before == self.sequence else 0
            if empty == 5:
                return
            await asyncio.sleep(0.05)
        raise AssertionError("gap fixture did not become quiet")

    async def finish(self):
        """Check the complete ledger and counters before sealing the window."""
        await self.quiet("finish")
        self.result["counter_end"] = await self.all_stats()
        counts = Counter(e["kind"] for e in self.events)
        accounting = dict(drops=0, errors=0, selections=0)
        for name, (_, kind, _) in PROGRAMS.items():
            before = self.result["counter_start"][name]
            after = self.result["counter_end"][name]
            assert before["gen"] == after["gen"]
            assert before["errors"] == after["errors"]
            assert before["safe_returns"] == after["safe_returns"]
            accounting[name] = after["fired"] - before["fired"]
            assert accounting[name] == (
                len(self.candidates) if kind == 4 else counts[kind]
            )
        ledger = self.authority.ledger[self.ledger_start :]
        clients = self.result["clients"]
        assert len(clients) == len(ledger) and not self.authority.errors
        by_attempt = {row["attempt"]: row for row in ledger}
        assert len(by_attempt) == len(ledger)
        for client in clients:
            assert client["result"] == by_attempt[client["result"]["attempt"]]
            assert client["body_sha256"] == client["result"]["body_sha256"]
        self.coverage.close(await self.identities())
        matched = self.coverage.match(self.events, self.candidates, ledger, accounting)
        assert matched == self.coverage.match(
            self.events, self.candidates, list(reversed(ledger)), accounting
        )
        for row in matched:
            if row["status"] == "attributed":
                expected = by_attempt[row["authority_attempt"]]
                assert row["actor"] == expected["actor"]
                assert row["operation"] == expected["operation"]
        self.result.update(
            server=ledger,
            accounting=accounting,
            join=matched,
            legacy_join=join(self.events, self.candidates, ledger, accounting),
            coverage=dict(
                reason=self.coverage.reason,
                changes=self.coverage.changes,
                closed=self.coverage.closed,
            ),
            summary=dict(
                events=self.sequence,
                responses=len(clients),
                statuses=dict(Counter(r["status"] for r in matched)),
            ),
        )
        await self.stop()


async def request(client, name, actor="agent-A"):
    """Send one independently checked authenticated fixture request."""
    return await client.request(name, actor, "/mcp", "tools/call", actor)


async def exercise(window, name, retained):
    """Keep fault injection in the fixture controller, outside the observer."""
    if name == "recovery":
        retained.receipt = window.result["clients"]
        window.clients.append(retained)
        await request(retained, "retained-connection", "agent-B")
        await retained.close()
        await window.quiet("retained-close")
    client = await window.client()
    await request(client, name + "-first")
    await window.drain("first")
    if name == "boundary-gap":
        first = {
            e["lifetime"] for e in window.events if e["kind"] == 2 and e["lifetime"]
        }
        await window.detach("init")
        await window.detach("fini")
        await client.close()
        await window.quiet("missed-close")
        client = await window.client()
        offset = len(window.events)
        await request(client, "new-occupant", "agent-B")
        await window.drain("missed-birth")
        later = {
            e["lifetime"]
            for e in window.events[offset:]
            if e["kind"] == 2 and e["lifetime"]
        }
        window.result["stale_interval_seen"] = bool(first & later)
        await window.attach("init")
        await window.attach("fini")
    elif name == "pause":
        for label in PROGRAMS:
            await window.detach(label)
        before = await window.all_stats()
        await request(client, "unobserved-request", "agent-B")
        assert before == await window.all_stats()
        for label in PROGRAMS:
            await window.attach(label)
        await request(client, "resumed-request", "agent-B")
    elif name == "capacity":
        for index in range(139):
            await client.close()
            await window.quiet("capacity-close")
            client = await window.client()
            await request(
                client, "capacity-" + str(index), "agent-B" if index % 2 else "agent-A"
            )
        await window.drain("capacity-last")
        assert any(e["flags"] & 256 for e in window.candidates)
        assert any(e["kind"] == 1 and e["flags"] & 4 for e in window.events)
        return client
    else:
        await request(client, name + "-second", "agent-B")
    await client.close()
    return None


async def gap_test(log, _config):
    """Retain each window and every cleanup error, including failed attempts."""
    path = Path(os.environ["ICAP_RESULT"])
    authority = Authority()
    windows = []
    result = dict(passed=False, windows=[], request_scope_validated=False)
    retained = None
    with path.open("x", encoding="utf-8") as output:
        try:
            result["acknowledgements"] = await configure(log, port=PORT)
            async with await asyncio.start_server(authority.serve, BACKEND, PORT):
                for name in (
                    "baseline",
                    "boundary-gap",
                    "pause",
                    "capacity",
                    "recovery",
                ):
                    window = GapSession(path.parent / name, authority)
                    windows.append(window)
                    result["windows"].append(dict(name=name, data=window.result))
                    await window.start()
                    for previous in windows[:-1]:
                        assert window.run_token != previous.run_token
                        assert all(
                            window.result["instances"][key]
                            != previous.result["instances"][key]
                            for key in PROGRAMS
                        )
                    retained = await exercise(window, name, retained)
                    await window.finish()
                    expected = {"attributed": 2}
                    if name in ("boundary-gap", "pause"):
                        expected = {"unknown": 2}
                    elif name == "capacity":
                        expected = {"unknown": 140}
                    elif name == "recovery":
                        expected = {"attributed": 2, "unknown": 1}
                    assert (
                        window.result["summary"]["statuses"] == expected
                    ), window.result["summary"]
            result.update(
                passed=True,
                controlled_gap_guard_validated=True,
                summary=dict(
                    windows=5,
                    responses=len(authority.ledger),
                    events=sum(w.sequence for w in windows),
                ),
            )
        except BaseException as error:
            result["error"] = repr(error)
            raise
        finally:
            errors = []
            for window in windows:
                try:
                    closed = await asyncio.gather(
                        *(c.close() for c in window.clients), return_exceptions=True
                    )
                    errors.extend(
                        repr(e) for e in closed if isinstance(e, BaseException)
                    )
                    await window.stop()
                except BaseException as error:
                    errors.append(repr(error))
            if errors:
                result.update(passed=False, cleanup_errors=errors)
            json.dump(result, output, indent=2)
            if errors:
                raise AssertionError(errors)
    return tao.Result.PASS


def publish_tests():
    """Expose only the registered controlled-gap experiment."""
    return [tao.test_types.DockerBaseTest2("controlled correlation gaps", gap_test)]
