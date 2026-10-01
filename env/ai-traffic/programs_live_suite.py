"""Check independent owners and shared entry hooks through real HTTP traffic."""

import asyncio
import json
import os
from pathlib import Path
import struct

import tao
import tao.test_types

from config_suite import Lifecycle
from icap_suite import BACKEND, VIP
from session_routing_suite import configure

REQUEST = b'{"jsonrpc":"2.0","id":"ownership","method":"tools/list","params":{}}'
REPLY = b'{"jsonrpc":"2.0","id":"ownership","result":{"tools":[]}}'


class Programs(Lifecycle):
    """Use a dedicated fixture ring and owner-local configuration/counters."""

    def __init__(self, output):
        super().__init__(output)
        self.directory = Path(os.environ["TEMPLATE_PROGRAM_DIR"])
        self.build = json.loads((self.directory / "program-build.json").read_text())
        self.owners = {}
        self.sequences = {}
        self.result.update(clients=[], backend_errors=[], loads=[])

    async def cli(self, *args, refuse=False):
        row = await self.run(
            "python3",
            str(self.directory / "ls-load.py"),
            *map(str, args),
            refuse=refuse
        )
        if not refuse and args[0] != "config-status":
            assert row["stdout"].startswith("OK "), row
        return row["stdout"]

    async def control(self, operation, owner, *args, refuse=False):
        return await self.cli(
            "program-" + operation,
            owner,
            self.owners[owner]["instance"],
            *args,
            refuse=refuse
        )

    async def load_owner(self, owner, marker):
        text = await self.cli(
            "program-load",
            owner,
            self.directory / "ownership.bpf.o",
            self.directory / "ownership.sig",
        )
        status = dict(word.split("=") for word in text.split()[1:])
        status = {key: int(value) for key, value in status.items()}
        self.owners[owner] = status
        assert status["entries"] == 2 and status["attached"] == status["mode"] == 0
        identity = json.loads(await self.cli("config-status", status["config_slot"]))
        assert int(identity["instance"], 16) == status["instance"]
        assert identity["revision"] == 0
        document = dict(identity)
        document["expected_revision"] = document.pop("revision")
        document.update(
            revision=1, schema=1, rows=[struct.pack("<4Q", marker, 0, 0, 0).hex()]
        )
        document.pop("entries")
        path = self.output.parent / ("config-%s-%s.json" % (owner, status["instance"]))
        path.write_text(json.dumps(document))
        await self.cli("config-publish", status["config_slot"], path)
        status["marker"] = marker
        self.result["loads"].append(dict(status))
        self.sequences[status["instance"]] = 0
        for entry in (0, 1):
            await self.control("attach", owner, entry)
        await self.control("mode", owner, 1)
        return document

    async def origin(self, reader, writer):
        try:
            headers = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            length = next(
                int(line.split(b":", 1)[1])
                for line in headers.split(b"\r\n")
                if line.lower().startswith(b"content-length:")
            )
            body = await asyncio.wait_for(reader.readexactly(length), 10)
            assert body == REQUEST
            self.result["origin"].append(
                dict(headers=headers.decode(), body=body.decode())
            )
            writer.write(
                (
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    "Connection: close\r\nContent-Length: %d\r\n\r\n" % len(REPLY)
                ).encode()
                + REPLY
            )
            await writer.drain()
        except Exception as error:
            self.result["backend_errors"].append(repr(error))
        finally:
            writer.close()
            await writer.wait_closed()

    async def phase(self, label, expected, count=2):
        active = expected
        for index in range(count):
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(VIP, 18095), 10
            )
            try:
                writer.write(
                    (
                        "POST /%s/%d HTTP/1.1\r\nHost: ownership\r\n"
                        "Content-Type: application/json\r\nConnection: close\r\n"
                        "Content-Length: %d\r\n\r\n" % (label, index, len(REQUEST))
                    ).encode()
                    + REQUEST
                )
                await writer.drain()
                response = await asyncio.wait_for(reader.read(), 15)
                headers, body = response.split(b"\r\n\r\n", 1)
                assert headers.startswith(b"HTTP/1.1 200 ") and body == REPLY, response
                self.result["clients"].append(
                    dict(phase=label, response=response.decode())
                )
            finally:
                writer.close()
                await writer.wait_closed()
        await asyncio.sleep(0.1)
        row = await self.run(
            os.environ["PROGRAMS_DRAIN"],
            "--segment",
            "/run/ls-stream/ls_tp_ring",
            "--once",
        )
        assert "0 drop(s) seen" in row["stderr"], row
        records = [json.loads(line) for line in row["stdout"].splitlines()]
        phase = dict(name=label, active=active, requests=count, records=records)
        self.result["phases"].append(phase)
        grouped = {owner: [] for owner in active}
        for record in records:
            assert record["hook"] == "prog" and record["len"] == 48, record
            instance, sequence, arg0, last, entry, marker = struct.unpack(
                "<6Q", bytes.fromhex(record["data"])
            )
            owner = next(
                key for key in active if self.owners[key]["instance"] == instance
            )
            assert entry in active[owner] and marker == self.owners[owner]["marker"]
            assert record["slot"] == 12 + 12 * owner + entry
            assert arg0 != 0xBAD and last != 0xBAD
            assert sequence == self.sequences[instance] + 1
            self.sequences[instance] = sequence
            grouped[owner].append((entry, arg0, last))
        for owner, entries in active.items():
            if 0 in entries:
                assert (
                    sum(value[0] == 0 for value in grouped[owner]) == count * 2
                ), phase
            if 1 in entries:
                assert any(value[0] == 1 for value in grouped[owner]), phase
        if set(active) == {0, 1}:
            shared = set(active[0]) & set(active[1])
            assert [r for r in grouped[0] if r[0] in shared] == [
                r for r in grouped[1] if r[0] in shared
            ]
        if not active:
            assert not records, phase
        phase["sequences"] = dict(self.sequences)

    async def exercise(self):
        old_config = await self.load_owner(0, 101)
        old_instance = self.owners[0]["instance"]
        await self.load_owner(1, 202)
        await self.control("attach", 0, 0, refuse=True)
        await self.control("mode", 0, 2, refuse=True)
        await self.cli("program-detach", 0, self.owners[1]["instance"], 0, refuse=True)
        await self.phase("both", {0: [0, 1], 1: [0, 1]}, 4)
        await self.control("detach", 0, 0)
        await self.phase("partial-detach", {0: [1], 1: [0, 1]})
        await self.control("attach", 0, 0)
        await self.phase("reattach", {0: [0, 1], 1: [0, 1]})
        await self.control("revoke", 0)
        del self.owners[0]
        await self.phase("owner-one-survives", {1: [0, 1]})
        await self.load_owner(0, 303)
        assert self.owners[0]["instance"] != old_instance
        await self.cli("program-revoke", 0, old_instance, refuse=True)
        path = self.output.parent / "stale-config.json"
        old_config.update(expected_revision=1, revision=2)
        path.write_text(json.dumps(old_config))
        await self.cli("config-publish", 56, path, refuse=True)
        await self.phase("replacement", {0: [0, 1], 1: [0, 1]})
        await self.control("mode", 0, 0)
        await self.phase("disabled-owner", {1: [0, 1]})
        await self.control("mode", 0, 1)
        await self.control("revoke", 1)
        del self.owners[1]
        await self.phase("owner-zero-survives", {0: [0, 1]})
        await self.control("revoke", 0)
        del self.owners[0]
        await self.phase("all-revoked", {})
        assert not self.result["backend_errors"]
        assert len(self.result["origin"]) == len(self.result["clients"]) == 18

    async def cleanup(self):
        errors = []
        for owner in list(self.owners):
            try:
                await self.control("revoke", owner)
                del self.owners[owner]
            except Exception as error:
                errors.append(repr(error))
        assert not errors, errors


async def programs_test(log, _config):
    """Retain failed attempts and always revoke test-owned programs."""
    test = Programs(Path(os.environ["ICAP_RESULT"]))
    with test.output.open("x", encoding="utf-8") as output:
        try:
            config, pool, acks = await configure(log)
            test.result.update(
                configuration=config, expected_pool=pool, acknowledgements=acks
            )
            origin = await asyncio.start_server(test.origin, BACKEND, 18095)
            async with origin:
                await test.exercise()
            test.result["passed"] = True
            return tao.Result.PASS
        except Exception as error:
            test.result["error"] = repr(error)
            raise
        finally:
            try:
                await test.cleanup()
            except Exception as error:
                test.result.update(passed=False, cleanup_error=repr(error))
                raise
            finally:
                json.dump(test.result, output, indent=2)


def publish_tests():
    """Publish the two-owner functional test."""
    return [tao.test_types.DockerBaseTest2("program ownership", programs_test)]
