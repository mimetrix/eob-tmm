"""Exercise both entries of one activity ELF on the isolated AIMCP fixture."""

import asyncio
import json
import os
from pathlib import Path

import tao
import tao.test_types

from activity_export import DECODERS, project_page
from activity_group_decode import MAGIC as GROUP_MAGIC, unwrap
from icap_suite import BACKEND, VIP
from session_routing_suite import SessionRouting, configure

PROGRAMS = {
    "json": (11, 0, "json_filter_handle_json_complete", 18095),
    "http": (9, 0, "hud_aimcp_handler", 18095),
}
CASES = (
    (
        {
            "jsonrpc": "2.0",
            "id": "one",
            "method": "tools/call",
            "params": {"name": "sum"},
        },
        {"jsonrpc": "2.0", "id": "one", "result": {"isError": False}},
    ),
    (
        {
            "jsonrpc": "2.0",
            "id": 9007199254740993,
            "method": "resources/read",
            "params": {"uri": "file:///one"},
        },
        {"jsonrpc": "2.0", "id": 9007199254740993, "error": {"code": -32601}},
    ),
    (
        {
            "jsonrpc": "2.0",
            "id": "three",
            "method": "tools/call",
            "params": {"name": "missing"},
        },
        {"jsonrpc": "2.0", "id": "three", "result": {"isError": True}},
    ),
)


def wire(value):
    """Use exact fixture bytes, including large integer spelling."""
    return json.dumps(value, separators=(",", ":")).encode()


class ActivityProgram(SessionRouting):
    """Keep both hooks armed throughout every request and reply."""

    def __init__(self, output):
        super().__init__(output)
        self.programs = PROGRAMS
        self.result["scope"] = "one artifact, two simultaneous entry hooks"
        self.sequences = {"json": 0, "http": 0}
        self.result["export_pages"] = []

    async def drain(self, label):
        counters = await self.counters()
        targets = {
            name: (
                counters[name]["fired"] - self.result["counter_start"][name]["fired"]
            )
            * (4 if name == "json" else 1)
            for name in PROGRAMS
        }
        for _ in range(100):
            current = await self.page(self.cursor)
            self.cursor = current["next_cursor"]
            self.result["stream_pages"].append(current)
            self.result["export_pages"].append(project_page(current))
            for row in current["events"]:
                envelope = row["event"]
                assert envelope["type"] != "observation_gap", envelope
                if envelope["type"] != "record":
                    continue
                raw = envelope["raw"]
                assert raw["slot"] in (9, 11)
                assert raw["hook_id"] == raw["schema"] == 100
                payload = bytes.fromhex(raw["data"])
                group = None
                if int.from_bytes(payload[:4], "little") == GROUP_MAGIC:
                    group, payload = unwrap(payload)
                kind, decoder = DECODERS[int.from_bytes(payload[:4], "little")]
                event = decoder(payload)
                name = "json" if raw["slot"] == 11 else "http"
                identity = self.identities[name]
                assert event["instance"] == int(identity["instance"], 16)
                assert event["revision"] == identity["revision"]
                assert event["run"] == self.run_token and not event["flags"]
                assert event["monotonic_ns"] and not event["output_failures"]
                self.sequences[name] += 1
                assert event["sequence"] == self.sequences[name]
                assert (kind == "http_response") == (name == "http")
                event.update(kind=kind, hook=name)
                if group is not None:
                    event["group"] = group
                self.events.append(event)
            if all(self.sequences[n] >= targets[n] for n in PROGRAMS):
                break
            await asyncio.sleep(0.05)
        assert self.sequences == targets, (label, self.sequences, targets)

    async def origin(self, reader, writer):
        try:
            headers = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            lines = headers.decode().split("\r\n")
            index = int(lines[0].split()[1].lstrip("/"))
            length = int(
                next(
                    line.split(":", 1)[1]
                    for line in lines
                    if line.lower().startswith("content-length:")
                )
            )
            request = await asyncio.wait_for(reader.readexactly(length), 10)
            assert request == wire(CASES[index][0])
            body = wire(CASES[index][1])
            self.result["origin"].append(
                {"case": index, "request_hex": request.hex(), "reply_hex": body.hex()}
            )
            writer.write(
                (
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                ).encode()
            )
            for chunk in (body[:7], body[7:]):
                writer.write(chunk)
                await writer.drain()
                await asyncio.sleep(0.02)
        except Exception as error:
            self.result["backend_errors"].append(repr(error))
        finally:
            writer.close()
            await writer.wait_closed()

    async def compare_case(self, index):
        start = len(self.events)
        request, reply = CASES[index]
        body = wire(request)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(VIP, 18095), 10)
        try:
            writer.write(
                (
                    f"POST /{index} HTTP/1.1\r\nHost: metadata\r\n"
                    "Content-Type: application/json\r\nConnection: close\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n"
                ).encode()
                + body
            )
            await writer.drain()
            response = await asyncio.wait_for(reader.read(), 15)
            assert response.startswith(b"HTTP/1.1 200 "), response
            assert response.split(b"\r\n\r\n", 1)[1] == wire(reply)
            self.result["clients"].append(
                {"case": index, "response_hex": response.hex()}
            )
        finally:
            writer.close()
            await writer.wait_closed()
        await self.drain(str(index))
        events = self.events[start:]
        self.result["comparisons"].append({"case": index, "events": events})
        for kind in ("method", "operation_target", "message_id", "reply"):
            assert sum(e["kind"] == kind for e in events) == 2
        method = next(e for e in events if e["kind"] == "method" and e["status"] == 1)
        assert bytes.fromhex(method["value_hex"]) == request["method"].encode()
        target = next(
            e for e in events if e["kind"] == "operation_target" and e["status"] == 1
        )
        assert (
            bytes.fromhex(target["value_hex"])
            == next(iter(request["params"].values())).encode()
        )
        ids = [e for e in events if e["kind"] == "message_id"]
        assert {e["flow_side_name"] for e in ids} == {"clientside", "serverside"}
        assert all(
            bytes.fromhex(e["value_hex"]) == str(request["id"]).encode() for e in ids
        )
        outcome = next(e for e in events if e["kind"] == "reply" and e["status"] == 1)
        if "error" in reply:
            assert outcome["code_state"] == 1 and outcome["error_code"] == -32601
        else:
            assert outcome["tool_error_state"] == 1
            assert bool(outcome["tool_error"]) == reply["result"]["isError"]
        http = [e for e in events if e["kind"] == "http_response"]
        assert (
            sum(e["http_status_state"] == 1 and e["http_status"] == 200 for e in http)
            == 2
        )
        assert (
            sum(
                e["completion_state"] == 1 and e["transfer_complete"] == 1 for e in http
            )
            == 2
        )

    async def finish(self):
        for label, (_, _, hook, _) in PROGRAMS.items():
            await self.cli("disarm", hook)
            self.armed_labels.remove(label)
        await self.drain("final")
        self.result["counter_end"] = await self.counters()
        for name in PROGRAMS:
            before, after = (
                self.result["counter_start"][name],
                self.result["counter_end"][name],
            )
            assert after["fired"] > before["fired"]
            assert all(after[k] == before[k] for k in ("errors", "safe_returns", "gen"))
        cursor, replay = self.initial_cursor, []
        for _ in range(20):
            current = await self.page(cursor)
            replay.extend(current["events"])
            cursor = current["next_cursor"]
            if not current["events"]:
                break
        else:
            raise RuntimeError("replay page limit")
        original = [r for p in self.result["stream_pages"] for r in p["events"]]
        assert [r for r in original if r["event"]["type"] == "record"] == [
            r for r in replay if r["event"]["type"] == "record"
        ]
        self.result["replay_consumer"] = {"events": replay, "next_cursor": cursor}


async def activity_program_test(log, _config):
    """Keep exact fixture results and restore both entries after any failure."""
    test = ActivityProgram(Path(os.environ["ICAP_RESULT"]))
    with test.output.open("x", encoding="utf-8") as output:
        try:
            config, pool, acks = await configure(log)
            test.result.update(
                configuration=config, expected_pool=pool, acknowledgements=acks
            )
            origin = await asyncio.start_server(test.origin, BACKEND, 18095)
            async with origin:
                await test.start()
                refused = await test.run(
                    "python3", "/work/ls-load.py", "arm", "9", PROGRAMS["json"][2]
                )
                assert (
                    "requested target differs from signed target" in refused["stdout"]
                )
                test.result["wrong_target_refusal"] = refused
                for index in range(len(CASES)):
                    await test.compare_case(index)
                await test.finish()
            assert (
                len(test.result["origin"]) == len(test.result["clients"]) == len(CASES)
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
    """Publish the simultaneous two-hook check."""
    return [
        tao.test_types.DockerBaseTest2(
            "combined activity program", activity_program_test
        )
    ]
