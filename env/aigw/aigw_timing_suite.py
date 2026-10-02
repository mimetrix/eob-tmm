"""P24: attribute each AI gateway request's latency to its stages.

One owned eBPF program (seven entries) is attached to the aigw host
functions. A mock provider holds the response headers for D1 and pauses D2
between two body chunks. Redis serves virtual-key resolution, so admission
includes a store round trip.

Each request's events are joined on the client-side aigw_scb address and the
stages are computed here, off the data path. Checks follow the falsifiers
registered in 02-RESEARCH-PARAMETERS.md P24.
"""

import asyncio
import json
import os
from pathlib import Path
import secrets
import struct
import time

import tao
import tao.test_types

import aigw_smoke_suite as smoke
import aigw_rbac_suite as rbac
from aigw_ebpf_suite import cli, drain, records

PROGRAM = 0
EVENT = struct.Struct("<II4QIIIIQ")
POINTS = {
    1: "admit",
    2: "store_send",
    3: "store_reply",
    4: "event",
    5: "reply_parse",
    6: "reply_done",
    7: "publish",
}
FORWARDED = 4
D1, D2 = 0.200, 0.150
TOL_US = 20_000  # registered lab bound for provider stages
SUM_US = 1_000  # registered bound for stage sum vs total


class DelayedMock(smoke.Mock):
    """Headers after D1, then two body chunks D2 apart."""

    async def serve(self, reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            lines = head.decode("latin-1").split("\r\n")
            length = next(
                (
                    int(l.split(":", 1)[1])
                    for l in lines
                    if l.lower().startswith("content-length:")
                ),
                0,
            )
            await asyncio.wait_for(reader.readexactly(length), 10)
            auth = [
                l.split(":", 1)[1].strip()
                for l in lines
                if l.lower().startswith("authorization:")
            ]
            self.requests.append(
                {
                    "request_line": lines[0],
                    "authorization_is_provider_key": auth == ["Bearer " + self.key],
                    "t_arrive": time.monotonic(),
                }
            )
            await asyncio.sleep(D1)
            body = json.dumps(smoke.REPLY).encode()
            half = len(body) // 2
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Connection: close\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\n\r\n"
                + body[:half]
            )
            await writer.drain()
            await asyncio.sleep(D2)
            writer.write(body[half:])
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()


def decode(frames):
    out = []
    for item in frames:
        data = bytes.fromhex(item["data"])
        if len(data) != EVENT.size:
            continue
        (
            magic,
            abi,
            instance,
            seq,
            mono,
            scb,
            point,
            flags,
            a,
            b,
            admit,
        ) = EVENT.unpack(data)
        if magic != 0x41544D47 or abi != 1:
            continue
        out.append(
            dict(
                seq=seq,
                ns=mono,
                scb=scb,
                point=POINTS.get(point, point),
                flags=flags,
                a=a,
                b=b,
                admit_ns=admit,
                instance=instance,
            )
        )
    return sorted(out, key=lambda e: e["seq"])


def requests_from(events):
    """Split each scb's events into requests at each admit."""
    by_scb, done = {}, []
    for e in events:
        if not e["scb"]:
            continue
        if e["point"] == "admit":
            if e["scb"] in by_scb:
                done.append(by_scb.pop(e["scb"]))
            by_scb[e["scb"]] = [e]
        elif e["scb"] in by_scb:
            by_scb[e["scb"]].append(e)
    return done + list(by_scb.values())


def stages(req):
    """Stage durations in microseconds, or None where a point is absent."""
    t0 = req[0]["ns"]
    first = lambda pred: next((e["ns"] for e in req if pred(e)), None)
    fwd = first(lambda e: e["point"] == "event" and e["a"] == FORWARDED)
    s_parse = first(lambda e: e["point"] == "reply_parse" and e["a"] == 1)
    s_done = first(lambda e: e["point"] == "reply_done" and e["a"] == 1)
    c_done = first(lambda e: e["point"] == "reply_done" and e["a"] == 0)
    # Awaited sends only: a send's reply comes back on the same scb. A
    # detached charge (eval at settle) has no reply and is not a stage.
    sends = [e["ns"] for e in req if e["point"] == "store_send"]
    replies = [e["ns"] for e in req if e["point"] == "store_reply"]
    us = lambda a, b: None if a is None or b is None else (b - a) // 1000
    return {
        "admission": us(t0, fwd),
        # Each awaited send is answered before the next is issued (the host
        # refuses a second while one is pending), so pair them in order.
        "store_round_trips": [us(s, r) for s, r in zip(sends, replies)],
        "store_total": sum(us(s, r) for s, r in zip(sends, replies)),
        "store_sends": len(sends),
        "store_replies": len(replies),
        # name kept for receipt continuity; means "until complete reply"
        "provider_first_byte": us(fwd, s_parse),
        "provider_body": us(s_parse, s_done),
        "delivery": us(s_done, c_done),
        "total": us(t0, c_done),
        "published": any(e["point"] == "publish" for e in req),
        "admit_consistent": all(e["admit_ns"] == t0 for e in req),
    }


async def timing_test(log, _config):
    output = Path(os.environ["AIGW_RESULT"])
    directory = Path(os.environ["AIGW_PROBE_DIR"])
    provider_key = "sk-time-" + secrets.token_hex(16)
    token = "vk-fixture-" + secrets.token_hex(12)
    base = {
        "active": "1",
        "team_id": "team-a",
        "org_id": "org-a",
        "model_scope": "",
        "vk_model_scope": "",
    }
    mock = DelayedMock(provider_key)
    result = {
        "passed": False,
        "commands": [],
        "drains": [],
        "clients": [],
        "started_ns": time.time_ns(),
        "d1_s": D1,
        "d2_s": D2,
    }
    instance = None
    with output.open("x", encoding="utf-8") as receipt:
        try:
            await rbac.seed(
                {"alice": (token, dict(base, vkid="vk-alice", principal_id="alice"))}
            )
            result["configuration"], result["acknowledgements"] = await rbac.configure(
                log, provider_key
            )
            text = await cli(
                result,
                "program-load",
                PROGRAM,
                str(directory / "aigw_timing.bpf.o"),
                str(directory / "aigw_timing.sig"),
            )
            status = {k: int(v) for k, v in (w.split("=") for w in text.split()[1:])}
            instance = status["instance"]
            assert status["entries"] == 8, status
            identity = json.loads(
                await cli(result, "config-status", status["config_slot"])
            )
            doc = dict(identity)
            doc["expected_revision"] = doc.pop("revision")
            doc.update(revision=doc["expected_revision"] + 1, schema=1, rows=[])
            doc.pop("entries")
            path = output.parent / "timing-config.json"
            path.write_text(json.dumps(doc))
            await cli(result, "config-publish", status["config_slot"], str(path))
            for entry in range(8):
                await cli(result, "program-attach", PROGRAM, instance, entry)
            await cli(result, "program-mode", PROGRAM, instance, 1)
            result["program_status_start"] = await cli(
                result, "program-status", PROGRAM
            )
            async with await asyncio.start_server(
                mock.serve, smoke.BACKEND, smoke.MOCK
            ):
                for i in range(3):
                    t = time.monotonic()
                    status_code, body = await rbac.request(token, smoke.MODEL)
                    result["clients"].append(
                        {
                            "case": f"seq-{i}",
                            "status": status_code,
                            "client_ms": (time.monotonic() - t) * 1000,
                        }
                    )
                    assert status_code == 200, body
                t = time.monotonic()
                both = await asyncio.gather(
                    rbac.request(token, smoke.MODEL), rbac.request(token, smoke.MODEL)
                )
                for j, (status_code, _b) in enumerate(both):
                    result["clients"].append(
                        {
                            "case": f"concurrent-{j}",
                            "status": status_code,
                            "client_ms": (time.monotonic() - t) * 1000,
                        }
                    )
                    assert status_code == 200
                status_code, _b = await rbac.request("vk-fixture-unknown", smoke.MODEL)
                result["clients"].append({"case": "refused", "status": status_code})
                assert status_code == 401
                await asyncio.sleep(0.3)
                frames = await drain(result)
            result["program_status_end"] = await cli(result, "program-status", PROGRAM)
            for entry in range(8):
                await cli(result, "program-detach", PROGRAM, instance, entry)
            await cli(result, "program-revoke", PROGRAM, instance)
            instance = None

            events = decode(frames)
            result["events"] = events
            reqs = requests_from(events)
            result["requests"] = [
                dict(stages(r), points=[e["point"] for e in r]) for r in reqs
            ]
            served = [
                s for s in result["requests"] if s["provider_first_byte"] is not None
            ]
            refused = [
                s for s in result["requests"] if s["provider_first_byte"] is None
            ]
            assert len(served) == 5 and len(refused) == 1, result["requests"]
            seqs = [e["seq"] for e in events]
            assert seqs == list(range(seqs[0], seqs[0] + len(seqs))), "sequence gap"
            assert all(not e["flags"] for e in events if e["scb"]), "flagged event"
            result["unkeyed_events"] = [e for e in events if not e["scb"]]
            for s in served:
                assert s["admit_consistent"], s
                assert all(
                    v is None or v >= 0
                    for k, v in s.items()
                    if isinstance(v, int) and not isinstance(v, bool)
                ), s
                # admission's store traffic: every reply pairs with a send
                assert s["store_replies"] >= 1, s
                assert s["store_sends"] >= s["store_replies"], s
                # Corrected after attempt 02 (P24): for a buffered JSON reply the
                # first server-side parse is the complete reply, so the
                # reference is D1 + D2; the "body" stage is TMM processing only.
                ref = (D1 + D2) * 1e6
                assert ref <= s["provider_first_byte"] <= ref + TOL_US, s
                assert 0 <= s["provider_body"] <= TOL_US, s
                parts = (
                    s["admission"]
                    + s["provider_first_byte"]
                    + s["provider_body"]
                    + s["delivery"]
                )
                assert abs(parts - s["total"]) <= SUM_US, s
            for s in refused:
                assert s["admission"] is None and s["store_replies"] == 1, s
            result["passed"] = True
            return tao.Result.PASS
        except Exception as error:
            result["error"] = repr(error)
            raise
        finally:
            if instance is not None:
                for entry in range(8):
                    try:
                        await cli(result, "program-detach", PROGRAM, instance, entry)
                    except Exception as error:
                        result.setdefault("cleanup_errors", []).append(repr(error))
                try:
                    await cli(result, "program-revoke", PROGRAM, instance)
                except Exception as error:
                    result.setdefault("cleanup_errors", []).append(repr(error))
            result["finished_ns"] = time.time_ns()
            text = json.dumps(result, indent=2, sort_keys=True)
            assert provider_key not in text and token not in text
            receipt.write(text + "\n")


def publish_tests():
    return [tao.test_types.DockerBaseTest2("aigw latency attribution", timing_test)]
