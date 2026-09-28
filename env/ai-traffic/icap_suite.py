"""SSA/Tao configuration and forwarding preflight for the isolated ICAP fixture.

Run with tao_runner in the pinned test image. This is a forwarding baseline;
successful execution does not establish inspection or release ordering.
"""

import asyncio
import hashlib
import json
import os
from pathlib import Path
import time

import tao
import tao.runner
import tao.test_types
import pru_ssa_config_builder as builder
import pru_ssa_config_server

import icap_gate

VIP = os.environ.get("ICAP_VIP", "10.203.72.50")
BACKEND = os.environ.get("ICAP_BACKEND", "10.203.72.11")
PORT = 18091
BODY = b"isolated-icap-forwarding-baseline\n"


async def write_http_response(writer, body):
    """Write an exact, fixed-length HTTP response for the independent origin."""
    writer.write(
        b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
        + body
    )
    await writer.drain()


async def configure(log, inspection=False, port=PORT):
    """Publish configuration and independently check asynchronous NATS ACKs."""
    pru_ssa_config_server.tmm_count = 1
    log.info("Waiting for isolated TMM configuration subscription")
    config_server = await asyncio.wait_for(pru_ssa_config_server.get_conf_svr(), 120)
    client = config_server.tmm_clients[0]
    heartbeat = client.nats_client.watch_subject(client.HEART_BEAT_SUBJECT)
    messages = builder.create_vs_msgs("eob-icap-baseline", (VIP, port))
    messages += builder.add_pool_member(messages, (BACKEND, port))
    messages += builder.add_profile(messages, builder.create_default_tcp_profile())
    messages += builder.add_profile(messages, builder.create_default_http_profile())
    if inspection:
        messages = icap_gate.configuration(messages)
    await asyncio.wait_for(config_server.send_create_msgs(messages), 60)
    acknowledgements = []
    while True:
        message = await asyncio.wait_for(heartbeat.get(), 10)
        ack = await client.unpack_dpc_msg(message.body)
        acknowledgements.append(
            {
                "generation": ack.generation,
                "sequence": ack.seq_start,
                "status": ack.status,
                "description": ack.description,
            }
        )
        assert ack.status == 0, str(ack)
        if (
            ack.generation == config_server.generation
            and ack.seq_start >= config_server.current_sequence
        ):
            break
    return acknowledgements


async def forwarding_baseline(log, _config):
    """Configure one HTTP virtual, verify exact content and archive the result."""
    output = Path(os.environ["ICAP_RESULT"])
    # Reserve before programming anything; never overwrite an earlier receipt.
    with output.open("x", encoding="utf-8") as receipt:
        result = {"stage": "configuration", "started_ns": time.time_ns()}
        origin_peers = []

        async def origin(reader, writer):
            try:
                request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
                origin_peers.append(
                    {
                        "peer": writer.get_extra_info("peername"),
                        "request_hex": request.hex(),
                    }
                )
                await write_http_response(writer, BODY)
            finally:
                writer.close()
                await writer.wait_closed()

        try:
            result["acknowledgements"] = await configure(log)
            result["stage"] = "forwarding"
            async with await asyncio.start_server(origin, BACKEND, PORT):
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(VIP, PORT), 10
                )
                try:
                    writer.write(
                        b"GET /baseline HTTP/1.1\r\nHost: fixture\r\n"
                        b"Connection: close\r\n\r\n"
                    )
                    await writer.drain()
                    response = await asyncio.wait_for(reader.read(), 10)
                finally:
                    writer.close()
                    await writer.wait_closed()
            headers, body = response.split(b"\r\n\r\n", 1)
            assert headers.startswith(b"HTTP/1.1 200 "), headers
            assert body == BODY, body
            assert len(origin_peers) == 1, origin_peers
            result.update(
                stage="complete",
                passed=True,
                response_hex=response.hex(),
                body_sha256=hashlib.sha256(body).hexdigest(),
            )
            return tao.Result.PASS
        except Exception as error:  # Receipt must survive configuration failures.
            result.update(passed=False, error=repr(error))
            raise
        finally:
            result.update(origin_peers=origin_peers, finished_ns=time.time_ns())
            json.dump(result, receipt, indent=2, sort_keys=True)
            receipt.write("\n")


async def inspection_cases(log, _config):
    """Run the three controlled verdicts, preserving failed-case observations."""
    output = Path(os.environ["ICAP_RESULT"])
    with output.open("x", encoding="utf-8") as receipt:
        result = {"passed": False, "cases": [], "stage": "configuration"}
        try:
            result["acknowledgements"] = await configure(log, inspection=True)
            result["stage"] = "inspection"
            for mode in ("allow", "deny", "timeout"):
                case = icap_gate.Case(mode, output.parent.name)
                try:
                    result["cases"].append(await case.run(VIP, PORT))
                except Exception:
                    result["cases"].append(
                        {
                            "mode": mode,
                            "events": case.events,
                            "errors": case.errors,
                            "response_hex": case.response.hex(),
                            "passed": False,
                        }
                    )
                    raise
            result.update(passed=True, stage="complete")
            return tao.Result.PASS
        except Exception as error:
            result["error"] = repr(error)
            raise
        finally:
            json.dump(result, receipt, indent=2, sort_keys=True)
            receipt.write("\n")


def publish_tests():
    """Expose only this explicitly selected baseline to the SSA test runner."""
    if os.environ.get("ICAP_SUITE", "baseline") == "gate":
        return [
            tao.test_types.DockerBaseTest2(
                "delayed inspection outcomes", inspection_cases
            )
        ]
    return [
        tao.test_types.DockerBaseTest2(
            "isolated ICAP fixture forwarding preflight", forwarding_baseline
        )
    ]
