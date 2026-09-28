"""Bounded synthetic ICAP inspector and independent socket-receipt checks.

All event timestamps use this process's monotonic clock. A receive event means
an application read completed, not a wire timestamp or an internal TMM release.
"""

import asyncio
import hashlib
import time

import pru_ssa_config_builder as builder
import pool_pb2
import profile_icap_pb2
import profile_responseadapt_pb2
import traffic_matching_criteria_pb2
import virtual_server_pb2


ADDRESS = "10.203.72.11"
INSPECTOR_PORT = 1344
TIMEOUT_MS = 3000
DELAY_SECONDS = 0.5
PREVIEW_BYTES = 4096
DENIAL = b"inspection denied\n"


def configuration(main):
    """Use the upstream SSA ICAP IVS/profile construction with one endpoint."""
    prefix = "eob-dlp-inspector"
    match = traffic_matching_criteria_pb2.traffic_matching_criteria(id=prefix + "-tmc")
    pool = pool_pb2.pool(
        id=prefix + "-pool",
        pool_member_list=builder.gen_anchors(prefix)[2],
        lb_mode="ROUND_ROBIN",
        service_down_action="POOLMBR_ACTION_NONE",
    )
    virtual = virtual_server_pb2.virtual_server(
        id=prefix,
        internal=True,
        enabled=True,
        port_translation=True,
        source_address_translation_type="SRC_TRANS_AUTOMAP",
        traffic_matching_criteria=prefix + "-tmc",
        default_pool=prefix + "-pool",
    )
    messages = [match, pool, virtual]
    messages += builder.add_pool_member(
        messages, (ADDRESS, INSPECTOR_PORT), prefix=prefix
    )
    messages += builder.add_profile(messages, builder.create_default_tcp_profile())
    messages += builder.add_profile(
        messages,
        profile_icap_pb2.profile_icap(
            id=prefix + "-icap",
            name=prefix + "-icap",
            uri="icap://${SERVER_IP}:${SERVER_PORT}/dlp",
            preview_length=PREVIEW_BYTES,
        ),
    )
    main += builder.add_profile(
        main,
        profile_responseadapt_pb2.profile_responseadapt(
            id="eob-dlp-response",
            name="eob-dlp-response",
            internal_virtual_name=prefix,
            enabled=True,
            timeout=TIMEOUT_MS,
            preview_size=PREVIEW_BYTES,
            service_down_action="SERVICE_DOWN_RESET",
        ),
        context="SERVERSIDE",
    )
    return messages + main


def http_response(status, body):
    """Produce an unambiguous fixed-length synthetic response."""
    return (
        f"HTTP/1.1 {status}\r\nConnection: close\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode() + body


class Case:
    """One serial inspection operation; no correlation inferred from timing."""

    def __init__(self, mode, run_id):
        self.mode = mode
        self.canary = f"DLP_CANARY_{run_id}".encode()
        self.body = b"prefix\n" + self.canary + b"\nsuffix\n"
        self.events = []
        self.errors = []
        self.response = bytearray()
        self.client_error = None

    def event(self, kind, **fields):
        """Record a socket/application observation in one clock domain."""
        self.events.append(
            {"kind": kind, "monotonic_ns": time.monotonic_ns(), **fields}
        )

    async def origin(self, reader, writer):
        """Send identical content with three paced body writes in each case."""
        try:
            request = await reader.readuntil(b"\r\n\r\n")
            self.event("origin_request", request_hex=request.hex())
            headers = http_response("200 OK", self.body).split(b"\r\n\r\n", 1)[0]
            writer.write(headers + b"\r\n\r\n")
            for part in (b"prefix\n", self.canary, b"\nsuffix\n"):
                await asyncio.sleep(0.2)
                writer.write(part)
                await writer.drain()
                self.event("origin_body", length=len(part))
        finally:
            writer.close()
            await writer.wait_closed()

    async def inspector(self, reader, writer):
        """Require a complete preview before issuing the selected verdict."""
        try:
            await asyncio.wait_for(self.inspect(reader, writer), 8)
        except (ValueError, AssertionError, OSError, asyncio.TimeoutError) as error:
            self.errors.append(repr(error))
        finally:
            writer.close()
            await writer.wait_closed()

    async def inspect(self, reader, writer):
        """Handle the deliberately narrow, bounded RESPMOD experiment."""
        headers = await reader.readuntil(b"\r\n\r\n")
        self.event("icap_headers", headers_hex=headers.hex())
        if headers.startswith(b"OPTIONS "):
            writer.write(
                b'ICAP/1.0 200 OK\r\nISTag: "eob-dlp-1"\r\nMethods: RESPMOD\r\n'
                b"Preview: 4096\r\nAllow: 204\r\nEncapsulated: null-body=0\r\n\r\n"
            )
            await writer.drain()
            return
        assert headers.startswith(b"RESPMOD "), headers
        fields = dict(line.split(b":", 1) for line in headers.split(b"\r\n")[1:-2])
        fields = {key.lower(): value.strip() for key, value in fields.items()}
        offsets = dict(
            item.strip().split(b"=") for item in fields[b"encapsulated"].split(b",")
        )
        offset = int(offsets[b"res-body"])
        assert 0 <= offset <= PREVIEW_BYTES, offset
        encapsulated = await reader.readexactly(offset)
        self.event("encapsulated_headers", headers_hex=encapsulated.hex())
        body = bytearray()
        while True:
            line = await reader.readuntil(b"\r\n")
            length = int(line.split(b";", 1)[0], 16)
            assert 0 <= length <= PREVIEW_BYTES - len(body), length
            if not length:
                assert await reader.readexactly(2) == b"\r\n"
                assert b"ieof" in line.lower(), "preview is not whole-message"
                break
            body.extend(await reader.readexactly(length))
            assert await reader.readexactly(2) == b"\r\n"
        assert bytes(body) == self.body, bytes(body)
        self.event(
            "inspection_pending",
            bytes=len(body),
            sha256=hashlib.sha256(body).hexdigest(),
        )
        if self.mode == "timeout":
            await asyncio.sleep(5)
            return
        await asyncio.sleep(DELAY_SECONDS)
        if self.mode == "allow":
            # The TMM preview path accepts 204; it need not advertise Allow: 204.
            assert int(fields[b"preview"]) == PREVIEW_BYTES, fields
            response = b'ICAP/1.0 204 No Content\r\nISTag: "eob-dlp-1"\r\n\r\n'
        else:
            http = http_response("403 Forbidden", DENIAL)
            offset = http.index(b"\r\n\r\n") + 4
            response = (
                (
                    'ICAP/1.0 200 OK\r\nISTag: "eob-dlp-1"\r\n'
                    f"Encapsulated: res-hdr=0, res-body={offset}\r\n\r\n"
                ).encode()
                + http[:offset]
                + f"{len(DENIAL):x}\r\n".encode()
                + DENIAL
                + b"\r\n0\r\n\r\n"
            )
        self.event("verdict_write", verdict=self.mode)
        writer.write(response)
        await writer.drain()

    async def receive(self, vip, port):
        """Read incrementally so early protected content remains observable."""
        self.event("client_start")
        reader, writer = await asyncio.open_connection(vip, port)
        try:
            writer.write(
                b"GET /protected HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n"
            )
            await writer.drain()
            while True:
                data = await reader.read(4096)
                self.event("client_read", data_hex=data.hex())
                if not data:
                    break
                self.response.extend(data)
                assert len(self.response) <= 65536, "unbounded response"
        except OSError as error:
            self.client_error = repr(error)
            self.event("client_error", error=self.client_error)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    def verify(self):
        """Check content and application receipt ordering, not hook semantics."""
        assert not self.errors, self.errors
        assert sum(event["kind"] == "inspection_pending" for event in self.events) == 1
        if self.mode == "allow":
            verdict = next(
                event["monotonic_ns"]
                for event in self.events
                if event["kind"] == "verdict_write"
            )
            early = b"".join(
                bytes.fromhex(event["data_hex"])
                for event in self.events
                if event["kind"] == "client_read" and event["monotonic_ns"] < verdict
            )
            # Even one byte of body before allow violates this fixture's contract.
            assert not early.partition(b"\r\n\r\n")[2], early
            assert bytes(self.response) == http_response(
                "200 OK", self.body
            ), self.response
        elif self.mode == "deny":
            assert self.canary not in self.response, self.response
            assert bytes(self.response) == http_response(
                "403 Forbidden", DENIAL
            ), self.response
        else:
            assert not self.response, self.response
            elapsed = (
                self.events[-1]["monotonic_ns"] - self.events[0]["monotonic_ns"]
            ) / 1e9
            assert elapsed >= TIMEOUT_MS / 1000 - 0.25, elapsed

    async def run(self, vip, port):
        """Exercise one operation with listeners owned by this case."""
        async with await asyncio.start_server(self.origin, ADDRESS, port):
            async with await asyncio.start_server(
                self.inspector, ADDRESS, INSPECTOR_PORT
            ):
                await asyncio.wait_for(self.receive(vip, port), 7)
                self.verify()
        return {
            "mode": self.mode,
            "events": self.events,
            "errors": self.errors,
            "response_hex": self.response.hex(),
            "client_error": self.client_error,
            "passed": True,
        }
