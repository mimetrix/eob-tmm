"""Client TLS mode on combined activity records (TLS-MODE.md, P23).

Three AIMCP virtual servers on one worker share one backend:
plain (18095), client SSL without certificate request (18096) and client SSL
with peer_cert_mode=request and a fixture CA (18097). Each reading is compared
with the client's own record of the negotiated TLS values.

Keys and certificates are generated per run in a private temporary directory,
sent to TMM inline, and deleted. Evidence keeps only certificate fingerprints.
"""

import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import uuid

from google.protobuf.json_format import MessageToDict
import tao
import tao.test_types
import pru_ssa_config_builder as builder
import pru_ssa_config_server
import profile_aimcp_pb2

from activity_combine import ActivityCombiner
from activity_combined_suite import CombinedActivity
from activity_program_suite import ActivityProgram, wire
from icap_suite import BACKEND, VIP

PLAIN, TERMINATED, REQUEST = 18095, 18096, 18097
SUITES = {  # IANA suite IDs for the names Python reports
    "TLS_AES_128_GCM_SHA256": 0x1301,
    "TLS_AES_256_GCM_SHA384": 0x1302,
    "TLS_CHACHA20_POLY1305_SHA256": 0x1303,
    "ECDHE-RSA-AES128-GCM-SHA256": 0xC02F,
    "ECDHE-RSA-AES256-GCM-SHA384": 0xC030,
    "ECDHE-RSA-CHACHA20-POLY1305": 0xCCA8,
}


class Pki:
    """A fixture CA, a server certificate, a trusted and an untrusted client."""

    def __init__(self):
        self.directory = Path(tempfile.mkdtemp(prefix="tls-mode-"))
        os.chmod(self.directory, 0o700)

        def run(*argv):
            subprocess.run(argv, cwd=self.directory, check=True, capture_output=True)

        for name in ("ca", "other-ca"):
            run(
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "2",
                "-subj",
                "/CN=fixture " + name,
                "-keyout",
                name + ".key",
                "-out",
                name + ".crt",
            )
        for name, ca in (("server", "ca"), ("client", "ca"), ("stranger", "other-ca")):
            run(
                "openssl",
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=fixture " + name,
                "-keyout",
                name + ".key",
                "-out",
                name + ".csr",
            )
            run(
                "openssl",
                "x509",
                "-req",
                "-in",
                name + ".csr",
                "-CA",
                ca + ".crt",
                "-CAkey",
                ca + ".key",
                "-set_serial",
                str(uuid.uuid4().int >> 64),
                "-days",
                "2",
                "-out",
                name + ".crt",
            )

    def text(self, name):
        return (self.directory / name).read_text()

    def path(self, name):
        return str(self.directory / name)

    def fingerprints(self):
        return {
            name: hashlib.sha256(
                ssl.PEM_cert_to_DER_cert(self.text(name + ".crt"))
            ).hexdigest()
            for name in ("ca", "other-ca", "server", "client", "stranger")
        }

    def remove(self):
        shutil.rmtree(self.directory)


async def configure(log, pki):
    """Three virtual servers; positive ACKs required."""
    pru_ssa_config_server.tmm_count = 1
    server = await asyncio.wait_for(pru_ssa_config_server.get_conf_svr(), 120)
    client = server.tmm_clients[0]
    heartbeat = client.nats_client.watch_subject(client.HEART_BEAT_SUBJECT)
    rows, recorded = [], []
    for port in (PLAIN, TERMINATED, REQUEST):
        vs = builder.create_vs_msgs(f"tls-mode-{port}", (VIP, port))
        vs += builder.add_pool_member(vs, (BACKEND, PLAIN))
        for profile in (
            builder.create_default_tcp_profile(),
            builder.create_default_http_profile(),
            builder.create_default_httprouter_profile(),
            builder.create_default_json_profile(),
            builder.create_default_sse_profile(),
        ):
            vs += builder.add_profile(vs, profile)
        native = profile_aimcp_pb2.profile_aimcp()
        native.id = native.name = str(uuid.uuid4())
        vs += builder.add_profile(vs, native)
        if port != PLAIN:
            ssl_profile = builder.create_default_clientssl_profile()
            ssl_profile.enable_session_ticket = False
            ssl_profile.cache_size = 0
            if port == REQUEST:
                ssl_profile.peer_cert_mode = "request"
                ssl_profile.trusted_ca = pki.text("ca.crt")
            vs += builder.add_profile(vs, ssl_profile, context="CLIENTSIDE")
            # Generated protobuf members are invisible to pylint.
            profile_id = ssl_profile.id  # pylint: disable=no-member
            pair = builder.create_key_certificate_pair(profile_id)
            pair.key, pair.cert = pki.text("server.key"), pki.text("server.crt")
            vs.append(pair)
        for row in vs:
            value = MessageToDict(row)
            for secret in ("key", "cert", "trustedCa"):
                if secret in value:
                    value[secret] = (
                        "<omitted sha256=%s>"
                        % hashlib.sha256(value[secret].encode()).hexdigest()
                    )
            recorded.append({"type": row.DESCRIPTOR.full_name, "value": value})
        rows += vs
    log.info("Enabling plain and client-SSL AIMCP virtual servers")
    await asyncio.wait_for(server.send_create_msgs(rows), 60)
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
            ack.generation == server.generation
            and ack.seq_start >= server.current_sequence
        ):
            break
    return recorded, acknowledgements


def context(pki, version, certificate=None):
    value = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    value.load_verify_locations(pki.path("ca.crt"))
    value.check_hostname = False
    value.minimum_version = value.maximum_version = getattr(ssl.TLSVersion, version)
    value.options |= getattr(ssl, "OP_NO_TICKET", 0x4000)
    if certificate:
        value.load_cert_chain(
            pki.path(certificate + ".crt"), pki.path(certificate + ".key")
        )
    return value


# (name, port, TLS version or None, client certificate, expected record)
PLAN = [
    ("plain", PLAIN, None, None, dict(mode="no_ssl_filter")),
    (
        "terminated-12",
        TERMINATED,
        "TLSv1_2",
        None,
        dict(
            mode="terminated",
            peer_cert_mode="ignore",
            client_certificate="not_requested",
        ),
    ),
    (
        "terminated-13",
        TERMINATED,
        "TLSv1_3",
        None,
        dict(
            mode="terminated",
            peer_cert_mode="ignore",
            client_certificate="not_requested",
        ),
    ),
    (
        "request-trusted-12",
        REQUEST,
        "TLSv1_2",
        "client",
        dict(
            mode="terminated", peer_cert_mode="request", client_certificate="verified"
        ),
    ),
    (
        "request-trusted-13",
        REQUEST,
        "TLSv1_3",
        "client",
        dict(
            mode="terminated", peer_cert_mode="request", client_certificate="verified"
        ),
    ),
    (
        "request-untrusted-12",
        REQUEST,
        "TLSv1_2",
        "stranger",
        dict(mode="terminated", peer_cert_mode="request", client_certificate="failed"),
    ),
    (
        "request-untrusted-13",
        REQUEST,
        "TLSv1_3",
        "stranger",
        dict(mode="terminated", peer_cert_mode="request", client_certificate="failed"),
    ),
    (
        "request-none-12",
        REQUEST,
        "TLSv1_2",
        None,
        dict(
            mode="terminated",
            peer_cert_mode="request",
            client_certificate="none_observed",
        ),
    ),
    (
        "request-none-13",
        REQUEST,
        "TLSv1_3",
        None,
        dict(
            mode="terminated",
            peer_cert_mode="request",
            client_certificate="none_observed",
        ),
    ),
]


def request_for(name):
    return (
        dict(jsonrpc="2.0", id="same", method="tools/call", params=dict(name=name)),
        dict(jsonrpc="2.0", id="same", result=dict(isError=False)),
    )


def all_cases():
    names = [c[0] for c in PLAN]
    names += [f"keep-{i}" for i in range(3)] + [f"concurrent-{i}" for i in range(4)]
    return [(n,) + request_for(n) for n in names]


class TlsMode(CombinedActivity):
    """Combined activity, with the client's own TLS record per exchange."""

    def __init__(self, output, pki):
        super().__init__(output)
        self.pki = pki
        self.bodies = {name: (wire(a), wire(b)) for name, a, b in all_cases()}
        self.result.update(
            scope="client TLS mode on combined records, one worker, HTTP/1",
            client_tls=[],
            certificate_sha256=pki.fingerprints(),
        )

    async def tls_client(self, names, port, version, certificate):
        tls = context(self.pki, version, certificate) if version else None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(VIP, port, ssl=tls), 10
        )
        try:
            seen = writer.get_extra_info("ssl_object")
            observed = None
            if seen is not None:
                name, _, _ = seen.cipher()
                observed = dict(
                    protocol=seen.version(),
                    cipher=name,
                    cipher_suite_id=SUITES.get(name),
                )
            for i, name in enumerate(names):
                request, reply = self.bodies[name]
                await self.exchange(
                    (name, request, reply, None, None),
                    reader,
                    writer,
                    i < len(names) - 1,
                )
                self.result["client_tls"].append(
                    dict(
                        case=name,
                        port=port,
                        version=version,
                        certificate=certificate,
                        observed=observed,
                    )
                )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ssl.SSLError, ConnectionError):
                pass

    async def finish(self):
        # Skip CombinedActivity.finish's fixed case list; keep its parents.
        await ActivityProgram.finish(self)
        self.result["combined"].extend(self.combiner.flush("end_of_input"))
        combined = [
            r
            for r in self.result["combined"]
            if r["event_type"] == "agent.activity.combined"
        ]
        assert len(combined) == len(all_cases()), len(combined)
        assert len({r["activity_id"] for r in combined}) == len(combined)
        client = {row["case"]: row for row in self.result["client_tls"]}
        plan = {
            name: (port, version, cert, expected)
            for name, port, version, cert, expected in PLAN
        }
        checked = []
        for row in combined:
            assert row["correlation"]["status"] == "observed_exchange", row
            assert row["identity"] is None and row["identity_binding"] == "unknown"
            name = row["activity"]["target"]["value"]
            tls = row["transport"]["client_tls"]
            assert tls["status"] == "observed", (name, tls)
            observed = client[name]["observed"]
            expected = (
                plan[name][3]
                if name in plan
                else dict(
                    mode="terminated",
                    peer_cert_mode="ignore",
                    client_certificate="not_requested",
                )
            )
            for key, value in expected.items():
                assert tls.get(key) == value, (name, key, tls)
            if observed is None:
                assert tls["mode"] == "no_ssl_filter" and "protocol" not in tls, (
                    name,
                    tls,
                )
            else:
                assert tls["protocol"] == observed["protocol"], (name, tls, observed)
                assert observed["cipher_suite_id"] is not None, observed
                assert tls["cipher_suite_id"] == observed["cipher_suite_id"], (
                    name,
                    tls,
                    observed,
                )
                assert tls["flags"]["handshake_ok"] and not tls["flags"]["passthru"]
            if tls.get("client_certificate") == "failed":
                assert tls["verify_result"] != 0, tls
            checked.append(dict(case=name, reading=tls, client=observed))
        self.result["tls_comparisons"] = checked
        replay = ActivityCombiner()
        split = []
        for event in self.result["replay_consumer"]["events"]:
            split.extend(replay.feed(dict(events=[event], next_cursor=event["cursor"])))
        split.extend(replay.flush("end_of_input"))
        assert [
            r for r in split if r["event_type"] == "agent.activity.combined"
        ] == combined
        self.result["single_row_page_replay"] = True


async def tls_mode_test(log, _config):
    pki = Pki()
    test = TlsMode(Path(os.environ["ICAP_RESULT"]), pki)
    with test.output.open("x", encoding="utf-8") as output:
        try:
            config, acks = await configure(log, pki)
            test.result.update(
                configuration=config, acknowledgements=acks, expected_pool=None
            )
            origin = await asyncio.start_server(test.origin, BACKEND, PLAIN)
            async with origin:
                await test.start()
                for name, port, version, certificate, _ in PLAN:
                    await test.tls_client([name], port, version, certificate)
                    await test.drain(name)
                await test.tls_client(
                    [f"keep-{i}" for i in range(3)], TERMINATED, "TLSv1_3", None
                )
                await test.drain("keep-alive")
                await asyncio.gather(
                    *(
                        test.tls_client(
                            [f"concurrent-{i}"], TERMINATED, "TLSv1_2", None
                        )
                        for i in range(4)
                    )
                )
                assert test.concurrent_arrivals == 4
                await test.drain("concurrent")
                await test.finish()
            assert (
                len(test.result["origin"])
                == len(test.result["clients"])
                == len(all_cases())
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
                pki.remove()
                text = json.dumps(test.result, indent=2)
                assert "PRIVATE KEY" not in text and "BEGIN CERTIFICATE" not in text
                output.write(text)


def publish_tests():
    return [tao.test_types.DockerBaseTest2("client TLS mode", tls_mode_test)]
