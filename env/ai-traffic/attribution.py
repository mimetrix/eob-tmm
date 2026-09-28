"""Synthetic request-proof authority and keep-alive attribution test transport.

This is a fixture protocol, not an identity-provider or MCP/A2A implementation.
Credential material stays in memory; receipts contain hashes and verified claims.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid


def encoded(value):
    """Canonical fixture JSON bytes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def proof(key, path, nonce, body):
    """Bind the request proof to its destination, attempt and exact body."""
    return hmac.new(
        key,
        b"POST\n" + path.encode() + b"\n" + nonce.encode() + b"\n" + body,
        hashlib.sha256,
    ).hexdigest()


async def read_message(reader):
    """Read a bounded fixed-length fixture HTTP message; reject ambiguity."""
    block = await reader.readuntil(b"\r\n\r\n")
    lines = block.decode("ascii").split("\r\n")
    headers = {}
    for line in lines[1:-2]:
        key, value = line.split(":", 1)
        key = key.lower()
        if key in headers:
            raise ValueError("duplicate fixture header")
        headers[key] = value.strip()
    if "transfer-encoding" in headers:
        raise ValueError("fixture requires fixed content length")
    length = int(headers["content-length"])
    if not 0 <= length <= 16384:
        raise ValueError("fixture message too large")
    return lines[0], headers, await reader.readexactly(length)


class Rejected(Exception):
    """A deliberate authentication or authorization rejection."""


class Authority:
    """Destination-side test authority with independently provisioned agents."""

    def __init__(self):
        self.keys = {name: secrets.token_bytes(32) for name in ("agent-A", "agent-B")}
        self.grant_key = secrets.token_bytes(32)
        self.seen = set()
        self.operations = {}
        self.ledger = []
        self.errors = []

    def mint(self, actor, params):
        """An actor can delegate only its own accepted operation and allowed scope."""
        parent = self.operations.get(params.get("parent"))
        if not parent or parent["actor"] != actor:
            raise Rejected("parent_not_owned")
        if params.get("recipient") not in self.keys or params.get("scope") != [
            "tools/call"
        ]:
            raise Rejected("delegation_not_permitted")
        claims = {
            "issuer": actor,
            "recipient": params["recipient"],
            "parent": parent["operation"],
            "originator": parent["originator"],
            "scope": params["scope"],
            "audience": "fixture-tools",
            "expires": time.time() + 60,
        }
        payload = base64.urlsafe_b64encode(encoded(claims)).decode()
        signature = hmac.new(
            self.grant_key, payload.encode(), hashlib.sha256
        ).hexdigest()
        return payload + "." + signature

    def delegation(self, token, actor, method):
        """Check authority, recipient, accepted parent, scope, audience and expiry."""
        try:
            payload, signature = token.split(".")
            expected = hmac.new(
                self.grant_key, payload.encode(), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(signature, expected):
                raise Rejected("invalid_grant_signature")
            claims = json.loads(base64.urlsafe_b64decode(payload))
            parent = self.operations.get(claims["parent"])
            if not parent or parent["actor"] != claims["issuer"]:
                raise Rejected("invalid_grant_parent")
            if claims["recipient"] != actor:
                raise Rejected("wrong_grant_recipient")
            if claims["audience"] != "fixture-tools" or method not in claims["scope"]:
                raise Rejected("grant_scope")
            if claims["expires"] <= time.time():
                raise Rejected("expired_grant")
            return claims
        except (ValueError, KeyError, TypeError) as error:
            raise Rejected("malformed_grant") from error

    def authenticate(self, headers, body, row):
        """Set an actor only after the request proof verifies under its own key."""
        actor = headers.get("x-agent-key")
        key = self.keys.get(actor)
        if (
            not key
            or not row["nonce"]
            or not hmac.compare_digest(
                proof(key, row["path"], row["nonce"], body),
                headers.get("x-request-proof", ""),
            )
        ):
            raise Rejected("invalid_request_proof")
        row.update(
            actor=actor,
            auth_evidence="fixture-hmac-request-proof",
            principal="configured-principal-" + actor,
            claim_mismatch=row["claimed_actor"] not in (None, actor),
        )
        return actor

    def process(self, path, headers, body, connection, peer):
        """Authenticate before attribution, then authorize before recording an action."""
        row = {
            "attempt": uuid.uuid4().hex,
            "nonce": headers.get("x-proof-nonce", ""),
            "connection": connection,
            "peer": peer,
            "path": path,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "actor": None,
            "originator": None,
            "parent": None,
            "claimed_actor": headers.get("x-claimed-agent"),
            "accepted": False,
            "reason": "unauthenticated",
        }
        response = {}
        status = 401
        try:
            actor = self.authenticate(headers, body, row)
            status = 403
            if (actor, row["nonce"]) in self.seen:
                raise Rejected("replayed_nonce")
            self.seen.add((actor, row["nonce"]))
            data = json.loads(body)
            row.update(
                method=data["method"],
                caller_id=data.get("id"),
                caller_operation=data.get("operation"),
                caller_session=data.get("session"),
                caller_task=data.get("task"),
            )
            originator, parent = actor, None
            if "delegation" in data:
                grant = self.delegation(data["delegation"], actor, data["method"])
                originator, parent = grant["originator"], grant["parent"]
                row["delegation_sha256"] = hashlib.sha256(
                    data["delegation"].encode()
                ).hexdigest()
            if path == "/delegate" and data["method"] == "delegate":
                if parent:
                    raise Rejected("redelegation_not_supported")
                response["grant"] = self.mint(actor, data["params"])
            elif (path, data["method"]) not in (
                ("/mcp", "tools/call"),
                ("/mcp", "resources/read"),
                ("/a2a", "SendMessage"),
            ):
                raise Rejected("unsupported_fixture_operation")
            row.update(
                accepted=True,
                reason="accepted",
                operation=uuid.uuid4().hex,
                originator=originator,
                parent=parent,
            )
            self.operations[row["operation"]] = row.copy()
            status = 200
        except Rejected as error:
            row["reason"] = str(error)
        self.ledger.append(row)
        response.update(row)
        return status, response

    async def serve(self, reader, writer):
        """Retain per-request identity while reusing the underlying connection."""
        connection = uuid.uuid4().hex
        peer = list(writer.get_extra_info("peername"))
        try:
            while True:
                first, headers, body = await read_message(reader)
                method, path, version = first.split()
                if method != "POST" or version != "HTTP/1.1":
                    raise ValueError("unexpected fixture request")
                status, response = self.process(path, headers, body, connection, peer)
                payload = encoded(response)
                writer.write(
                    f"HTTP/1.1 {status} Fixture\r\nContent-Length: {len(payload)}\r\n"
                    "Content-Type: application/json\r\n\r\n".encode() + payload
                )
                await writer.drain()
        except asyncio.IncompleteReadError as error:
            if error.partial:
                self.errors.append("truncated request")
        except (OSError, ValueError, KeyError) as error:
            self.errors.append(repr(error))
        finally:
            writer.close()
            await writer.wait_closed()


class Client:
    """Client-side expectations independent of the server's actor decision."""

    def __init__(self, reader, writer, keys, receipt):
        self.reader = reader
        self.writer = writer
        self.keys = keys
        self.receipt = receipt

    async def exchange(self, headers, body):
        """Exchange one fixed-length message on this persistent connection."""
        self.writer.write(headers.encode() + b"\r\n" + body)
        await self.writer.drain()
        first, _, raw = await read_message(self.reader)
        return int(first.split()[1]), json.loads(raw)

    async def request(self, name, actor, path, method, expected_actor, **options):
        """Submit a signed attempt with deliberately colliding untrusted IDs."""
        nonce = options.get("nonce") or uuid.uuid4().hex
        body = encoded(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "operation": "same-operation",
                "session": "same-session",
                "task": "same-task",
                "method": method,
                **{k: v for k, v in options.items() if k in ("params", "delegation")},
            }
        )
        signature = proof(self.keys[options.get("key_actor", actor)], path, nonce, body)
        headers = (
            f"POST {path} HTTP/1.1\r\nHost: fixture\r\nContent-Length: {len(body)}\r\n"
            f"X-Agent-Key: {actor}\r\nX-Proof-Nonce: {nonce}\r\n"
            f"X-Request-Proof: {signature}\r\n"
        )
        if options.get("claimed"):
            headers += f"X-Claimed-Agent: {options['claimed']}\r\n"
        observed, result = await self.exchange(headers, body)
        # Do not archive signed grant credentials returned by /delegate.
        self.receipt.append(
            {
                "case": name,
                "expected_actor": expected_actor,
                "expected_status": options.get("status", 200),
                "status": observed,
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "nonce": nonce,
                "result": {k: v for k, v in result.items() if k != "grant"},
            }
        )
        assert observed == options.get("status", 200), self.receipt[-1]
        assert result["actor"] == expected_actor, self.receipt[-1]
        assert result["accepted"] == (observed == 200), self.receipt[-1]
        if observed == 200:
            assert result["originator"] == options.get(
                "originator", actor
            ), self.receipt[-1]
        return result

    async def close(self):
        """Close the persistent client connection."""
        self.writer.close()
        await self.writer.wait_closed()
