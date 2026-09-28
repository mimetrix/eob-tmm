"""SSA/Tao two-agent attribution oracle through the isolated TMM fixture."""

import asyncio
from collections import Counter
import json
import os
from pathlib import Path
import uuid

import tao
import tao.runner
import tao.test_types

from attribution import Authority, Client
from icap_suite import BACKEND, VIP, configure


PORT = 18092


async def exercise(client):
    """Challenge identity, retry and delegation on one shared connection."""
    root = await client.request("root-A", "agent-A", "/a2a", "SendMessage", "agent-A")
    await client.request("root-B", "agent-B", "/a2a", "SendMessage", "agent-B")
    await client.request("tool-A", "agent-A", "/mcp", "tools/call", "agent-A")
    await client.request("tool-B", "agent-B", "/mcp", "tools/call", "agent-B")
    claimed = await client.request(
        "spoof-claim", "agent-A", "/mcp", "tools/call", "agent-A", claimed="agent-B"
    )
    assert claimed["claim_mismatch"], claimed
    await client.request(
        "forged-credential",
        "agent-B",
        "/mcp",
        "tools/call",
        None,
        status=401,
        key_actor="agent-A",
    )
    nonce = uuid.uuid4().hex
    first = await client.request(
        "before-replay", "agent-A", "/mcp", "tools/call", "agent-A", nonce=nonce
    )
    await client.request(
        "replay", "agent-A", "/mcp", "tools/call", "agent-A", status=403, nonce=nonce
    )
    retry = await client.request(
        "fresh-retry", "agent-A", "/mcp", "tools/call", "agent-A"
    )
    assert retry["operation"] != first["operation"], retry
    params = {
        "parent": root["operation"],
        "recipient": "agent-B",
        "scope": ["tools/call"],
    }
    minted = await client.request(
        "delegate-A-to-B", "agent-A", "/delegate", "delegate", "agent-A", params=params
    )
    grant = minted["grant"]
    delegated = await client.request(
        "delegated-tool",
        "agent-B",
        "/mcp",
        "tools/call",
        "agent-B",
        originator="agent-A",
        delegation=grant,
    )
    assert delegated["parent"] == root["operation"], delegated
    await client.request(
        "wrong-recipient",
        "agent-A",
        "/mcp",
        "tools/call",
        "agent-A",
        status=403,
        delegation=grant,
    )
    await client.request(
        "out-of-scope",
        "agent-B",
        "/mcp",
        "resources/read",
        "agent-B",
        status=403,
        delegation=grant,
    )
    modified = grant[:-1] + ("0" if grant[-1] != "0" else "1")
    await client.request(
        "tampered-grant",
        "agent-B",
        "/mcp",
        "tools/call",
        "agent-B",
        status=403,
        delegation=modified,
    )
    await client.request(
        "foreign-parent",
        "agent-B",
        "/delegate",
        "delegate",
        "agent-B",
        status=403,
        params=params,
    )


async def concurrent(client, actor):
    """Interleave two independent connections without changing caller labels."""
    for index in range(4):
        await client.request(
            f"concurrent-{actor}-{index}", actor, "/mcp", "tools/call", actor
        )
        await asyncio.sleep(0.005)


def reconcile(result, authority):
    """Require exact attempt/action reconciliation and demonstrated reuse."""
    clients, server = result["clients"], authority.ledger
    assert not authority.errors, authority.errors
    assert len(clients) == len(server) == 23, (len(clients), len(server))
    assert Counter(row["result"]["attempt"] for row in clients) == Counter(
        row["attempt"] for row in server
    )
    assert sum(row["accepted"] for row in server) == 17
    shared = [
        row["result"] for row in clients if not row["case"].startswith("concurrent-")
    ]
    assert (
        len({row["connection"] for row in shared}) == 1
    ), "backend connection not reused"
    assert {row["actor"] for row in shared if row["accepted"]} == {"agent-A", "agent-B"}
    assert all(
        row["peer"][0] == "10.203.72.10" for row in server
    ), "unexpected origin peer"
    by_attempt = {row["attempt"]: row for row in server}
    for row in clients:
        observed = by_attempt[row["result"]["attempt"]]
        assert observed == row["result"], row["case"]
        assert observed["body_sha256"] == row["body_sha256"]
    result["summary"] = {
        "attempts": len(server),
        "accepted": 17,
        "rejected": 6,
        "shared_connection_requests": len(shared),
        "actors": ["agent-A", "agent-B"],
    }


async def attribution_test(log, _config):
    """Configure the HTTP-only listener and execute the independent oracle."""
    authority = Authority()
    result = {
        "passed": False,
        "clients": [],
        "server": authority.ledger,
        "server_errors": authority.errors,
        "scope": "destination-authenticated fixture; no eBPF attached",
    }
    clients = []
    path = Path(os.environ["ICAP_RESULT"])
    with path.open("x", encoding="utf-8") as output:
        try:
            result["acknowledgements"] = await configure(log, port=PORT)
            async with await asyncio.start_server(authority.serve, BACKEND, PORT):
                for _ in range(3):
                    reader, writer = await asyncio.open_connection(VIP, PORT)
                    clients.append(
                        Client(reader, writer, authority.keys, result["clients"])
                    )
                await asyncio.wait_for(exercise(clients[0]), 30)
                await asyncio.wait_for(
                    asyncio.gather(
                        concurrent(clients[1], "agent-A"),
                        concurrent(clients[2], "agent-B"),
                    ),
                    30,
                )
                reconcile(result, authority)
                result["passed"] = True
                return tao.Result.PASS
        except Exception as error:
            result.update(error=repr(error))
            raise
        finally:
            closed = await asyncio.gather(
                *(client.close() for client in clients), return_exceptions=True
            )
            errors = [
                repr(error) for error in closed if isinstance(error, BaseException)
            ]
            if errors:
                result.update(passed=False, close_errors=errors)
            json.dump(result, output, indent=2, sort_keys=True)
            output.write("\n")


def publish_tests():
    """Publish a single explicitly selected attribution test."""
    return [tao.test_types.DockerBaseTest2("two-agent attribution", attribution_test)]
