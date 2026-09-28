#!/usr/bin/env python3
"""Challenge the join with a retained authority ledger and synthetic observations.

No observation in this check is a live TMM event. Collision proofs use fresh
in-memory fixture keys, which are never serialized into the receipt.
"""

import argparse
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path

from attribution import Authority, encoded, proof
from attribution_join import join


def observations(ledger):
    """Explicitly synthetic request scope; never presented as a TMM capture."""
    return [
        {
            "process_session": "SYNTHETIC-NOT-TMM",
            "request_seq": index + 1,
            "path": row["path"],
            "nonce": row["nonce"],
            "config_instance": "SYNTHETIC-CONFIG",
            "config_revision": 1,
        }
        for index, row in enumerate(ledger)
    ]


def counts(size):
    """Synthetic accounting is used only to test the consumer's decision rules."""
    return {
        "requests": size,
        "fired": size,
        "events": size,
        "ledger_attempts": size,
        "drops": 0,
        "errors": 0,
    }


def collision_ledger():
    """The authority really verifies A/B with the same nonce, then rejects replay."""
    authority = Authority()
    body = encoded({"method": "tools/call", "id": 7})
    for actor, expected in (("agent-A", 200), ("agent-B", 200), ("agent-A", 403)):
        headers = {
            "x-agent-key": actor,
            "x-proof-nonce": "deliberately-shared-nonce",
            "x-request-proof": proof(
                authority.keys[actor], "/mcp", "deliberately-shared-nonce", body
            ),
        }
        status, _ = authority.process("/mcp", headers, body, "fixture", ["fixture", 1])
        assert status == expected
    return authority.ledger


def check(ledger, record):
    """Retain each challenge's output, including the conservative replay refusal."""
    events = observations(ledger)

    def run(name, source=events, authority=ledger, **options):
        output = join(
            source,
            authority,
            accounting=options.get("accounting", counts(len(events))),
            request_scope_validated=options.get("qualified", True),
        )
        record["checks"].append({"name": name, "output": output})
        return output

    baseline = run("retained-ledger-with-synthetic-candidates")
    assert Counter(row["status"] for row in baseline) == {
        "attributed": 16,
        "rejected": 4,
        "unknown": 3,
    }
    for result, authority in zip(baseline, ledger):
        if result["status"] == "attributed":
            assert result["authenticated_actor"] == authority["actor"]
            assert result["operation"] == authority["operation"]
            assert result["parent"] == authority["parent"]
            assert result["originator"] == authority["originator"]
        else:
            assert result["operation"] is None and result["parent"] is None
        if authority.get("claim_mismatch"):
            assert result["authenticated_actor"] == "agent-A"
            assert result["claimed_actor"] == "agent-B"
    assert any(row["parent"] for row in baseline), "delegation edge not exercised"
    assert run("ledger-order-irrelevant", authority=list(reversed(ledger))) == baseline
    assert run("event-order-irrelevant", source=list(reversed(events))) == list(
        reversed(baseline)
    )
    for label, options in (
        ("scope-unvalidated", {"qualified": False}),
        ("scope-not-boolean", {"qualified": 1}),
        ("missing-accounting", {"accounting": {}}),
        ("reported-drop", {"accounting": dict(counts(len(events)), drops=1)}),
        ("reported-error", {"accounting": dict(counts(len(events)), errors=1)}),
        ("boolean-count", {"accounting": dict(counts(len(events)), drops=False)}),
        ("counter-mismatch", {"accounting": dict(counts(len(events)), fired=24)}),
    ):
        assert all(row["status"] == "unknown" for row in run(label, **options))
    assert all(
        row["status"] == "unknown"
        for row in run("missing-ledger-row", authority=ledger[:-1])
    )
    assert all(
        row["status"] == "unknown" for row in run("missing-event", source=events[:-1])
    )
    duplicate = copy.deepcopy(events)
    duplicate[1]["request_seq"] = duplicate[0]["request_seq"]
    assert all(
        row["status"] == "unknown"
        for row in run("duplicate-request-identity", source=duplicate)
    )
    duplicate[0]["request_seq"] = True
    assert all(
        row["status"] == "unknown"
        for row in run("boolean-request-sequence", source=duplicate)
    )
    for label, changes, reason in (
        ("missing-candidate", {"nonce": ""}, "missing_candidate"),
        ("no-matching-ledger", {"nonce": "not-in-ledger"}, "missing_ledger_match"),
        (
            "duplicate-candidate-event",
            {"nonce": events[1]["nonce"], "path": events[1]["path"]},
            "ambiguous_candidate",
        ),
    ):
        modified = copy.deepcopy(events)
        modified[0].update(changes)
        output = run(label, source=modified)
        assert output[0]["status"] == "unknown" and output[0]["reason"] == reason
    modified = copy.deepcopy(ledger)
    modified[0].pop("auth_evidence")
    assert run("identity-without-proof", authority=modified)[0]["status"] == "unknown"
    modified = copy.deepcopy(ledger)
    modified[0].pop("operation")
    assert (
        run("incomplete-accepted-record", authority=modified)[0]["status"] == "unknown"
    )
    modified = copy.deepcopy(events)
    modified[0].update(config_instance="OTHER-CONFIG", config_revision=99)
    output = run("configuration-does-not-authenticate", source=modified)
    assert output[0]["authenticated_actor"] == baseline[0]["authenticated_actor"]
    assert output[0]["config_instance"] == "OTHER-CONFIG"
    collision = collision_ledger()
    record["collision_authority_ledger"] = collision
    output = run(
        "verified-A-B-nonce-collision-and-replay",
        source=observations(collision),
        authority=collision,
        accounting=counts(3),
    )
    assert all(row["reason"] == "ambiguous_candidate" for row in output)
    assert all(row["authenticated_actor"] is None for row in output)
    record["baseline_dispositions"] = dict(Counter(row["status"] for row in baseline))


def main():
    """Accept the immutable baseline snapshot; write a new receipt even on failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    record = {
        "passed": False,
        "scope": "join algorithm fixture; synthetic candidate observations, no live TMM join",
        "checks": [],
    }
    with args.receipt.open("x", encoding="utf-8") as receipt:
        try:
            record["baseline_sha256"] = hashlib.sha256(
                args.baseline.read_bytes()
            ).hexdigest()
            snapshot = json.loads(args.baseline.read_text())
            files = json.loads(snapshot["result"]["records"][1]["stdout"])
            baseline = json.loads(files["/evidence/attribution-01/result.json"])
            assert baseline["passed"] and len(baseline["server"]) == 23
            record["sources"] = {
                name: hashlib.sha256(
                    Path(__file__).with_name(name).read_bytes()
                ).hexdigest()
                for name in (
                    "attribution.py",
                    "attribution_join.py",
                    Path(__file__).name,
                )
            }
            check(baseline["server"], record)
            record["passed"] = True
        finally:
            json.dump(record, receipt, indent=2)
    print(json.dumps({"passed": True, "checks": len(record["checks"])}))


if __name__ == "__main__":
    main()
