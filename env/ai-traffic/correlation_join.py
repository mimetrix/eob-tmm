"""A bounded fixture join. Candidate equality is not credential validation."""
from collections import Counter, defaultdict


def join(lifetimes, candidates, ledger, accounting):
    """Check the complete recorded window before matching untrusted values."""
    completed = [e for e in lifetimes if e["kind"] == 2 and e["value"] == 0]
    output = [
        {
            "observation_sequence": e["sequence"],
            "lifetime": e["lifetime"],
            "attempt": e["attempt"],
            "status": "unknown",
            "reason": None,
            "actor": None,
            "operation": None,
        }
        for e in completed
    ]
    try:
        stream = sorted(lifetimes + candidates, key=lambda e: e["sequence"])
        assert stream and all(type(e["sequence"]) is int for e in stream)
        assert [e["sequence"] for e in stream] == list(range(1, len(stream) + 1))
        assert len({e["run"] for e in stream}) == 1 and stream[0]["run"] > 0
        assert all(e["failures"] == 0 for e in stream)
        counts = Counter(e["kind"] for e in lifetimes)
        for key, expected in (
            ("init", counts[1]),
            ("parse", counts[2]),
            ("fini", counts[3]),
            ("candidate", len(candidates)),
            ("drops", 0),
            ("errors", 0),
            ("selections", 0),
        ):
            assert type(accounting[key]) is int and accounting[key] == expected
        assert len(ledger) == len(completed)
        born, ended, attempts, pending = set(), set(), Counter(), {}
        for e in lifetimes:
            life = e["lifetime"]
            if e["kind"] == 1:
                assert not e["flags"] and life > 0 and life not in born
                assert not e["value"] or e["value"] in ended
                born.add(life)
            elif e["flags"] == 32:
                assert not life and not e["attempt"]
            elif e["kind"] == 2:
                assert not e["flags"] and life in born and life not in ended
                assert e["value"] in (0, 17)
                if not pending.get(life):
                    attempts[life] += 1
                assert e["attempt"] == attempts[life]
                pending[life] = e["value"] == 17
            else:
                assert e["kind"] == 3 and life in born and life not in ended
                assert e["flags"] == (256 if pending.get(life) else 0)
                assert e["attempt"] == attempts[life]
                ended.add(life)
        assert born == ended
    except (AssertionError, KeyError, TypeError, ValueError):
        for row in output:
            row["reason"] = "incomplete_or_invalid_window"
        return output
    by_interval = defaultdict(list)
    for event in candidates:
        by_interval[(event["lifetime"], event["attempt"])].append(event)
    values = []
    for e in completed:
        group = by_interval[(e["lifetime"], e["attempt"])] if e["lifetime"] else []
        terminal = [c for c in group if c["flags"] == 1]
        valid = (
            len(terminal) == 1
            and all(c["flags"] in (0, 1) for c in group)
            and all(c["sequence"] < e["sequence"] for c in group)
        )
        c = terminal[0] if valid else {}
        key = (c.get("path"), c.get("nonce"))
        valid = valid and key[0] in ("/mcp", "/a2a", "/delegate")
        valid = valid and isinstance(key[1], str) and len(key[1]) == 32
        valid = valid and all(ch in "0123456789abcdefABCDEF" for ch in key[1])
        values.append(key if valid else None)
    frequency = Counter(values)
    authority = defaultdict(list)
    for row in ledger:
        authority[(row.get("path"), row.get("nonce"))].append(row)
    for result, event, key in zip(output, completed, values):
        if not event["lifetime"]:
            result["reason"] = "missing_parser_initialization"
        elif key is None:
            result["reason"] = "unavailable_candidate"
        elif frequency[key] != 1 or len(authority[key]) > 1:
            result["reason"] = "ambiguous_candidate"
        elif not authority[key]:
            result["reason"] = "missing_ledger_match"
        else:
            matched = authority[key][0]
            result["authority_attempt"] = matched["attempt"]
            if not matched.get("actor") or not matched.get("auth_evidence"):
                result["reason"] = "no_authentication_evidence"
            elif matched.get("accepted") is False:
                result.update(
                    status="rejected",
                    reason="authority_rejected",
                    actor=matched["actor"],
                )
            elif matched.get("accepted") is True and matched.get("operation"):
                result.update(
                    status="attributed",
                    reason="unique_authenticated_fixture_attempt",
                    actor=matched["actor"],
                    operation=matched["operation"],
                    originator=matched.get("originator"),
                    parent=matched.get("parent"),
                )
            else:
                result["reason"] = "incomplete_authority_record"
    return output
