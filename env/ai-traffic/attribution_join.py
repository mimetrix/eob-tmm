"""Conservative bounded-window join; identity comes only from a trusted ledger.

The caller must authenticate the ledger's provenance and independently establish
request scope and window accounting. These inputs are evidence gates, not caller
headers. No live TMM producer has yet qualified those gates for attribution.
"""

from collections import Counter, defaultdict


def integer(value):
    """JSON booleans are not valid counts or request sequences."""
    return isinstance(value, int) and not isinstance(value, bool)


def candidate(row):
    """A correlation candidate is never an authenticated attempt identifier."""
    path, nonce = row.get("path"), row.get("nonce")
    if not isinstance(path, str) or not path.startswith("/"):
        return None
    if not isinstance(nonce, str) or not nonce:
        return None
    return path, nonce


def window_error(observations, ledger, accounting, request_scope_validated):
    """Fail closed before matching when cardinality or lifetime is unproven."""
    if request_scope_validated is not True:
        return "unvalidated_request_scope"
    expected = {
        "requests": len(observations),
        "fired": len(observations),
        "events": len(observations),
        "ledger_attempts": len(observations),
        "drops": 0,
        "errors": 0,
    }
    if len(ledger) != len(observations) or any(
        not integer(accounting.get(key)) or accounting[key] != value
        for key, value in expected.items()
    ):
        return "incomplete_or_lossy_window"
    identities = []
    for event in observations:
        session, sequence = event.get("process_session"), event.get("request_seq")
        if (
            not isinstance(session, str)
            or not session
            or not integer(sequence)
            or sequence < 1
        ):
            return "invalid_request_identity"
        identities.append((session, sequence))
    if len(set(identities)) != len(identities):
        return "duplicate_request_identity"
    return None


def join(observations, ledger, *, accounting, request_scope_validated=False):
    """Return one disposition per observation; never break ambiguous ties."""
    error = window_error(observations, ledger, accounting, request_scope_validated)
    observed = Counter(candidate(row) for row in observations)
    attempts = defaultdict(list)
    for row in ledger:
        attempts[candidate(row)].append(row)
    result = []
    for event in observations:
        row = {
            "process_session": event.get("process_session"),
            "request_seq": event.get("request_seq"),
            "config_instance": event.get("config_instance"),
            "config_revision": event.get("config_revision"),
            "status": "unknown",
            "reason": error,
            "authenticated_actor": None,
            "operation": None,
            "originator": None,
            "parent": None,
        }
        result.append(row)
        if error:
            continue
        key = candidate(event)
        matches = attempts.get(key, [])
        if key is None:
            row["reason"] = "missing_candidate"
        elif observed[key] != 1 or len(matches) > 1:
            row["reason"] = "ambiguous_candidate"
        elif not matches:
            row["reason"] = "missing_ledger_match"
        else:
            authority = matches[0]
            row.update(
                attempt=authority.get("attempt"),
                claimed_actor=authority.get("claimed_actor"),
                accepted=authority.get("accepted") is True,
                authority_reason=authority.get("reason"),
            )
            if authority.get("accepted") is True and not authority.get("operation"):
                row["reason"] = "incomplete_authority_record"
            elif not authority.get("actor") or not authority.get("auth_evidence"):
                row["reason"] = "no_authentication_evidence"
            else:
                row.update(
                    authenticated_actor=authority["actor"],
                    auth_evidence=authority["auth_evidence"],
                    status="rejected",
                    reason="authority_rejected",
                )
                if authority.get("accepted") is True and authority.get("operation"):
                    row.update(
                        status="attributed",
                        reason="unique_authenticated_attempt",
                        operation=authority["operation"],
                        originator=authority.get("originator"),
                        parent=authority.get("parent"),
                    )
    return result
