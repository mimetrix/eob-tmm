#!/usr/bin/env python3
"""Export one collector replay page as versioned agent activity observations."""
import argparse
import json
from pathlib import Path
import sqlite3
import sys

from id_flow_decode import decode as decode_id_flow
from message_id_decode import decode as decode_id
from method_decode import decode as decode_method
from operation_target_decode import decode as decode_target
from reply_metadata_decode import decode as decode_reply
from response_metadata_decode import decode as decode_response
from token_method_decode import decode as decode_token_method
from activity_group_decode import MAGIC as GROUP_MAGIC, unwrap


DECODERS = {
    0x4A4D4554: ("method", decode_method),
    0x544D4554: ("method", decode_token_method),
    0x4F544754: ("operation_target", decode_target),
    0x52504C59: ("reply", decode_reply),
    0x5253504D: ("http_response", decode_response),
    0x4D534749: ("message_id", decode_id),
    0x4944464C: ("message_id", decode_id_flow),
}
COUNTERS = ("instance", "revision", "run", "monotonic_ns", "sequence", "output_failures")
DIAGNOSTICS = {"source_boundary", "observation_gap", "discard", "ring_health"}


def string_field(record):
    """Keep bytes and extraction state; decode text only for complete strings."""
    field = {"status": record["status_name"], "raw_hex": record["value_hex"],
             "representation": "json_string_escaped_bytes",
             "original_length": record["original_length"]}
    if record["status"] == 1:
        try:
            field["value"] = json.loads('"' + bytes.fromhex(record["value_hex"]).decode("utf-8") + '"')
        except (ValueError, UnicodeError):
            field["text_error"] = "invalid_json_string_bytes"
    return field


def fields(kind, record):
    activity, outcome = {}, {}
    if kind == "method":
        activity["method"] = string_field(record)
    elif kind == "operation_target":
        activity["target"] = dict(string_field(record), kind=record["target_kind_name"])
    elif kind == "message_id":
        if record["id_kind"] == 1:
            value = string_field(record)
        else:
            value = {"status": record["status_name"], "raw_hex": record["value_hex"],
                     "representation": "json_token_bytes"}
            if record["status"] == 1:
                # Numeric spelling is an observation, not a floating-point number.
                value["value"] = bytes.fromhex(record["value_hex"]).decode("ascii")
        activity["message_id"] = dict(value, kind=record["id_kind_name"])
        if "flow_status_name" in record:
            activity["flow_side"] = {"status": record["flow_status_name"],
                                     "value": record["flow_side_name"]}
    elif kind == "reply":
        outcome["status"] = record["status_name"]
        if record["status"] == 1:
            outcome.update(result_present=bool(record["result_present"]),
                           error_present=bool(record["error_present"]))
            for name, state, value in (("error_code", "code_state", "error_code"),
                                       ("tool_error", "tool_error_state", "tool_error")):
                outcome[name] = {"status": record[state + "_name"]}
                if record[state] == 1:
                    outcome[name]["value"] = bool(record[value]) if name == "tool_error" else record[value]
    elif kind == "http_response":
        for name, state, value in (("http_status", "http_status_state", "http_status"),
                                   ("local_transfer_complete", "completion_state", "transfer_complete")):
            outcome[name] = {"status": record[state + "_name"]}
            if record[state] == 1:
                outcome[name]["value"] = bool(record[value]) if name == "local_transfer_complete" else record[value]
        if record.get("client_tls", {}).get("mode", "not_applicable") != "not_applicable":
            # TMM's client-side SSL filter state. Evidence of a TMM state,
            # not an identity; see TLS-MODE.md.
            activity["client_tls"] = record["client_tls"]
    return activity, outcome


def project_event(event):
    """One observation per input. No identity inference or cross-record joins."""
    evidence = {"source_id": event.get("source_id"), "event_id": event.get("event_id"),
                "source": event.get("source"), "continuity": "not_established",
                "program_binding": "not_verified_by_exporter"}
    output = {"schema_version": 1, "event_type": "agent.observation",
              "identity_binding": "unknown", "identity": None,
              "correlation": {"status": "unknown"},
              "activity": {}, "reported_outcome": {}, "evidence": evidence}
    kind = event.get("type")
    if kind != "record":
        output["event_type"] = "agent." + kind if kind in DIAGNOSTICS else "agent.observation"
        evidence.update(status="diagnostic", diagnostic=event)
        return output
    raw = event.get("raw", {})
    evidence["raw"] = raw
    try:
        if not isinstance(raw, dict) or not isinstance(raw.get("data"), str) or len(raw["data"]) > 1024:
            raise ValueError("invalid or oversize record")
        payload = bytes.fromhex(raw["data"])
        if int.from_bytes(payload[:4], "little") == GROUP_MAGIC:
            evidence["group"], payload = unwrap(payload)
        decoder = DECODERS.get(int.from_bytes(payload[:4], "little"))
        if raw.get("schema") != 100 or decoder is None:
            evidence["status"] = "unsupported_schema"
            return output
        kind, decode = decoder
        record = decode(payload)
    except (ValueError, TypeError) as error:
        evidence.update(status="malformed_record", error=str(error))
        return output
    evidence.update(status="decoded", observation=kind,
                    record={k: str(v) if k in COUNTERS else v for k, v in record.items()},
                    output_loss_reported=bool(record["output_failures"]))
    if record["flags"] or not all(record[key] for key in ("instance", "revision", "run", "sequence")):
        evidence["status"] = "unqualified_record"
        return output
    output["event_type"] = "agent.activity"
    output["activity"], output["reported_outcome"] = fields(kind, record)
    return output


def project_page(page):
    """Keep replay boundaries and every cursor, including diagnostic rows."""
    if not isinstance(page, dict):
        raise ValueError("expected a collector replay object")
    if "error" in page:
        return dict(page)
    if not isinstance(page.get("events"), list) or len(page["events"]) > 128:
        raise ValueError("expected a bounded collector replay page")
    if not isinstance(page.get("next_cursor"), str):
        raise ValueError("missing replay cursor")
    if any(not isinstance(row, dict) or not isinstance(row.get("cursor"), str)
           or not isinstance(row.get("event"), dict) for row in page["events"]):
        raise ValueError("invalid replay row")
    result = dict(page)
    result["format"] = "agent_activity/v1"
    result["events"] = [{"cursor": row["cursor"], "event": project_event(row["event"])}
                        for row in page["events"]]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--socket", type=Path, help="existing collector replay socket")
    source.add_argument("--journal", type=Path, help="local collector SQLite journal, read-only")
    source.add_argument("--page", type=Path, help="saved collector replay page (JSON)")
    parser.add_argument("--after", help="last cursor accepted by this consumer")
    parser.add_argument("--limit", type=int, default=128)
    args = parser.parse_args()
    if not 1 <= args.limit <= 128:
        parser.error("limit must be 1..128")
    if args.page and args.after:
        parser.error("--after applies to a socket or journal, not a saved page")
    status = 200
    try:
        if args.socket:
            from collector_client import page
            document = page(args.socket, args.after, args.limit)
        elif args.journal:
            from stream_collector import replay
            status, document = replay(args.journal, args.after, args.limit)
        else:
            document = json.loads(args.page.read_text())
        result = project_page(document)
        print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
        return 0 if status == 200 and "error" not in result else 1
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as error:
        print("activity export failed; cursor not advanced: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
