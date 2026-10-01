#!/usr/bin/env python3
"""Combine explicitly keyed activity records across collector replay pages."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import time

from activity_export import project_page


def nanoseconds(value):
    """Read an exact positive uint64 timestamp, without float conversion."""
    if isinstance(value, str) and value.isascii() and value.isdecimal() and len(value) <= 20:
        value = int(value)
    return value if type(value) is int and 0 < value < 1 << 64 else None


def timestamp(value):
    value = nanoseconds(value)
    if value is None:
        return None
    seconds, fraction = divmod(value, 1_000_000_000)
    date = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    return date.strftime("%Y-%m-%dT%H:%M:%S") + f".{fraction:09d}Z"


def observation_timing(rows):
    """Source observation times; an invalidation/flush is not a response end."""
    first, last = [row["event"]["evidence"] for row in (rows[0], rows[-1])]
    ended = last["group"]["phase"] == 3
    start = nanoseconds(first["record"].get("monotonic_ns"))
    end = nanoseconds(last["record"].get("monotonic_ns")) if ended else None
    duration = str(end - start) if start is not None and end is not None and end >= start else None
    timing = dict(started_at=timestamp(first["raw"].get("ts_ns")),
                  ended_at=timestamp(last["raw"].get("ts_ns")) if ended else None,
                  last_observed_at=timestamp(last["raw"].get("ts_ns")),
                  duration_ns=duration)
    timing["status"] = "complete" if all(v is not None for v in timing.values()) else "incomplete"
    if start is not None and end is not None and end < start:
        timing["status"] = "invalid"
    return timing


class ActivityCombiner:
    """Bounded HTTP/1 exchange groups. IDs and addresses never select a group."""

    def __init__(self, capacity=128, max_records=128):
        self.capacity, self.max_records = capacity, max_records
        self.pending, self.sequences = {}, {}
        self.cursor = None

    def flush(self, reason):
        rows = [self.finish(key, reason) for key in list(self.pending)]
        self.sequences.clear()
        return rows

    def finish(self, key, reason=None):
        group = self.pending.pop(key)
        rows = group["rows"]
        fields = {}
        issues = list(group["issues"])
        if reason:
            issues.append(reason)
        calls = {1: set(), 2: set()}
        http_producers, confirmations = set(), []
        for row in rows:
            event = row["event"]
            evidence = event["evidence"]
            frame, kind = evidence["group"], evidence["observation"]
            if kind == "http_response":
                http_producers.add((evidence["record"]["instance"], evidence["record"]["revision"]))
                if frame["side"] == 1 and evidence["record"]["code"] == 142:
                    confirmations.append(row["cursor"])
                continue
            side = frame["side"]
            if side not in calls:
                issues.append("unknown_side")
                continue
            record = evidence["record"]
            calls[side].add((record["instance"], record["revision"], frame["invocation"]))
            name = (side, kind)
            if name in fields:
                issues.append("duplicate_field")
            fields[name] = row
        for side in (1, 2):
            if len(calls[side]) != 1:
                issues.append("missing_or_multiple_json_messages")
            for kind in ("method", "operation_target", "message_id", "reply"):
                if (side, kind) not in fields:
                    issues.append("missing_field")
        if len({call[:2] for side in calls.values() for call in side}) != 1:
            issues.append("json_producer_changed")
        if len(http_producers) != 1 or len(confirmations) != 1:
            issues.append("missing_or_conflicting_http_confirmation")
        activity, outcome, sources = {}, {}, {}
        for name, kind in (("method", "method"), ("target", "operation_target"),
                           ("message_id", "message_id")):
            row = fields.get((1, kind))
            if row:
                value = row["event"]["activity"].get(name)
                if value:
                    activity[name] = value
                    sources[name] = row["cursor"]
                    if value["status"] != "complete" or "text_error" in value:
                        issues.append("incomplete_" + name)
        ids = [fields.get((side, "message_id")) for side in (1, 2)]
        if all(ids):
            values = [row["event"]["activity"]["message_id"] for row in ids]
            if any(v["status"] != "complete" for v in values):
                issues.append("incomplete_id")
            elif (values[0]["kind"], values[0]["raw_hex"]) != (values[1]["kind"], values[1]["raw_hex"]):
                issues.append("reply_id_mismatch")
        reply = fields.get((2, "reply"))
        if reply:
            outcome.update(reply["event"]["reported_outcome"])
            sources["reply"] = reply["cursor"]
            if outcome.get("status") != "complete":
                issues.append("incomplete_reply")
        for row in rows:
            event = row["event"]
            if event["evidence"]["group"]["side"] != 1:
                continue
            for name in ("http_status", "local_transfer_complete"):
                value = event["reported_outcome"].get(name)
                if value and value["status"] == "complete":
                    if name in outcome and outcome[name] != value:
                        issues.append("conflicting_" + name)
                    outcome[name] = value
                    sources[name] = row["cursor"]
        if "http_status" not in outcome or "local_transfer_complete" not in outcome:
            issues.append("incomplete_http")
        identity = hashlib.sha256(json.dumps(key, separators=(",", ":")).encode()).hexdigest()
        issues = sorted(set(issues))
        return dict(schema_version=1, event_type="agent.activity.combined",
                    activity_id=identity, identity_binding="unknown", identity=None,
                    correlation=dict(status="incomplete" if issues else "observed_exchange",
                                     scope="single_worker_nonpipelined_http1", issues=issues),
                    activity=activity, reported_outcome=outcome,
                    timing=observation_timing(rows),
                    evidence=dict(source_id=key[0], ring=key[1], run=key[2],
                                  owner_instance=key[3], exchange=key[4],
                                  first_cursor=group["first"], last_cursor=rows[-1]["cursor"],
                                  record_count=len(rows), field_sources=sources,
                                  program_binding="not_verified_by_exporter",
                                  continuity="observed_records_only"))

    def feed(self, page):
        if "error" in page:
            raise ValueError(page)
        output = []
        for row in project_page(page)["events"]:
            cursor = row["cursor"]
            journal, number = cursor.rsplit(":", 1)
            number = int(number)
            if self.cursor:
                previous, offset = self.cursor.rsplit(":", 1)
                if journal != previous or number <= int(offset):
                    raise ValueError("replay cursor changed journal or moved backwards")
                if journal != previous or number != int(offset) + 1:
                    output += self.flush("cursor_discontinuity")
            self.cursor = cursor
            event = row["event"]
            evidence = event["evidence"]
            frame = evidence.get("group")
            if event["event_type"] != "agent.activity" or not frame:
                # DISCARD includes ring wrap padding. Keep the diagnostic;
                # producer sequence gaps and missing fields still invalidate
                # an exchange if actual metadata was lost.
                if event["event_type"] not in ("agent.ring_health", "agent.discard"):
                    output += self.flush("diagnostic_or_unqualified_record")
                output.append(event)
                continue
            record, raw = evidence["record"], evidence["raw"]
            kind = evidence["observation"]
            http = kind == "http_response"
            expected = int(record["sequence"]) if http else (int(record["sequence"]) - 1) // 4 + 1
            valid = (isinstance(evidence["source_id"], str) and bool(evidence["source_id"])
                     and type(raw.get("ring")) is int and 0 <= raw["ring"] < 16
                     and int(frame["invocation"]) in (0, expected))
            if frame["exchange"] != "0":
                valid &= (frame["invocation"] == str(expected) and
                          (http or frame["owner_instance"] == record["instance"]))
                if frame["phase"] == 1:
                    valid &= (kind == "method" and frame["side"] == 1
                              and frame["exchange"] == record["sequence"] and frame["status"] == 1)
                elif frame["phase"] == 3:
                    valid &= http and frame["side"] == 1 and record["code"] == 29 and frame["status"] == 1
                elif frame["phase"] == 4:
                    valid &= ((http and record["code"] in (1, 5, 57, 142)) or
                              (kind == "method" and frame["side"] == 1 and frame["status"] == 4))
                elif not http:
                    valid &= (int(record["sequence"]) - 1) % 4 == {
                        "method": 0, "operation_target": 1, "message_id": 2, "reply": 3}[kind]
                    if kind == "message_id":
                        valid &= (record.get("flow_status") == 1 and
                                  record.get("flow_side") == frame["side"])
            if not valid:
                output += self.flush("invalid_frame_binding")
                event["event_type"] = "agent.observation"
                evidence["status"] = "invalid_frame_binding"
                output.append(event)
                continue
            producer = (evidence["source_id"], raw["ring"], record["instance"], record["run"])
            sequence = int(record["sequence"])
            previous = self.sequences.get(producer)
            if previous is not None and sequence <= previous:
                output += self.flush("duplicate_or_regressed_sequence")
                self.sequences[producer] = previous
                event["event_type"] = "agent.observation"
                evidence["status"] = "duplicate_or_regressed_sequence"
                output.append(event)
                continue
            if (previous is not None and sequence != previous + 1) or int(record["output_failures"]):
                output += self.flush("producer_gap")
            if len(self.sequences) >= self.capacity and producer not in self.sequences:
                output += self.flush("producer_capacity")
            self.sequences[producer] = sequence
            if not frame["exchange"] or frame["exchange"] == "0":
                output.append(event)
                continue
            key = (evidence["source_id"], raw["ring"], record["run"],
                   frame["owner_instance"], frame["exchange"])
            if frame["phase"] == 1:
                if key in self.pending:
                    output.append(self.finish(key, "duplicate_start"))
                    output.append(event)
                    continue
                if len(self.pending) >= self.capacity:
                    output.append(self.finish(next(iter(self.pending)), "capacity"))
                self.pending[key] = dict(first=cursor, rows=[], issues=[], confirmed=False)
            group = self.pending.get(key)
            if group is None:
                event["correlation"] = dict(status="unknown", reason="unobserved_start")
                output.append(event)
                continue
            group["rows"].append(row)
            if http and record["code"] == 142 and frame["side"] == 1 and frame["status"] == 1:
                group["confirmed"] = True
            if not http and frame["side"] == 2 and not group["confirmed"]:
                group["issues"].append("reply_before_http_confirmation")
            if frame["status"] != 1:
                group["issues"].append("invalid_group")
            if frame["phase"] in (3, 4):
                output.append(self.finish(key, "invalidated" if frame["phase"] == 4 else None))
            elif len(group["rows"]) >= self.max_records:
                output.append(self.finish(key, "record_capacity"))
        return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--journal", type=Path)
    source.add_argument("--socket", type=Path)
    parser.add_argument("--after")
    parser.add_argument("--follow", action="store_true")
    args = parser.parse_args()
    if args.follow and not args.socket:
        parser.error("--follow requires --socket")
    combiner, cursor = ActivityCombiner(), args.after
    try:
        while True:
            if args.journal:
                from stream_collector import replay
                status, page = replay(args.journal, cursor, 128)
                if status != 200:
                    raise ValueError(page)
            else:
                from collector_client import page as read_page
                page = read_page(args.socket, cursor, 128)
            if "error" in page:
                raise ValueError(page)
            for event in combiner.feed(page):
                print(json.dumps(event, separators=(",", ":")), flush=True)
            cursor = page["next_cursor"]
            if not page["events"]:
                if not args.follow:
                    break
                time.sleep(.1)
    finally:
        for event in combiner.flush("end_of_input"):
            print(json.dumps(event, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
