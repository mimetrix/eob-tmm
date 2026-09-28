#!/usr/bin/env python3
"""Display actual field records from a saved live metadata receipt.

Values come from the captured ring payloads, not the fixture's expected values.
The original records remain available alongside the readable field values.
"""
import argparse
import hashlib
import json
from pathlib import Path

from method_decode import decode


DEFAULT_RECEIPT = (
    Path(__file__).resolve().parents[2]
    / "evidence/cache/method-live-01-20260928.json"
)


def export(path):
    raw = path.read_bytes()
    receipt = json.loads(raw)
    test = json.loads(receipt["files"]["result.json"])
    if not receipt["passed"] or not test["passed"]:
        raise ValueError("this export requires a passed live receipt")
    program = receipt["program_build"]["programs"]["method"]
    records = []
    for batch in test["batches"]:
        for item in batch["transport"]:
            payload = bytes.fromhex(item["data"])
            if (
                item["hook"] != "prog"
                or item["slot"] != program["slot"]
                or item["len"] != len(payload)
            ):
                raise ValueError("unexpected transport record")
            records.append(decode(payload))
    if records != test["events"]:
        raise ValueError("ring payloads differ from the saved decoded records")
    if [event for case in test["comparisons"] for event in case["events"]] != records:
        raise ValueError("fixture comparison records differ from the captured records")

    observations = []
    for record in records:
        value = None
        if record["status_name"] in ("complete", "truncated"):
            value_bytes = bytes.fromhex(record["value_hex"])
            try:
                text = value_bytes.decode("utf-8")
            except UnicodeDecodeError:
                text = None
            value = {
                "text": text,
                "hex": record["value_hex"],
                "original_bytes": record["original_length"],
                "copied_bytes": record["copied_length"],
            }
        observations.append(
            {
                "field": "root_object.method" if value is not None else None,
                "value": value,
                "record": record,
            }
        )
    return {
        "schema": "application_metadata_export/v1",
        "evidence_tier": "MEASURED",
        "value_witness": "SELF: probe output from authored live fixture requests",
        "source_receipt": path.name,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "runtime": receipt["program_build"]["runtime"],
        "hook": program["section"],
        "program_sha256": program["sha256"],
        "representation": "json_string_escaped_bytes",
        "observations": observations,
        "fixture_cases_without_records": [
            {"case": case["case"], "configured_filter": case["filter"]}
            for case in test["comparisons"]
            if not case["events"]
        ],
    }


def markdown(document):
    lines = [
        "# Extracted application metadata",
        "",
        "**MEASURED — saved live TMM run.** These are actual probe",
        "values from authored fixture requests. They are not production agent data.",
        "Values below are decoded from the captured ring payloads. The exporter",
        "checks them against the saved records before displaying them.",
        "",
        "## Values",
        "",
        "Field: `root_object.method`. Values use JSON notation. Escapes in the",
        "application's string are preserved; the exporter does not expand them.",
        "",
        "| Sequence | Extracted value (JSON notation) | Status | Original bytes | Copied bytes | Getter result |",
        "|---|---|---|---|---|---|",
    ]
    for observation in document["observations"]:
        record = observation["record"]
        value = observation["value"]
        shown, original = "—", "unknown"
        if value is not None:
            if value["text"] is None:
                shown = "hex: " + value["hex"]
            else:
                shown = json.dumps(value["text"], ensure_ascii=True)
                shown = shown.replace("|", r"\u007c").replace("`", r"\u0060")
            shown = "`" + shown + "`"
            original = str(value["original_bytes"])
        lines.append(
            f"| {record['sequence']} | {shown} | {record['status_name']} | "
            f"{original} | {record['copied_length']} | {record['getter_result']} |"
        )
    lines += [
        "",
        "An empty string with complete status is a captured value. An error or",
        "budget-exhausted record has no extracted value; it does not establish absence.",
        "The truncated record contains only the displayed prefix.",
        "",
        "## Inputs without a field observation",
        "",
        "These labels come from the isolated fixture, not from probe field extraction.",
        "",
    ]
    for case in document["fixture_cases_without_records"]:
        lines.append(
            f"- `{case['case']}` (configured filter: `{case['configured_filter']}`): "
            "no getter record."
        )
    lines += [
        "",
        "These cases have no extracted field value; no missing value is filled in.",
        "",
        "## Source and record context",
        "",
        f"- Receipt: `evidence/cache/{document['source_receipt']}`.",
        f"- Receipt SHA-256: `{document['source_sha256']}`.",
        f"- TMM build ID: `{document['runtime']['build_id']}`.",
        f"- Hook: `{document['hook']}`.",
        f"- Program SHA-256: `{document['program_sha256']}`.",
        "- Value witness: SELF. See the evidence index for the separate kernel witnesses.",
        "",
        "The JSON export also retains each complete probe record: instance, config",
        "revision, run token, monotonic timestamp, sequence, return code, read counts",
        "and output-health fields. No object addresses are exported.",
        "",
        "## Reproduce the export",
        "",
        "From the repository root:",
        "",
        "```sh",
        "python3 env/ai-traffic/metadata_export.py",
        "python3 env/ai-traffic/metadata_export.py --format markdown",
        "```",
        "",
        "Both commands read the saved receipt. They do not load a probe or send traffic.",
        "The first command emits JSON, including exact hexadecimal value bytes.",
        "",
        "[Field scope and limits](METADATA.md#7-field-result--measured-on-the-pinned-build)",
        "· [Evidence index](../../SOURCES.md#root-object-method-extraction-2026-09-28)",
    ]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", nargs="?", type=Path, default=DEFAULT_RECEIPT)
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    args = parser.parse_args()
    document = export(args.receipt)
    if args.format == "markdown":
        print(markdown(document), end="")
    else:
        print(json.dumps(document, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()
