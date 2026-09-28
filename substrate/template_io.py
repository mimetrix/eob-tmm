#!/usr/bin/env python3
"""Create tutorial configuration or decode tutorial records from ls_drain."""
import argparse
import json
from pathlib import Path
import struct
import sys

FIELDS = (
    "magic", "abi", "instance", "revision", "monotonic_ns", "seen",
    "observed", "threshold", "result", "kind", "flags", "version",
    "header_count", "matched", "verdict",
)
EVENT = struct.Struct("<II7Q6I")


def unsigned(value):
    number = int(value, 0)
    if not 0 <= number < 1 << 64:
        raise argparse.ArgumentTypeError("expected an unsigned 64-bit integer")
    return number


def policy(args):
    identity = json.loads(args.identity.read_text())
    revision = identity["revision"]
    if type(revision) is not int or not 0 <= revision < (1 << 64) - 1:
        raise ValueError("invalid or exhausted configuration revision")
    flags = args.enabled | (2 if args.request_safe_return else 0)
    document = {
        "abi": 1, "schema": 2,
        "session": identity["session"], "instance": identity["instance"],
        "program_sha256": identity["program_sha256"],
        "expected_revision": revision, "revision": revision + 1,
        "rows": [struct.pack("<QQQII", args.threshold, 0,
                             args.reset_token, flags, 0).hex()],
    }
    print(json.dumps(document, indent=2))


def decode():
    for line in sys.stdin:
        record = json.loads(line)
        # SAFE_RETURN can also produce a separate, host-owned audit event.
        if record.get("hook") != "prog":
            continue
        payload = bytes.fromhex(record["data"])
        if len(payload) != EVENT.size or record["len"] != EVENT.size:
            raise ValueError("unexpected tutorial event size")
        values = dict(zip(FIELDS, EVENT.unpack(payload)))
        if values["magic"] != 0x544D4D31 or values["abi"] != 1:
            raise ValueError("unexpected tutorial event format")
        print(json.dumps({"transport": {k: v for k, v in record.items() if k != "data"},
                          "tutorial": values}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    config = commands.add_parser("policy", help="write one configuration JSON to stdout")
    config.add_argument("--identity", type=Path, required=True)
    config.add_argument("--threshold", type=unsigned, default=1024)
    config.add_argument("--reset-token", type=unsigned, default=1)
    config.add_argument("--enabled", type=int, choices=(0, 1), default=1)
    config.add_argument("--request-safe-return", action="store_true")
    commands.add_parser("decode", help="read ls_drain JSON lines from stdin")
    args = parser.parse_args()
    try:
        if args.command == "policy":
            policy(args)
        else:
            decode()
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
