"""Decode a bounded, escaped root-object method value; never infer absence."""
import struct

RECORD = struct.Struct("<II6Q4IHHI64s")
FIELDS = (
    "magic",
    "abi",
    "instance",
    "revision",
    "run",
    "monotonic_ns",
    "sequence",
    "output_failures",
    "status",
    "getter_result",
    "original_length",
    "copied_length",
    "flags",
    "reads",
    "source_bytes",
    "value",
)
STATUSES = {
    1: "complete",
    2: "truncated",
    3: "read_failed",
    4: "out_of_scope",
    5: "budget_exhausted",
    6: "getter_error",
    7: "unavailable",
}


def decode(payload):
    if len(payload) != RECORD.size:
        raise ValueError("wrong method record size")
    event = dict(zip(FIELDS, RECORD.unpack(payload)))
    if event["magic"] != 0x4A4D4554 or event["abi"] != 1:
        raise ValueError("wrong method record schema")
    status = event["status"]
    copied = event["copied_length"]
    original = event["original_length"]
    if (
        status not in STATUSES
        or copied > 64
        or copied > original
        or event["reads"] > 12
        or event["source_bytes"] > 320
    ):
        raise ValueError("invalid method extraction bounds")
    if (
        status == 1
        and copied != original
        or status == 2
        and not (copied == 64 and original > 64)
        or status not in (1, 2)
        and copied
    ):
        raise ValueError("inconsistent method extraction status")
    value = event.pop("value")
    if any(value[copied:]):
        raise ValueError("nonzero bytes outside copied value")
    event["value_hex"] = value[:copied].hex()
    event["status_name"] = STATUSES[status]
    event["representation"] = "json_string_escaped_bytes"
    return event
