"""Decode handler metadata without interpreting agent activity."""

import struct

FORMAT = struct.Struct("<II6Q4I")
FIELDS = (
    "magic",
    "abi",
    "instance",
    "revision",
    "run",
    "monotonic_ns",
    "sequence",
    "output_failures",
    "kind",
    "code",
    "presence",
    "flags",
)


def decode(data, event_names):
    """Keep unknown numeric codes; names come from the build's enum manifest."""
    if len(data) != FORMAT.size:
        raise ValueError("invalid metadata record length")
    result = dict(zip(FIELDS, FORMAT.unpack(data)))
    if result["magic"] != 0x4D455441 or result["abi"] != 1:
        raise ValueError("unsupported metadata record schema")
    if result["kind"] not in (1, 2) or result["presence"] & ~7:
        raise ValueError("invalid metadata record fields")
    result["event_name"] = event_names.get(str(result["code"]))
    return result
