"""Decode bounded method bytes from the token-cache probe, not from inputs."""
import struct

FORMAT = struct.Struct("<II6Q4IHHI64s")
STATUS = {1: "complete", 2: "truncated", 3: "read_failed", 4: "out_of_scope",
          5: "budget_exhausted", 7: "unavailable", 8: "no_literal_method",
          9: "invalid_cache", 10: "nonstring"}


def decode(payload):
    if len(payload) != FORMAT.size:
        raise ValueError("token method record size")
    names = ("magic", "abi", "instance", "revision", "run", "monotonic_ns",
             "sequence", "output_failures", "status", "root_members",
             "original_length", "copied_length", "flags", "reads", "source_bytes", "value")
    event = dict(zip(names, FORMAT.unpack(payload)))
    value = event.pop("value")
    n = event["copied_length"]
    if (event["magic"] != 0x544D4554 or event["abi"] != 1 or
            event["status"] not in STATUS or n > 64 or
            event["reads"] > 40 or event["source_bytes"] > 1024 or any(value[n:])):
        raise ValueError("invalid token method record")
    if event["status"] not in (1, 2) and n:
        raise ValueError("value on unavailable token method record")
    if event["status"] == 1 and n != event["original_length"]:
        raise ValueError("incomplete complete token method record")
    if event["status"] == 2 and not (n == 64 < event["original_length"]):
        raise ValueError("invalid truncated token method record")
    event["status_name"] = STATUS[event["status"]]
    event["value_hex"] = value[:n].hex()
    event["representation"] = "escaped JSON string bytes; literal key; first match"
    return event
