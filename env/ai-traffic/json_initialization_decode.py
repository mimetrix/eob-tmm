"""Decode bounded initialization records. Completion is not storage lifetime."""
import struct

FORMAT = struct.Struct("<II7Q8I")
FIELDS = ("magic", "abi", "instance", "revision", "run", "invocation", "monotonic_ns",
          "sequence", "output_failures", "code", "status", "flags", "flow_side",
          "reads", "source_bytes", "guards", "reserved")


def decode(data):
    if len(data) != FORMAT.size:
        raise ValueError("initialization record length")
    value = dict(zip(FIELDS, FORMAT.unpack(data)))
    if value["magic"] != 0x4A494E49 or value["abi"] != 1:
        raise ValueError("initialization record ABI")
    if value["reserved"] or value["status"] > 6 or value["flags"] & ~15:
        raise ValueError("initialization record fields")
    if value["reads"] > 3 or value["source_bytes"] > 9:
        raise ValueError("initialization read budget")
    if value["guards"] > 3 or value["flow_side"] > 2:
        raise ValueError("initialization guard fields")
    if value["status"] == 1 and (value["code"] != 57 or value["guards"] != 3
                                  or value["flow_side"] not in (1, 2)
                                  or value["reads"] != 3 or value["source_bytes"] != 9):
        raise ValueError("initialization completion without entry guards")
    value["initialization_completed"] = bool(
        value["status"] == 1 and not value["flags"] and not value["output_failures"]
        and all(value[key] for key in ("instance", "revision", "run", "invocation",
                                      "sequence", "monotonic_ns")))
    value["lifecycle_validated"] = False
    return value
