"""Decode the explicit exchange frame emitted by the combined activity ELF."""
import struct

MAGIC = 0x41474331
HEADER = struct.Struct("<4I2Q2IQ")


def unwrap(payload):
    if len(payload) < HEADER.size:
        raise ValueError("short activity group frame")
    magic, abi, length, side, owner, exchange, status, phase, invocation = HEADER.unpack_from(payload)
    if (magic != MAGIC or abi != 2 or length not in (96, 104, 144)
            or len(payload) != HEADER.size + length or side not in (0, 1, 2)
            or status not in range(7) or phase not in range(5)):
        raise ValueError("invalid activity group frame")
    if (bool(owner) != bool(exchange) or bool(phase) != bool(exchange)
            or (exchange and (not side or not invocation))
            or (status == 1 and not exchange)):
        raise ValueError("inconsistent activity group key")
    return dict(owner_instance=str(owner), exchange=str(exchange), status=status,
                phase=phase, side=side, invocation=str(invocation)), payload[HEADER.size:]
