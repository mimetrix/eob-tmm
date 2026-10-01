"""Decode same-invocation ID and flow side; never infer a common lifetime."""
import struct
from message_id_decode import decode as decode_id

MAGIC = 0x4944464c
SIDES = {0: None, 1: 'clientside', 2: 'serverside'}
STATES = {0: 'unavailable', 1: 'complete', 2: 'out_of_scope',
          3: 'read_failed', 4: 'invalid', 5: 'budget_exhausted'}


def decode(payload):
    if len(payload) != 144 or struct.unpack_from('<II', payload) != (MAGIC, 1):
        raise ValueError('ID/flow size or schema')
    flags, = struct.unpack_from('<H', payload, 72)
    side, status = (flags >> 4) & 3, (flags >> 8) & 7
    if (flags & ~0x073f or side not in SIDES or status not in STATES
            or (status == 1) != (side in (1, 2))
            or ((flags & 3) and (side or status))):
        raise ValueError('invalid flow side')
    base = bytearray(payload)
    struct.pack_into('<I', base, 0, 0x4d534749)
    struct.pack_into('<H', base, 72, flags & 15)
    event = decode_id(base)
    event.update(magic=MAGIC, wire_flags=flags, flow_side=side,
                 flow_side_name=SIDES[side], flow_status=status,
                 flow_status_name=STATES[status])
    return event
