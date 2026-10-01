"""Decode exact ID bytes and types without assigning request or caller identity."""
import re
import struct

FORMAT = struct.Struct('<II6Q4IHHI64s')
STATES = {1: 'complete', 2: 'truncated', 3: 'read_failed', 4: 'out_of_scope',
          5: 'budget_exhausted', 7: 'unavailable', 8: 'missing',
          9: 'invalid_cache', 10: 'wrong_type', 11: 'ambiguous'}
NUMBER = re.compile(rb'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?')


def decode(payload):
    if len(payload) != FORMAT.size:
        raise ValueError('message ID size')
    names = ('magic', 'abi', 'instance', 'revision', 'run', 'monotonic_ns',
             'sequence', 'output_failures', 'status', 'id_kind',
             'original_length', 'copied_length', 'flags', 'reads', 'source_bytes', 'value')
    e = dict(zip(names, FORMAT.unpack(payload)))
    n = e['copied_length']
    if (e['magic'] != 0x4d534749 or e['abi'] != 1 or e['status'] not in STATES
            or e['id_kind'] not in (0, 1, 2, 3) or e['flags'] & ~15
            or e['reads'] > 80 or e['source_bytes'] > 2048 or n > 64
            or any(e['value'][n:])):
        raise ValueError('invalid message ID')
    value = e.pop('value')[:n]
    if e['status'] in (1, 2):
        if (not e['id_kind'] or n != min(e['original_length'], 64)
                or (e['status'] == 2) != (e['original_length'] > 64)):
            raise ValueError('invalid ID length or kind')
        if e['id_kind'] == 2 and (e['status'] != 1 or NUMBER.fullmatch(value) is None):
            raise ValueError('invalid numeric ID')
        if e['id_kind'] == 3 and (e['status'] != 1 or value != b'null'):
            raise ValueError('invalid null ID')
    elif n or e['id_kind'] not in (0, 1):
        raise ValueError('value on unavailable ID')
    e['value_hex'] = value.hex()
    e['status_name'] = STATES[e['status']]
    e['id_kind_name'] = {0: None, 1: 'string', 2: 'number', 3: 'null'}[e['id_kind']]
    e['representation'] = 'raw_json_string_bytes' if e['id_kind'] == 1 else 'raw_json_token_bytes'
    return e
