"""Decode bounded raw JSON target bytes without assigning request identity."""
import struct

FORMAT = struct.Struct('<II6Q4IHHI64s')
STATES = {1: 'complete', 2: 'truncated', 3: 'read_failed', 4: 'out_of_scope',
          5: 'budget_exhausted', 7: 'unavailable', 8: 'no_literal_method',
          9: 'invalid_cache', 10: 'nonstring', 11: 'no_literal_target',
          12: 'unsupported_method'}


def decode(payload):
    if len(payload) != FORMAT.size:
        raise ValueError('operation target size')
    names = ('magic', 'abi', 'instance', 'revision', 'run', 'monotonic_ns',
             'sequence', 'output_failures', 'status', 'target_kind',
             'original_length', 'copied_length', 'flags', 'reads', 'source_bytes', 'value')
    e = dict(zip(names, FORMAT.unpack(payload)))
    n = e['copied_length']
    if (e['magic'] != 0x4f544754 or e['abi'] != 1 or e['status'] not in STATES
            or e['target_kind'] not in (0, 1, 2) or e['flags'] & ~15
            or e['reads'] > 96 or e['source_bytes'] > 4096 or n > 64
            or any(e['value'][n:])):
        raise ValueError('invalid operation target')
    if e['status'] in (1, 2):
        if (not e['target_kind'] or n != min(e['original_length'], 64)
                or (e['status'] == 2) != (e['original_length'] > 64)):
            raise ValueError('invalid target length or kind')
    elif n:
        raise ValueError('value on unavailable target')
    e['value_hex'] = e.pop('value')[:n].hex()
    e['status_name'] = STATES[e['status']]
    e['target_kind_name'] = {0: None, 1: 'tool_name', 2: 'resource_uri'}[e['target_kind']]
    e['representation'] = 'raw_json_string_bytes'
    return e
