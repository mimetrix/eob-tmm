"""Decode reported fields, with explicit missing and ambiguous states."""
import struct

FORMAT = struct.Struct('<II6Q7Ii4I')
FIELDS = ('status', 'result_present', 'error_present', 'code_state', 'error_code',
          'tool_error_state', 'tool_error')
STATES = {0: 'not_applicable', 1: 'complete', 3: 'read_failed',
          4: 'out_of_scope', 5: 'budget_exhausted', 7: 'unavailable',
          9: 'invalid_cache', 10: 'wrong_type', 11: 'ambiguous'}


def decode(payload):
    if len(payload) != FORMAT.size:
        raise ValueError('reply metadata size')
    names = ('magic', 'abi', 'instance', 'revision', 'run', 'monotonic_ns',
             'sequence', 'output_failures', 'flags', 'reads', 'source_bytes',
             *FIELDS, 'reserved0', 'reserved1')
    event = dict(zip(names, FORMAT.unpack(payload)))
    if (event['magic'] != 0x52504c59 or event['abi'] != 1
            or event['flags'] & ~15 or event['reads'] > 80
            or event['source_bytes'] > 2048 or event['reserved0'] or event['reserved1']
            or any(event[k] not in STATES for k in ('status', 'code_state', 'tool_error_state'))
            or any(event[k] not in (0, 1) for k in ('result_present', 'error_present', 'tool_error'))):
        raise ValueError('invalid reply metadata')
    if event['status'] == 1:
        if event['result_present'] + event['error_present'] != 1:
            raise ValueError('invalid reply presence')
        if bool(event['code_state']) != bool(event['error_present']):
            raise ValueError('invalid error field state')
        if bool(event['tool_error_state']) != bool(event['result_present']):
            raise ValueError('invalid result field state')
    elif any(event[k] for k in FIELDS[1:]):
        raise ValueError('fields on unqualified reply')
    if ((event['code_state'] != 1 and event['error_code'])
            or (event['tool_error_state'] != 1 and event['tool_error'])):
        raise ValueError('value without complete field')
    for key in ('status', 'code_state', 'tool_error_state'):
        event[key + '_name'] = STATES[event[key]]
    return event
