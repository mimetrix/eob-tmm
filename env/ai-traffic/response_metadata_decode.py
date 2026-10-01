"""Decode observed HTTP status and local response-done arguments."""
import struct

FORMAT = struct.Struct('<II6Q10I')
STATES = {0: 'not_applicable', 1: 'complete', 3: 'read_failed',
          4: 'out_of_scope', 7: 'unavailable'}
EVENTS = {28: 'HUDCTL_RESPONSE', 144: 'HUDEVT_RESPONSE',
          29: 'HUDCTL_RESPONSE_DONE', 145: 'HUDEVT_RESPONSE_DONE',
          1: 'HUDCTL_ABORT', 34: 'HUDEVT_ABORTED', 5: 'HUDCTL_TEARDOWN',
          142: 'HUDEVT_REQUEST', 27: 'HUDCTL_REQUEST_DONE', 143: 'HUDEVT_REQUEST_DONE'}


def decode(payload):
    if len(payload) != FORMAT.size:
        raise ValueError('response metadata size')
    names = ('magic', 'abi', 'instance', 'revision', 'run', 'monotonic_ns',
             'sequence', 'output_failures', 'code', 'presence', 'flags', 'reads',
             'source_bytes', 'http_status_state', 'http_status',
             'completion_state', 'transfer_complete', 'reserved')
    event = dict(zip(names, FORMAT.unpack(payload)))
    status, done = event['http_status_state'], event['completion_state']
    if (event['magic'] != 0x5253504d or event['abi'] != 1 or event['reserved']
            or event['presence'] > 7 or event['flags'] & ~15
            or event['reads'] > 4 or event['source_bytes'] > 16
            or status not in STATES or done not in (0, 1, 4, 7)):
        raise ValueError('invalid response metadata')
    if (event['code'] in (28, 144)) != (status != 0):
        raise ValueError('status on wrong event')
    if (event['code'] in (29, 145)) != (done != 0):
        raise ValueError('completion on wrong event')
    if status == 1:
        if not 100 <= event['http_status'] <= 999:
            raise ValueError('invalid HTTP status')
    elif event['http_status']:
        raise ValueError('value on unavailable HTTP status')
    if done == 1:
        if event['transfer_complete'] not in (0, 1):
            raise ValueError('invalid completion Boolean')
    elif event['transfer_complete']:
        raise ValueError('value on unavailable completion')
    event['http_status_state_name'] = STATES[status]
    event['completion_state_name'] = STATES[done]
    event['event_name'] = EVENTS.get(event['code'])
    return event
