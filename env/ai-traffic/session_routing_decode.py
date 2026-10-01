"""Decode session-header and selected-route observations without identity inference."""
import ipaddress
import struct

FORMAT = struct.Struct('<II6Q4IHHI64s16sHHI')
STATUS = {1: 'complete', 2: 'truncated', 3: 'read_failed', 4: 'out_of_scope',
          5: 'budget_exhausted', 7: 'unavailable'}


def decode(payload):
    if len(payload) != FORMAT.size:
        raise ValueError('session/routing record size')
    names = ('magic', 'abi', 'instance', 'revision', 'run', 'monotonic_ns',
             'sequence', 'output_failures', 'status', 'kind', 'original_length',
             'copied_length', 'flags', 'reads', 'source_bytes', 'value',
             'address', 'port', 'domain', 'endpoint_status')
    event = dict(zip(names, FORMAT.unpack(payload)))
    value, address = event.pop('value'), event.pop('address')
    n = event['copied_length']
    status, endpoint = event['status'], event['endpoint_status']
    if (event['magic'] != 0x53524d45 or event['abi'] != 1 or event['kind'] not in (1, 2)
            or status not in STATUS or n > 64 or any(value[n:])
            or event['reads'] > 80 or event['source_bytes'] > 256):
        raise ValueError('invalid session/routing record')
    if status not in (1, 2) and n:
        raise ValueError('value on unavailable field')
    if status == 1 and n != event['original_length']:
        raise ValueError('incomplete complete field')
    if status == 2 and not (n == 64 < event['original_length']):
        raise ValueError('invalid truncated field')
    if event['kind'] == 1 and endpoint != 0:
        raise ValueError('endpoint on session header')
    if event['kind'] == 2 and endpoint not in (1, 3, 4, 5, 7):
        raise ValueError('invalid endpoint status')
    if endpoint != 1 and (any(address) or event['port'] or event['domain']):
        raise ValueError('bytes on unavailable endpoint')
    event['field'] = 'observed_session_header' if event['kind'] == 1 else 'selected_pool_name'
    event['value_hex'] = value[:n].hex()
    event['status_name'] = STATUS[status]
    event['original_length_known'] = event['original_length'] != 0xffffffff
    event['endpoint_status_name'] = STATUS.get(endpoint, 'not_applicable')
    event['address_hex'] = address.hex() if endpoint == 1 else None
    if endpoint == 1:
        ip = ipaddress.IPv6Address(address)
        event['address'] = str(ip.ipv4_mapped or ip)
    else:
        event['address'] = None
    return event
