"""Decode boundary observations without promoting tags to lifecycle identity."""
import struct

NAMES = ('magic abi instance revision run monotonic_ns sequence output_failures '
         'context_tag kind code status flags flow_side scb_flags cache_present '
         'seen_mask reads source_bytes payload_bytes reserved').split()
STATES = ('unavailable', 'observed', 'address_only', 'unsupported', 'read_failed',
          'disabled', 'capacity', 'overflow', 'map_failed', 'run_mismatch')


def decode(payload):
    if len(payload) != 112:
        raise ValueError('boundary size')
    e = dict(zip(NAMES, struct.unpack('<II7Q12I', payload)))
    if (e['magic'] != 0x4a4c4244 or e['abi'] != 1 or e['kind'] not in (1, 2, 3)
            or e['status'] >= len(STATES) or e['flags'] & ~15 or e['reserved']
            or e['flow_side'] > 2 or e['scb_flags'] & ~0x3fff or e['cache_present'] > 1
            or e['seen_mask'] & ~15 or e['reads'] > 4 or e['source_bytes'] > 29
            or e['context_tag'] > 128):
        raise ValueError('boundary fields')
    if e['kind'] == 3 and any(e[k] for k in ('code', 'flow_side', 'scb_flags',
                                            'cache_present', 'reads', 'source_bytes', 'payload_bytes')):
        raise ValueError('reset has no qualified source fields')
    if e['status'] in (1, 5) and (e['kind'] == 3 or e['flow_side'] not in (1, 2)):
        raise ValueError('observed storage requires side')
    e['status_name'] = STATES[e['status']]
    e['lifecycle_validated'] = False
    return e


def window(events, breaks=()):
    """Report boundary evidence only; known breaks invalidate the whole window."""
    invalid = list(breaks)
    identities = {}
    run = events[0]['run'] if events else None
    for n, e in enumerate(events, 1):
        identity = (e['instance'], e['revision'])
        previous = identities.setdefault(e['kind'], identity)
        if identity != previous or e['run'] != run:
            invalid.append('source_changed')
        if e['sequence'] != n or e['flags'] or e['output_failures'] or e['status'] not in (1, 2):
            invalid.append('diagnostic_or_gap')
    return dict(boundaries_usable=not invalid, reasons=invalid,
                lifecycle_validated=False, request_scope_validated=False,
                message_association_validated=False)
