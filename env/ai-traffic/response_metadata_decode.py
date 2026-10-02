"""Decode observed HTTP status and local response-done arguments."""
import struct

FORMAT = struct.Struct('<II6Q10I')
TLS = struct.Struct('<8I')
STATES = {0: 'not_applicable', 1: 'complete', 3: 'read_failed',
          4: 'out_of_scope', 7: 'unavailable'}
EVENTS = {28: 'HUDCTL_RESPONSE', 144: 'HUDEVT_RESPONSE',
          29: 'HUDCTL_RESPONSE_DONE', 145: 'HUDEVT_RESPONSE_DONE',
          1: 'HUDCTL_ABORT', 34: 'HUDEVT_ABORTED', 5: 'HUDCTL_TEARDOWN',
          142: 'HUDEVT_REQUEST', 27: 'HUDCTL_REQUEST_DONE', 143: 'HUDEVT_REQUEST_DONE'}
TLS_MODES = {0: 'not_applicable', 1: 'terminated', 2: 'ssl_filter_not_decrypting',
             3: 'no_ssl_filter', 4: 'unknown'}
TLS_REASONS = {0: None, 1: 'read_failed', 2: 'walk_limit', 3: 'multiple_ssl_filters',
               4: 'server_side_entity', 5: 'inactive_context', 6: 'invalid_flow'}
TLS_BITS = ('handshake_ok', 'passthru', 'chain_present', 'session_cert_present',
            'retain_certificate', 'ticket_resumed', 'session_resumed', 'allow_nonssl')
PROTOCOLS = {0: None, 1: 'SSLv2', 2: 'SSLv3', 3: 'TLSv1', 4: 'TLSv1.1', 5: 'TLSv1.2',
             6: 'TLSv1.3', 7: 'DTLSv1', 8: 'DTLSv1.2', 9: 'GMSSLv1.1'}
CERT_MODES = {0: 'ignore', 1: 'require', 2: 'request'}


def decode_tls(payload):
    """Raw TLS facts plus a derived certificate state (TLS-MODE.md)."""
    mode, reason, nodes, bits, proto, suite, pcm, vfy = TLS.unpack(payload)
    if (mode not in TLS_MODES or reason not in TLS_REASONS or nodes > 16
            or bits >> len(TLS_BITS) or proto not in PROTOCOLS or suite > 0xffff
            or pcm not in CERT_MODES or vfy > 127):
        raise ValueError('invalid TLS block')
    if (mode == 4) != bool(reason):
        raise ValueError('TLS reason on wrong mode')
    detail = mode in (1, 2)
    if not detail and (bits or proto or suite or pcm or vfy):
        raise ValueError('TLS values without an SSL filter reading')
    if mode == 0 and nodes:
        raise ValueError('TLS walk on an inapplicable event')
    flags = {name: bool(bits >> i & 1) for i, name in enumerate(TLS_BITS)}
    result = dict(mode=TLS_MODES[mode], filter_nodes=nodes)
    if mode == 4:
        result['reason'] = TLS_REASONS[reason]
    if mode == 1 and (not flags['handshake_ok'] or flags['passthru']):
        raise ValueError('terminated without a completed decrypting handshake')
    if mode == 2 and flags['handshake_ok'] and not flags['passthru']:
        raise ValueError('not-decrypting with a completed decrypting handshake')
    if detail:
        present = flags['chain_present'] or flags['session_cert_present']
        if pcm == 0:
            certificate = 'not_requested'
        elif present:
            certificate = 'verified' if vfy == 0 else 'failed'
        elif flags['retain_certificate']:
            certificate = 'none_observed'
        else:
            certificate = 'unknown'
        result.update(protocol=PROTOCOLS[proto], protocol_number=proto,
                      cipher_suite_id=suite, peer_cert_mode=CERT_MODES[pcm],
                      verify_result=vfy, client_certificate=certificate, flags=flags)
    return result


def decode(payload):
    if len(payload) not in (FORMAT.size, FORMAT.size + TLS.size):
        raise ValueError('response metadata size')
    names = ('magic', 'abi', 'instance', 'revision', 'run', 'monotonic_ns',
             'sequence', 'output_failures', 'code', 'presence', 'flags', 'reads',
             'source_bytes', 'http_status_state', 'http_status',
             'completion_state', 'transfer_complete', 'reserved')
    event = dict(zip(names, FORMAT.unpack_from(payload)))
    status, done = event['http_status_state'], event['completion_state']
    if (event['magic'] != 0x5253504d or event['abi'] not in (1, 2)
            or len(payload) != (FORMAT.size if event['abi'] == 1 else FORMAT.size + TLS.size)
            or event['reserved']
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
    if event['abi'] == 2:
        tls = decode_tls(payload[FORMAT.size:])
        if event['code'] != 142 and tls['mode'] != 'not_applicable':
            raise ValueError('TLS reading on wrong event')
        event['client_tls'] = tls
    event['http_status_state_name'] = STATES[status]
    event['completion_state_name'] = STATES[done]
    event['event_name'] = EVENTS.get(event['code'])
    return event
