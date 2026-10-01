#!/usr/bin/env python3
"""Verify retained ID/side observations, negative decoding, replay and cleanup."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sqlite3
import struct
import tarfile
import traceback
import xml.etree.ElementTree as ET
from id_flow_decode import decode
from id_flow_cases import cases, all_cases, repeated
from message_id_decode import decode as decode_id
from message_id_cases import cases as id_cases
from message_id_verify import compare

ROOT = Path(__file__).resolve().parents[2]
RUN = 'id-flow-live-01'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def reject(payload, decoder=decode):
    try:
        decoder(payload)
    except ValueError:
        return
    raise AssertionError('malformed or incompatible record accepted')


def verify(cache, source_root, substrate_root):
    manifest = {name: sha for sha, name in
                (line.split() for line in (cache / 'MANIFEST.sha256').read_text().splitlines()
                 if line and not line.startswith('#'))}
    receipts, checked_sources = {}, 0
    for name in ('id-flow-build-01.json', 'id-flow-create-01.json', RUN + '.json',
                 'id-flow-cleanup-01.json', 'id-flow-evidence-01.tar.gz'):
        data = (cache / name).read_bytes()
        assert digest(data) == manifest[name], name
        if not name.endswith('.json'):
            continue
        doc = json.loads(data)
        receipts[Path(name).stem] = doc
        for path, source in doc.get('sources', {}).items():
            assert digest(source['text'].encode()) == source['sha256'], path
            checked_sources += 1
            target = (substrate_root / path.split('/substrate/', 1)[1]
                      if '/substrate/' in path else source_root / Path(path).name)
            if target.suffix != '.md':
                assert digest(target.read_bytes()) == source['sha256'], path
    build, live, cleanup = (receipts['id-flow-' + n] for n in ('build-01', 'live-01', 'cleanup-01'))
    assert all(r['passed'] for r in receipts.values())
    assert build == live['program_build']
    assert build['discovery_sha256'] == manifest['message-id-discovery-01.json']
    assert build['scope_sha256'] == manifest['message-scope-discovery-02.json']
    assert build['scope_check']['passed']
    assert cleanup['live_sha256'] == manifest[RUN + '.json']
    assert cleanup['archive']['sha256'] == manifest['id-flow-evidence-01.tar.gz']
    assert live['before'] == live['after'] and not live.get('collection_errors')
    assert live['image_build']['image'] == live['collector']['image']
    assert live['source_binding']['sha256'] == build['runtime']['sha256']
    assert any(m['Destination'] == '/collector-api' and not m['RW'] for m in live['fixture_mounts'])
    raw_native = [bytes.fromhex(line[7:]) for cmd in build['commands']
                  for line in cmd['stdout'].splitlines() if line.startswith('RECORD ')]
    native = [decode(raw) for raw in raw_native]
    assert native == build['programs']['id']['native_events'] and len(native) == 224
    assert digest(build['fixtures']['text'].encode()) == build['fixtures']['sha256']
    expected_fields = [e for c in id_cases() for e in c[3:]]
    for offset in (1, 98):
        for event, expected in zip(native[offset:offset + 70], expected_fields):
            compare(event, expected)
            assert event['flow_side'] == event['flow_status'] == 0
        malformed = native[offset + 70:offset + 82]
        assert len(malformed) == 12
        assert all(e['status'] == 10 and not e['id_kind'] and not e['value_hex'] for e in malformed)
    expected_flow = [(0, 0, 7), (1, 1, 1), (1, 2, 1), (4, 0, 1), (4, 0, 1),
                     (1, 1, 1), (1, 2, 1), (0, 0, 1), (2, 0, 1), (4, 0, 1),
                     (3, 0, 1), (4, 0, 1), (1, 1, 4), (1, 1, 1), (1, 1, 1)]
    for offset in (194, 209):
        block = native[offset:offset + 15]
        assert [(e['flow_status'], e['flow_side'], e['status']) for e in block] == expected_flow
        assert not block[0]['reads'] and not block[0]['source_bytes']
        for e in block[1:]:
            if e['status'] == 1:
                compare(e, (1, 1, b'sample'))
        assert block[-2]['output_failures'] == 0 and block[-1]['output_failures'] == 1
    challenges = []
    for flags in (0x130, 0x100, 0x210, 0x600, 0x150, 0x111, 0x910):
        payload = bytearray(raw_native[195])
        struct.pack_into('<H', payload, 72, flags)
        challenges.append(payload)
    for offset, value in ((0, 0x4d534749), (4, 2)):
        payload = bytearray(raw_native[195])
        struct.pack_into('<I', payload, offset, value)
        challenges.append(payload)
    challenges += [raw_native[195][:-1], raw_native[195] + b'\x00']
    for payload in challenges:
        reject(payload)
    reject(raw_native[195], decode_id)
    verified, = [c for c in build['commands'] if c['argv'][0].endswith('/prevail')]
    assert verified['rc'] == 0 and verified['stdout'].startswith('PASS:')
    assert verified['argv'][-2:] == ['--stack-size', '256']
    assert all(f in verified['argv'] for f in ('--termination', '--strict', '--no-division-by-zero'))
    files = {}
    with tarfile.open(cache / 'id-flow-evidence-01.tar.gz', 'r:gz') as archive:
        for member in archive.getmembers():
            assert member.isdir() or member.isfile(), member.name
            if member.isfile():
                name = member.name.removeprefix('./')
                assert name not in files and not Path(name).is_absolute() and '..' not in Path(name).parts
                assert not name.endswith(('.pem', '.key', '.p12', '.bpf.o', '.sig'))
                files[name] = archive.extractfile(member).read()
                assert b'PRIVATE KEY-----' not in files[name]
    assert {name: digest(data) for name, data in files.items()} == cleanup['manifest']
    assert len(files) == cleanup['archive']['files']
    for name, text in live['files'].items():
        assert files[RUN + '/' + name].decode() == text, name
    assert digest(files[RUN + '/events.sqlite']) == live['journal_sha256']
    xml = ET.fromstring(files[RUN + '/tao.xml'])
    assert list(xml.iter('testcase'))
    for node in xml.iter():
        assert node.tag not in ('failure', 'error', 'skipped')
        assert not any(int(node.get(k, '0')) for k in ('failures', 'errors', 'skipped'))
    assert files[RUN + '/exit-status'].strip() == files[RUN + '/checked-exit-status'].strip() == b'0'
    test = json.loads(live['files']['result.json'])
    assert test['passed'] and not test['cleanup_errors'] and not test['backend_errors']
    assert len(test['clients']) == len(test['origin']) == len(all_cases()) == 44
    assert len(test['comparisons']) == len(cases()) + 2 == 39
    assert test['acknowledgements'] and all(r['status'] == 0 for r in test['acknowledgements'])
    assert test['keep_alive_client_connections'] == 1
    assert test['concurrent_requests_before_replies'] == 4
    before = [r for page in test['pre_run_pages'] for r in page['events']]
    assert not test['pre_run_pages'][-1]['events']
    assert test['pre_run_pages'][-1]['next_cursor'] == test['initial_cursor']
    rows = [r for page in test['stream_pages'] for r in page['events']]
    assert len({r['cursor'] for r in before + rows}) == len(before + rows)
    records = [r['event'] for r in rows if r['event']['type'] == 'record']
    assert records == [r['event'] for r in test['replay_consumer']['events'] if r['event']['type'] == 'record']
    assert len({r['event_id'] for r in records}) == len(records) == 88
    events = [decode(bytes.fromhex(r['raw']['data'])) for r in records]
    assert events == test['events'] == [e for c in test['comparisons'] for e in c['events']]
    identity = test['instances']['id']
    for n, (record, event) in enumerate(zip(records, events), 1):
        assert record['raw']['slot'] == 11 and record['raw']['hook_id'] == record['raw']['schema'] == 100
        assert event['sequence'] == n and event['instance'] == int(identity['instance'], 16)
        assert event['revision'] == identity['revision'] and event['run'] == test['run_token']
        assert event['monotonic_ns'] and not event['flags'] and not event['output_failures']
        assert event['flow_status'] == 1 and event['flow_side'] in (1, 2)
    clients, origins = ({r['case']: r for r in test[key]} for key in ('clients', 'origin'))
    assert len(clients) == len(origins) == 44
    for name, request, reply, _, _ in all_cases():
        assert origins[name]['request_sha256'] == digest(request)
        assert origins[name]['response_sha256'] == digest(reply)
        response = bytes.fromhex(clients[name]['response_hex'])
        assert response.startswith(b'HTTP/1.1 200 ') and response.split(b'\r\n\r\n', 1)[1] == reply
    assert len({origins['concurrent-' + str(i)]['fixture_connection'] for i in range(4)}) == 4
    for expected, case in zip(cases(), test['comparisons']):
        name, _, _, request_expected, reply_expected = expected
        assert case['case'] == name
        assert case['expected'] == [[s, k, None if v is None else v.hex()] for s, k, v in (request_expected, reply_expected)]
        assert len(case['events']) == 2
        assert [e['flow_side'] for e in case['events']] == [1, 2]
        for event, fields in zip(case['events'], (request_expected, reply_expected)):
            compare(event, fields)
    for case, label, prefix, count in zip(test['comparisons'][-2:], ('keep-alive', 'concurrent'), ('keep', 'concurrent'), (3, 4)):
        group = repeated(prefix, count)
        assert case['case'] == label and case['comparison_mode'] == 'multiset'
        assert case['cases'] == [c[0] for c in group]
        expected = [(side, s, k, v.hex()) for c in group for side, (s, k, v) in enumerate(c[3:], 1)]
        assert case['expected'] == [list(row) for row in expected]
        actual = [(e['flow_side'], e['status'], e['id_kind'], e['value_hex']) for e in case['events']]
        assert Counter(actual) == Counter(expected)
        for e in case['events']:
            compare(e, (1, 1, b'shared'))
    start, end = test['counter_start']['id'], test['counter_end']['id']
    assert end['fired'] - start['fired'] == len(events)
    assert all(end[k] == start[k] for k in ('errors', 'safe_returns', 'gen'))
    witness = live['witnesses']['id']
    assert witness['returncode'] == 0 and witness['initial']['sha256'] == build['runtime']['sha256']
    assert witness['initial']['bytes'].startswith('9090909090')
    assert len([r for r in witness['changes'] if r['bytes'].startswith('e8')]) == 1
    final = witness['changes'][-1]
    assert final['final'] and final['bytes'] == witness['initial']['bytes']
    assert final['stat'].split()[21] == witness['initial']['stat'].split()[21]
    db = sqlite3.connect(':memory:')
    try:
        db.deserialize(files[RUN + '/events.sqlite'])
        assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        stored = [json.loads(r[0]) for r in db.execute('SELECT body FROM events ORDER BY id')]
        captured = [r['event'] for r in before + rows]
        assert stored[:len(captured)] == captured
        assert all(r['type'] == 'ring_health' for r in stored[len(captured):])
        assert not any(r['type'] == 'observation_gap' for r in stored)
        health = [r for r in stored if r['type'] == 'ring_health']
        assert health and all(int(r['raw']['drops']) == 0 for r in health)
    finally:
        db.close()
    assert not any(r['project'] == 'eob-template-20260925' for r in cleanup['after'])
    assert [r for r in cleanup['before'] if r['project'] != 'eob-template-20260925'] == cleanup['after']
    statuses = [c for c in cleanup['commands'] if c['argv'][-3:-1] == ['/work/ls-load.py', 'status']]
    assert {int(c['argv'][-1]) for c in statuses} == set(range(12))
    assert all(c['rc'] == 0 and ('armed=0' in c['stdout'] or 'mode=0' in c['stdout']) for c in statuses)
    return dict(passed=True, evidence_tier='MEASURED', value_witness='SELF',
                checked_sources=checked_sources, native_records=len(native), decoder_rejections=len(challenges) + 1,
                live_requests=44, live_records=len(events), status_counts=dict(Counter(e['status_name'] for e in events)),
                flow_side_counts=dict(Counter(e['flow_side_name'] for e in events)),
                journal_events=len(stored), pre_run_events=len(before), archive_files=len(files),
                max_reads=max(e['reads'] for e in events), max_source_bytes=max(e['source_bytes'] for e in events),
                replay_retries=test['replay_retries'], request_scope_validated=False,
                message_association_validated=False, authenticated_identity_validated=False,
                source_receipt=RUN + '.json', source_sha256=manifest[RUN + '.json'], observations=events)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, default=ROOT / 'evidence/cache')
    parser.add_argument('--source-root', type=Path, default=ROOT / 'env/ai-traffic')
    parser.add_argument('--substrate-root', type=Path, default=ROOT / 'substrate')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--export', action='store_true')
    args = parser.parse_args()
    output = args.output.open('x') if args.output else None
    receipt = dict(passed=False, sources={})
    try:
        for name in ('id_flow_verify.py', 'id_flow_decode.py', 'id_flow_cases.py',
                     'message_id_verify.py', 'message_id_decode.py', 'message_id_cases.py'):
            data = Path(__file__).with_name(name).read_bytes()
            receipt['sources'][name] = dict(sha256=digest(data), text=data.decode())
        result = verify(args.cache, args.source_root, args.substrate_root)
        receipt.update(passed=True, result=result)
        shown = dict(result)
        if not args.export:
            shown.pop('observations')
        print(json.dumps(shown, indent=2))
    except BaseException as error:
        receipt.update(error=repr(error), traceback=traceback.format_exc())
        raise
    finally:
        if output:
            json.dump(receipt, output, indent=2)
            output.close()
