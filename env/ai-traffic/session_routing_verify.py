#!/usr/bin/env python3
"""Verify saved session/routing receipts, source hashes, bytes and journal replay."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import tarfile
import xml.etree.ElementTree as ET
from session_routing_decode import decode

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / 'evidence/cache'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify():
    manifest = dict((name, sha) for sha, name in
                    (line.split() for line in (CACHE / 'MANIFEST.sha256').read_text().splitlines()
                     if line and not line.startswith('#')))
    receipts = {}
    checked_sources = 0
    for path in sorted(CACHE.glob('session-routing-*')):
        data = path.read_bytes()
        assert digest(data) == manifest[path.name], path.name
        if path.suffix != '.json':
            continue
        doc = json.loads(data)
        receipts[path.stem] = doc
        for name, source in doc.get('sources', doc.get('files', {})).items():
            if isinstance(source, dict) and 'text' in source:
                assert digest(source['text'].encode()) == source['sha256'], name
                checked_sources += 1
    build = receipts['session-routing-build-02']
    live = receipts['session-routing-live-04']
    cleanup = receipts['session-routing-cleanup-01']
    assert build['passed'] and live['passed'] and cleanup['passed']
    assert all(not receipts[f'session-routing-live-{i:02}']['passed'] for i in (1, 2, 3))
    assert build == live['program_build']
    assert build['discovery_sha256'] == manifest['session-routing-discovery-02.json']
    assert cleanup['live_sha256'] == manifest['session-routing-live-04.json']
    assert cleanup['archive']['sha256'] == manifest['session-routing-evidence-01.tar.gz']
    assert live['before'] == live['after']
    assert live['image_build']['image'] == live['collector']['image']
    assert live['source_binding']['sha256'] == build['runtime']['sha256']
    for suffix in ('surfaces/session_routing.bpf.c', 'surfaces/session_routing_abi.h',
                   'surfaces/json_method_abi.h', 'check_session_routing.c', 'check_session_routing_pair.c'):
        source, = [s for name, s in build['sources'].items() if name.endswith('/' + suffix)]
        assert digest((ROOT / 'substrate' / suffix).read_bytes()) == source['sha256'], suffix
    for name, source in live['sources'].items():
        if name.endswith('.md') or name.startswith('/'):
            continue
        assert digest((ROOT / 'env/ai-traffic' / name).read_bytes()) == source['sha256'], name
    native = [decode(bytes.fromhex(line[7:])) for cmd in build['commands']
              for line in cmd['stdout'].splitlines() if line.startswith('RECORD ')]
    assert native == (build['programs']['session']['native_events'] +
                      build['programs']['route']['native_events'] + build['paired_events'])
    assert len(native) == 80
    verified = [cmd for cmd in build['commands'] if cmd['argv'][0].endswith('/prevail')]
    assert len(verified) == 2
    assert all(cmd['rc'] == 0 and cmd['stdout'].startswith('PASS:')
               and cmd['argv'][-2:] == ['--stack-size', '256'] for cmd in verified)
    files = {}
    with tarfile.open(CACHE / 'session-routing-evidence-01.tar.gz', 'r:gz') as archive:
        for member in archive.getmembers():
            assert member.isdir() or member.isfile(), member.name
            if member.isfile():
                name = member.name.removeprefix('./')
                assert name not in files and not Path(name).is_absolute() and '..' not in Path(name).parts
                files[name] = archive.extractfile(member).read()
    assert {name: digest(data) for name, data in files.items()} == cleanup['manifest']
    test = json.loads(live['files']['result.json'])
    assert files['session-routing-live-04/result.json'].decode() == live['files']['result.json']
    xml = ET.fromstring(files['session-routing-live-04/tao.xml'])
    assert list(xml.iter('testcase'))
    for node in xml.iter():
        assert node.tag not in ('failure', 'error', 'skipped')
        assert not any(int(node.get(key, '0')) for key in ('failures', 'errors', 'skipped'))
    assert test['passed'] and not test['cleanup_errors'] and not test['backend_errors']
    assert len(test['clients']) == len(test['origin']) == len(test['comparisons']) == 7
    before = [row for page in test['pre_run_pages'] for row in page['events']]
    assert not test['pre_run_pages'][-1]['events']
    assert test['pre_run_pages'][-1]['next_cursor'] == test['initial_cursor']
    rows = [row for page in test['stream_pages'] for row in page['events']]
    assert len({r['cursor'] for r in before + rows}) == len(before + rows)
    records = [r['event'] for r in rows if r['event']['type'] == 'record']
    assert len(records) == len({r['event_id'] for r in records}) == 12
    assert records == [r['event'] for r in test['replay_consumer']['events'] if r['event']['type'] == 'record']
    events = [decode(bytes.fromhex(r['raw']['data'])) for r in records]
    assert events == test['events'] == [e for c in test['comparisons'] for e in c['events']]
    for record, event in zip(records, events):
        assert record['raw']['slot'] == (7 if event['kind'] == 1 else 8)
        assert record['raw']['hook_id'] == record['raw']['schema'] == 100
        assert event['monotonic_ns']
    for label, kind, count in (('session', 1, 5), ('route', 2, 7)):
        values = [e for e in events if e['kind'] == kind]
        identity = test['instances'][label]
        assert len(values) == count
        for n, event in enumerate(values, 1):
            assert event['sequence'] == n and event['instance'] == int(identity['instance'], 16)
            assert event['revision'] == identity['revision'] and event['run'] == test['run_token']
            assert not event['flags'] and not event['output_failures']
        start, end = test['counter_start'][label], test['counter_end'][label]
        assert end['fired'] - start['fired'] == count
        assert all(end[key] == start[key] for key in ('errors', 'safe_returns', 'gen'))
        witness = live['witnesses'][label]
        assert witness['returncode'] == 0 and witness['initial']['sha256'] == build['runtime']['sha256']
        assert witness['initial']['bytes'].startswith('9090909090')
        assert len([r for r in witness['changes'] if r['bytes'].startswith('e8')]) == 1
        final = witness['changes'][-1]
        assert final['final'] and final['bytes'] == witness['initial']['bytes']
        assert final['stat'].split()[21] == witness['initial']['stat'].split()[21]
    expected = [None, b'fixture-session-01', b'future.session:v7+alpha',
                b'x' * 64, b'y' * 65, b'case-sensitive-VALUE', None]
    for case, value in zip(test['comparisons'], expected):
        assert case['expected_session_hex'] == (None if value is None else value.hex())
        session = [e for e in case['events'] if e['kind'] == 1]
        assert len(session) == (0 if value is None else 1)
        if value is not None:
            assert session[0]['value_hex'] == value[:64].hex()
            assert session[0]['original_length'] == len(value)
            assert session[0]['status_name'] == ('truncated' if len(value) > 64 else 'complete')
        route, = [e for e in case['events'] if e['kind'] == 2]
        assert route['status_name'] == route['endpoint_status_name'] == 'complete'
        assert route['value_hex'] == test['expected_pool'].encode().hex()
        assert route['address'] == '10.203.76.11' and route['port'] == 18095 and route['domain'] == 0
    pool, = [r['value'] for r in test['configuration'] if r['type'].split('.')[-1] == 'pool']
    assert pool['id'] == test['expected_pool']
    assert test['acknowledgements'] and all(row['status'] == 0 for row in test['acknowledgements'])
    for client in test['clients']:
        response = bytes.fromhex(client['response_hex'])
        assert response.startswith(b'HTTP/1.1 200 ') and b'"observed":true' in response
    journal = files['session-routing-live-04/events.sqlite']
    assert digest(journal) == live['journal_sha256']
    db = sqlite3.connect(':memory:')
    try:
        db.deserialize(journal)
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
    statuses = [cmd for cmd in cleanup['commands'] if cmd['argv'][-3:-1] == ['/work/ls-load.py', 'status']]
    assert {int(cmd['argv'][-1]) for cmd in statuses} == set(range(12))
    assert all(cmd['rc'] == 0 and ('armed=0' in cmd['stdout'] or 'mode=0' in cmd['stdout'])
               for cmd in statuses)
    return dict(passed=True, evidence_tier='MEASURED', value_witness='SELF',
                checked_sources=checked_sources, native_records=len(native), live_requests=7,
                session_records=5, route_records=7, journal_events=len(stored),
                pre_run_events=len(before), current_run_events=len(rows), archive_files=len(files),
                replay_retries=test['replay_retries'], expected_pool=test['expected_pool'],
                max_reads=max(e['reads'] for e in events), max_source_bytes=max(e['source_bytes'] for e in events),
                source_receipt='session-routing-live-04.json',
                source_sha256=manifest['session-routing-live-04.json'], observations=events)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--export', action='store_true')
    args = parser.parse_args()
    result = verify()
    if not args.export:
        result.pop('observations')
    print(json.dumps(result, indent=2))
