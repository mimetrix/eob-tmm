#!/usr/bin/env python3
"""Verify saved response fields, native checks, journal and fixture cleanup."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import tarfile
import xml.etree.ElementTree as ET
from response_metadata_decode import decode

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / 'evidence/cache'
RUN = 'response-metadata-live-02'
CASES = {'ok': 200, 'bodyless': 204, 'not-found': 404, 'unavailable': 503,
         'unfamiliar': 777, 'paced': 200, 'chunked': 200, 'stream': 200, 'interrupted': 200}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify():
    manifest = {name: sha for sha, name in
                (line.split() for line in (CACHE / 'MANIFEST.sha256').read_text().splitlines()
                 if line and not line.startswith('#'))}
    receipts, checked_sources = {}, 0
    for path in sorted(CACHE.glob('response-metadata-*')):
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
    build = receipts['response-metadata-build-03']
    live = receipts[RUN]
    cleanup = receipts['response-metadata-cleanup-01']
    assert build['passed'] and live['passed'] and cleanup['passed']
    assert receipts['response-metadata-create-01']['passed']
    assert not receipts['response-metadata-live-01']['passed']
    assert not receipts['response-metadata-build-02']['passed']
    assert build == live['program_build']
    assert build['discovery_sha256'] == manifest['response-metadata-discovery-02.json']
    assert cleanup['live_sha256'] == manifest[RUN + '.json']
    assert cleanup['archive']['sha256'] == manifest['response-metadata-evidence-01.tar.gz']
    assert live['before'] == live['after'] and not live.get('collection_errors')
    assert live['image_build']['image'] == live['collector']['image']
    assert live['source_binding']['sha256'] == build['runtime']['sha256']
    for name in ('response_metadata_build.py', 'response_metadata_decode.py'):
        source, = [s for path, s in build['sources'].items() if path.endswith('/' + name)]
        assert digest((ROOT / 'env/ai-traffic' / name).read_bytes()) == source['sha256'], name
    for suffix in ('surfaces/response_metadata.bpf.c', 'surfaces/response_metadata_abi.h',
                   'surfaces/json_method_abi.h', 'check_response_metadata.c'):
        source, = [s for name, s in build['sources'].items() if name.endswith('/' + suffix)]
        assert digest((ROOT / 'substrate' / suffix).read_bytes()) == source['sha256'], suffix
    for name, source in live['sources'].items():
        if not name.endswith('.md'):
            assert digest((ROOT / 'env/ai-traffic' / name).read_bytes()) == source['sha256'], name
    native = [decode(bytes.fromhex(line[7:])) for cmd in build['commands']
              for line in cmd['stdout'].splitlines() if line.startswith('RECORD ')]
    assert native == build['programs']['response']['native_events'] and len(native) == 80
    assert max(e['reads'] for e in native) == 2 and max(e['source_bytes'] for e in native) == 5
    verified, = [c for c in build['commands'] if c['argv'][0].endswith('/prevail')]
    assert verified['rc'] == 0 and verified['stdout'].startswith('PASS:')
    assert verified['argv'][-2:] == ['--stack-size', '256']
    assert all(flag in verified['argv'] for flag in ('--termination', '--strict', '--no-division-by-zero'))
    files = {}
    with tarfile.open(CACHE / 'response-metadata-evidence-01.tar.gz', 'r:gz') as archive:
        for member in archive.getmembers():
            assert member.isdir() or member.isfile(), member.name
            if member.isfile():
                name = member.name.removeprefix('./')
                assert name not in files and not Path(name).is_absolute() and '..' not in Path(name).parts
                assert not name.endswith(('.pem', '.key', '.p12', '.bpf.o', '.sig'))
                files[name] = archive.extractfile(member).read()
                assert b'PRIVATE KEY-----' not in files[name]
    assert {name: digest(data) for name, data in files.items()} == cleanup['manifest']
    for run in ('response-metadata-live-01', RUN):
        for name, text in receipts[run]['files'].items():
            assert files[run + '/' + name].decode() == text, (run, name)
        assert digest(files[run + '/events.sqlite']) == receipts[run]['journal_sha256']
    xml = ET.fromstring(files[RUN + '/tao.xml'])
    assert list(xml.iter('testcase'))
    for node in xml.iter():
        assert node.tag not in ('failure', 'error', 'skipped')
        assert not any(int(node.get(k, '0')) for k in ('failures', 'errors', 'skipped'))
    assert files[RUN + '/exit-status'].strip() == files[RUN + '/checked-exit-status'].strip() == b'0'
    test = json.loads(live['files']['result.json'])
    assert test['passed'] and not test['cleanup_errors'] and not test['backend_errors']
    assert len(test['clients']) == len(test['origin']) == len(test['comparisons']) == len(CASES)
    assert [c['case'] for c in test['comparisons']] == list(CASES)
    assert test['acknowledgements'] and all(r['status'] == 0 for r in test['acknowledgements'])
    before = [r for page in test['pre_run_pages'] for r in page['events']]
    assert not test['pre_run_pages'][-1]['events']
    assert test['pre_run_pages'][-1]['next_cursor'] == test['initial_cursor']
    rows = [r for page in test['stream_pages'] for r in page['events']]
    assert len({r['cursor'] for r in before + rows}) == len(before + rows)
    records = [r['event'] for r in rows if r['event']['type'] == 'record']
    assert records == [r['event'] for r in test['replay_consumer']['events'] if r['event']['type'] == 'record']
    assert len({r['event_id'] for r in records}) == len(records)
    events = [decode(bytes.fromhex(r['raw']['data'])) for r in records]
    assert len(events) == 201
    assert events == test['events'] == [e for c in test['comparisons'] for e in c['events']]
    identity = test['instances']['response']
    for n, (record, event) in enumerate(zip(records, events), 1):
        assert record['raw']['slot'] == 9 and record['raw']['hook_id'] == record['raw']['schema'] == 100
        assert event['sequence'] == n and event['instance'] == int(identity['instance'], 16)
        assert event['revision'] == identity['revision'] and event['run'] == test['run_token']
        assert event['monotonic_ns'] and not event['flags'] and not event['output_failures']
    summaries = []
    for case, client, origin in zip(test['comparisons'], test['clients'], test['origin']):
        name = case['case']
        assert client['case'] == origin['case'] == name
        assert case['expected_status'] == origin['status'] == CASES[name]
        response = bytes.fromhex(client['response_hex'])
        assert response.startswith(f'HTTP/1.1 {CASES[name]} '.encode())
        status = [e for e in case['events'] if e['http_status_state']]
        done = [e for e in case['events'] if e['completion_state']]
        assert len(status) == 2 and {e['code'] for e in status} == {28, 144}
        assert all(e['http_status_state'] == 1 and e['http_status'] == CASES[name] for e in status)
        assert len(done) == 2 and {e['code'] for e in done} == {29, 145}
        assert all(e['completion_state'] == 1 and e['transfer_complete'] == int(name != 'interrupted') for e in done)
        if name == 'interrupted':
            headers, body = response.split(b'\r\n\r\n', 1)
            assert b'content-length: 25' in headers.lower() and body == b'short'
        if name == 'bodyless':
            assert not response.split(b'\r\n\r\n', 1)[1]
        summaries.append(dict(case=name, http_status=CASES[name], status_records=len(status),
                              done_records=len(done), transfer_complete=done[0]['transfer_complete'],
                              handler_records=len(case['events'])))
    prefix = test['paced_before_release']
    paced, = [c for c in test['comparisons'] if c['case'] == 'paced']
    assert prefix == paced['events'][:len(prefix)]
    assert any(e['http_status_state'] == 1 and e['http_status'] == 200 for e in prefix)
    assert not any(e['completion_state'] for e in prefix)
    start, end = test['counter_start']['response'], test['counter_end']['response']
    assert end['fired'] - start['fired'] == len(events)
    assert all(end[k] == start[k] for k in ('errors', 'safe_returns', 'gen'))
    for run in ('response-metadata-live-01', RUN):
        witness = receipts[run]['witnesses']['response']
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
                checked_sources=checked_sources, native_records=len(native), live_requests=len(CASES),
                handler_records=len(events), cases=summaries, journal_events=len(stored),
                pre_run_events=len(before), current_run_events=len(rows), archive_files=len(files),
                replay_retries=test['replay_retries'], max_reads=max(e['reads'] for e in events),
                max_source_bytes=max(e['source_bytes'] for e in events),
                source_receipt=RUN + '.json', source_sha256=manifest[RUN + '.json'], observations=events)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--export', action='store_true')
    args = parser.parse_args()
    result = verify()
    if not args.export:
        result.pop('observations')
    print(json.dumps(result, indent=2))
