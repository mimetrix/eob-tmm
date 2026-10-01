#!/usr/bin/env python3
"""Verify saved reply fields, failed attempts, native checks, replay and cleanup."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sqlite3
import tarfile
import xml.etree.ElementTree as ET
from reply_metadata_decode import decode, FIELDS
from reply_metadata_cases import CASES

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / 'evidence/cache'
RUN = 'reply-metadata-live-03'
REQUEST = b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def archive_files(name, receipt):
    files = {}
    with tarfile.open(CACHE / name, 'r:gz') as archive:
        for member in archive.getmembers():
            assert member.isdir() or member.isfile()
            if not member.isfile():
                continue
            path = member.name.removeprefix('./')
            assert path not in files and not Path(path).is_absolute() and '..' not in Path(path).parts
            assert not path.endswith(('.pem', '.key', '.p12', '.bpf.o', '.sig'))
            files[path] = archive.extractfile(member).read()
            assert not any(marker in files[path] for marker in (
                b'-----BEGIN PRIVATE KEY-----', b'-----BEGIN OPENSSH PRIVATE KEY-----',
                b'-----BEGIN RSA PRIVATE KEY-----', b'-----BEGIN EC PRIVATE KEY-----'))
    assert {path: digest(data) for path, data in files.items()} == receipt['manifest']
    assert len(files) == receipt['archive']['files']
    return files


def verify():
    manifest = {name: sha for sha, name in
                (line.split() for line in (CACHE / 'MANIFEST.sha256').read_text().splitlines()
                 if line and not line.startswith('#'))}
    receipts, checked_sources = {}, 0
    for path in sorted(CACHE.glob('reply-metadata-*')):
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
    discovery = receipts['reply-metadata-discovery-01']
    assert discovery['completed'] and discovery['base'] == receipts['reply-metadata-discovery-01-base']
    assert discovery['base_sha256'] == manifest['reply-metadata-discovery-01-base.json']
    build, live, cleanup = (receipts['reply-metadata-' + n] for n in ('build-03', 'live-03', 'cleanup-01'))
    assert build['passed'] and live['passed'] and cleanup['passed']
    assert all(receipts['reply-metadata-create-' + n]['passed'] for n in ('01', '02'))
    assert build == live['program_build']
    assert build['discovery_sha256'] == manifest['reply-metadata-discovery-01.json']
    assert cleanup['live_sha256'] == manifest[RUN + '.json']
    assert cleanup['archive']['sha256'] == manifest['reply-metadata-evidence-01.tar.gz']
    assert live['before'] == live['after'] and not live.get('collection_errors')
    assert live['image_build']['image'] == live['collector']['image']
    assert live['source_binding']['sha256'] == build['runtime']['sha256']
    assert any(m['Destination'] == '/collector-api' and not m['RW'] for m in live['fixture_mounts'])
    for name, source in build['sources'].items():
        target = (ROOT / 'substrate' / name.split('/substrate/', 1)[1] if '/substrate/' in name
                  else ROOT / 'env/ai-traffic' / Path(name).name)
        if target.suffix != '.md':
            assert digest(target.read_bytes()) == source['sha256'], name
    for name, source in live['sources'].items():
        if not name.endswith('.md'):
            assert digest((ROOT / 'env/ai-traffic' / name).read_bytes()) == source['sha256'], name
    for version in ('01', '02', '03'):
        built = receipts['reply-metadata-build-' + version]
        assert built['passed']
        assert digest(built['fixtures']['text'].encode()) == built['fixtures']['sha256']
        native = [decode(bytes.fromhex(line[7:])) for cmd in built['commands']
                  for line in cmd['stdout'].splitlines() if line.startswith('RECORD ')]
        assert native == built['programs']['reply']['native_events'] and len(native) == 106
        for offset in (1, 54):
            assert [tuple(e[k] for k in FIELDS) for e in native[offset:offset + len(CASES)]] == [c[2] for c in CASES]
        verified, = [c for c in built['commands'] if c['argv'][0].endswith('/prevail')]
        assert verified['rc'] == 0 and verified['stdout'].startswith('PASS:')
        assert verified['argv'][-2:] == ['--stack-size', '256']
        assert all(f in verified['argv'] for f in ('--termination', '--strict', '--no-division-by-zero'))
    failed1, failed2 = (receipts['reply-metadata-live-' + n] for n in ('01', '02'))
    assert not failed1['passed'] and 'collector socket not ready' in failed1['error']
    assert not failed2['passed'] and 'TimeoutError' in json.loads(failed2['files']['result.json'])['error']
    for failed in (failed1, failed2):
        witness = failed['witnesses']['reply']
        assert failed['before'] == failed['after']
        assert all(r['bytes'] == witness['initial']['bytes'] for r in witness['changes'])
    repair = receipts['reply-metadata-mount-repair-01']
    assert repair['passed']
    assert not any(m['Destination'] == '/collector-api' for m in repair['mounts_before'])
    assert any(m['Destination'] == '/collector-api' and not m['RW'] for m in repair['mounts_after'])
    assert not receipts['reply-metadata-reset-01']['passed']
    assert "KeyError('sha256')" in receipts['reply-metadata-reset-01']['error']
    assert not receipts['reply-metadata-reset-02']['passed']
    reset = receipts['reply-metadata-reset-03']
    assert reset['passed'] and reset['live_sha256'] == manifest['reply-metadata-live-02.json']
    assert reset['archive']['sha256'] == manifest['reply-metadata-failed-evidence-01.tar.gz']
    failed_files = archive_files('reply-metadata-failed-evidence-01.tar.gz', reset)
    assert failed_files['reply-metadata-live-01/reply-metadata-live-01.json'] == (CACHE / 'reply-metadata-live-01.json').read_bytes()
    for name, text in failed2['files'].items():
        assert failed_files['reply-metadata-live-02/' + name].decode() == text
    files = archive_files('reply-metadata-evidence-01.tar.gz', cleanup)
    for name, text in live['files'].items():
        assert files[RUN + '/' + name].decode() == text
    assert digest(files[RUN + '/events.sqlite']) == live['journal_sha256']
    xml = ET.fromstring(files[RUN + '/tao.xml'])
    assert list(xml.iter('testcase'))
    for node in xml.iter():
        assert node.tag not in ('failure', 'error', 'skipped')
        assert not any(int(node.get(k, '0')) for k in ('failures', 'errors', 'skipped'))
    assert files[RUN + '/exit-status'].strip() == files[RUN + '/checked-exit-status'].strip() == b'0'
    test = json.loads(live['files']['result.json'])
    assert test['passed'] and not test['cleanup_errors'] and not test['backend_errors']
    assert len(test['clients']) == len(test['origin']) == len(test['comparisons']) == len(CASES) == 38
    assert test['acknowledgements'] and all(r['status'] == 0 for r in test['acknowledgements'])
    before = [r for page in test['pre_run_pages'] for r in page['events']]
    assert not test['pre_run_pages'][-1]['events']
    assert test['pre_run_pages'][-1]['next_cursor'] == test['initial_cursor']
    rows = [r for page in test['stream_pages'] for r in page['events']]
    assert len({r['cursor'] for r in before + rows}) == len(before + rows)
    records = [r['event'] for r in rows if r['event']['type'] == 'record']
    assert records == [r['event'] for r in test['replay_consumer']['events'] if r['event']['type'] == 'record']
    assert len({r['event_id'] for r in records}) == len(records) == 76
    events = [decode(bytes.fromhex(r['raw']['data'])) for r in records]
    assert events == test['events'] == [e for c in test['comparisons'] for e in c['events']]
    identity = test['instances']['reply']
    for n, (record, event) in enumerate(zip(records, events), 1):
        assert record['raw']['slot'] == 11 and record['raw']['hook_id'] == record['raw']['schema'] == 100
        assert event['sequence'] == n and event['instance'] == int(identity['instance'], 16)
        assert event['revision'] == identity['revision'] and event['run'] == test['run_token']
        assert event['monotonic_ns'] and not event['flags'] and not event['output_failures']
    for expected, case, client, origin in zip(CASES, test['comparisons'], test['clients'], test['origin']):
        name, body, fields = expected
        assert case['case'] == client['case'] == origin['case'] == name
        assert origin['request_sha256'] == digest(REQUEST)
        assert origin['response_sha256'] == digest(body.encode())
        response = bytes.fromhex(client['response_hex'])
        assert response.startswith(b'HTTP/1.1 200 ') and response.split(b'\r\n\r\n', 1)[1] == body.encode()
        assert tuple(case['expected']) == fields
        request, reply = case['events']
        assert tuple(request[k] for k in FIELDS) == (0,) * 7
        assert tuple(reply[k] for k in FIELDS) == fields
    start, end = test['counter_start']['reply'], test['counter_end']['reply']
    assert end['fired'] - start['fired'] == len(events)
    assert all(end[k] == start[k] for k in ('errors', 'safe_returns', 'gen'))
    witness = live['witnesses']['reply']
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
    for removed in (reset, cleanup):
        assert not any(r['project'] == 'eob-template-20260925' for r in removed['after'])
        assert [r for r in removed['before'] if r['project'] != 'eob-template-20260925'] == removed['after']
        statuses = [c for c in removed['commands'] if c['argv'][-3:-1] == ['/work/ls-load.py', 'status']]
        assert {int(c['argv'][-1]) for c in statuses} == set(range(12))
        assert all(c['rc'] == 0 and ('armed=0' in c['stdout'] or 'mode=0' in c['stdout']) for c in statuses)
    return dict(passed=True, evidence_tier='MEASURED', value_witness='SELF',
                checked_sources=checked_sources, native_records=len(native), live_requests=len(CASES),
                live_records=len(events), status_counts=dict(Counter(e['status_name'] for e in events)),
                journal_events=len(stored), pre_run_events=len(before), archive_files=len(files),
                failed_archive_files=len(failed_files), max_reads=max(e['reads'] for e in events),
                max_source_bytes=max(e['source_bytes'] for e in events), replay_retries=test['replay_retries'],
                source_receipt=RUN + '.json', source_sha256=manifest[RUN + '.json'], observations=events)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--export', action='store_true')
    args = parser.parse_args()
    result = verify()
    if not args.export:
        result.pop('observations')
    print(json.dumps(result, indent=2))
