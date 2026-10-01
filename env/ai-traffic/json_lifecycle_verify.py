#!/usr/bin/env python3
"""Check saved boundary evidence without granting a lifecycle or request scope."""
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
from id_flow_cases import all_cases
from json_lifecycle_decode import decode, window

ROOT = Path(__file__).resolve().parents[2]
RUN = 'json-lifecycle-live-02'
PREFIX = 'json-lifecycle-'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def archive_files(path, receipt):
    files = {}
    with tarfile.open(path, 'r:gz') as archive:
        for member in archive.getmembers():
            assert member.isdir() or member.isfile()
            if not member.isfile():
                continue
            name = member.name.removeprefix('./')
            assert name not in files and not Path(name).is_absolute() and '..' not in Path(name).parts
            assert not name.endswith(('.pem', '.key', '.p12', '.sig', '.bpf.o'))
            data = archive.extractfile(member).read()
            assert b'PRIVATE KEY-----' not in data and b'BEGIN CERTIFICATE' not in data
            files[name] = data
    assert {n: digest(d) for n, d in files.items()} == receipt['manifest']
    assert len(files) == receipt['archive']['files'] == 9
    return files


def check_removal(receipt):
    assert receipt['passed']
    assert [r for r in receipt['before'] if r['project'] != 'eob-template-20260925'] == receipt['after']
    statuses = [c for c in receipt['commands'] if c['argv'][-3:-1] == ['/work/ls-load.py', 'status']]
    assert {int(c['argv'][-1]) for c in statuses} == set(range(12))
    assert all(c['rc'] == 0 and ('armed=0' in c['stdout'] or 'mode=0' in c['stdout']) for c in statuses)


def verify(cache, source_root, substrate_root):
    manifest = {name: sha for sha, name in (line.split() for line in
                (cache / 'MANIFEST.sha256').read_text().splitlines() if line and not line.startswith('#'))}
    docs, checked_sources = {}, 0
    current = {'build-03', 'live-02', 'create-02', 'cleanup-01', 'reset-01'}
    for stem in ('discovery-01', 'build-01', 'build-02', 'build-03', 'create-01',
                 'create-02', 'live-01', 'live-02', 'reset-01', 'cleanup-01'):
        name = PREFIX + stem + '.json'
        data = (cache / name).read_bytes()
        assert digest(data) == manifest[name], name
        docs[stem] = doc = json.loads(data)
        for path, row in doc.get('sources', {}).items():
            assert digest(row['text'].encode()) == row['sha256'], path
            checked_sources += 1
            if stem in current:
                target = (substrate_root / path.split('/substrate/', 1)[1]
                          if '/substrate/' in path else source_root / Path(path).name)
                if target.suffix != '.md':
                    assert digest(target.read_bytes()) == row['sha256'], path
    for name in ('evidence-01.tar.gz', 'failed-evidence-01.tar.gz'):
        assert digest((cache / (PREFIX + name)).read_bytes()) == manifest[PREFIX + name]
    discovery, build, live = (docs[k] for k in ('discovery-01', 'build-03', 'live-02'))
    cleanup, failed, reset = (docs[k] for k in ('cleanup-01', 'live-01', 'reset-01'))
    assert discovery['completed'] and discovery['scope_check']['passed']
    for name, row in discovery['files'].items():
        assert digest(row['text'].encode()) == row['sha256'], name
        checked_sources += 1
    assert discovery['runtime'] == build['runtime'] == live['program_build']['runtime']
    assert build['runtime'] == dict(build_id='ca69b84f4f5c9e225813b2ed3997c59f18ba2a31',
        sha256='05d17517531d99b26eb9e8f00f5b5326f660b5bef492226c9555368b887a9611')
    assert build == live['program_build'] and build['discovery_sha256'] == manifest[PREFIX + 'discovery-01.json']
    assert all(docs[k]['passed'] for k in current) and docs['build-02']['passed'] and docs['create-01']['passed']
    assert not docs['build-01']['passed'] and not failed['passed']
    assert any("unused function 'read_field'" in c['stderr'] for c in docs['build-01']['commands'])
    assert 'assert event["status"] in (1, 2, 5)' in failed['files']['tao.xml']
    for key, receipt in (('cleanup-01', live), ('reset-01', failed)):
        suffix = 'live-02' if key == 'cleanup-01' else 'live-01'
        assert docs[key]['live_sha256'] == manifest[PREFIX + suffix + '.json']
        assert receipt['before'] == receipt['after'] and not receipt.get('collection_errors')
        check_removal(docs[key])
    verifications = [c for c in build['commands'] if c['argv'][0].endswith('/prevail')]
    assert len(verifications) == 3 and all(c['rc'] == 0 for c in build['commands'])
    for c in verifications:
        assert c['stdout'].startswith('PASS:') and c['argv'][-2:] == ['--stack-size', '256']
        assert all(f in c['argv'] for f in ('--termination', '--strict', '--no-division-by-zero'))
    raw_native = [bytes.fromhex(line[7:]) for c in build['commands']
                  for line in c['stdout'].splitlines() if line.startswith('RECORD ')]
    native = [decode(raw) for raw in raw_native]
    assert native == build['native_events'] and len(native) == 312 and build['consumer_checks'] == 5
    for start in (0, 156):
        block = native[start:start + 156]
        expected = [0, 0, 0, 2, 1, 1, 2, 1, 1, 1, 1, 5] + [4] * 5 + [0] + [3] * 6 + [1] * 126 + [6, 1, 2, 2, 9, 7]
        assert [e['status'] for e in block] == expected
        assert all(e['flags'] == 1 and not e['reads'] and not e['sequence'] for e in block[:3])
        assert not block[3]['context_tag'] and not block[3]['seen_mask']
        assert [e['seen_mask'] for e in block[4:10]] == [1, 3, 7, 15, 15, 2]
        assert all(e['context_tag'] == 1 for e in block[4:9]) and block[9]['context_tag'] == 2
        assert [e['reads'] for e in block[12:16]] == [1, 2, 3, 4]
        assert [e['context_tag'] for e in block[24:150]] == list(range(3, 129))
        assert block[151]['context_tag'] == 1 and block[152]['output_failures'] == 0 and block[153]['output_failures'] == 1
        assert all(not e['reads'] and not e['context_tag'] for e in block[154:])
    clean = [dict(native[4], sequence=1)]
    assert window(clean)['boundaries_usable'] and not window(clean)['lifecycle_validated']
    assert not window(clean, ['detached_both_boundaries'])['boundaries_usable']
    for changes in (dict(instance=1), dict(revision=2), dict(run=124), dict(sequence=3),
                    dict(output_failures=1), dict(flags=1), dict(status=0), dict(status=5), dict(status=6)):
        assert not window(clean + [dict(clean[0], sequence=2) | changes])['boundaries_usable']
    assert not window(native)['boundaries_usable']
    bad = [raw_native[4][:-1], raw_native[4] + b'\x00']
    for offset, value in ((0, 0), (4, 2), (64, 4), (72, 10), (76, 16), (80, 3),
                          (84, 0x4000), (88, 2), (92, 16), (96, 5), (100, 30), (108, 1)):
        payload = bytearray(raw_native[4]); struct.pack_into('<I', payload, offset, value); bad.append(payload)
    for payload in bad:
        try:
            decode(payload)
        except ValueError:
            continue
        raise AssertionError('malformed boundary accepted')
    assert cleanup['archive']['sha256'] == manifest[PREFIX + 'evidence-01.tar.gz']
    assert reset['archive']['sha256'] == manifest[PREFIX + 'failed-evidence-01.tar.gz']
    files = archive_files(cache / (PREFIX + 'evidence-01.tar.gz'), cleanup)
    failed_files = archive_files(cache / (PREFIX + 'failed-evidence-01.tar.gz'), reset)
    for receipt, saved, run in ((live, files, RUN), (failed, failed_files, PREFIX + 'live-01')):
        for name, text in receipt['files'].items():
            assert saved[run + '/' + name].decode() == text
        assert digest(saved[run + '/events.sqlite']) == receipt['journal_sha256']
        for label, program in receipt['program_build']['programs'].items():
            witness = receipt['witnesses'][label]
            assert witness['returncode'] == 0 and witness['initial']['sha256'] == build['runtime']['sha256']
            pad = program['pad'] * 2
            assert witness['initial']['bytes'][pad:].startswith('9090909090')
            assert len([r for r in witness['changes'] if r['bytes'][pad:].startswith('e8')]) == 1
            final = witness['changes'][-1]
            assert final['final'] and final['bytes'] == witness['initial']['bytes']
            assert final['stat'].split()[21] == witness['initial']['stat'].split()[21]
    xml = ET.fromstring(files[RUN + '/tao.xml'])
    assert list(xml.iter('testcase'))
    for node in xml.iter():
        assert node.tag not in ('failure', 'error', 'skipped')
        assert not any(int(node.get(k, '0')) for k in ('failures', 'errors', 'skipped'))
    assert files[RUN + '/exit-status'].strip() == files[RUN + '/checked-exit-status'].strip() == b'0'
    test = json.loads(live['files']['result.json'])
    assert test['passed'] and not test['backend_errors'] and not test['cleanup_errors']
    assert test['acknowledgements'] and all(r['status'] == 0 for r in test['acknowledgements'])
    assert live['image_build']['image'] == live['collector']['image']
    assert live['source_binding']['sha256'] == build['runtime']['sha256']
    assert any(m['Destination'] == '/collector-api' and not m['RW'] for m in live['fixture_mounts'])
    before = [r for p in test['pre_run_pages'] for r in p['events']]
    rows = [r for p in test['stream_pages'] for r in p['events']]
    assert not before and not test['pre_run_pages'][-1]['events']
    assert len({r['cursor'] for r in rows}) == len(rows)
    records = [r['event'] for r in rows if r['event']['type'] == 'record']
    assert records == [r['event'] for r in test['replay_consumer']['events'] if r['event']['type'] == 'record']
    assert len({r['event_id'] for r in records}) == len(records) == 306
    events = [decode(bytes.fromhex(r['raw']['data'])) for r in records]
    assert events == test['events']
    for n, (record, event) in enumerate(zip(records, events), 1):
        label = {1: 'handler', 2: 'complete', 3: 'reset'}[event['kind']]
        identity = test['instances'][label]
        assert record['raw']['slot'] == event['kind'] + 7 and record['raw']['hook_id'] == record['raw']['schema'] == 100
        assert event['sequence'] == n and event['instance'] == int(identity['instance'], 16)
        assert event['revision'] == identity['revision'] and event['run'] == test['run_token']
        assert identity['program_sha256'] == build['programs'][label]['sha256']
        assert event['monotonic_ns'] and not event['flags'] and not event['output_failures']
        assert event['status'] in (0, 1, 2)
        if event['status'] == 0:
            assert event['kind'] == 1 and event['code'] == 2
            assert not any(event[k] for k in ('context_tag', 'flow_side', 'seen_mask', 'reads', 'source_bytes'))
    assert Counter(e['kind'] for e in events) == {1: 255, 2: 25, 3: 26}
    assert Counter(e['status'] for e in events) == {0: 11, 1: 269, 2: 26}
    late = test['late_client_completion']
    assert late in events and late['kind'] == 2 and late['flow_side'] == 1 and late['seen_mask'] == 2
    assert test['boundary_window'] == window(events) and not test['boundary_window']['boundaries_usable']
    assert test['known_gap_window'] == window(events, ['controller_reported_detach'])
    assert test['keep_alive_client_connections'] == 1 and test['concurrent_requests_before_replies'] == 4
    expected_cases = {c[0]: c[1:3] for c in all_cases() if c[0] in
                      ('number', 'large-integer', 'escaped-value') or c[0].startswith(('keep-', 'concurrent-'))}
    expected_cases.update(late=(b'{"id":1}', b'{"id":1,"result":{}}'),
                          paced=(b'{"id":1}', b'{"id":1,"result":{}}'),
                          **{'parse-error': (b'{"id":bad}', b'{"id":1,"result":{}}')})
    clients, origins = ({r['case']: r for r in test[k]} for k in ('clients', 'origin'))
    assert len(test['clients']) == len(test['origin']) == len(expected_cases) == 13
    assert set(clients) == set(origins) == set(expected_cases)
    for name, (request, reply) in expected_cases.items():
        assert origins[name]['request_sha256'] == digest(request) and origins[name]['response_sha256'] == digest(reply)
        response = bytes.fromhex(clients[name]['response_hex'])
        assert response.startswith(b'HTTP/1.1 200 ') and response.split(b'\r\n\r\n', 1)[1] == reply
    assert len({origins['concurrent-' + str(i)]['fixture_connection'] for i in range(4)}) == 4
    comparisons = {c['case']: c for c in test['comparisons']}
    assert len(comparisons) == 7
    assert [e['flow_side'] for e in comparisons['parse-error']['events'] if e['kind'] == 2] == [2]
    for name, count in (('keep-alive', 3), ('concurrent', 4)):
        complete = [e for e in comparisons[name]['events'] if e['kind'] == 2]
        assert Counter(e['flow_side'] for e in complete) == {1: count, 2: count}
    for name, program in build['programs'].items():
        start, end = test['counter_start'][name], test['counter_end'][name]
        assert end['fired'] - start['fired'] == sum(e['kind'] == program['kind'] for e in events)
        assert all(end[k] == start[k] for k in ('errors', 'safe_returns', 'gen'))
    db = sqlite3.connect(':memory:')
    try:
        db.deserialize(files[RUN + '/events.sqlite'])
        assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        stored = [json.loads(r[0]) for r in db.execute('SELECT body FROM events ORDER BY id')]
        captured = [r['event'] for r in rows]
        assert stored[:len(captured)] == captured
        assert all(r['type'] == 'ring_health' for r in stored[len(captured):])
        assert not any(r['type'] == 'observation_gap' for r in stored)
        health = [r for r in stored if r['type'] == 'ring_health']
        assert health and all(int(r['raw']['drops']) == 0 for r in health)
    finally:
        db.close()
    return dict(passed=True, evidence_tier='MEASURED', value_witness='SELF', checked_sources=checked_sources,
        native_records=len(native), decoder_rejections=len(bad), live_exchanges=13, live_records=len(events),
        kind_counts=dict(Counter(e['kind'] for e in events)), status_counts=dict(Counter(e['status_name'] for e in events)),
        handler_code_counts=dict(Counter(build['event_names'][str(e['code'])] for e in events if e['kind'] == 1)),
        observed_storage_tags=len({e['context_tag'] for e in events} - {0}),
        journal_events=len(stored), archive_files=len(files), failed_archive_files=len(failed_files),
        max_reads=max(e['reads'] for e in events), max_source_bytes=max(e['source_bytes'] for e in events),
        replay_retries=test['replay_retries'], boundary_window=test['boundary_window'],
        unvalidated_challenges=test['unvalidated_challenges'], lifecycle_validated=False,
        request_scope_validated=False, message_association_validated=False, authenticated_identity_validated=False,
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
        for name in ('json_lifecycle_verify.py', 'json_lifecycle_decode.py', 'id_flow_cases.py', 'message_id_cases.py'):
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
