#!/usr/bin/env python3
"""Archive pre-arm failures, then remove only the isolated reply test fixture."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
from config_live_run import WITNESS
from lifetime_fixture import COMPOSE, PROJECT, ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    args = parser.parse_args()
    env = dict(os.environ,
        COLLECTOR_IMAGE='sha256:26f3184a4e3fe96b61f780761497933facc385f3d62d6f1cf66f04e56abd5054',
        COLLECTOR_SOURCE_DIR=str(ROOT / 'reply-metadata-source-02'))
    record = dict(passed=False, commands=[], sources={}, witness_script=WITNESS)

    def run(*argv):
        p = subprocess.run(argv, cwd=ROOT, env=env, text=True, capture_output=True, timeout=240, check=False)
        record['commands'].append(dict(argv=argv, rc=p.returncode, stdout=p.stdout, stderr=p.stderr))
        p.check_returncode()
        return p.stdout

    def inventory():
        return [json.loads(run('docker', 'inspect', identity, '--format',
            '{"id":{{json .Id}},"image":{{json .Image}},"name":{{json .Name}},"state":{{json .State}},"restarts":{{.RestartCount}},'
            '"project":{{json (index .Config.Labels "com.docker.compose.project")}}}'))
            for identity in run('docker', 'ps', '-aq').split()]

    with args.output.open('x') as output:
        try:
            for name in ('reply_metadata_reset.py', 'collector-compose.yaml'):
                path = ROOT / name
                record['sources'][name] = dict(text=path.read_text(), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            record['before'] = inventory()
            fixture, tmm = PROJECT + '-fixture-1', PROJECT + '-tmm-1'
            path = ROOT / 'reply-metadata-live-02.json'
            failed = json.loads(path.read_text())
            record['live_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
            result = json.loads(failed['files']['result.json'])
            assert not failed['passed'] and not result['events'] and not result.get('instances')
            witness = failed['witnesses']['reply']
            assert all(r['bytes'] == witness['initial']['bytes'] for r in witness['changes'])
            record['witness'] = [json.loads(line) for line in run(
                'docker', 'exec', tmm, 'python3', '-u', '-c', WITNESS, '0xd93540').splitlines()]
            assert record['witness'][0]['sha256'] == witness['initial']['sha256']
            assert all(r['bytes'] == witness['initial']['bytes'] and
                       r['stat'].split()[21] == witness['initial']['stat'].split()[21]
                       for r in record['witness'])
            for slot in range(12):
                status = run('docker', 'exec', fixture, 'python3', '/work/ls-load.py', 'status', str(slot))
                assert status.startswith('OK ') and ('mode=0' in status or 'armed=0' in status)
            record['manifest'] = json.loads(run('docker', 'exec', fixture, 'python3', '-c',
                'import hashlib,json,pathlib; root=pathlib.Path("/evidence"); '
                'print(json.dumps({str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() '
                'for p in root.rglob("*") if p.is_file()}))'))
            p = subprocess.run(['docker', 'exec', fixture, 'tar', 'czf', '-', '-C', '/evidence', '.'],
                capture_output=True, timeout=60, check=True)
            members = {}
            with tarfile.open(fileobj=io.BytesIO(p.stdout), mode='r:gz') as archive:
                for member in archive.getmembers():
                    assert member.isdir() or member.isfile()
                    if member.isfile():
                        name = member.name.removeprefix('./')
                        assert name not in members and not name.endswith(('.pem', '.key', '.sig', '.bpf.o'))
                        data = archive.extractfile(member).read()
                        assert not any(marker in data for marker in (
                            b'-----BEGIN PRIVATE KEY-----', b'-----BEGIN RSA PRIVATE KEY-----',
                            b'-----BEGIN OPENSSH PRIVATE KEY-----', b'-----BEGIN EC PRIVATE KEY-----'))
                        members[name] = hashlib.sha256(data).hexdigest()
            assert members == record['manifest'] and members
            with args.archive.open('xb') as archive:
                archive.write(p.stdout)
            record['archive'] = dict(files=len(members), sha256=hashlib.sha256(p.stdout).hexdigest())
            run(*COMPOSE, '-f', 'collector-compose.yaml', 'down', '--volumes', '--remove-orphans')
            record['after'] = inventory()
            assert [r for r in record['before'] if r['project'] != PROJECT] == record['after']
            for kind in ('container', 'network', 'volume'):
                assert not run('docker', kind, 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + PROJECT).strip()
            record['passed'] = True
        except BaseException as error:
            record['error'] = repr(error)
            raise
        finally:
            json.dump(record, output, indent=2)
    print(json.dumps(dict(passed=record['passed'], archive=record['archive'])))


if __name__ == '__main__':
    main()
