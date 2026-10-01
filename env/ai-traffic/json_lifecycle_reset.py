#!/usr/bin/env python3
"""Archive a failed JSON boundary run before removing its isolated fixture."""
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
    parser.add_argument('--live', type=Path, required=True)
    parser.add_argument('--source-dir', type=Path, required=True)
    args = parser.parse_args()
    failed = json.loads(args.live.read_text())
    environment = dict(os.environ, COLLECTOR_IMAGE=failed['collector']['image'],
                       COLLECTOR_SOURCE_DIR=str(args.source_dir.resolve()))
    record = dict(passed=False, commands=[], sources={}, witnesses={}, witness_script=WITNESS)

    def run(*argv):
        row = subprocess.run(argv, cwd=ROOT, env=environment, capture_output=True, text=True, timeout=240, check=False)
        record['commands'].append(dict(argv=argv, rc=row.returncode, stdout=row.stdout, stderr=row.stderr))
        row.check_returncode()
        return row.stdout

    def inventory():
        return [json.loads(run('docker', 'inspect', identity, '--format',
            '{"id":{{json .Id}},"image":{{json .Image}},"name":{{json .Name}},"state":{{json .State}},"restarts":{{.RestartCount}},'
            '"project":{{json (index .Config.Labels "com.docker.compose.project")}}}'))
            for identity in run('docker', 'ps', '-aq').split()]

    with args.output.open('x') as output:
        try:
            assert not args.archive.exists()
            assert not failed['passed'] and failed['before'] == failed['after']
            result = json.loads(failed['files']['result.json'])
            assert not result['passed'] and not result['cleanup_errors']
            record['live_sha256'] = hashlib.sha256(args.live.read_bytes()).hexdigest()
            for name in ('json_lifecycle_reset.py', 'collector-compose.yaml'):
                path = ROOT / name
                record['sources'][name] = dict(text=path.read_text(), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            record['before'] = inventory()
            owned = [r for r in record['before'] if r['project'] == PROJECT]
            assert len(owned) == 3
            assert next(r['id'] for r in owned if r['name'].endswith('-tmm-1')) == json.loads(failed['before'].split()[0])
            fixture, tmm = PROJECT + '-fixture-1', PROJECT + '-tmm-1'
            for name, program in failed['program_build']['programs'].items():
                expected = failed['witnesses'][name]['initial']
                rows = [json.loads(line) for line in run('docker', 'exec', tmm, 'python3', '-u', '-c', WITNESS, program['entry']).splitlines()]
                record['witnesses'][name] = rows
                assert rows[0]['sha256'] == expected['sha256']
                assert all(r['bytes'] == expected['bytes'] and r['stat'].split()[21] == expected['stat'].split()[21] for r in rows)
            for slot in range(12):
                status = run('docker', 'exec', fixture, 'python3', '/work/ls-load.py', 'status', str(slot))
                assert status.startswith('OK ') and ('mode=0' in status or 'armed=0' in status)
            record['manifest'] = json.loads(run('docker', 'exec', fixture, 'python3', '-c',
                'import hashlib,json,pathlib; root=pathlib.Path("/evidence"); '
                'print(json.dumps({str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob("*") if p.is_file()}))'))
            archive = subprocess.run(['docker', 'exec', fixture, 'tar', 'czf', '-', '-C', '/evidence', '.'], capture_output=True, timeout=60, check=True)
            members = {}
            with tarfile.open(fileobj=io.BytesIO(archive.stdout), mode='r:gz') as stream:
                for member in stream.getmembers():
                    assert member.isdir() or member.isfile()
                    if member.isfile():
                        name = member.name.removeprefix('./')
                        assert name not in members and not Path(name).is_absolute() and '..' not in Path(name).parts
                        assert not name.endswith(('.pem', '.key', '.p12', '.sig', '.bpf.o'))
                        data = stream.extractfile(member).read()
                        assert b'PRIVATE KEY-----' not in data and b'BEGIN CERTIFICATE' not in data
                        members[name] = hashlib.sha256(data).hexdigest()
            assert members == record['manifest'] and members
            with args.archive.open('xb') as archive_file:
                archive_file.write(archive.stdout)
            record['archive'] = dict(files=len(members), sha256=hashlib.sha256(archive.stdout).hexdigest())
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
