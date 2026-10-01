#!/usr/bin/env python3
"""Repair only the missing collector API mount in the isolated test fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from lifetime_fixture import COMPOSE, PROJECT, ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    image = 'sha256:26f3184a4e3fe96b61f780761497933facc385f3d62d6f1cf66f04e56abd5054'
    source = ROOT / 'reply-metadata-source-01'
    env = dict(os.environ, COLLECTOR_IMAGE=image, COLLECTOR_SOURCE_DIR=str(source))
    record = dict(passed=False, commands=[], sources={})

    def run(*argv):
        p = subprocess.run(argv, cwd=ROOT, env=env, text=True, capture_output=True, timeout=240, check=False)
        record['commands'].append(dict(argv=argv, rc=p.returncode, stdout=p.stdout, stderr=p.stderr))
        p.check_returncode()
        return p.stdout

    def inventory():
        return [json.loads(run('docker', 'inspect', identity, '--format',
            '{"id":{{json .Id}},"image":{{json .Image}},"name":{{json .Name}},"state":{{json .State}},"restarts":{{.RestartCount}}}'))
            for identity in run('docker', 'ps', '-aq').split()]

    with args.output.open('x') as output:
        try:
            for name in ('reply_metadata_fixture_repair.py', 'collector-compose.yaml'):
                path = ROOT / name
                record['sources'][name] = dict(text=path.read_text(), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            fixture = PROJECT + '-fixture-1'
            record['before'] = inventory()
            record['mounts_before'] = json.loads(run('docker', 'inspect', fixture, '--format', '{{json .Mounts}}'))
            assert not any(m['Destination'] == '/collector-api' for m in record['mounts_before'])
            failure = ROOT / 'reply-metadata-live-01.json'
            doc = json.loads(failure.read_text())
            assert not doc['passed'] and 'collector socket not ready' in doc['error']
            assert not any('/work/reply-metadata-run.sh' in c['argv'] for c in doc['commands'])
            run('docker', 'exec', fixture, 'ls', '-d', '/evidence')
            run('docker', 'exec', fixture, 'mkdir', '/evidence/reply-metadata-live-01')
            for path in (failure, source / 'events.sqlite'):
                record[path.name + '_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
                run('docker', 'cp', str(path), fixture + ':/evidence/reply-metadata-live-01/' + path.name)
            run(*COMPOSE, '-f', 'collector-compose.yaml', 'up', '-d', '--no-deps', '--wait', '--wait-timeout', '180', 'fixture')
            record['mounts_after'] = json.loads(run('docker', 'inspect', fixture, '--format', '{{json .Mounts}}'))
            mount, = [m for m in record['mounts_after'] if m['Destination'] == '/collector-api']
            assert mount['Name'] == PROJECT + '_collector-api' and not mount['RW']
            record['after'] = inventory()
            assert [r for r in record['before'] if r['name'] != '/' + fixture] == [
                r for r in record['after'] if r['name'] != '/' + fixture]
            record['passed'] = True
        except BaseException as error:
            record['error'] = repr(error)
            raise
        finally:
            json.dump(record, output, indent=2)
    print(json.dumps(dict(passed=record['passed'])))


if __name__ == '__main__':
    main()
