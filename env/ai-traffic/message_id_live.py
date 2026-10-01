#!/usr/bin/env python3
"""Run bounded message-ID extraction with source pins and kernel witnesses."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import traceback
from config_live_run import WITNESS
from lifetime_fixture import COMPOSE, PROJECT, ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True)
    parser.add_argument('--artifact-dir', type=Path, required=True)
    parser.add_argument('--image-build', type=Path, required=True)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert args.run.replace('-', '').isalnum()
    assert not args.artifact_dir.is_absolute() and '..' not in args.artifact_dir.parts
    record = dict(passed=False, commands=[], sources={}, witnesses={}, witness_script=WITNESS)
    image_build = json.loads(args.image_build.read_text())
    assert image_build['passed']
    image = image_build['image']
    environment = dict(os.environ, COLLECTOR_IMAGE=image, COLLECTOR_SOURCE_DIR=str(args.source_dir.resolve()))
    compose = COMPOSE + ('-f', 'collector-compose.yaml')
    tmm, fixture, collector = (PROJECT + '-' + n + '-1' for n in ('tmm', 'fixture', 'collector'))
    monitor, started = None, False

    def run(*argv, timeout=60):
        row = subprocess.run(list(map(str, argv)), cwd=ROOT, env=environment,
                             capture_output=True, text=True, timeout=timeout, check=False)
        record['commands'].append(dict(argv=list(map(str, argv)), rc=row.returncode, stdout=row.stdout, stderr=row.stderr))
        row.check_returncode()
        return row.stdout

    def state():
        return run('docker', 'inspect', tmm, '--format', '{{json .Id}} {{json .Image}} {{json .State}} {{.RestartCount}}')

    with args.output.open('x') as receipt:
        try:
            for name in ('message_id_live.py', 'message_id_suite.py', 'message_id_decode.py',
                         'message_id_cases.py', 'message-id-run.sh', 'session_routing_suite.py',
                         'session_routing_decode.py', 'session_routing_client.py', 'metadata_suite.py',
                         'config_suite.py', 'icap_suite.py', 'collector_client.py', 'collector_container.py',
                         'stream_collector.py', 'collector-compose.yaml', 'icap_check_result.py',
                         'MESSAGE-ID.md', 'lifetime_fixture.py'):
                path = ROOT / name
                record['sources'][name] = dict(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), text=path.read_text())
            for name in ('collector_container.py', 'stream_collector.py', 'collector-compose.yaml', 'collector_client.py'):
                assert record['sources'][name]['sha256'] == image_build['sources'][name]['sha256']
            record['image_build'] = image_build
            build = json.loads((ROOT / args.artifact_dir / 'metadata-program-build.json').read_text())
            assert build['passed']
            record['program_build'] = build
            record['before'] = state()
            run('docker', 'exec', fixture, 'mkdir', '/evidence/' + args.run)
            record['fixture_mounts'] = json.loads(run('docker', 'inspect', fixture, '--format', '{{json .Mounts}}'))
            assert any(m['Destination'] == '/collector-api' and m.get('Name') == PROJECT + '_collector-api'
                       and not m['RW'] for m in record['fixture_mounts']), 'missing collector API mount'
            run('docker', 'exec', fixture, 'python3', '-m', 'black', '--check',
                '/work/message_id_suite.py', '/work/message_id_cases.py')
            run('docker', 'exec', fixture, 'python3', '-m', 'pylint', '--disable=C,R,broad-exception-caught',
                '/work/message_id_suite.py', '/work/message_id_cases.py')
            program = build['programs']['id']
            obj = ROOT / args.artifact_dir / program['object']
            assert hashlib.sha256(obj.read_bytes()).hexdigest() == program['sha256']
            assert hashlib.sha256(obj.with_suffix('.sig').read_bytes()).hexdigest() == program['signature_sha256']
            monitor = subprocess.Popen(['docker', 'exec', '-i', tmm, 'python3', '-u', '-c', WITNESS, program['entry']],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            witness = json.loads(monitor.stdout.readline())
            record['witnesses']['id'] = dict(initial=witness)
            assert witness['sha256'] == build['runtime']['sha256'] and witness['bytes'].startswith('9090909090')
            source = json.loads(run('docker', 'exec', tmm, 'python3', '-c',
                'import json,pathlib; print(json.dumps({"boot":pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip(),'
                '"pid_namespace":str(pathlib.Path("/proc/self/ns/pid").stat().st_ino)}))'))
            source.update(pid=witness['pid'], start=witness['stat'].split()[21], sha256=witness['sha256'])
            record['source_binding'] = source
            with (args.source_dir / 'source.json').open('x') as output:
                json.dump(source, output)
            run(*compose, 'up', '-d', '--no-deps', 'collector')
            started = True
            record['collector'] = json.loads(run('docker', 'inspect', collector, '--format',
                '{"id":{{json .Id}},"image":{{json .Image}},"host":{{json .HostConfig}},"mounts":{{json .Mounts}}}'))
            assert record['collector']['image'] == image
            ready = '''import sys,time,json
sys.path.insert(0,"/work")
from session_routing_client import page
for i in range(100):
 try: print(json.dumps(page("/collector-api/events.sock"))); break
 except (OSError,ValueError) as error:
  last=repr(error)
  if i < 3: print(json.dumps({"readiness_error":last}), flush=True)
  time.sleep(.1)
else: raise RuntimeError(("collector socket not ready",last))
'''
            record['api_initial'] = json.loads(run('docker', 'exec', fixture, 'python3', '-c', ready, timeout=30).splitlines()[-1])
            run('docker', 'exec', '-e', 'TEMPLATE_PROGRAM_DIR=' + str(Path('/work') / args.artifact_dir), fixture,
                'bash', '/work/message-id-run.sh', args.run, timeout=300)
            record['passed'] = True
        except BaseException as error:
            record.update(error=repr(error), traceback=traceback.format_exc())
        finally:
            errors = []
            if started:
                try:
                    record['collector_logs'] = run('docker', 'logs', collector)
                    run(*compose, 'stop', 'collector')
                    journal = args.source_dir / 'events.sqlite'
                    assert not journal.exists()
                    run('docker', 'cp', collector + ':/journal/events.sqlite', journal)
                    run('docker', 'cp', journal, fixture + ':/evidence/' + args.run + '/events.sqlite')
                    record['journal_sha256'] = hashlib.sha256(journal.read_bytes()).hexdigest()
                except BaseException as error:
                    errors.append('collector: ' + repr(error))
            if monitor is not None:
                try:
                    stdout, stderr = monitor.communicate('stop\n', timeout=20)
                    row = record['witnesses']['id']
                    row.update(changes=[json.loads(line) for line in stdout.splitlines()], stderr=stderr, returncode=monitor.returncode)
                    assert monitor.returncode == 0
                    final = row['changes'][-1]
                    assert final['final'] and final['bytes'] == row['initial']['bytes']
                    assert final['stat'].split()[21] == row['initial']['stat'].split()[21]
                    if record['passed']:
                        assert len([e for e in row['changes'] if e['bytes'].startswith('e8')]) == 1
                except BaseException as error:
                    errors.append('witness: ' + repr(error))
            try:
                record['after'] = state()
                assert record['after'] == record['before']
                record['files'] = json.loads(run('docker', 'exec', fixture, 'python3', '-c',
                    'import json,pathlib,sys; root=pathlib.Path("/evidence")/sys.argv[1]; '
                    'print(json.dumps({p.name:p.read_text() for p in root.iterdir() if p.is_file() and p.suffix!=".sqlite"}))', args.run))
                assert 'mode=0' in run('docker', 'exec', fixture, 'python3', '/work/ls-load.py', 'status', '11')
            except BaseException as error:
                errors.append('final: ' + repr(error))
            if errors:
                record.update(passed=False, collection_errors=errors)
            json.dump(record, receipt, indent=2)
    print(json.dumps(dict(passed=record['passed'], error=record.get('error'), collection_errors=record.get('collection_errors'))))
    raise SystemExit(0 if record['passed'] else 1)


if __name__ == '__main__':
    main()
