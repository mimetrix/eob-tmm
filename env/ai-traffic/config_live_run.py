#!/usr/bin/env python3
"""Run one isolated SSA lifecycle attempt with kernel memory/ELF witnesses.

Run on the build box after packaging and signing. The fixture has sole ownership
of its output ring. Never collects container environments or key/cert files.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


WITNESS = r'''
import hashlib,json,os,pathlib,select,sys,time
matches=[]
for path in pathlib.Path('/proc').glob('[0-9]*/exe'):
    try:
        if path.resolve().name in ('tmm','tmm64','tmm.no_pgo','tmm64.no_pgo'):
            matches.append(path)
    except OSError:
        pass
assert len(matches)==1, matches
exe=matches[0]
fd=os.open(str(exe.parent/'mem'),os.O_RDONLY)
address=int(sys.argv[1],16)
def sample():
    return os.pread(fd,16,address).hex()
first=sample()
identity={'pid':exe.parent.name,'sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
          'stat':(exe.parent/'stat').read_text(),'entry':address,'bytes':first}
print(json.dumps(identity),flush=True)
previous=first
while not select.select([sys.stdin],[],[],0.02)[0]:
    current=sample()
    if current!=previous:
        print(json.dumps({'time_ns':time.time_ns(),'bytes':current}),flush=True)
        previous=current
print(json.dumps({'final':True,'bytes':sample(),
                  'stat':(exe.parent/'stat').read_text()}),flush=True)
os.close(fd)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--suite', choices=('configuration', 'tutorial', 'request-scope'), default='configuration')
    parser.add_argument('--project', default='eob-config-20260925')
    parser.add_argument('--artifact-dir', type=Path, default=Path('.'))
    args = parser.parse_args()
    assert args.run.replace('-', '').replace('_', '').isalnum()
    root = Path('/home/starin/eob-config-20260925')
    assert args.project.replace('-', '').isalnum()
    assert not args.artifact_dir.is_absolute() and '..' not in args.artifact_dir.parts
    fixture = args.project + '-fixture-1'
    tmm = args.project + '-tmm-1'
    record = {'passed': False, 'commands': [], 'started': time.time(),
               'scope': 'isolated ' + args.suite + ' lifecycle; not a performance test',
              'witness_script': WITNESS}
    monitor = None

    def run(*command, timeout=60):
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=timeout, check=False)
        row = {'command': command, 'returncode': result.returncode,
               'stdout': result.stdout, 'stderr': result.stderr}
        record['commands'].append(row)
        return result

    def state():
        result = run('docker', 'inspect', tmm, '--format',
                     '{{json .Id}} {{json .Image}} {{json .State}} {{.RestartCount}}')
        result.check_returncode()
        return result.stdout

    with args.output.open('x') as receipt:
        try:
            record['sources'] = {
                p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in root.iterdir()
                if p.is_file() and p.suffix in ('.py', '.sh', '.yaml', '.env', '.o', '.sig')
            }
            build_name = {'tutorial': 'template', 'request-scope': 'scope'}.get(args.suite, 'config')
            build = json.loads((root / args.artifact_dir / (build_name + '-program-build.json')).read_text())
            assert build['passed']
            record['program_build'] = build
            if args.suite == 'tutorial':
                precursor = json.loads((root / args.artifact_dir / 'config-program-build.json').read_text())
                assert precursor['passed'] and precursor['map_reuse']
                assert precursor['runtime'] == build['runtime']
                record['precursor_build'] = precursor
            record['before'] = state()
            # The signed binding's emitted address is checked by bind_target against
            # the packaged ELF. Avoid a separately hard-coded target address here.
            if 'entry' in build:
                address = build['entry']
            else:
                binding = next(row['stdout'] for row in build['commands']
                               if any(value.endswith('/bind_target.py') for value in row['command']))
                address = binding.split(' -> ')[1].split()[0]
            monitor = subprocess.Popen(
                ['docker', 'exec', '-i', tmm, 'python3', '-u', '-c', WITNESS, address],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            initial = monitor.stdout.readline()
            record['witness_initial'] = json.loads(initial)
            assert record['witness_initial']['sha256'] == build['runtime']['sha256']
            assert record['witness_initial']['bytes'].startswith('f30f1efa9090909090')
            outcome = run('docker', 'exec', '-e', 'TEMPLATE_PROGRAM_DIR=' + str(Path('/work') / args.artifact_dir),
                          fixture, 'bash', '/work/icap-run-suite.sh',
                          args.run, args.suite, timeout=300)
            print(outcome.stdout, outcome.stderr, flush=True)
            outcome.check_returncode()
            record['passed'] = True
        except Exception as error:
            record['error'] = repr(error)
        finally:
            try:
                if monitor is not None:
                    stdout, stderr = monitor.communicate('stop\n', timeout=20)
                    record['witness_changes'] = [json.loads(line) for line in stdout.splitlines()]
                    record['witness_stderr'] = stderr
                    record['witness_exit'] = monitor.returncode
                    assert monitor.returncode == 0, stderr
                    changes = record['witness_changes']
                    assert changes[-1]['final'] is True
                    assert changes[-1]['bytes'] == record['witness_initial']['bytes']
                    # Kernel starttime stays stable; normal scheduling fields do not.
                    assert changes[-1]['stat'].split()[21] == record['witness_initial']['stat'].split()[21]
                record['after'] = state()
                files = run('docker', 'exec', fixture, 'python3', '-c',
                            'import json,pathlib,sys; root=pathlib.Path("/evidence")/sys.argv[1]; '
                            'print(json.dumps({p.name:p.read_text() for p in root.iterdir() if p.is_file()}))',
                            args.run)
                files.check_returncode()
                record['files'] = json.loads(files.stdout)
                assert record['before'] == record['after']
                if record['passed']:
                    assert any(row['bytes'].startswith('f30f1efae8') for row in changes), 'missing call rel32 witness'
                    if args.suite == 'tutorial':
                        assert len([row for row in changes if row['bytes'].startswith('f30f1efae8')]) == 3
            except Exception as error:
                record['passed'] = False
                record['collection_error'] = repr(error)
            record['finished'] = time.time()
            json.dump(record, receipt, indent=2)
    print(json.dumps({'passed': record['passed'], 'output': str(args.output)}))
    raise SystemExit(0 if record['passed'] else 1)


if __name__ == '__main__':
    main()
