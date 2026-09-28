#!/usr/bin/env python3
"""Archive read-only evidence from the explicitly named isolated ICAP fixture.

Runs on the control machine. It archives fixture logs, never certificate/key files
or container environment dumps. An output path must not already exist.
"""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shlex
import subprocess


REMOTE = r'''
import hashlib, json, pathlib, subprocess
root = pathlib.Path('/home/starin/eob-dlp-20260924')
def run(*args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=60)
    return {'argv': args, 'returncode': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr}
records = [run('docker', 'compose', '-f', str(root / 'icap-compose.yaml'), 'ps', '-a', '--format', 'json')]
records.append(run('docker', 'exec', 'eob-dlp-20260924-fixture-1', 'python3', '-c',
    "import json,pathlib; print(json.dumps({str(p): p.read_text() for p in pathlib.Path('/evidence').rglob('*') if p.is_file() and (p.suffix in ('.json', '.log', '.xml') or p.name in ('exit-status', 'checked-exit-status'))}))"))
records.append(run('docker', 'exec', 'eob-dlp-20260924-fixture-1', 'python3', '-c',
    "import hashlib,json,pathlib; root=pathlib.Path('/opt/venv/lib/python3.10/site-packages'); names=['pru_ssa_config_server/nats.py','pru_ssa_config_server/proto_v2.py','pru_mock_nats/__init__.py']; print(json.dumps({n: {'sha256': hashlib.sha256((root/n).read_bytes()).hexdigest(), 'text': (root/n).read_text()} for n in names}))"))
for name in ('fixture', 'tmm'):
    container = 'eob-dlp-20260924-' + name + '-1'
    records += [run('docker', 'logs', container), run('docker', 'inspect', container,
        '--format', '{{json .State}} {{json .Image}} {{json .NetworkSettings.Networks}}')]
records.append(run('docker', 'exec', 'eob-dlp-20260924-tmm-1', 'python3', '-c',
    "import hashlib,json,pathlib,subprocess; out=[]; "
    "exec(\"for p in pathlib.Path('/proc').glob('[0-9]*/exe'):\\n try:\\n  target=p.resolve(); name=target.name\\n  if name in ('tmm', 'tmm64', 'tmm.debug', 'tmm.no_pgo', 'tmm64.no_pgo'):\\n   out.append({'pid':p.parent.name,'exe':str(target),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'proc_stat':(p.parent/'stat').read_text()})\\n except (OSError,RuntimeError): pass\"); print(json.dumps(out)); assert len(out) == 1, 'expected one executing TMM ELF'"))
runtime_path = pathlib.Path('/home/starin/embedded-p17-20260924/target/usr/bin/tmm64.no_pgo')
runtime_reference = {'path': str(runtime_path), 'sha256': hashlib.sha256(runtime_path.read_bytes()).hexdigest()}
records.append(run('readelf', '-n', str(runtime_path)))
if (root / 'attribution.py').is_file():
    names = ['/work/attribution.py', '/work/attribution_suite.py', '/work/icap_check_result.py', '/work/icap_suite.py']
    for tool, flags in (('black', ['--check']), ('pylint', [])):
        records.append(run('docker', 'exec', 'eob-dlp-20260924-fixture-1', 'python3', '-m', tool, *flags, *names))
    records.append(run('docker', 'exec', 'eob-dlp-20260924-fixture-1', 'bash', '-n', '/work/icap-run-suite.sh'))
    records.append(run('docker', 'exec', 'eob-dlp-20260924-fixture-1', 'python3', '-c',
        "import pathlib,sys; sys.path.insert(0,'/work'); from icap_check_result import check; "
        "exec(\"for name,expected in [('gate-01',False),('gate-02',False),('gate-03',True),('attribution-01',True)]:\\n try:\\n  check(pathlib.Path('/evidence')/name); observed=True\\n except ValueError:\\n  observed=False\\n assert observed == expected, name\\n print(name, observed)\")"))
sources = {}
for p in sorted(root.glob('*')):
    if p.is_file() and p.suffix in ('.py', '.sh', '.yaml', '.tgz', '.c'):
        data = p.read_bytes()
        sources[p.name] = {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}
        if p.suffix != '.tgz':
            sources[p.name]['text'] = data.decode()
probe = {}
for name in ('build.json', 'icap-state.bpf.o', 'icap-state.final.bpf.o', 'icap-state.final.bpf.sig'):
    p = root / 'probe-01' / name
    if p.is_file():
        data = p.read_bytes()
        probe[name] = {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}
        if p.suffix == '.json':
            probe[name]['text'] = data.decode()
print(json.dumps({'records': records, 'sources': sources, 'icap_probe': probe, 'runtime_reference': runtime_reference}, sort_keys=True))
raise SystemExit(int(any(record['returncode'] for record in records)))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='starin@10.145.37.36')
    parser.add_argument('--key', default=str(Path.home() / '.ssh/id_ed25519'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with args.output.open('x') as output:
        cmd = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=12', '-o',
               'IdentitiesOnly=yes', '-i', args.key, args.host, 'python3 -']
        p = subprocess.run(cmd, input=REMOTE, capture_output=True, text=True, timeout=240)
        record = {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'command': shlex.join(cmd), 'script': REMOTE, 'returncode': p.returncode,
                  'stderr': p.stderr, 'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        try:
            record['result'] = json.loads(p.stdout)
        except json.JSONDecodeError:
            record['stdout'] = p.stdout
        json.dump(record, output, indent=2, sort_keys=True)
        output.write('\n')
    print(f'{hashlib.sha256(args.output.read_bytes()).hexdigest()}  {args.output}')
    if p.returncode:
        raise SystemExit(p.returncode)


if __name__ == '__main__':
    main()
