#!/usr/bin/env python3
"""Archive isolated lifecycle or attribution-join checks and source revisions."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

REMOTE = r'''
import hashlib,json,pathlib,subprocess
root=pathlib.Path('/home/starin/eob-config-20260925')
records=[]
def run(*argv):
    p=subprocess.run(argv,capture_output=True,text=True,timeout=60)
    records.append({'argv':argv,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
run('docker','exec','eob-config-20260925-fixture-1','python3','-c',
    "import json,pathlib; print(json.dumps({str(p):p.read_text() for p in pathlib.Path('/evidence').glob('lifecycle-*/*') if p.is_file()}))")
run('docker','exec','eob-config-20260925-fixture-1','python3','-m','black','--check',
    '/work/config_suite.py','/work/config_build_probe.py','/work/icap_suite.py')
run('docker','exec','eob-config-20260925-fixture-1','python3','-m','pylint',
    '/work/config_suite.py','/work/config_build_probe.py','/work/icap_suite.py')
run('docker','exec','eob-config-20260925-fixture-1','bash','-n','/work/icap-run-suite.sh')
run('docker','exec','eob-config-20260925-fixture-1','python3','/work/ls-load.py','status','5')
for name in ('fixture','tmm'):
    container='eob-config-20260925-'+name+'-1'
    run('docker','inspect',container,'--format','{{json .Id}} {{json .Image}} {{json .State}} {{.RestartCount}}')
run('docker','logs','eob-config-20260925-tmm-1')
sources={}
for p in root.iterdir():
    if p.is_file() and p.suffix in ('.py','.sh','.yaml','.env','.o','.sig'):
        sources[p.name]={'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
        if p.suffix in ('.py','.sh'):
            sources[p.name]['text']=p.read_text()
print(json.dumps({'records':records,'sources':sources}))
raise SystemExit(int(any(row['returncode'] for row in records)))
'''

JOIN_REMOTE = r'''
import hashlib,json,pathlib,subprocess
root=pathlib.Path('/home/starin/eob-config-20260925')
fixture='eob-config-20260925-fixture-1'
records=[]
def run(*argv):
    p=subprocess.run(argv,capture_output=True,text=True,timeout=60)
    records.append({'argv':argv,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
run('docker','exec',fixture,'python3','-c',
    "import json,pathlib; print(json.dumps({str(p):p.read_text() for p in pathlib.Path('/evidence').glob('attribution-join-*.json')}))")
run('docker','inspect',fixture,'--format','{{json .Id}} {{json .Image}} {{json .State}}')
names=['attribution.py','attribution_join.py','check_attribution_join.py']
for tool,flags in [('black',['--check']),('pylint',[])]:
    run('docker','exec',fixture,'python3','-m',tool,*flags,*['/work/'+n for n in names])
sources={n:{'sha256':hashlib.sha256((root/n).read_bytes()).hexdigest(),
            'text':(root/n).read_text()} for n in names}
print(json.dumps({'records':records,'sources':sources,
                  'scope':'join consumer checks, synthetic observations; not a live TMM join'}))
raise SystemExit(int(any(row['returncode'] for row in records)))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--join', action='store_true', help='collect join-consumer checks instead')
    args = parser.parse_args()
    script = JOIN_REMOTE if args.join else REMOTE
    with args.output.open('x') as output:
        command = ['ssh', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-i',
                   str(Path.home() / '.ssh/id_ed25519'), 'starin@10.145.37.36', 'python3 -']
        result = subprocess.run(command, input=script, capture_output=True,
                                text=True, timeout=180, check=False)
        record = {'script': script, 'returncode': result.returncode,
                  'stderr': result.stderr, 'result': json.loads(result.stdout)}
        json.dump(record, output, indent=2)
    print(hashlib.sha256(args.output.read_bytes()).hexdigest(), args.output)
    result.check_returncode()


if __name__ == '__main__':
    main()
