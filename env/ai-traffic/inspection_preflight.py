#!/usr/bin/env python3
"""Read-only, build-box/cluster inventory for the proposed delayed-DLP experiment.

This collects source and configuration evidence; it does not configure inspection,
load a program, consume a ring, or claim that a candidate hook covers live traffic.
Use a new output path on each invocation. SSH identities remain on the local host.
"""

import argparse
import concurrent.futures
import datetime
import hashlib
import json
from pathlib import Path
import shlex
import subprocess


BUILD_SCRIPT = r'''
import hashlib, json, pathlib, re, subprocess
root = pathlib.Path('/home/starin/code/tmm')
def git(*args):
    p = subprocess.run(['git', '-C', str(root), *args], capture_output=True, text=True)
    return {'argv': list(args), 'returncode': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr}
specs = {
    'src/modules/hudfilter/inference/inference.h': [(145, 175)],
    'src/modules/hudfilter/inference/inference.c': [(1517, 1558)],
    'src/modules/hudfilter/ext_proc_cs/ext_proc_cs.c': [(959, 990)],
    'src/modules/hudfilter/adapt/adapt_internal.h': [(35, 200)],
    'src/modules/hudfilter/adapt/adapt_tcl.c': [(48, 136), (432, 451)],
    'src/modules/hudfilter/adapt/adapt.c': [(14, 48), (790, 840), (1658, 1705),
        (1780, 1836), (3340, 3485), (3538, 3695)],
    'test/ssa_functional/sslo_tao/tests/icap_service_test.py': [(35, 126), (148, 159)],
    'test/ssa_functional/sslo_tao/py_libs/create_object.py': [(160, 205), (245, 295)],
    'test/ssa_functional/sslo_tao/py_libs/sslo_common.py': [(17, 21), (277, 289), (476, 520)],
    'test/ssa_functional/sslo_tao/sslo_tao.yaml': [(95, 128)],
}
files = {}
for name, ranges in specs.items():
    data = (root / name).read_bytes()
    lines = data.decode().splitlines()
    files[name] = {'sha256': hashlib.sha256(data).hexdigest(),
        'excerpts': [{'first_line': a, 'last_line': min(b, len(lines)),
                      'text': '\n'.join(lines[a-1:b])} for a, b in ranges]}
catalogs = {}
for name in ('hook-index.tsv', 'signatures.tsv'):
    path = pathlib.Path('/home/starin/lstools') / name
    if not path.exists():
        catalogs[name] = {'missing': True}
        continue
    data = path.read_bytes()
    lines = data.decode().splitlines()
    catalogs[name] = {'sha256': hashlib.sha256(data).hexdigest(),
        'headers': lines[:3], 'candidate_rows': [s for s in lines if re.search(
            r'\b(adapt_(handle_result|handle_result_tcl_done|process_error|set_state|timeout_callback|ivs_forward_data_from_ivs|send_preview_data_to_proxy_if_bypassing)|ext_proc_\w+)\b', s)]}
queries = [
    git('rev-parse', 'HEAD'),
    git('status', '--porcelain', '--', *specs, 'src/compile/filelist'),
    git('ls-files', 'src/modules/hudfilter/inference/*', 'src/modules/hudfilter/ext_proc_cs/*'),
    git('grep', '-n', '-E', 'hudfilter/(adapt|icap|inference|ext_proc_cs)', '--', 'src/compile/filelist'),
    git('grep', '-n', '-E', 'profile_responseadapt|profile_requestadapt|profile_icap|ext_proc', '--',
        'src/pbuf/declarative/decl_atomic_config.c', 'src/pbuf/declarative/handlers/decl_profile.c',
        'src/pbuf/declarative/handlers/decl_tmos_handlers.c'),
]
print(json.dumps({'queries': queries, 'files': files, 'catalogs': catalogs}, sort_keys=True))
'''


CLUSTER_SCRIPT = r"""
import json, re, subprocess
pod = POD_NAME
base = ['kubectl', '--context=kind-vs']
def get(*args):
    p = subprocess.run([*base, *args], capture_output=True, text=True, timeout=90)
    if p.returncode:
        raise RuntimeError(f'{args}: {p.stderr}')
    return json.loads(p.stdout)
def identity():
    p = get('-n', 'default', 'get', 'pod', pod, '-o', 'json')
    return {'name': p['metadata']['name'], 'uid': p['metadata']['uid'],
        'node': p['spec']['nodeName'], 'phase': p['status']['phase'],
        'containers': p['status'].get('containerStatuses', [])}
before = identity()
crds = get('get', 'crd', '-o', 'json')
inventory, selected, hits = [], {}, []
pattern = re.compile(r'icap|adaptation|response.?adapt|request.?adapt|ext.?proc|external.?process|guardrail|inference', re.I)
def walk(value, path):
    if isinstance(value, dict):
        for k, v in value.items():
            if pattern.search(k) or (isinstance(v, str) and pattern.search(v)):
                hits.append({'path': path + '/' + k, 'value': v})
            walk(v, path + '/' + k)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            walk(v, path + '/' + str(i))
for c in crds['items']:
    name = c['metadata']['name']
    inventory.append({'name': name, 'kind': c['spec']['names']['kind']})
    for v in c['spec']['versions']:
        if not v.get('served'):
            continue
        schema = v.get('schema', {}).get('openAPIV3Schema', {})
        walk(schema, name + '/' + v['name'])
        if name in ('f5-virtualservers.k8s.f5net.com', 'f5-big-http-settings.k8s.f5net.com',
                    'f5-big-svc-policies.k8s.f5net.com'):
            selected[name + '/' + v['name']] = schema
runtime_script = '''
import hashlib, json, os, pathlib
pid = 24
env = pathlib.Path(f'/proc/{pid}/environ').read_bytes().split(b'\\0')
ring = pathlib.Path('/dev/shm/ls_tp_ring')
st = ring.stat() if ring.exists() else None
consumers = []
for p in pathlib.Path('/proc').iterdir():
    if p.name.isdigit():
        try:
            argv = (p / 'cmdline').read_bytes().split(b'\\0')
            if argv and pathlib.Path(os.fsdecode(argv[0])).name == 'ls_drain':
                consumers.append({'pid': p.name, 'argv': [os.fsdecode(v) for v in argv if v]})
        except (OSError, ValueError):
            pass
print(json.dumps({'pid': pid, 'runtime_sha256': hashlib.sha256(pathlib.Path(f'/proc/{pid}/exe').read_bytes()).hexdigest(),
    'environment': [v.decode() for v in env if v.startswith((b'LS_TP', b'LS_VM', b'LS_SHIELD'))],
    'ring': {'exists': st is not None, 'size': st.st_size if st else None, 'inode': st.st_ino if st else None},
    'drainers_in_container_pid_namespace': consumers}))
'''
runtime = get('-n', 'default', 'exec', pod, '-c', 'f5-tmm', '--', 'python3', '-c', runtime_script)
listener = get('-n', 'default', 'get', 'f5-virtualservers', 'ai-traffic', '-o', 'json')
print(json.dumps({'identity_before': before, 'identity_after': identity(),
    'runtime': runtime, 'crd_inventory': inventory, 'selected_schemas': selected,
    'inspection_schema_hits': hits, 'baseline_listener': listener}, sort_keys=True))
"""


def collect(host, key, script):
    command = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=12',
               '-o', 'IdentitiesOnly=yes', '-i', str(key), host, 'python3 -']
    result = subprocess.run(command, input=script, text=True, capture_output=True, timeout=240)
    receipt = {'host': host, 'command': shlex.join(command), 'script': script,
               'returncode': result.returncode, 'stderr': result.stderr}
    try:
        receipt['result'] = json.loads(result.stdout)
    except json.JSONDecodeError:
        receipt['stdout'] = result.stdout
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-host', default='starin@10.145.37.36')
    parser.add_argument('--cluster-host', default='starin@10.145.40.193')
    parser.add_argument('--key', type=Path, default=Path.home() / '.ssh/id_ed25519')
    parser.add_argument('--pod', default='f5-tmm-7597dfff8b-28s9z')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    # Reserve exclusively before remote work, preserving old receipts.
    with args.output.open('x') as output:
        started = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = {
                'build': pool.submit(collect, args.build_host, args.key, BUILD_SCRIPT),
                'cluster': pool.submit(collect, args.cluster_host, args.key,
                    CLUSTER_SCRIPT.replace('POD_NAME', repr(args.pod), 1)),
            }
            receipts = {}
            for name, future in futures.items():
                try:
                    receipts[name] = future.result()
                except Exception as exc:
                    receipts[name] = {'error': str(exc)}
        record = {'scope': 'read-only source/configuration inventory; no live inspection result',
                  'started_utc': started, 'finished_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), **receipts}
        json.dump(record, output, indent=2, sort_keys=True)
        output.write('\n')
    print(f'{hashlib.sha256(args.output.read_bytes()).hexdigest()}  {args.output}')
    if any(r.get('returncode') != 0 or 'result' not in r for r in receipts.values()):
        raise SystemExit('Incomplete inventory: inspect the preserved receipt.')


if __name__ == '__main__':
    main()
