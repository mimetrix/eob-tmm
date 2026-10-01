#!/usr/bin/env python3
"""Build and sign the registered session/routing probes on the pinned VM."""
import argparse
import json
from pathlib import Path
import subprocess
from metadata_build import digest
from session_routing_decode import decode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--discovery', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir()
    base = Path('/home/starin/eob-tmm-staged/substrate')
    ubpf = Path('/home/starin/code/tmm/.ubpf')
    verifier = base.parent / 'ebpf-verifier/bin/prevail'
    package = Path('/home/starin/observability-20260925/image-context')
    debug = Path('/home/starin/observability-20260925/debug/usr/lib/debug/usr/bin/tmm64.no_pgo.debug')
    objcopy = '/usr/lib/llvm-18/bin/llvm-objcopy'
    record = dict(passed=False, commands=[], sources={}, programs={}, event_names={})

    def run(*argv):
        row = subprocess.run(list(map(str, argv)), capture_output=True, text=True,
                             timeout=240, check=False)
        record['commands'].append(dict(argv=list(map(str, argv)), rc=row.returncode,
                                       stdout=row.stdout, stderr=row.stderr))
        if row.returncode:
            print(row.stdout, row.stderr, flush=True)
        row.check_returncode()
        return row.stdout

    with (args.output / 'metadata-program-build.json').open('x') as output:
        try:
            discovery = json.loads(args.discovery.read_text())
            assert discovery['completed']
            record['discovery_sha256'] = digest(args.discovery)
            record['layout'] = discovery['layout']
            assert '$1 = 64\n$2 = 44\n$3 = 72\n$4 = 184\n$5 = 0\n$6 = 136\n$7 = 32' in discovery['layout']
            paths = [base / name for name in (
                'surfaces/session_routing.bpf.c', 'surfaces/session_routing_abi.h',
                'surfaces/json_method_abi.h', 'check_session_routing.c', 'check_session_routing_pair.c',
                'ls_map_glue.h', 'ls_map.h', 'ls_config.h', 'config_snapshot.bpf.h',
                'bind_target.py', 'ls_buildid.py', 'sign_shield.py')]
            paths += [Path(__file__), Path(__file__).with_name('session_routing_decode.py'),
                      Path(__file__).with_name('SESSION-ROUTING.md')]
            for path in paths:
                record['sources'][str(path)] = dict(sha256=digest(path), text=path.read_text())
            assert '18.1.3' in run('clang-18', '--version')
            assert '13.3.0' in run('gcc', '--version')
            assert run('git', '-C', ubpf, 'rev-parse', 'HEAD').strip() == 'c900ed9faf1d41358a7ea9217ccd0b64a4ee8d5d'
            assert run('git', '-C', verifier.parent.parent, 'rev-parse', 'HEAD').strip() == '06769f7b508214e63b97905d275920f7e90182fa'
            record['tool_inputs'] = {str(p): digest(p) for p in (verifier, ubpf / 'build/lib/libubpf.a', debug)}
            record['runtime'] = discovery['runtime']
            assert digest(package / 'tmm64.no_pgo') == record['runtime']['sha256']
            native = args.output / 'native'
            run('gcc', '-O2', '-Wall', '-Wextra', '-Werror', '-I' + str(ubpf / 'vm/inc'),
                '-I' + str(ubpf / 'build/vm'), base / 'check_session_routing.c',
                ubpf / 'build/lib/libubpf.a', '-lm', '-o', native)
            record['native_sha256'] = digest(native)
            for kind, label, hook, entry, slot in (
                (1, 'session', 'aimcp_decrypt_and_parse_sessionid.constprop.0', '0xbbcf40', 7),
                (2, 'route', 'hud_aimcp_add_persist.isra.0', '0xbbca80', 8)):
                obj = args.output / ('metadata-' + label + '.bpf.o')
                run('clang-18', '-target', 'bpf', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                    '-DSR_KIND=' + str(kind), '-c', base / 'surfaces/session_routing.bpf.c', '-o', obj)
                run(objcopy, '--remove-section=.BTF', '--remove-section=.BTF.ext', '--remove-section=.rel.BTF.ext', obj)
                run('python3', base / 'bind_target.py', '--prog', obj, '--binary', package / 'tmm64.no_pgo',
                    '--index', package / 'hook-index.tsv', '--debug', debug, '--objcopy', objcopy)
                section = 'fentry/' + hook
                assert run(verifier, obj, section, '--termination', '--strict', '--no-division-by-zero',
                           '--stack-size', '256').startswith('PASS:')
                text = run(native, obj, kind)
                events = [decode(bytes.fromhex(line[7:])) for line in text.splitlines() if line.startswith('RECORD ')]
                build_id = '0x' + record['runtime']['build_id'][:8]
                signature = obj.with_suffix('.sig')
                run('python3', base / 'sign_shield.py', '--key', Path.home() / '.ls-signing/shield_sk.pem',
                    '--prog', obj, '--hook', hook, '--mode-ceiling', 'monitor', '--build-min', build_id,
                    '--build-max', build_id, '-o', signature)
                record['programs'][label] = dict(slot=slot, section=section, entry=entry, pad=0,
                    object=obj.name, sha256=digest(obj), signature_sha256=digest(signature), native_events=events)
            paired = args.output / 'native-pair'
            run('gcc', '-O2', '-Wall', '-Wextra', '-Werror', '-I' + str(ubpf / 'vm/inc'),
                '-I' + str(ubpf / 'build/vm'), base / 'check_session_routing_pair.c',
                ubpf / 'build/lib/libubpf.a', '-lm', '-o', paired)
            text = run(paired, args.output / 'metadata-session.bpf.o', args.output / 'metadata-route.bpf.o')
            record['paired_events'] = [decode(bytes.fromhex(line[7:])) for line in text.splitlines() if line.startswith('RECORD ')]
            assert len(record['paired_events']) == 8
            record['passed'] = True
        except BaseException as error:
            record['error'] = repr(error)
            raise
        finally:
            json.dump(record, output, indent=2)
    print(json.dumps(dict(passed=True, records={k: len(v['native_events']) for k, v in record['programs'].items()})))


if __name__ == '__main__':
    main()
