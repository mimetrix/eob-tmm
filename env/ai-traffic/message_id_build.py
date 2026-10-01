#!/usr/bin/env python3
"""Build and verify the bounded message-ID probe on the pinned build box."""
import argparse
import json
from pathlib import Path
import subprocess
from metadata_build import digest
from message_id_decode import decode
from message_id_cases import write_native


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
        row = subprocess.run(list(map(str, argv)), capture_output=True, text=True, timeout=240, check=False)
        record['commands'].append(dict(argv=list(map(str, argv)), rc=row.returncode, stdout=row.stdout, stderr=row.stderr))
        if row.returncode:
            print(row.stdout, row.stderr, flush=True)
        row.check_returncode()
        return row.stdout

    with (args.output / 'metadata-program-build.json').open('x') as output:
        try:
            paths = [base / name for name in ('surfaces/message_id.bpf.c',
                'surfaces/message_id_abi.h', 'surfaces/token_method_abi.h', 'surfaces/json_method_abi.h',
                'check_message_id.c', 'ls_map_glue.h', 'ls_map.h', 'ls_config.h', 'config_snapshot.bpf.h',
                'bind_target.py', 'ls_buildid.py', 'sign_shield.py')]
            paths += [Path(__file__).with_name(name) for name in ('message_id_build.py',
                'message_id_decode.py', 'message_id_cases.py', 'MESSAGE-ID.md')]
            for path in paths:
                record['sources'][str(path)] = dict(sha256=digest(path), text=path.read_text())
            discovery = json.loads(args.discovery.read_text())
            assert discovery['completed']
            record['discovery_sha256'] = digest(args.discovery)
            d = discovery['base']
            record['layout'] = d['layout']
            layout = ' '.join(d['layout'].split())
            for expected in ('/* 8 | 24 */ struct xbuf', '/* 40 | 8 */ jxmntok_t (*tokens)[];',
                             '/* 64 | 4 */ BOOL raw_valid;', '/* 16 | 4 */ int sibling;',
                             '/* 6 | 2 */ __arch_uint16_t doff;', '/* 8 | 8 */ __arch_uint8_t *base;',
                             '/* 24 | 8 */ struct tmm_json_cache *json;',
                             '/* 88: 5 | 4 */ BOOL f_valid_parse : 1;',
                             '/* 89: 4 | 4 */ BOOL f_ingress_msg_mode : 1;'):
                assert expected in layout, expected
            assert '18.1.3' in run('clang-18', '--version')
            assert '13.3.0' in run('gcc', '--version')
            assert run('git', '-C', ubpf, 'rev-parse', 'HEAD').strip() == 'c900ed9faf1d41358a7ea9217ccd0b64a4ee8d5d'
            assert run('git', '-C', verifier.parent.parent, 'rev-parse', 'HEAD').strip() == '06769f7b508214e63b97905d275920f7e90182fa'
            record['tool_inputs'] = {str(p): digest(p) for p in (verifier, ubpf / 'build/lib/libubpf.a', debug)}
            record['runtime'] = json.loads((package / 'runtime-identity.json').read_text())
            assert record['runtime']['sha256'] == d['binary_sha256'] == digest(package / 'tmm64.no_pgo')
            assert record['runtime']['build_id'] == d['build_id'] == 'ca69b84f4f5c9e225813b2ed3997c59f18ba2a31'
            assert digest(package / 'hook-index.tsv') == d['files'][str(package / 'hook-index.tsv')]['sha256']
            obj, native = args.output / 'metadata-id.bpf.o', args.output / 'native'
            run('clang-18', '-target', 'bpf', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                '-c', base / 'surfaces/message_id.bpf.c', '-o', obj)
            run(objcopy, '--remove-section=.BTF', '--remove-section=.BTF.ext', '--remove-section=.rel.BTF.ext', obj)
            run('python3', base / 'bind_target.py', '--prog', obj, '--binary', package / 'tmm64.no_pgo',
                '--index', package / 'hook-index.tsv', '--debug', debug, '--objcopy', objcopy)
            section = 'fentry/json_filter_handle_json_complete'
            assert run(verifier, obj, section, '--termination', '--strict', '--no-division-by-zero',
                       '--stack-size', '256').startswith('PASS:')
            run('gcc', '-O2', '-Wall', '-Wextra', '-Werror', '-I' + str(ubpf / 'vm/inc'),
                '-I' + str(ubpf / 'build/vm'), base / 'check_message_id.c',
                ubpf / 'build/lib/libubpf.a', '-lm', '-o', native)
            fixtures = args.output / 'native-cases.txt'
            write_native(fixtures)
            record['fixtures'] = dict(text=fixtures.read_text(), sha256=digest(fixtures))
            text = run(native, obj, fixtures)
            events = [decode(bytes.fromhex(line[7:])) for line in text.splitlines() if line.startswith('RECORD ')]
            record['native_sha256'] = digest(native)
            build_id = '0x' + record['runtime']['build_id'][:8]
            sig = obj.with_suffix('.sig')
            run('python3', base / 'sign_shield.py', '--key', Path.home() / '.ls-signing/shield_sk.pem',
                '--prog', obj, '--hook', 'json_filter_handle_json_complete', '--mode-ceiling', 'monitor',
                '--build-min', build_id, '--build-max', build_id, '-o', sig)
            record['programs']['id'] = dict(slot=11, section=section, entry=d['hook']['entry'], pad=0,
                object=obj.name, sha256=digest(obj), signature_sha256=digest(sig), native_events=events)
            record['passed'] = True
        except BaseException as error:
            record['error'] = repr(error)
            raise
        finally:
            json.dump(record, output, indent=2)
    print(json.dumps(dict(passed=True, native_records=len(events))))


if __name__ == '__main__':
    main()
