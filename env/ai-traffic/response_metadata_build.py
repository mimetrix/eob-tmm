#!/usr/bin/env python3
"""Pinned build, native checks, verification and signing for response metadata."""
import argparse
import json
from pathlib import Path
import subprocess
from metadata_build import digest
from response_metadata_decode import decode


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
    record = dict(passed=False, commands=[], sources={}, programs={})

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
            assert '$1 = 28\n$2 = 36' in record['layout']
            assert "('is_trailer', 0, 1)" in record['layout']
            assert "('is_request', 1, 1)" in record['layout']
            record['event_names'] = discovery['event_names']
            assert record['event_names']['28'] == 'HUDCTL_RESPONSE'
            assert record['event_names']['29'] == 'HUDCTL_RESPONSE_DONE'
            assert record['event_names']['144'] == 'HUDEVT_RESPONSE'
            assert record['event_names']['145'] == 'HUDEVT_RESPONSE_DONE'
            paths = [base / name for name in (
                'surfaces/response_metadata.bpf.c', 'surfaces/response_metadata_abi.h',
                'surfaces/json_method_abi.h', 'check_response_metadata.c', 'ls_map_glue.h',
                'ls_map.h', 'ls_config.h', 'config_snapshot.bpf.h',
                'bind_target.py', 'ls_buildid.py', 'sign_shield.py')]
            paths += [Path(__file__), Path(__file__).with_name('response_metadata_decode.py'),
                      Path(__file__).with_name('RESPONSE-METADATA.md')]
            for path in paths:
                record['sources'][str(path)] = dict(sha256=digest(path), text=path.read_text())
            assert '18.1.3' in run('clang-18', '--version')
            assert '13.3.0' in run('gcc', '--version')
            assert run('git', '-C', ubpf, 'rev-parse', 'HEAD').strip() == 'c900ed9faf1d41358a7ea9217ccd0b64a4ee8d5d'
            assert run('git', '-C', verifier.parent.parent, 'rev-parse', 'HEAD').strip() == '06769f7b508214e63b97905d275920f7e90182fa'
            record['tool_inputs'] = {str(p): digest(p) for p in (verifier, ubpf / 'build/lib/libubpf.a', debug)}
            record['runtime'] = discovery['runtime']
            assert digest(package / 'tmm64.no_pgo') == record['runtime']['sha256']
            native, obj = args.output / 'native', args.output / 'metadata-response.bpf.o'
            run('gcc', '-O2', '-Wall', '-Wextra', '-Werror', '-I' + str(ubpf / 'vm/inc'),
                '-I' + str(ubpf / 'build/vm'), base / 'check_response_metadata.c',
                ubpf / 'build/lib/libubpf.a', '-lm', '-o', native)
            record['native_sha256'] = digest(native)
            run('clang-18', '-target', 'bpf', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                '-c', base / 'surfaces/response_metadata.bpf.c', '-o', obj)
            run(objcopy, '--remove-section=.BTF', '--remove-section=.BTF.ext', '--remove-section=.rel.BTF.ext', obj)
            run('python3', base / 'bind_target.py', '--prog', obj, '--binary', package / 'tmm64.no_pgo',
                '--index', package / 'hook-index.tsv', '--debug', debug, '--objcopy', objcopy)
            section = 'fentry/hud_aimcp_handler'
            assert run(verifier, obj, section, '--termination', '--strict', '--no-division-by-zero',
                       '--stack-size', '256').startswith('PASS:')
            text = run(native, obj)
            events = [decode(bytes.fromhex(line[7:])) for line in text.splitlines() if line.startswith('RECORD ')]
            build_id = '0x' + record['runtime']['build_id'][:8]
            signature = obj.with_suffix('.sig')
            run('python3', base / 'sign_shield.py', '--key', Path.home() / '.ls-signing/shield_sk.pem',
                '--prog', obj, '--hook', 'hud_aimcp_handler', '--mode-ceiling', 'monitor',
                '--build-min', build_id, '--build-max', build_id, '-o', signature)
            # The fixture's entry field is the kernel witness patch address.
            record['programs']['response'] = dict(slot=9, section=section, entry='0xbbd304',
                function_entry='0xbbd300', pad=4, object=obj.name, sha256=digest(obj),
                signature_sha256=digest(signature), native_events=events)
            record['passed'] = True
        except BaseException as error:
            record['error'] = repr(error)
            raise
        finally:
            json.dump(record, output, indent=2)
    print(json.dumps(dict(passed=True, native_records=len(events))))


if __name__ == '__main__':
    main()
