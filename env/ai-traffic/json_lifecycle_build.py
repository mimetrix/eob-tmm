#!/usr/bin/env python3
"""Build the three bounded JSON boundary probes on the pinned toolchain."""
import argparse
import json
from pathlib import Path
import subprocess
from metadata_build import digest
from json_lifecycle_decode import decode, window


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
    record = dict(passed=False, sources={}, commands=[], programs={})

    def run(*argv):
        row = subprocess.run(list(map(str, argv)), capture_output=True, text=True, timeout=240, check=False)
        record['commands'].append(dict(argv=list(map(str, argv)), rc=row.returncode, stdout=row.stdout, stderr=row.stderr))
        if row.returncode: print(row.stdout, row.stderr, flush=True)
        row.check_returncode()
        return row.stdout

    with (args.output / 'metadata-program-build.json').open('x') as output:
        try:
            d = json.loads(args.discovery.read_text())
            assert d['completed']
            record['discovery_sha256'] = digest(args.discovery)
            for name, row in d['files'].items():
                if name.startswith('/home/starin/code/tmm/'):
                    assert digest(Path(name)) == row['sha256'], name
            layout = {t: {f['name']: f['bitpos'] for f in fields} for t, fields in d['layout']['types'].items()}
            assert all(layout['struct hudnode'][k] == v for k, v in dict(ctx_sz=352, f_active=374, f_ctx=375, f_stream=377, ctx=512).items())
            assert all(layout['struct json_scb'][k] == v for k, v in dict(json=192, payload_bytes=640, f_disabled=704).items())
            assert all(d['layout']['events'][k] == v for k, v in dict(HUDEVT_FLOW_INIT=57, HUDCTL_ABORT=1, HUDCTL_TEARDOWN=5).items())
            paths = [base / name for name in ('surfaces/json_lifecycle.bpf.c', 'surfaces/json_lifecycle_abi.h',
                'surfaces/json_method_abi.h', 'check_json_lifecycle.c', 'ls_map_glue.h', 'ls_map.h',
                'ls_config.h', 'config_snapshot.bpf.h', 'bind_target.py', 'ls_buildid.py', 'sign_shield.py')]
            paths += [Path(__file__).with_name(n) for n in ('json_lifecycle_build.py', 'json_lifecycle_decode.py', 'JSON-LIFECYCLE.md')]
            for p in paths: record['sources'][str(p)] = dict(sha256=digest(p), text=p.read_text())
            assert '18.1.3' in run('clang-18', '--version')
            assert '13.3.0' in run('gcc', '--version')
            assert run('git', '-C', ubpf, 'rev-parse', 'HEAD').strip() == 'c900ed9faf1d41358a7ea9217ccd0b64a4ee8d5d'
            assert run('git', '-C', verifier.parent.parent, 'rev-parse', 'HEAD').strip() == '06769f7b508214e63b97905d275920f7e90182fa'
            record['runtime'] = json.loads((package / 'runtime-identity.json').read_text())
            assert record['runtime'] == d['runtime']
            assert digest(package / 'tmm64.no_pgo') == record['runtime']['sha256']
            assert digest(package / 'hook-index.tsv') == d['files'][str(package / 'hook-index.tsv')]['sha256']
            record['tool_inputs'] = {str(p): digest(p) for p in (verifier, ubpf / 'build/lib/libubpf.a', debug)}
            record['event_names'] = {str(v): k for k, v in d['layout']['events'].items()}
            objects = []
            for kind, label, hook, address, pad in (
                    (1, 'handler', 'hud_json_handler', '0xd94100', 4),
                    (2, 'complete', 'json_filter_handle_json_complete', '0xd93540', 0),
                    (3, 'reset', 'json_filter_reset_ingress_for_reuse', '0xd927c0', 0)):
                obj = args.output / ('metadata-' + label + '.bpf.o'); objects.append(obj)
                section = 'fentry/' + hook
                run('clang-18', '-target', 'bpf', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                    '-DJL_KIND=' + str(kind), '-c', base / 'surfaces/json_lifecycle.bpf.c', '-o', obj)
                run(objcopy, '--remove-section=.BTF', '--remove-section=.BTF.ext', '--remove-section=.rel.BTF.ext', obj)
                run('python3', base / 'bind_target.py', '--prog', obj, '--binary', package / 'tmm64.no_pgo',
                    '--index', package / 'hook-index.tsv', '--debug', debug, '--objcopy', objcopy)
                assert run(verifier, obj, section, '--termination', '--strict', '--no-division-by-zero', '--stack-size', '256').startswith('PASS:')
                sig = obj.with_suffix('.sig'); build = '0x' + record['runtime']['build_id'][:8]
                run('python3', base / 'sign_shield.py', '--key', Path.home() / '.ls-signing/shield_sk.pem',
                    '--prog', obj, '--hook', hook, '--mode-ceiling', 'monitor', '--build-min', build, '--build-max', build, '-o', sig)
                record['programs'][label] = dict(kind=kind, slot=kind+7, section=section, entry=address, pad=pad,
                    object=obj.name, sha256=digest(obj), signature_sha256=digest(sig))
            native = args.output / 'native'
            run('gcc', '-O2', '-Wall', '-Wextra', '-Werror', '-I' + str(ubpf / 'vm/inc'),
                '-I' + str(ubpf / 'build/vm'), base / 'check_json_lifecycle.c', ubpf / 'build/lib/libubpf.a', '-lm', '-o', native)
            text = run(native, *objects)
            events = [decode(bytes.fromhex(line[7:])) for line in text.splitlines() if line.startswith('RECORD ')]
            record['native_events'] = events; record['native_sha256'] = digest(native)
            assert not window(events)['boundaries_usable']
            clean = [dict(events[4], sequence=1)]
            assert window(clean)['boundaries_usable'] and not window(clean)['lifecycle_validated']
            assert not window(clean, ['detached_both_boundaries'])['boundaries_usable']
            assert not window(clean + [dict(clean[0], sequence=2, instance=clean[0]['instance'] + 1)])['boundaries_usable']
            assert not window(clean + [dict(clean[0], sequence=2, run=124)])['boundaries_usable']
            record['consumer_checks'] = 5
            record['passed'] = True
        except BaseException as error:
            record['error'] = repr(error)
            raise
        finally: json.dump(record, output, indent=2)
    print(json.dumps(dict(passed=True, native_records=len(events))))


if __name__ == '__main__': main()
