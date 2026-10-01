#!/usr/bin/env python3
"""Capture pinned admission and compiled paths for JSON initialization candidates."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--boundary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    tree = Path('/home/starin/code/tmm')
    base = Path('/home/starin/eob-tmm-staged/substrate')
    package = Path('/home/starin/observability-20260925/image-context')
    binary = package / 'tmm64.no_pgo'
    debug = Path('/home/starin/observability-20260925/debug/usr/lib/debug/usr/bin/tmm64.no_pgo.debug')
    result = dict(completed=False, sources={}, commands=[], admission={})

    def run(*argv, allow_refusal=False):
        row = subprocess.run(list(map(str, argv)), capture_output=True, text=True,
                             timeout=240, check=False)
        saved = dict(argv=list(map(str, argv)), rc=row.returncode, stdout=row.stdout, stderr=row.stderr)
        result['commands'].append(saved)
        if not allow_refusal:
            row.check_returncode()
        return saved

    def source(path):
        result['sources'][str(path)] = dict(sha256=digest(path), text=path.read_text())

    with args.output.open('x') as receipt:
        try:
            assert digest(args.boundary) == 'bea20f4ae1fba8feef7a1688bcfa3996fcccae570cccfbb8339bcad62e088889'
            old = json.loads(args.boundary.read_text())
            assert old['completed']
            result['boundary_sha256'] = digest(args.boundary)
            for name, row in old['files'].items():
                if name.startswith(str(tree) + '/') or name.startswith(str(package) + '/'):
                    assert digest(Path(name)) == row['sha256'], name
                    result['sources'][name] = row
            for path in (Path(__file__), Path(__file__).with_name('JSON-INITIALIZATION.md'),
                         base / 'exit_admit.py', base / 'bind_target.py', base / 'ls_buildid.py',
                         tree / 'src/base/ls_fexit.c', tree / 'src/base/ls_fexit.h'):
                source(path)
            result['runtime'] = old['runtime']
            assert digest(binary) == result['runtime']['sha256']
            result['debug_sha256'] = digest(debug)
            result['tree_head'] = run('git', '-C', tree, 'rev-parse', 'HEAD')['stdout'].strip()
            assert result['tree_head'] == old['tree_head']
            paths = run('git', '-C', tree, 'ls-files', '*hud_orbit*')['stdout'].splitlines()
            result['orbit_paths'] = paths
            for path in paths:
                if path.endswith(('.c', '.h')):
                    source(tree / path)
            status = run('git', '-C', tree, 'status', '--porcelain',
                         'src/modules/hudfilter/json', 'src/modules/hudfilter/hudfilter.h', *paths)
            assert not status['stdout']
            for command in (('clang-18', '--version'), ('gdb', '--version'), ('objdump', '--version'),
                            ('/usr/lib/llvm-18/bin/llvm-dwarfdump', '--version')):
                run(*command)
            for file in (binary, debug):
                notes = run('readelf', '-n', file)['stdout']
                assert re.findall(r'Build ID: ([0-9a-f]+)', notes) == [result['runtime']['build_id']]
            for hook in ('hud_json_handler', 'json_filter_reset_ingress_for_reuse', 'tmm_json_value_get_string'):
                result['admission'][hook] = run('python3', base / 'exit_admit.py', debug, binary, hook, allow_refusal=True)
            run('gdb', '-nx', '-batch', debug, '-ex', 'ptype hud_json_handler',
                '-ex', 'ptype hud_orbit_handler', '-ex', 'ptype hud_orbit_handle_upper',
                '-ex', 'ptype hud_orbit_handle_lower',
                '-ex', 'p/x (unsigned long)&((struct hudnode *)0)->above',
                '-ex', 'p/x HUDEVT_FLOW_INIT')
            names = ('hud_json_handler', 'hud_json_init_scb', 'hud_json_uninit_scb',
                     'json_filter_reset_ingress_for_reuse', 'hud_orbit_handle_default',
                     'hud_orbit_handle_upper', 'hud_orbit_handle_lower', 'hud_orbit_handler',
                     'hud_orbit_handler_fastpath', 'xbuf_embed_init')
            index = (package / 'hook-index.tsv').read_text().splitlines()
            result['hooks'] = [line.split('\t') for line in index if any(
                line.split('\t')[0] == n or line.split('\t')[0].startswith(n + '.') for n in names)]
            symbols = run('nm', '-S', debug)['stdout']
            result['candidate_symbols'] = [line for line in symbols.splitlines() if any(
                line.split()[-1] == n or line.split()[-1].startswith(n + '.') for n in names)]
            for start, stop in ((0xd94100, 0xd95680), (0xd15700, 0xd15e80),
                                (0xe27900, 0xe27b00), (0xd927c0, 0xd92900)):
                run('objdump', '-d', '--start-address=' + hex(start), '--stop-address=' + hex(stop), binary)
            run('objdump', '-s', '--start-address=0x22ae328', '--stop-address=0x22ae330', binary)
            result['xbuf_binding'] = run('python3', '-c',
                'import sys; sys.path.insert(0,sys.argv[1]); from bind_target import resolve; '
                'print(resolve(sys.argv[2],sys.argv[3],"xbuf_embed_init"))',
                base, package / 'hook-index.tsv', binary, allow_refusal=True)
            result['completed'] = True
        except BaseException as error:
            result['error'] = repr(error)
            raise
        finally:
            json.dump(result, receipt, indent=2)
    print(json.dumps(dict(completed=True, admission={k: dict(rc=v['rc'], stdout=v['stdout'], stderr=v['stderr'])
        for k, v in result['admission'].items()}), indent=2))


if __name__ == '__main__':
    main()
