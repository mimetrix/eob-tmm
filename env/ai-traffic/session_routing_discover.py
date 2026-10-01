#!/usr/bin/env python3
"""Record session/routing source and binary qualification on the pinned VM."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    tree = Path('/home/starin/code/tmm')
    package = Path('/home/starin/observability-20260925/image-context')
    debug = Path('/home/starin/observability-20260925/debug/usr/lib/debug/usr/bin/tmm64.no_pgo.debug')
    record = dict(completed=False, files={}, commands=[])

    def run(*argv):
        result = subprocess.run(list(map(str, argv)), capture_output=True,
                                text=True, timeout=120, check=False)
        record['commands'].append(dict(argv=list(map(str, argv)), rc=result.returncode,
                                       stdout=result.stdout, stderr=result.stderr))
        result.check_returncode()
        return result.stdout

    with args.output.open('x') as output:
        try:
            paths = [tree / name for name in (
                'AGENTS.md', 'src/modules/hudfilter/aimcp/aimcp.c',
                'src/modules/hudfilter/aimcp/aimcp.h',
                'src/modules/hudproxy/mr/mr_api.h', 'src/sys/xbuf.h',
                'src/modules/hudfilter/http/http_api.h',
                'src/modules/hudfilter/hudfilter.h', 'src/base/flow_table.h',
                'src/base/pool.h')]
            paths += [package / 'hook-index.tsv', package / 'runtime-identity.json',
                      Path(__file__), Path(__file__).with_name('SESSION-ROUTING.md')]
            for path in paths:
                data = path.read_bytes()
                record['files'][str(path)] = dict(sha256=hashlib.sha256(data).hexdigest(), text=data.decode())
            record['tree_head'] = run('git', '-C', tree, 'rev-parse', 'HEAD').strip()
            assert not run('git', '-C', tree, 'status', '--porcelain', 'src/modules/hudfilter/aimcp')
            runtime = json.loads((package / 'runtime-identity.json').read_text())
            with (package / 'tmm64.no_pgo').open('rb') as binary:
                assert hashlib.file_digest(binary, 'sha256').hexdigest() == runtime['sha256']
            assert runtime['build_id'] == 'ca69b84f4f5c9e225813b2ed3997c59f18ba2a31'
            assert 'Build ID: ' + runtime['build_id'] in run('readelf', '-n', debug)
            record['runtime'] = runtime
            record['hooks'] = [line for line in (package / 'hook-index.tsv').read_text().splitlines()
                               if any(line.startswith(name + '\t') or line.startswith(name + '.') for name in
                                      ('hud_aimcp_handler', 'aimcp_decrypt_and_parse_sessionid',
                                       'aimcp_parse_augmented_sessionid', 'hud_aimcp_add_persist', 'http_header_value'))]
            run('objdump', '-d', '--start-address=0xbbca80', '--stop-address=0xbbdc00', package / 'tmm64.no_pgo')
            record['layout'] = run('gdb', '-nx', '-batch', debug,
                '-ex', 'ptype /o struct aimcp_scb', '-ex', 'ptype /o struct aimcp_sessionid_parts',
                '-ex', 'ptype /o struct mr_refstring', '-ex', 'ptype /o ip_tuple_t',
                '-ex', 'ptype /o struct hudnode', '-ex', 'ptype /o xcursor_t',
                '-ex', 'ptype /o struct http_header_cache_info',
                '-ex', 'p/d &((struct hudnode *)0)->ctx',
                '-ex', 'p/d &((struct hudnode *)0)->ctx_sz',
                '-ex', 'p/d &((struct connflow *)0)->peer',
                '-ex', 'p/d &((struct connflow *)0)->pmbr',
                '-ex', 'p/d &((struct poolmbr *)0)->pool',
                '-ex', 'p/d &((struct poolmbr *)0)->tuple',
                '-ex', 'p/d &((struct pool *)0)->name')
            record['completed'] = True
        except BaseException as error:
            record['error'] = repr(error)
            raise
        finally:
            json.dump(record, output, indent=2)
    print(json.dumps(dict(completed=True, hooks=record['hooks'], layout=record['layout']), indent=2))


if __name__ == '__main__':
    main()
