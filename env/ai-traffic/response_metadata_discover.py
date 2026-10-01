#!/usr/bin/env python3
"""Cache response-field qualification on the authoritative build box."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    tree = Path('/home/starin/code/tmm')
    package = Path('/home/starin/observability-20260925/image-context')
    debug = Path('/home/starin/observability-20260925/debug/usr/lib/debug/usr/bin/tmm64.no_pgo.debug')
    record = dict(completed=False, files={}, commands={})

    def run(label, *argv):
        result = subprocess.run(list(map(str, argv)), capture_output=True,
                                text=True, timeout=120, check=False)
        record['commands'][label] = dict(argv=list(map(str, argv)), rc=result.returncode,
                                        stdout=result.stdout, stderr=result.stderr)
        result.check_returncode()
        return result.stdout

    with args.output.open('x') as output:
        try:
            names = ('AGENTS.md', 'src/modules/modules.h', 'src/modules/hudmsg.h',
                     'src/modules/hudfilter/aimcp/aimcp.c', 'src/modules/hudfilter/hudfilter.h',
                     'src/modules/hudfilter/http/http.h', 'src/modules/hudfilter/http/http.c',
                     'src/modules/hudfilter/http/http_api.c', 'src/modules/hudfilter/http/http_parser.h',
                     'src/modules/hudfilter/http/http_parser.c', 'src/modules/hudfilter/http2/http2_headers.c',
                     'src/modules/hudproxy/mr/http/http_mr_proxy.c',
                     'src/modules/hudfilter/json/json_filter.c', 'src/modules/hudfilter/sse/sse.c')
            paths = [tree / name for name in names]
            paths += [package / 'hook-index.tsv', package / 'runtime-identity.json',
                      Path(__file__), Path(__file__).with_name('RESPONSE-METADATA.md')]
            for path in paths:
                data = path.read_bytes()
                record['files'][str(path)] = dict(sha256=hashlib.sha256(data).hexdigest(), text=data.decode())
            record['tree_head'] = run('tree_head', 'git', '-C', tree, 'rev-parse', 'HEAD').strip()
            assert not run('source_status', 'git', '-C', tree, 'status', '--porcelain',
                           'src/modules/hudfilter/aimcp', 'src/modules/hudfilter/http',
                           'src/modules/hudfilter/json', 'src/modules/hudfilter/sse',
                           'src/modules/hudfilter/http2/http2_headers.c')
            runtime = json.loads((package / 'runtime-identity.json').read_text())
            with (package / 'tmm64.no_pgo').open('rb') as binary:
                assert hashlib.file_digest(binary, 'sha256').hexdigest() == runtime['sha256']
            assert runtime['build_id'] == 'ca69b84f4f5c9e225813b2ed3997c59f18ba2a31'
            assert 'Build ID: ' + runtime['build_id'] in run('debug_id', 'readelf', '-n', debug)
            record['runtime'] = runtime
            record['hooks'] = [line for line in (package / 'hook-index.tsv').read_text().splitlines()
                               if line.startswith(('hud_aimcp_handler\t', 'http_send_done_message\t',
                                                   'http_status_code\t'))]
            run('handler', 'objdump', '-d', '--start-address=0xbbd300', '--stop-address=0xbbda00',
                package / 'tmm64.no_pgo')
            run('status_accessor', 'objdump', '-d', '--start-address=0xc8ba80', '--stop-address=0xc8bac0',
                package / 'tmm64.no_pgo')
            record['layout'] = run('layout', 'gdb', '-nx', '-batch', debug,
                '-ex', 'ptype /o struct http_data', '-ex', 'ptype /o struct http_parse_info',
                '-ex', 'p/d &((struct http_data *)0)->ci.http',
                '-ex', 'p/d &((struct http_data *)0)->ci.http.status_code',
                '-ex', 'python t=gdb.lookup_type("struct http_parse_info"); print([(f.name,f.bitpos,f.bitsize) for f in t.fields()])')
            names = ('HUDCTL_RESPONSE', 'HUDEVT_RESPONSE', 'HUDCTL_RESPONSE_DONE', 'HUDEVT_RESPONSE_DONE',
                     'HUDCTL_ABORT', 'HUDEVT_ABORTED', 'HUDCTL_TEARDOWN', 'HUDEVT_REQUEST',
                     'HUDCTL_REQUEST_DONE', 'HUDEVT_REQUEST_DONE')
            args_gdb = [arg for name in names for arg in ('-ex', 'p/d ' + name)]
            text = run('events', 'gdb', '-nx', '-batch', debug, *args_gdb)
            values = re.findall(r'^\$\d+ = (\d+)$', text, re.M)
            assert len(values) == len(names)
            record['event_names'] = {int(value): name for name, value in zip(names, values)}
            record['completed'] = True
        except BaseException as error:
            record['error'] = repr(error)
            raise
        finally:
            json.dump(record, output, indent=2)
    print(json.dumps({k: record[k] for k in ('completed', 'hooks', 'layout', 'event_names')}, indent=2))


if __name__ == '__main__':
    main()
