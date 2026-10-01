#!/usr/bin/env python3
"""Recheck JSON boundary arguments, storage guards and event codes on the build box."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from message_scope_verify import verify, BINARY_SHA256


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    tree = Path('/home/starin/code/tmm')
    package = Path('/home/starin/observability-20260925/image-context')
    debug = Path('/home/starin/observability-20260925/debug/usr/lib/debug/usr/bin/tmm64.no_pgo.debug')
    record = dict(completed=False, files={}, commands=[])

    def run(*argv):
        row = subprocess.run(list(map(str, argv)), capture_output=True, text=True, timeout=120, check=False)
        record['commands'].append(dict(argv=list(map(str, argv)), rc=row.returncode, stdout=row.stdout, stderr=row.stderr))
        row.check_returncode()
        return row.stdout

    with args.output.open('x') as output:
        try:
            record['scope_check'] = verify(args.scope)
            old = json.loads(args.scope.read_text())
            for name, row in old['files'].items():
                if name.startswith(str(tree) + '/') or name.startswith(str(package) + '/'):
                    path = Path(name)
                    assert sha(path) == row['sha256'], name
                    record['files'][name] = row
            for path in (tree / 'src/modules/modules.h', Path(__file__),
                         Path(__file__).with_name('JSON-LIFECYCLE.md')):
                record['files'][str(path)] = dict(sha256=sha(path), text=path.read_text())
            assert sha(package / 'tmm64.no_pgo') == BINARY_SHA256
            record['runtime'] = old['runtime']
            record['tree_head'] = run('git', '-C', tree, 'rev-parse', 'HEAD').strip()
            assert record['tree_head'] == old['tree_head']
            assert not run('git', '-C', tree, 'status', '--porcelain',
                           'src/modules/hudfilter/json/json_filter.c',
                           'src/modules/hudfilter/hudfilter.h', 'src/modules/modules.h')
            expression = '''python import gdb,json; print("LAYOUT " + json.dumps({"types":{t:[{"name":f.name,"bitpos":f.bitpos,"bitsize":f.bitsize} for f in gdb.lookup_type(t).fields() if f.name] for t in ("struct hudnode","struct json_scb")},"events":{f.name:f.enumval for f in gdb.lookup_type("hud_msg_t").fields()}}))'''
            text = run('gdb', '-nx', '-batch', debug, '-ex', expression)
            record['layout'] = json.loads(next(line[7:] for line in text.splitlines() if line.startswith('LAYOUT ')))
            for start, stop in ((0xd94100, 0xd94200), (0xd94c20, 0xd94cf0),
                                (0xd94790, 0xd94890), (0xd927c0, 0xd928c0),
                                (0xd93540, 0xd935d0)):
                run('objdump', '-d', '--start-address=' + hex(start),
                    '--stop-address=' + hex(stop), package / 'tmm64.no_pgo')
            record['completed'] = True
        except BaseException as error:
            record['error'] = repr(error)
            raise
        finally:
            json.dump(record, output, indent=2)
    print(json.dumps(dict(completed=True, layout=record['layout']), indent=2))


if __name__ == '__main__':
    main()
