#!/usr/bin/env python3
"""Read-only P21 TMM build preflight; run on the build box, receipt path required."""
import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    args = parser.parse_args()
    root = Path('/home/starin/code/tmm')
    stage = Path('/home/starin/eob-tmm-staged')
    record = {'scope': 'read-only P21 TMM build integration preflight', 'time': time.time(),
              'commands': [], 'files': {}}
    # Reserve the receipt before starting; never overwrite an earlier attempt.
    with args.receipt.open('x') as target:
        try:
            for name in ('AGENTS.md', 'src/AGENTS.md', 'src/base/AGENTS.md',
                         'src/compile/AGENTS.md', 'src/compile/default_whitelist_x86_64',
                         'src/compile/debug_whitelist_x86_64'):
                path = root / name
                if path.is_file():
                    data = path.read_bytes()
                    record['files'][str(path)] = {'sha256': hashlib.sha256(data).hexdigest(),
                                                'text': data.decode()}
                    print(str(path), data.decode(), flush=True)
            for name in ('ls_config.h', 'ls_map.h', 'ls_map_glue.h', 'ls_tp_emit.c', 'ls_vm.c', 'ls_vm_load.c',
                         'shield_abi.h', 'ls_audit.c', 'ls_sig_pubkey.h'):
                for base in (root / 'src/base', stage / 'substrate', args.candidate):
                    path = base / name
                    if path.is_file():
                        data = path.read_bytes()
                        row = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
                        record['files'][str(path)] = row
                        print(path, json.dumps(row), flush=True)
            commands = [
                ['git', '-C', str(root), 'status', '--porcelain', 'src/'],
                ['git', '-C', str(root), 'rev-parse', 'HEAD'],
                ['docker', 'ps', '--format', '{{.Names}} {{.Image}} {{.Status}}'],
                ['docker', 'image', 'inspect', 'tmm:CATALOGFREE-20260924', '--format', '{{.Id}}'],
                ['ps', '-eo', 'pid,ppid,user,comm'],
                ['df', '-h', str(root)], ['free', '-m'],
            ]
            for command in commands:
                result = subprocess.run(command, text=True, capture_output=True, timeout=60,
                                        check=False)
                row = dict(argv=command, returncode=result.returncode,
                           stdout=result.stdout, stderr=result.stderr)
                record['commands'].append(row)
                print(json.dumps(row), flush=True)
                result.check_returncode()
        finally:
            json.dump(record, target, indent=2)


if __name__ == '__main__':
    main()
