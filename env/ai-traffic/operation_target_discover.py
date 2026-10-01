#!/usr/bin/env python3
"""Requalify the existing token-cache path and retain the target contract."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    record = dict(completed=False, files={}, commands=[])
    with args.output.open('x') as output:
        try:
            # Keep the reused discovery's output immutable, as a separate receipt.
            base = args.output.with_name(args.output.stem + '-base.json')
            command = ['python3', str(root / 'token_method_discover.py'), '--output', str(base)]
            row = subprocess.run(command, capture_output=True, text=True, timeout=240, check=False)
            record['commands'].append(dict(argv=command, rc=row.returncode, stdout=row.stdout, stderr=row.stderr))
            row.check_returncode()
            record['base'] = json.loads(base.read_text())
            record['base_sha256'] = hashlib.sha256(base.read_bytes()).hexdigest()
            for name in ('operation_target_discover.py', 'token_method_discover.py', 'OPERATION-TARGET.md'):
                data = (root / name).read_bytes()
                record['files'][name] = dict(text=data.decode(), sha256=hashlib.sha256(data).hexdigest())
            record['completed'] = record['base']['completed']
        except BaseException as error:
            record['error'] = repr(error)
            raise
        finally:
            json.dump(record, output, indent=2)
    print(json.dumps(dict(completed=record['completed'], hook=record['base']['hook'])))


if __name__ == '__main__':
    main()
