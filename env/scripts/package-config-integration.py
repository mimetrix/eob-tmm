#!/usr/bin/env python3
"""Run the existing packaging/bake gates for a separate P21 test image; no rollout."""
import argparse
import json
import os
import subprocess
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--image', required=True)
    args = parser.parse_args()
    root = Path('/home/starin/eob-tmm-staged')
    record = {'scope': 'package and catalog-free image checks; no deployment',
              'started': time.time(), 'commands': [], 'passed': False}
    with (args.out / 'package-result.json').open('x') as receipt:
        try:
            assert json.loads((args.out / 'build-result.json').read_text())['passed'] is True
            env = dict(os.environ, CTX=str(args.out / 'image-context'), REPO=str(root))
            commands = [
                ['sh', str(root / 'env/scripts/bnk-package.sh')],
                ['sh', str(root / 'env/scripts/bnk-bake-tools.sh'), 'tmm:local', args.image],
            ]
            for index, command in enumerate(commands):
                row = {'argv': command, 'started': time.time()}
                record['commands'].append(row)
                log = args.out / ('package-step-%d.log' % index)
                with log.open('xb') as stream:
                    result = subprocess.run(command, env=env, stdout=stream,
                                            stderr=subprocess.STDOUT, timeout=7200, check=False)
                row.update(returncode=result.returncode, finished=time.time(), log=str(log))
                result.check_returncode()
            record['image'] = subprocess.check_output(
                ['docker', 'image', 'inspect', args.image, '--format', '{{.Id}}'], text=True).strip()
            record['runtime'] = json.loads((args.out / 'image-context/runtime-identity.json').read_text())
            record['passed'] = True
        except Exception as error:
            record['error'] = str(error)
            raise
        finally:
            record['finished'] = time.time()
            json.dump(record, receipt, indent=2)


if __name__ == '__main__':
    main()
