#!/usr/bin/env python3
"""Build P21 through the TMM toolchain and record artifact-level checks; no deployment."""
import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True, help='existing, unique run directory')
    args = parser.parse_args()
    tree = Path('/home/starin/code/tmm')
    record = {'scope': 'TMM toolchain build and artifact checks only', 'started': time.time(),
              'passed': False, 'sources': {}}
    with (args.out / 'build-result.json').open('x') as receipt:
        try:
            for name in ('ls_config.h', 'ls_map.h', 'ls_map_glue.h', 'ls_tp_emit.c', 'ls_vm.c', 'ls_vm_load.c',
                         'shield_abi.h', 'ls_audit.c', 'ls_sig_pubkey.h'):
                path = tree / 'src/base' / name
                record['sources'][name] = sha(path)
                if name != 'ls_sig_pubkey.h':
                    assert sha(path) == sha(Path('/home/starin/eob-tmm-staged/substrate') / name)
            for name in ('default_whitelist_x86_64', 'debug_whitelist_x86_64'):
                path = tree / 'src/compile' / name
                assert path.read_text().splitlines().count('g_ls_config') == 1
                assert path.read_text().splitlines().count('g_ls_map_registry') == 1
                record['sources'][name] = sha(path)
            command = ['script', '-qec', 'make tmm', str(args.out / 'build.log')]
            record['command'] = command
            with (args.out / 'build-console.log').open('xb') as console:
                result = subprocess.run(command, cwd=tree, stdout=console,
                                        stderr=subprocess.STDOUT, timeout=7200, check=False)
            record['returncode'] = result.returncode
            result.check_returncode()
            binary = tree / 'src/compile/obj_x86_64.no_pgo/tmm.no_pgo'
            stat = binary.stat()
            assert stat.st_mtime >= record['started'], 'linked artifact is stale'
            symbols = subprocess.check_output(['nm', str(binary)], text=True)
            config_symbols = [line for line in symbols.splitlines() if 'g_ls_config' in line]
            assert any(line.endswith(' g_ls_config') for line in config_symbols)
            assert any(line.endswith(' g_ls_config_view') for line in config_symbols)
            assert any(line.endswith(' g_ls_map_registry') for line in symbols.splitlines())
            assert b'config revision conflict' in binary.read_bytes()
            record['artifact'] = dict(path=str(binary), sha256=sha(binary), mtime=stat.st_mtime,
                                      bytes=stat.st_size, config_symbols=config_symbols,
                                      elf_notes=subprocess.check_output(['readelf', '-n', str(binary)],
                                                                        text=True))
            assert sha(tree / 'src/base/ls_sig_pubkey.h') == record['sources']['ls_sig_pubkey.h']
            record['passed'] = True
        except Exception as error:
            record['error'] = str(error)
            raise
        finally:
            record['finished'] = time.time()
            json.dump(record, receipt, indent=2)


if __name__ == '__main__':
    main()
