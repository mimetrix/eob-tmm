#!/usr/bin/env python3
"""Build-box-only negative admission artifacts; never arm these programs.

The original program must already have passed PREVAIL. Only attachment metadata
changes here. Dedicated signatures let the live tests distinguish cryptographic
refusal from authenticated-but-incompatible metadata. These are test artifacts.
"""
import argparse
from pathlib import Path
import struct
import subprocess
import sys

from bind_target import sections

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('directory')
ap.add_argument('--key', required=True)
a = ap.parse_args()
d = Path(a.directory)
original = (d / 'ctx96-fentry.bpf.o').read_bytes()
sh = next(s for n, s in sections(original) if n == '.ls.target')
offset = sh[4]
bid = original[offset + 8:offset + 48].decode()
for name, at, value in (
    ('wrong-build', offset + 47, b'1' if original[offset + 47] != ord('1') else b'2'),
    ('wrong-kind', offset + 56, b'\1'),
    ('wrong-address', offset + 48, struct.pack('<Q', 1)),
    ('tampered-target', offset + 48, struct.pack('<Q', 1)),
):
    blob = bytearray(original)
    blob[at:at + len(value)] = value
    obj = d / (name + '.bpf.o')
    sig = d / (name + '.bpf.sig')
    obj.write_bytes(blob)
    if name == 'tampered-target':
        sig.write_bytes((d / 'ctx96-fentry.bpf.sig').read_bytes())
    else:
        subprocess.run([sys.executable, str(Path(__file__).with_name('sign_shield.py')),
                        '--prog', str(obj), '--key', a.key, '--hook', 'http_parse_client_headers',
                        '--mode-ceiling', 'monitor', '--build-min', '0x' + bid[:8],
                        '--build-max', '0x' + bid[:8], '-o', str(sig)], check=True)
    print('NEGATIVE TEST ONLY:', obj)
