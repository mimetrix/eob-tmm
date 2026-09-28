#!/bin/sh
# Image-build gate. Full layer inspection is additionally required by bake/ship;
# an absent final file does not prove it was absent from an earlier image layer.
set -eu
test -x /usr/bin/ls_drain
test -x /usr/bin/ls-load.py
python3 - <<'PY'
import hashlib, json, os, sys
sys.path.insert(0, '/usr/share/ls')
from ls_buildid import build_id
path = os.path.realpath('/usr/bin/tmm')
if path != '/usr/bin/tmm64.no_pgo':
    sys.exit('unexpected executing binary: ' + path)
receipt = json.load(open('/usr/share/ls/runtime-identity.json'))
blob = open(path, 'rb').read()
bid = build_id(path)
if bid != receipt['build_id'] or hashlib.sha256(blob).hexdigest() != receipt['sha256']:
    sys.exit('runtime identity mismatch against packaged binary')
for name in ('hook-index.tsv', 'signatures.tsv', 'hook-map.json', 'types.json', 'tmm.btf'):
    if os.path.lexists('/usr/share/ls/' + name):
        sys.exit('deployed catalog forbidden: ' + name)
if b'ls_vm: LOAD REFUSED --- signed target/build/mode contract' not in blob:
    sys.exit('runtime lacks authenticated attachment contract')
if blob.count(b'\xf3\x0f\x1e\xfa' + b'\x90' * 5) < 1000:
    sys.exit('runtime does not carry the expected entry pads')
print('ls-tools: runtime identity matches, build ' + bid)
print('ls-tools: authenticated per-program targets; no bulk catalogs in /usr/share/ls')
PY
