#!/bin/bash
# Reuse the exact API schema already cached by the authoritative TMM build.
# The upstream image's normal entrypoint downloads it with authentication.
set -eu

python3 - <<'PY'
import hashlib
from pathlib import Path
path = Path('/work/mbip-apis-pb-303.43.0.tgz')
expected = '702364ce971c6353e7d15532a6be576aae56e5d85bc48f1e1099e5af3d7afe99'
actual = hashlib.sha256(path.read_bytes()).hexdigest()
if actual != expected:
    raise SystemExit(f'API schema hash mismatch: {actual}')
print(f'Pinned API schema: {actual}', flush=True)
PY

mkdir -p /package/proto /package/py_libs/mbip
tar -xf /work/mbip-apis-pb-303.43.0.tgz -C /package/proto \
  --no-same-owner --no-same-permissions
python3 -m grpc_tools.protoc -I=/package/proto/package/proto/ \
  --python_out=/package/py_libs/mbip --grpc_python_out=/package/py_libs/mbip \
  /package/proto/package/proto/grpc_webscale.proto
exec /package/entrypoint.sh
