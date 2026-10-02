#!/bin/bash
# Use the MR's branch API schema (it carries profile_ai_gateway); the released
# 303.43.0 schema does not. Hash-pinned; no network fetch.
set -eu
python3 - <<'PY'
import hashlib
from pathlib import Path
path = Path('/work/mbip-apis-pb-303.43.0-rpotluri-aigw-rel-k8s-2-4-052b1eb0-18545749.tgz')
expected = 'be3b96700f25ebde4d6f41db7c88afee22756ffa6d5c6a2319222593928484ff'
actual = hashlib.sha256(path.read_bytes()).hexdigest()
if actual != expected:
    raise SystemExit(f'API schema hash mismatch: {actual}')
print(f'Pinned API schema: {actual}', flush=True)
PY
mkdir -p /package/proto /package/py_libs/mbip
tar -xf /work/mbip-apis-pb-303.43.0-rpotluri-aigw-rel-k8s-2-4-052b1eb0-18545749.tgz \
  -C /package/proto --no-same-owner --no-same-permissions
python3 -m grpc_tools.protoc -I=/package/proto/package/proto/ \
  --python_out=/package/py_libs/mbip --grpc_python_out=/package/py_libs/mbip \
  /package/proto/package/proto/grpc_webscale.proto
# grpc_webscale imports every profile; generate them all.
python3 -m grpc_tools.protoc -I=/package/proto/package/proto/ \
  --python_out=/package/py_libs/mbip /package/proto/package/proto/*.proto
exec /package/entrypoint.sh
