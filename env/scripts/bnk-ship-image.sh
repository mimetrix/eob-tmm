#!/bin/sh
# Verify a locally built TMM image, then roll it out on datkube.
#
# FOUR TRAPS THIS ENCODES, each of which cost a build or a wrong conclusion:
#
# 1. Dockerfile.runtime overrides /usr/bin/tmm to tmm.debug WHEN A DEBUG BINARY IS
#    PRESENT. So an image can contain a correctly padded tmm64.no_pgo and still run
#    something else. This checks what `tmm` actually RESOLVES to, not what exists.
# 2. Packaging RE-LINKS the binary, so addresses differ from the build tree. Get
#    them with bnk-entry-address.sh from the deb pair, never from obj_*/.
# 3. `make clean_rpms` does NOT clear docker_build/DEBS, and a stale BUILD_x86_64/
#    gives "gcc: fatal error: no input files" on an unrelated object. If a rebuild
#    behaves impossibly, clear both before believing anything.
# 4. datkube is a `kind` cluster: an image loaded on one node is NOT visible to the
#    others. It must be imported per node, and imagePullPolicy must be Never or
#    kubelet will try to pull `tmm:local` from a registry and fail.
#
# usage:  bnk-ship-image.sh [tag]        (default tmm:local)
#         steps 1-2 on the build box, 3-4 wherever kubectl targets datkube.
set -e
TAG="${1:-tmm:local}"

echo "=== 1. what does /usr/bin/tmm actually resolve to?"
docker run --rm --entrypoint sh "$TAG" -c '
  echo "  tmm -> $(readlink -f /usr/bin/tmm)"
  if [ -e /usr/bin/tmm.debug ]; then
    echo "  *** tmm.debug PRESENT --- Dockerfile.runtime points tmm at it."
    echo "      That is not the production shape and probably not what you measured."
  else
    echo "  ok  no debug binary (production shape)"
  fi' 2>/dev/null

echo "=== 2. is the binary it resolves to actually padded?"
cid=$(docker create "$TAG")
trap 'docker rm "$cid" >/dev/null 2>&1 || true' EXIT
docker cp "$cid:/usr/bin/tmm64.no_pgo" /tmp/.shipcheck >/dev/null 2>&1
python3 - <<'PY'
d = open('/tmp/.shipcheck', 'rb').read()
pad = b'\xf3\x0f\x1e\xfa' + b'\x90' * 5          # endbr64 + the 5-byte entry pad
n = d.count(pad)
print(f"  pad signatures : {n:,}")
print(f"  VM linked      : {b'ls_vm: init  build=' in d}")
print("  VERDICT        :", "READY" if n > 1000 else "*** NOT PADDED --- check Makefile.overrides")
PY

echo "=== 3. import on EVERY node (kind does not share images between nodes)"
for node in $(kubectl get nodes -o name | sed 's|node/||'); do
    printf "  %s ... " "$node"
    docker exec "$node" ctr -n k8s.io images ls -q 2>/dev/null | grep -q "$TAG" \
        && echo "already present" \
        || echo "MISSING --- docker save $TAG | docker exec -i $node ctr -n k8s.io images import -"
done

echo "=== 4. point the deployment at it and roll"
kubectl set image deploy/f5-tmm "f5-tmm=docker.io/library/$TAG"
kubectl patch deploy f5-tmm --type=json \
    -p='[{"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"Never"}]'
kubectl rollout status deploy/f5-tmm --timeout=180s 2>&1 | tail -2 | sed 's/^/  /'
kubectl get pods -l app=f5-tmm -o wide --no-headers 2>/dev/null \
    | awk '{print "  "$1"  "$2"  "$3"  restarts="$4"  node="$7}'

echo
echo "  restarts must be 0. A pod that restarts once and comes back looks healthy in"
echo "  `kubectl get pods` and is usually the VM failing at INIT_LATE --- check the logs."
