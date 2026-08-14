#!/bin/sh
# Verify a built TMM image, then get it running on datkube.
#
# TWO MACHINES, TWO SUBCOMMANDS --- and conflating them is the first mistake to
# avoid. The image is built and lives in docker on the BUILD BOX. The datkube host
# has no tmm images in docker at all: datkube is a `kind` cluster, so images live
# in each node container's CONTAINERD. A script that tries to `docker run` the
# image on the datkube host finds nothing and, with `set -e`, dies without saying
# why. (That is exactly how the first version of this script failed.)
#
#   bnk-ship-image.sh verify [tag]     on the BUILD BOX  --- is this image shippable?
#   bnk-ship-image.sh deploy [tag]     on the DATKUBE HOST --- import per node, roll
#
# THREE MORE TRAPS THIS ENCODES, each of which cost a build or a wrong conclusion:
#
# * Dockerfile.runtime overrides /usr/bin/tmm to tmm.debug WHEN A DEBUG BINARY IS
#   PRESENT. An image can hold a correctly padded tmm64.no_pgo and still run
#   something else, so `verify` checks what tmm RESOLVES to, not what exists.
# * `make clean_rpms` does NOT clear docker_build/DEBS, and a stale BUILD_x86_64/
#   gives "gcc: fatal error: no input files" on an unrelated object. If a rebuild
#   behaves impossibly, clear both before believing anything.
# * kind does not share images between nodes, and imagePullPolicy must be Never or
#   kubelet tries to pull `tmm:local` from a registry and fails.
#
# Addresses for arming come from bnk-entry-address.sh, never from the build tree:
# packaging re-links the binary.
set -e

MODE="${1:-verify}"
TAG="${2:-tmm:local}"

case "$MODE" in
verify)
    docker image inspect "$TAG" >/dev/null 2>&1 || {
        echo "*** no such image here: $TAG"
        echo "    'verify' runs on the BUILD BOX, where the image was built."
        echo "    On the datkube host the image is in the kind nodes' containerd, not docker."
        exit 1
    }

    echo "=== 1. what does /usr/bin/tmm actually resolve to?"
    docker run --rm --entrypoint sh "$TAG" -c '
      echo "  tmm -> $(readlink -f /usr/bin/tmm)"
      if [ -e /usr/bin/tmm.debug ]; then
        echo "  *** FATAL FOR ARMING: tmm.debug PRESENT and tmm points at it."
        echo "      The debug build overrides CFLAGS_OPTIMIZE, which is where"
        echo "      -fpatchable-function-entry lives --- so tmm64.debug has NO pads on"
        echo "      TMM-core functions and NOTHING CAN EVER BE ARMED in it. Arming"
        echo "      fails with \"no pad\", which reads like a wrong address and is not."
        echo "      This is not a fidelity caveat. Rebuild with 'make tmm && make container'"
        echo "      (no INSTALL_DEBUG_TMM) before trying to arm anything."
      else
        echo "  ok  no debug binary (production shape)"
      fi'

    echo "=== 2. is the binary it resolves to actually padded?"
    # Check the binary tmm RESOLVES to, not a padded one that happens to be in
    # the image. An image can carry a perfectly padded tmm64.no_pgo and run
    # tmm64.debug instead --- which is exactly what tmm:0b and tmm:cve1 did.
    RESOLVED=$(docker run --rm --entrypoint sh "$TAG" -c 'readlink -f /usr/bin/tmm' 2>/dev/null)
    echo "  checking $RESOLVED (what tmm resolves to)"
    cid=$(docker create "$TAG")
    docker cp "$cid:$RESOLVED" /tmp/.shipcheck
    docker rm "$cid" >/dev/null
    python3 - <<'PY'
d = open('/tmp/.shipcheck', 'rb').read()
pad = b'\xf3\x0f\x1e\xfa' + b'\x90' * 5          # endbr64 + the 5-byte entry pad
n = d.count(pad)
print(f"  pad signatures : {n:,}")
print(f"  VM linked      : {b'ls_vm: init  build=' in d}")
print("  VERDICT        :", "READY" if n > 1000 else "*** NOT PADDED --- check Makefile.overrides")
PY
    rm -f /tmp/.shipcheck
    echo
    echo "  Next: docker save $TAG | ssh <datkube> 'cat > /tmp/$TAG.tar'"
    echo "        then  bnk-ship-image.sh deploy $TAG  on the datkube host."
    ;;

deploy)
    echo "=== 1. is the image in every kind node's containerd?"
    missing=0
    for node in $(docker ps --format '{{.Names}}' | grep datkube); do
        printf "  %-26s " "$node"
        if docker exec "$node" ctr -n k8s.io images ls -q 2>/dev/null | grep -q "$TAG"; then
            echo "present"
        else
            echo "MISSING"
            missing=$((missing + 1))
        fi
    done
    if [ "$missing" -ne 0 ]; then
        echo
        echo "*** $missing node(s) lack the image. Import into EACH, or those nodes'"
        echo "    pods will never start:"
        echo "      for n in \$(docker ps --format '{{.Names}}' | grep datkube); do"
        echo "        docker exec -i \$n ctr -n k8s.io images import - < /tmp/$TAG.tar"
        echo "      done"
        exit 1
    fi

    echo "=== 2. point the deployment at it and roll"
    kubectl set image deploy/f5-tmm "f5-tmm=docker.io/library/$TAG"
    kubectl patch deploy f5-tmm --type=json \
        -p='[{"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"Never"}]'
    kubectl rollout status deploy/f5-tmm --timeout=180s 2>&1 | tail -2 | sed 's/^/  /'
    kubectl get pods -l app=f5-tmm -o wide --no-headers 2>/dev/null \
        | awk '{print "  "$1"  "$2"  "$3"  restarts="$4"  node="$7}'
    echo
    echo "  restarts must be 0. A pod that restarts once and comes back looks healthy in"
    echo "  'kubectl get pods' and is usually the VM failing at INIT_LATE --- read the logs."
    ;;

*)
    echo "usage: $0 verify|deploy [tag]"
    exit 2
    ;;
esac
