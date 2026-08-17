#!/bin/sh
# Do the cluster and the build box agree on what is running?
#
# WHY THIS EXISTS. On 2026-08-16/17 the deployed image diverged from the source
# tree twice, and it was noticed once. Everything measured in between was
# measured against code that was not the code in the repo -- including several
# hours spent concluding "maps do not work" from a binary that had no map code.
#
# Divergence is invisible from either side alone. `kubectl get pods` shows
# Running; `make` reports success; the tag can be identical while the contents
# are not, because a tag is re-pointed by every `docker build -t`.
#
# So compare the BUILD ID, which is the only thing that cannot be re-pointed.
#
#   bnk-check-deployed.sh [image-tag]     run from the DATKUBE HOST
#
# Requires ssh to the build box, since the local build's ID lives there.
set -e

TAG="${1:-tmm:demo}"
BUILD_BOX="${BUILD_BOX:-starin@10.145.42.119}"

echo "=== what the cluster is running ==="
IMG=$(kubectl get deploy f5-tmm -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null)
echo "  deployment image : ${IMG:-<none>}"
kubectl get pods -l app=f5-tmm --no-headers 2>/dev/null \
    | awk '{printf "  %-26s %s restarts=%s age=%s\n",$1,$3,$4,$5}'

# The running binary's build ID, read from inside a live pod. This is the ground
# truth -- not the tag, not the deployment spec.
POD=$(kubectl get pods -l app=f5-tmm --no-headers 2>/dev/null | grep Running | head -1 | awk '{print $1}')
RUNNING=""
if [ -n "$POD" ]; then
    RUNNING=$(kubectl exec "$POD" -c f5-tmm -- sh -c \
        'readelf -n "$(readlink -f /usr/bin/tmm)" 2>/dev/null | grep -o "Build ID: .*"' 2>/dev/null \
        | head -1 | sed 's/Build ID: //')
fi
echo "  running build id : ${RUNNING:-<unreadable>}"

echo "=== what the build box last produced ==="
LOCAL=$(ssh -o StrictHostKeyChecking=no "$BUILD_BOX" \
    'cid=$(docker create '"$TAG"' 2>/dev/null); [ -z "$cid" ] && exit 0
     R=$(docker run --rm --entrypoint sh '"$TAG"' -c "readlink -f /usr/bin/tmm" 2>/dev/null)
     docker cp "$cid:${R:-/usr/bin/tmm64.no_pgo}" /tmp/.bid >/dev/null 2>&1
     docker rm "$cid" >/dev/null 2>&1
     readelf -n /tmp/.bid 2>/dev/null | grep -o "Build ID: .*" | head -1 | sed "s/Build ID: //"
     rm -f /tmp/.bid' 2>/dev/null | tail -1)
echo "  $TAG build id : ${LOCAL:-<no such image>}"

echo "=== uncommitted TMM-tree changes not in ANY image ==="
ssh -o StrictHostKeyChecking=no "$BUILD_BOX" \
    'cd ~/code/tmm && git status --porcelain src/ 2>/dev/null | grep "^ M" | head -8' \
    2>/dev/null | sed 's/^/  /'

echo
if [ -z "$RUNNING" ] || [ -z "$LOCAL" ]; then
    echo "  VERDICT : CANNOT COMPARE --- one side unreadable. Treat as diverged."
    exit 1
elif [ "$RUNNING" = "$LOCAL" ]; then
    echo "  VERDICT : AGREE --- the cluster is running $TAG"
    exit 0
else
    cat <<'EOT'
  VERDICT : DIVERGED. The cluster is NOT running the last local build.

      Any measurement taken now describes different code than the source tree.
      That has already produced hours of wrong conclusions -- a tag is re-pointed
      by every `docker build -t`, so identical tags prove nothing.

      Reship before measuring anything.
EOT
    exit 1
fi
