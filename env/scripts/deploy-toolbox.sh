#!/bin/sh
# deploy-toolbox.sh --- build + ship + deploy the TMM trace toolbox pod. RUN ON THE
# BUILD BOX (has docker + the toolchain + the key + datkube reach).
#
#   bash deploy-toolbox.sh
#
# Result: a `tmmtrace-toolbox` pod on the cluster you exec into to run the DSL:
#   kubectl exec -it deploy/tmmtrace-toolbox -- tmmtrace run 'fentry/<hook> { count() }'
#
# The signing key is shipped once into a k8s Secret for the demo; in production it
# stays in a sign service the toolbox calls, and never enters the cluster.
set -e
DK="${DK:-10.145.40.193}"; KEY="${KEY:-$HOME/.ssh/id_datpush}"; SK="${SK:-$HOME/.ls-signing/shield_sk.pem}"
STAGE="${STAGE:-$HOME/eob-tmm-staged}"

echo "== 1. assemble context + build image =="
ctx=$(mktemp -d); trap 'rm -rf "$ctx"' EXIT
cp "$STAGE/ebpf-verifier/bin/prevail" "$STAGE/substrate/tmmtrace.py" \
   "$STAGE/substrate/gen_type_catalog.py" "$STAGE/substrate/sign_shield.py" "$ctx/"
cp "$HOME/lstools/signatures.tsv" "$HOME/lstools/types.json" "$HOME/lstools/hook-map.json" "$ctx/"
cp "$STAGE/env/toolbox/tmmtrace" "$ctx/tmmtrace"
cp "$STAGE/env/toolbox/Dockerfile" "$ctx/Dockerfile"
docker build -q -t tmmtrace-toolbox:latest "$ctx" >/dev/null && echo "  built tmmtrace-toolbox:latest"

echo "== 2. ship image + manifest + key to datkube =="
docker save tmmtrace-toolbox:latest > /tmp/tmmtrace-toolbox.tar
scp -i "$KEY" -o StrictHostKeyChecking=no /tmp/tmmtrace-toolbox.tar \
    "$STAGE/env/toolbox/toolbox.yaml" "$SK" starin@"$DK":/tmp/ >/dev/null
echo "  shipped ($(du -h /tmp/tmmtrace-toolbox.tar | cut -f1))"

echo "== 3. import per node + secret + deploy =="
ssh -i "$KEY" -o StrictHostKeyChecking=no starin@"$DK" '
  set -e
  for n in $(docker ps --format "{{.Names}}" | grep datkube); do
    printf "  import into %s ... " "$n"
    docker exec -i "$n" ctr -n k8s.io images import - < /tmp/tmmtrace-toolbox.tar >/dev/null && echo ok
  done
  kubectl create secret generic tmmtrace-signkey \
    --from-file=shield_sk.pem=/tmp/shield_sk.pem --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl apply -f /tmp/toolbox.yaml
  kubectl rollout status deploy/tmmtrace-toolbox --timeout=120s | tail -1
  rm -f /tmp/shield_sk.pem /tmp/tmmtrace-toolbox.tar
  kubectl get pods -l app=tmmtrace-toolbox --no-headers | awk "{print \"  pod \"\$1\" \"\$3}"
'
echo
echo "== ready. try it: =="
echo "  kubectl exec -it deploy/tmmtrace-toolbox -- tmmtrace run 'fentry/http_parse_client_headers { count() }'"
echo "  kubectl exec -it deploy/tmmtrace-toolbox -- tmmtrace list '*http*'"
