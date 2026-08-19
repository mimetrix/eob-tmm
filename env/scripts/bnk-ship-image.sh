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
#   bnk-ship-image.sh verify [tag] [token]  on the BUILD BOX  --- shippable, and does
#                                           it actually contain your change?
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
    # TEST WHAT tmm RESOLVES TO, not whether a debug binary exists. The earlier
    # version of this check called mere PRESENCE fatal, which is wrong twice over: an
    # image can legitimately carry tmm64.debug for gdb while running the padded binary
    # (Dockerfile.ls-tools repoints the symlink and asserts it), and the message
    # asserted "tmm points at it" without having checked. A guard that cries wolf on a
    # correct image gets ignored, which is worse than not having it.
    docker run --rm --entrypoint sh "$TAG" -c '
      R=$(readlink -f /usr/bin/tmm)
      echo "  tmm -> $R"
      case "$R" in
      *debug*)
        echo "  *** FATAL FOR ARMING: tmm RESOLVES to a debug binary."
        echo "      The debug build overrides CFLAGS_OPTIMIZE, which is where"
        echo "      -fpatchable-function-entry lives --- so tmm64.debug has NO pads on"
        echo "      TMM-core functions and NOTHING CAN EVER BE ARMED in it. Arming"
        echo "      fails with \"no pad\", which reads like a wrong address and is not."
        echo "      Fix the symlink: ln -sf /usr/bin/tmm.default /usr/bin/tmm"
        echo "      (Dockerfile.ls-tools does this and asserts the result.)"
        exit 1 ;;
      *)
        if [ -e /usr/bin/tmm.debug ]; then
          echo "  ok  tmm.debug present but NOT what tmm resolves to --- fine for arming"
        else
          echo "  ok  no debug binary (production shape)"
        fi ;;
      esac
      # And, when the image carries an index, that it describes THIS binary. A correct
      # symlink over a stale index fails at arm time instead, which is later and less
      # obvious.
      if [ -f /usr/share/ls/hook-index.tsv ] && [ -f /usr/share/ls/ls_buildid.py ]; then
        IDX=$(awk -F"\t" "/^#build_id/{print \$2}" /usr/share/ls/hook-index.tsv)
        LIVE=$(python3 /usr/share/ls/ls_buildid.py "$R")
        if [ "$IDX" = "$LIVE" ]; then
          echo "  ok  hook index matches the running binary (build ${LIVE%%${LIVE#????????}}...)"
        else
          echo "  *** index build id $IDX != binary $LIVE --- arming by name will refuse"
          exit 1
        fi
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
    echo "=== 3. does the binary CONTAIN the change? ==="
    if [ -n "$3" ]; then
        sh "$(dirname "$0")/bnk-verify-artifact.sh" "$TAG" "$3" || {
            echo "*** REFUSING TO PROCEED --- see bnk-verify-artifact.sh output above."
            exit 1
        }
    else
        cat <<'EOT'
  *** NO TOKEN GIVEN, so this step was SKIPPED and the build is unverified.
      Pass a string unique to your change:
          bnk-ship-image.sh verify <tag> 'ls_map: reloc'
      On 2026-08-17 four builds shipped without this check and none of them
      contained the code being tested. Hours of cluster measurements were taken
      against a binary compiled before the fixes. One grep would have caught it.
EOT
    fi
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
    WANT="docker.io/library/$TAG"
    HAVE=$(kubectl get deploy f5-tmm -o jsonpath='{.spec.template.spec.containers[0].image}')
    kubectl set image deploy/f5-tmm "f5-tmm=$WANT" >/dev/null
    kubectl patch deploy f5-tmm --type=json \
        -p='[{"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"Never"}]' >/dev/null

    # A REBAKE REUSES THE TAG, AND THEN NOTHING ROLLS.
    #
    # The deployment already names docker.io/library/tmm:ls, so `set image` to the same
    # string changes no field, the pull policy is already Never, and the pod template is
    # byte-identical. Kubernetes correctly does nothing. `rollout status` then reports
    # "successfully rolled out" IMMEDIATELY --- about the pods that were already there,
    # running the PREVIOUS contents of that tag. A clean success message for a deploy that
    # did not happen, which is the worst shape a failure can take.
    #
    # Importing into containerd replaces what the tag resolves to, so the new bits are on
    # the node; only the pods are stale. `rollout restart` is what picks them up.
    if [ "$HAVE" = "$WANT" ]; then
        echo "  image string unchanged ($WANT) --- forcing a restart, because"
        echo "  set image alone would change nothing and report success anyway."
        kubectl rollout restart deploy/f5-tmm >/dev/null
    fi
    kubectl rollout status deploy/f5-tmm --timeout=180s 2>&1 | tail -2 | sed 's/^/  /'
    kubectl get pods -l app=f5-tmm -o wide --no-headers 2>/dev/null \
        | awk '{print "  "$1"  "$2"  "$3"  restarts="$4"  node="$7}'
    echo
    echo "  restarts must be 0. A pod that restarts once and comes back looks healthy in"
    echo "  'kubectl get pods' and is usually the VM failing at INIT_LATE --- read the logs."

    echo
    echo "=== 3. VERIFY BY CONTENT, from inside the new pods"
    # Not by rollout status, and not by tag. The only question that matters is whether the
    # artifacts in the running pod describe the binary the running pod executes --- which is
    # what ls-load.py will refuse on. Ask each pod, not the deployment.
    # SKIP PODS THAT ARE GOING AWAY. The first run of this check flagged a pod BAD that was
    # merely Terminating: `rollout status` returns as soon as the new replicas are Ready,
    # while the old pod is still shutting down and still listed. It carries the previous
    # layer, so of course its artifacts do not match --- reporting that as a deploy failure
    # sends you looking at the wrong node. A pod with a deletionTimestamp is not evidence
    # about anything.
    bad=0
    # kubectl's jsonpath has no negation operator, so the timestamp is printed and filtered
    # here. A pod being deleted prints a second field; a live one prints nothing after its name.
    for p in $(kubectl get pods -l app=f5-tmm \
                 -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.metadata.deletionTimestamp}{"\n"}{end}' \
               | awk 'NF==1 {print $1}'); do
        printf "  %-26s " "$p"
        out=$(kubectl exec -c f5-tmm "$p" -- sh -c '
            R=$(readlink -f /usr/bin/tmm)
            L=$(python3 /usr/share/ls/ls_buildid.py "$R")
            H=$(awk -F"\t" "/^#build_id/{print \$2}" /usr/share/ls/hook-index.tsv 2>/dev/null)
            S=$(awk -F"\t" "/^#build_id/{print \$2}" /usr/share/ls/signatures.tsv 2>/dev/null)
            N=$(grep -vc "^#" /usr/share/ls/signatures.tsv 2>/dev/null || echo 0)
            if [ "$L" = "$H" ] && [ "$L" = "$S" ]; then
                echo "OK $L hook+sig match, $N signatures"
            else
                echo "BAD binary=$L hook=${H:-none} sig=${S:-none}"
            fi' 2>&1 | tr -d '\r')
        echo "$out"
        case "$out" in OK*) ;; *) bad=$((bad + 1)) ;; esac
    done
    [ "$bad" -eq 0 ] || {
        echo
        echo "*** $bad pod(s) carry artifacts that do not describe their own binary."
        echo "    Arming by name will refuse there --- correct, and useless. Either the"
        echo "    import did not reach that node's containerd, or the pod did not restart."
        exit 1
    }
    ;;

*)
    echo "usage: $0 verify|deploy [tag]"
    exit 2
    ;;
esac
