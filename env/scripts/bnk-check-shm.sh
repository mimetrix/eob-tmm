#!/bin/sh
# Can the egress ring live in shared memory, and where can a drain agent run?
#
# WHY THIS IS THE FIRST THING TO RUN. The whole egress design
# (data-plane-egress-primitives.md) puts a per-core ring in shared memory so the
# producer is a bounded memcpy on the poll thread and everything else happens in
# another process. If shm does not work in this container, section 5.7's entire
# lifecycle needs rethinking and the feed becomes an in-process drain instead.
# Cheap to answer, expensive to assume -- the same reasoning that should have
# been applied to TMM's allocator before the loader hung on it.
#
# WHAT THIS PROVES, AND WHAT IT DOES NOT.
#   Proves: /dev/shm exists and is writable in the f5-tmm container; two
#           processes can map the same segment and see each other's writes; and
#           whether a SIDECAR container can see the producer's segment, which
#           decides where the drain agent is deployed.
#   Does NOT prove: that a TMM POLL THREAD can do this. TMM has its own memory
#           manager, and a thread we create already cannot call malloc (it spins
#           on an uninitialised spinlock -- load-path-scope.md section 1). Only a
#           build with the mapping done from INIT_LATE settles that half.
#
# usage:  bnk-check-shm.sh          run where kubectl targets datkube
set -e

POD=$(kubectl get pods -l app=f5-tmm -o name 2>/dev/null | head -1)
[ -n "$POD" ] || { echo "no f5-tmm pod found"; exit 1; }
POD=${POD#pod/}
echo "pod: $POD"

echo "=== 1. is /dev/shm usable in the f5-tmm container?"
kubectl exec "$POD" -c f5-tmm -- sh -c '
  grep -E " /dev/shm " /proc/mounts | sed "s/^/  /"
  echo "  size cap above is the ceiling on TOTAL ring bytes across all cores."
  (echo probe > /dev/shm/.lsprobe && echo "  writable: YES" && rm -f /dev/shm/.lsprobe) \
    || echo "  writable: NO --- shm-backed rings are not available here"'

echo "=== 2. can two processes share a mapping? (the ring's basic requirement)"
kubectl exec "$POD" -c f5-tmm -- python3 -c '
import mmap, os, struct, subprocess, sys
path, SZ = "/dev/shm/ls_egress_spike", 4096
fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600); os.ftruncate(fd, SZ)
m = mmap.mmap(fd, SZ, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
m[0:8] = struct.pack("<Q", 0xC0FFEE)                       # producer writes
r = subprocess.run([sys.executable, "-c",
  "import mmap,os,struct;fd=os.open(\"/dev/shm/ls_egress_spike\",os.O_RDWR);"
  "m=mmap.mmap(fd,4096,mmap.MAP_SHARED);print(hex(struct.unpack(\"<Q\",m[0:8])[0]));"
  "m[8:16]=struct.pack(\"<Q\",0xBEEF)"], capture_output=True, text=True)
ok_r = r.stdout.strip() == "0xc0ffee"
ok_w = struct.unpack("<Q", m[8:16])[0] == 0xBEEF
print("  consumer read producer write :", "PASS" if ok_r else "FAIL " + r.stderr[:60])
print("  producer saw consumer write  :", "PASS" if ok_w else "FAIL")
os.close(fd); os.unlink(path)
raise SystemExit(0 if (ok_r and ok_w) else 1)'

echo "=== 3. WHERE CAN THE DRAIN AGENT RUN? (can a sidecar see the segment?)"
SIDE=$(kubectl get pod "$POD" -o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}' \
       | grep -v '^f5-tmm$' | head -1)
if [ -z "$SIDE" ]; then
    echo "  no sidecar in this pod --- the drain agent would have to live in f5-tmm"
else
    kubectl exec "$POD" -c f5-tmm -- sh -c 'echo from-tmm > /dev/shm/.xcprobe'
    if kubectl exec "$POD" -c "$SIDE" -- cat /dev/shm/.xcprobe >/dev/null 2>&1; then
        echo "  sidecar '$SIDE' CAN see the segment."
        echo "  Containers in a pod share the IPC namespace by default, so containerd"
        echo "  bind-mounts one /dev/shm into each. The drain agent can be a sidecar"
        echo "  with NO deployment change --- no emptyDir{medium:Memory}, no volume."
    else
        echo "  sidecar '$SIDE' CANNOT see it. The drain agent must either live inside"
        echo "  f5-tmm, or the deployment needs an explicit emptyDir{medium:Memory}"
        echo "  mounted at /dev/shm in BOTH containers."
    fi
    kubectl exec "$POD" -c f5-tmm -- rm -f /dev/shm/.xcprobe 2>/dev/null || true
fi

echo
echo "  Still open (step 0b): whether a TMM POLL THREAD can create and write this"
echo "  mapping. That needs a build with the mapping done from INIT_LATE."
