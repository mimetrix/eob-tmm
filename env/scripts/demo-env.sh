# Source this in EVERY xterm you use for the CVE-2025-41414 demo.
#
#   . ~/demo-env.sh
#
# WHY IT EXISTS. The TMM pod name changes every time TMM dies --- which the demo does
# on purpose, halfway through --- so every window holding a stale $POD breaks at the
# moment you need it. Nothing here caches: each function re-resolves the pod when it
# is called. That is the whole point.
#
# The functions are deliberately tiny and print what they did, so an audience can see
# a command rather than a wall of kubectl.

DEMO_VIP=11.11.11.99
DEMO_HTTP_PORT=8081          # plain HTTP --- SAFE to probe
DEMO_CVE_PORT=8082           # the CRASH PATH --- never use this as a health check
DEMO_HOOK=http2_http_data_to_frames
DEMO_SLOT=3
DEMO_PROG=$HOME/nobtf-shields/h2_trailer_guard.bpf.o

# The current TMM pod. Re-resolved on every call, never cached.
tmm_pod() {
    kubectl get pods -l app=f5-tmm --no-headers 2>/dev/null \
        | awk '$3=="Running" && $2=="2/2"{print $1}' | head -1
}

# The loader socket inside that pod (it carries TMM's instance number).
tmm_sock() {
    local p; p=$(tmm_pod); [ -n "$p" ] || return 1
    kubectl exec "$p" -c f5-tmm -- sh -c 'ls /tmp/ls_load.sock.* 2>/dev/null | head -1'
}

# Run ls-load.py in the pod with the socket set.
loader() {
    local p s; p=$(tmm_pod); s=$(tmm_sock)
    [ -n "$p" ] && [ -n "$s" ] || { echo "*** no Running 2/2 TMM pod yet"; return 1; }
    kubectl exec "$p" -c f5-tmm -- env LS_LOAD_SOCKET="$s" python3 /usr/bin/ls-load.py "$@"
}

# Wait until a replacement pod is serving. Use this after the crash.
tmm_wait() {
    printf 'waiting for a 2/2 TMM pod'
    until [ -n "$(tmm_pod)" ]; do printf .; sleep 5; done
    echo " -> $(tmm_pod)"
    # ONE THROWAWAY REQUEST. The first request after a pod replacement returns 000
    # (a ~3-request warm-up window). Burning it here keeps it off the screen while
    # an audience is watching.
    kubectl exec client -n default -- curl -s -o /dev/null --max-time 8 \
        "http://$DEMO_VIP:$DEMO_HTTP_PORT/" 2>/dev/null
    echo "warmed up; ready"
}

# Normal HTTP traffic. N requests, prints the status codes.
normal() {
    local n=${1:-5}
    kubectl exec client -n default -- sh -c \
      "for i in \$(seq 1 $n); do curl -s -o /dev/null -w '%{http_code} ' --max-time 8 \
       http://$DEMO_VIP:$DEMO_HTTP_PORT/; done; echo"
}

# The attack. N HTTP/2 requests whose response carries a zero-header trailer.
attack() {
    local n=${1:-1}
    kubectl exec client -n default -- sh -c \
      "for i in \$(seq 1 $n); do curl -sk -o /dev/null -w '%{http_code} ' \
       --http2-prior-knowledge --max-time 10 http://$DEMO_VIP:$DEMO_CVE_PORT/; done; echo"
}

# Does the shipped binary carry any internal type information? Expect 0.
btf_bytes() {
    kubectl exec "$(tmm_pod)" -c f5-tmm -- python3 -c '
import struct
b=open("/usr/bin/tmm64.no_pgo","rb").read()
o,=struct.unpack_from("<Q",b,0x28); e,n,x=struct.unpack_from("<HHH",b,0x3A)
sh=lambda i: struct.unpack_from("<IIQQQQ",b,o+i*e)
_,_,_,_,so,sz=sh(x); nm=b[so:so+sz]; t=0
for i in range(n):
    a,_,_,_,_,z=sh(i)
    if nm[a:nm.find(b"\0",a)].decode().startswith(".BTF"): t+=z
print(".BTF section bytes in the running binary:", t)'
}

# Pre-flight. Run this before the demo; every line must be green.
preflight() {
    local p s; p=$(tmm_pod)
    echo "pod       : ${p:-*** NONE 2/2}"
    [ -n "$p" ] || return 1
    echo "image     : $(kubectl get deploy f5-tmm -o jsonpath='{.spec.template.spec.containers[0].image}')"
    s=$(tmm_sock); echo "socket    : ${s:-*** MISSING}"
    printf 'http path : '; normal 3
    echo -n 'disclosure: '; btf_bytes
    echo 'slots     :'
    local i st bad=0
    for i in 0 1 2 3 4 5 6 7; do
        st=$(loader status $i 2>/dev/null | grep -oE 'armed=[0-9]+')
        [ "$st" = "armed=0" ] || { echo "  *** slot $i is $st --- disarm it or replace the pod"; bad=1; }
    done
    [ "$bad" = 0 ] && echo '  all 8 slots armed=0'
    echo
    if [ "$bad" = 0 ]; then echo 'READY'; else echo 'NOT READY --- see above'; fi
}

# The universal reset. Fixes a refusing data path AND a stale armed flag.
tmm_reset() {
    local p; p=$(tmm_pod)
    echo "replacing $p"
    kubectl delete pod "$p" --wait=false >/dev/null 2>&1
    sleep 8
    tmm_wait
}

echo "demo-env loaded. vip=$DEMO_VIP http=$DEMO_HTTP_PORT cve=$DEMO_CVE_PORT slot=$DEMO_SLOT"
echo "functions: preflight  tmm_pod  tmm_wait  loader  normal  attack  btf_bytes  tmm_reset"
