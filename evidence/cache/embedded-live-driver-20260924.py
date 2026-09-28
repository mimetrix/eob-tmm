"""Datkube P17 monitor-only HTTP/1 test; exact driver retained with evidence."""
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import time

POD = "f5-tmm-7597dfff8b-28s9z"
BUILD = "c3b81927dfdcc31137cd8212b5e23bb85677a06c"
HASH = "a4b9e777a1daccd8c2b8c7f1aa7eba920b6040253f45f017605ea0a5f0a8afd7"
PROGS = Path("/tmp/embedded-p17-20260924")
FIXTURE = "/tmp/catalog-tools/ctx-contract-test.yaml"
K = ["kubectl", "exec", POD, "-c", "f5-tmm", "--"]


def run(*args, quiet=False, **kw):
    p = subprocess.run([str(a) for a in args], text=True, capture_output=True, timeout=120, **kw)
    if not quiet:
        print(p.stdout, end="", flush=True)
    if p.stderr:
        print(p.stderr, end="", flush=True)
    p.check_returncode()
    return p.stdout


def identity():
    d = json.loads(run("kubectl", "get", "pod", POD, "-o", "json", quiet=True))
    c = next(c for c in d["status"]["containerStatuses"] if c["name"] == "f5-tmm")
    assert c["ready"] and not d["metadata"].get("deletionTimestamp")
    return d["metadata"]["uid"], c["containerID"], c["restartCount"], c["imageID"]


def loadcmd(*args):
    out = run(*K, "/usr/bin/ls-load.py", *args)
    assert "ERR " not in out, out
    return out


def status():
    return {k: int(v) for k, v in re.findall(r"(\w+)=(\d+)", loadcmd("status", "2"))}


def pad():
    return run(*K, "python3", "-c",
               'f=open("/proc/24/mem","rb",buffering=0); f.seek(0xccc604); print(f.read(5).hex())').strip()


def traffic(n):
    out = run("kubectl", "exec", "client", "--", "sh", "-c",
              'for i in $(seq 1 "$1"); do curl -x "" --http1.1 --fail --silent --show-error --max-time 8 -H "Connection: close" -o /dev/null -w "%{http_code}\\n" http://11.11.11.99:18081/ || exit; done',
              "p17", str(n))
    assert out.splitlines() == ["200"] * n


assert run("kubectl", "config", "current-context").strip() == "kind-vs"
before = identity()
print("PINNED", POD, before, flush=True)
assert before[0] == "42259fbc-3303-492a-95b1-9146b4105583" and before[2] == 0
observed = run(*K, "python3", "-c", '''
import hashlib,json,os,subprocess
p="/proc/24/exe"
bid=subprocess.check_output(["python3","/usr/share/ls/ls_buildid.py",p],text=True).strip()
receipt=json.load(open("/usr/share/ls/runtime-identity.json"))
sha=hashlib.sha256(open(p,"rb").read()).hexdigest()
assert receipt=={"build_id":bid,"sha256":sha}
assert not any(os.path.exists("/usr/share/ls/"+n) for n in ("types.json","signatures.tsv","hook-index.tsv","hook-map.json","tmm.btf"))
print(bid,sha,"bulk catalogs absent")
''')
assert BUILD in observed and HASH in observed
assert status()["mode"] == 0 and pad() == "9090909090"
existing = json.loads(run("kubectl", "get", "-f", FIXTURE, "--ignore-not-found", "-o", "json", quiet=True) or '{"items":[]}')
assert not existing.get("items"), "fixture already exists"
vs = json.loads(run("kubectl", "get", "f5-virtualservers", "-o", "json", quiet=True))
assert not any(v["spec"].get("destinationPort") == 18081 for v in vs["items"])
pools = json.loads(run("kubectl", "get", "f5-big-cne-pools", "-o", "json", quiet=True))
assert "22.22.22.113" not in json.dumps(pools)
pods = json.loads(run("kubectl", "get", "pods", "-o", "json", quiet=True))
assert "22.22.22.113" not in json.dumps(pods)
armed, loaded = False, False
try:
    run("kubectl", "apply", "-f", FIXTURE)
    run("kubectl", "wait", "--for=condition=Ready", "pod/ctx-contract-test", "--timeout=90s")
    time.sleep(10)
    run("kubectl", "get", "f5-virtualservers", "ctx-contract-test", "-o", "yaml")
    run("kubectl", "exec", "ctx-contract-test", "--", "curl", "-x", "", "--fail", "--max-time", "3", "http://127.0.0.1:18081/")
    run("kubectl", "exec", "ctx-contract-test", "--", "ip", "route")
    capture = subprocess.Popen(K + ["timeout", "12", "tcpdump", "-n", "-e", "-i", "tmm-server", "arp or tcp port 18081"],
                               text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    backend_capture = subprocess.Popen(["kubectl", "exec", "ctx-contract-test", "--", "timeout", "12", "tcpdump",
                                        "-n", "-e", "-i", "any", "arp or tcp port 18081"],
                                       text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for attempt in range(4):
        warm = subprocess.run(["kubectl", "exec", "client", "--", "curl", "-x", "",
                               "--http1.1", "--fail", "--silent", "--show-error", "--verbose", "--max-time", "2",
                               "-H", "Connection: close", "http://11.11.11.99:18081/"],
                              text=True, capture_output=True, timeout=15)
        print("WARMUP", attempt + 1, warm.returncode, warm.stdout, warm.stderr, flush=True)
        if warm.returncode == 0:
            print("SERVER-SIDE CAPTURE", capture.communicate(timeout=20)[0], flush=True)
            print("BACKEND CAPTURE", backend_capture.communicate(timeout=20)[0], flush=True)
            break
        if attempt == 0:
            run("kubectl", "exec", "ctx-contract-test", "--", "ip", "link", "show", "dev", "server-net")
            run("kubectl", "exec", "ctx-contract-test", "--", "arping", "-U", "-I", "server-net", "-c", "3", "22.22.22.113")
            print("SERVER-SIDE CAPTURE", capture.communicate(timeout=20)[0], flush=True)
            print("BACKEND CAPTURE", backend_capture.communicate(timeout=20)[0], flush=True)
            run("kubectl", "exec", "ctx-contract-test", "--", "ip", "neigh", "show", "22.22.22.150")
            links = json.loads(run(*K, "ip", "-j", "link", "show", "dev", "tmm-server", quiet=True))
            mac = links[0]["address"]
            print("PIN TEMPORARY BACKEND NEIGHBOR TO SELECTED TMM", mac, flush=True)
            run("kubectl", "exec", "ctx-contract-test", "--", "ip", "neigh", "replace", "22.22.22.150",
                "lladdr", mac, "nud", "permanent", "dev", "server-net")
            run("kubectl", "exec", "ctx-contract-test", "--", "ip", "neigh", "show", "22.22.22.150")
        time.sleep(2)
    else:
        raise AssertionError("HTTP/1 fixture did not become reachable during bounded warm-up")
    traffic(8)
    for name, matches in (("nested", 16), ("nested-control", 0), ("embedded-pointer", 16)):
        obj = PROGS / (name + ".bpf.o")
        print("CASE", name, "SHA256", hashlib.sha256(obj.read_bytes()).hexdigest(), flush=True)
        out = run("python3", "/tmp/catalog-tools/bnk-deliver-program.py", obj,
                  "2", "1", "http_parse_client_headers", env={**os.environ, "POD": POD})
        assert "OK loaded" in out
        loaded = True
        assert "OK ARMED LIVE" in loadcmd("arm", "2", "http_parse_client_headers")
        armed = True
        assert pad().startswith("e8")
        a = status()
        traffic(16)
        b = status()
        delta = {k: b[k] - a[k] for k in ("fired", "safe_returns", "errors")}
        print("DELTA", name, delta, flush=True)
        assert delta == {"fired": 16, "safe_returns": matches, "errors": 0}, delta
        assert "OK DISARMED LIVE" in loadcmd("disarm", "http_parse_client_headers")
        armed = False
        assert pad() == "9090909090"
        a = status()
        traffic(8)
        assert status() == a, "counters changed after disarm"
        loadcmd("revoke", "2")
        loaded = False
        assert identity() == before
        print("PASS", name, "16 HTTP 200s; restored NOPs; 8 post-disarm HTTP 200s without fires", flush=True)
finally:
    try:
        if armed:
            assert "OK DISARMED LIVE" in loadcmd("disarm", "http_parse_client_headers")
        if loaded:
            loadcmd("revoke", "2")
    finally:
        run("kubectl", "delete", "-f", FIXTURE, "--ignore-not-found", "--wait=true")
assert status()["mode"] == 0 and pad() == "9090909090" and identity() == before
print("PASS P17 live HTTP/1 probes: stable pod, zero restarts, slot 2 disabled, fixture deleted", flush=True)
