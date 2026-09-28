#!/usr/bin/env python3
"""Deploy/run/remove the isolated HTTP/1 AI traffic jig on datkube (kind-vs)."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time
import uuid

HERE = Path(__file__).resolve().parent
NAME = "ai-traffic"
LABEL = {"app.kubernetes.io/managed-by": "eob-ai-traffic-jig"}
IMAGE = "artifactory.f5net.com/f5-positron-docker/testing-utils:v1.1.2"
BUILD = "c3b81927dfdcc31137cd8212b5e23bb85677a06c"
RUNTIME_HASH = "a4b9e777a1daccd8c2b8c7f1aa7eba920b6040253f45f017605ea0a5f0a8afd7"


def command(*argv, **kw):
    p = subprocess.run(list(map(str, argv)), text=True, capture_output=True, timeout=180, **kw)
    if p.returncode:
        raise RuntimeError(f"{argv}: {p.stdout}\n{p.stderr}")
    return p.stdout


def kube(*argv, **kw):
    return command("kubectl", "--context=kind-vs", "-n", "default", *argv, **kw)


def identity(pod):
    data = json.loads(kube("get", "pod", pod, "-o", "json"))
    status = next(s for s in data["status"]["containerStatuses"] if s["name"] == "f5-tmm")
    assert status["ready"] and not data["metadata"].get("deletionTimestamp")
    return {"pod": pod, "uid": data["metadata"]["uid"], "node": data["spec"]["nodeName"],
            **{key: status[key] for key in ("containerID", "imageID", "restartCount")}}


def manifest(node):
    def obj(api, kind, name, **fields):
        return dict(apiVersion=api, kind=kind,
                    metadata=dict(name=name, namespace="default", labels=LABEL), **fields)

    scripts = {name: (HERE / name).read_text() for name in ("backend.py", "client.py")}
    objects = [obj("v1", "ConfigMap", NAME, data=scripts)]
    for role, net, ip in (("backend", "server-net", "22.22.22.114"),
                          ("client", "client-net", "11.11.11.114")):
        container = dict(name=role, image=IMAGE,
                         command=["python3", "/opt/jig/backend.py"] if role == "backend" else ["sleep", "infinity"],
                         securityContext={"capabilities": {"add": ["NET_ADMIN"]}},
                         volumeMounts=[{"name": "scripts", "mountPath": "/opt/jig", "readOnly": True}])
        if role == "backend":
            container["readinessProbe"] = {"tcpSocket": {"port": 18090}}
        pod = obj("v1", "Pod", NAME + "-" + role, spec={"nodeName": node, "containers": [container],
                  "volumes": [{"name": "scripts", "configMap": {"name": NAME}}]})
        pod["metadata"]["annotations"] = {"k8s.v1.cni.cncf.io/networks": json.dumps([
            {"name": net, "interface": net, "ips": [ip + "/24"]}])}
        objects.append(pod)
    objects.append(obj("k8s.f5net.com/v1", "F5BigCnePool", NAME, spec={"members": [
        {"address": "22.22.22.114", "port": 18090, "priorityGroup": 0}], "minActiveMembers": 0}))
    objects.append(obj("k8s.f5net.com/v1", "F5VirtualServer", NAME, spec={
        "destinationAddress": "11.11.11.99", "destinationPort": 18090,
        "http": {"clientside": "sys-default-http", "serverside": "sys-default-http"},
        "httpRouter": True, "ipfamilies": "IPv4", "loadBalancingMethod": "ROUND_ROBIN", "pool": NAME,
        "protocol": "tcp", "protocolProfile": {"clientside": "sys-default-tcp", "serverside": "sys-default-tcp"},
        "snat": {"pool": "", "type": "automap"}, "sourcePort": "preserve",
        "translateAddress": True, "translatePort": True,
        "vlans": {"disableListedVlans": False, "vlanList": ["tmm-client"]}}))
    return {"apiVersion": "v1", "kind": "List", "items": objects}


def resources(doc):
    text = kube("get", "-f", "-", "--ignore-not-found", "-o", "json", input=json.dumps(doc))
    return json.loads(text or '{"items": []}')["items"]


def remove(doc):
    for item in resources(doc):
        assert item["metadata"].get("labels", {}).get("app.kubernetes.io/managed-by") == LABEL["app.kubernetes.io/managed-by"], "resource name is not owned by jig"
    print(kube("delete", "-f", "-", "--ignore-not-found", "--wait=true", input=json.dumps(doc)), end="")


def pin_neighbors(pod):
    links = json.loads(kube("exec", pod, "-c", "f5-tmm", "--", "ip", "-j", "address", "show"))
    rows = []
    for role, iface, target in (("client", "tmm-client", "11.11.11.99"),
                                ("backend", "tmm-server", "22.22.22.150")):
        link = next(link for link in links if link["ifname"] == iface)
        if role == "backend":
            assert any(a.get("local") == target for a in link["addr_info"]), "unexpected SNAT network"
        net = "client-net" if role == "client" else "server-net"
        kube("exec", NAME + "-" + role, "--", "ip", "neigh", "replace", target,
             "lladdr", link["address"], "nud", "permanent", "dev", net)
        rows.append(kube("exec", NAME + "-" + role, "--", "ip", "neigh", "show", target).strip())
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("action", choices=("up", "run", "down", "manifest"))
    ap.add_argument("--pod", default="f5-tmm-7597dfff8b-28s9z")
    ap.add_argument("--workers", type=int, choices=range(1, 9), default=3)
    ap.add_argument("--rounds", type=int, choices=range(1, 21), default=1)
    ap.add_argument("--output", type=Path, help="new evidence directory (required for run)")
    args = ap.parse_args()
    if args.action in ("down", "manifest"):
        doc = manifest("vs-worker")
        if args.action == "down":
            remove(doc)
        else:
            print(json.dumps(doc, indent=2))
        return
    before = identity(args.pod)
    doc = manifest(before["node"])
    runtime = json.loads(kube("exec", args.pod, "-c", "f5-tmm", "--", "python3", "-c",
        'import hashlib,json,subprocess; p="/proc/24/exe"; '
        'print(json.dumps({"build_id":subprocess.check_output(["python3","/usr/share/ls/ls_buildid.py",p],text=True).strip(),'
        '"sha256":hashlib.sha256(open(p,"rb").read()).hexdigest()}))'))
    assert runtime == {"build_id": BUILD, "sha256": RUNTIME_HASH}, "update pinned identity deliberately for a new build"
    if args.action == "up":
        assert not resources(doc), "fixture exists; use run, or down then up to update scripts"
        for kind in ("pods", "f5-big-cne-pools", "f5-virtualservers"):
            state = kube("get", kind, "-o", "json")
            assert "22.22.22.114" not in state and "11.11.11.114" not in state, "fixture IP in use"
            if kind == "f5-virtualservers":
                assert not any(v["spec"].get("destinationPort") == 18090 for v in json.loads(state)["items"]), "fixture port in use"
        try:
            print(kube("create", "-f", "-", input=json.dumps(doc)), end="")
            for role in ("client", "backend"):
                kube("wait", "--for=condition=Ready", "pod/" + NAME + "-" + role, "--timeout=90s")
            print("NEIGHBORS", json.dumps(pin_neighbors(args.pod)))
            for _ in range(30):
                vs = json.loads(kube("get", "f5-virtualservers", NAME, "-o", "json"))
                if any(c.get("type") == "Programmed" and c.get("status") == "True" for c in vs.get("status", {}).get("conditions", [])):
                    break
                time.sleep(2)
            else:
                raise RuntimeError("AI fixture listener never became Programmed")
            health = kube("exec", NAME + "-client", "--", "curl", "-x", "", "--fail", "--silent", "--show-error",
                          "--retry", "3", "--retry-all-errors", "--max-time", "5", "http://11.11.11.99:18090/health")
            assert json.loads(health)["fixture"] == NAME
            assert identity(args.pod) == before
            print("READY http://11.11.11.99:18090 (HTTP proxy; native AI filters disabled)")
        except BaseException:
            remove(doc)
            raise
        return
    assert args.output is not None, "run requires --output NEW_DIRECTORY"
    items = resources(doc)
    assert len(items) == 5 and all(i["metadata"].get("labels", {}) == LABEL for i in items)
    installed = next(i for i in items if i["kind"] == "ConfigMap")["data"]
    assert installed == doc["items"][0]["data"], "installed fixture code differs; down/up to update"
    args.output.mkdir(parents=True, exist_ok=False)
    def save(name, value):
        (args.output / name).write_text(value if isinstance(value, str) else json.dumps(value, indent=2) + "\n")
    run = "ai-" + uuid.uuid4().hex[:12]
    preflight = {"run_id": run, "tmm": before, "runtime": runtime,
                 "neighbors": pin_neighbors(args.pod),
                 "sources": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (HERE / "backend.py", HERE / "client.py", HERE / "jig.py")},
                 "fixture_resources": items}
    save("preflight.json", preflight)
    capture = subprocess.Popen(["kubectl", "--context=kind-vs", "-n", "default", "exec", args.pod,
        "-c", "f5-tmm", "--", "timeout", "30", "tcpdump", "-n", "-e", "-i", "tmm-client",
        "-c", "20", "tcp port 18090"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(2)
    try:
        p = subprocess.run(["kubectl", "--context=kind-vs", "-n", "default", "exec", NAME + "-client", "--",
            "python3", "/opt/jig/client.py", "--workers", str(args.workers), "--rounds", str(args.rounds), "--run-id", run],
            text=True, capture_output=True, timeout=300)
        save("client-and-backend.jsonl", p.stdout)
        save("client-stderr.log", p.stderr)
        p.check_returncode()
        summary = json.loads(p.stdout.splitlines()[-1])
        assert summary["event"] == "PASS" and summary["backend_peer_ips"] == ["22.22.22.150"]
        vs = json.loads(kube("get", "f5-virtualservers", NAME, "-o", "json"))
        assert not any(vs["spec"].get(k) for k in ("a2a", "mcp", "json", "sse")), "baseline unexpectedly enables AI filters"
        save("listener.json", vs)
        assert identity(args.pod) == before, "TMM identity/restarts changed"
    finally:
        output, _ = capture.communicate(timeout=40)
        save("tmm-packets.log", output)
        save("backend-stdout.jsonl", kube("logs", NAME + "-backend"))
    assert capture.returncode == 0 and "11.11.11.114" in output and "11.11.11.99.18090" in output, "no selected-TMM packet witness"
    save("result.json", {**summary, "tmm_after": identity(args.pod), "runtime": runtime})
    print(json.dumps(summary, sort_keys=True))
    print("PASS selected-TMM packet capture; stable identity; evidence:", args.output)


if __name__ == "__main__":
    main()
