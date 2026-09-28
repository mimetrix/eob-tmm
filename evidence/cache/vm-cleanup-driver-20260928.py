#!/usr/bin/env python3
"""Record and remove the September 24–28 disposable lab fixtures only."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tarfile
import time

ROOT = Path(__file__).resolve().parents[2]
HOSTS = {"build": "10.145.37.36", "deploy": "10.145.40.193"}
PROJECTS = ("eob-config-20260925", "eob-template-20260925", "eob-dlp-20260924")
RESOURCE_TYPES = "configmaps,pods,f5-big-cne-pools,f5-virtualservers"
LABEL = "app.kubernetes.io/managed-by=eob-ai-traffic-jig"
INSPECT = '''{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"state":{{json .State}},"restarts":{{json .RestartCount}},"mounts":{{json .Mounts}},"project":{{json (index .Config.Labels "com.docker.compose.project")}}}'''
PROBES = '''import json,runpy
m=runpy.run_path("/usr/bin/ls-load.py")
print(json.dumps({str(i):m["send"](m["msg"](3,slot=i)) for i in range(12)}))
'''
RUNTIME = '''import hashlib,json,pathlib,runpy
m=runpy.run_path("/usr/bin/ls-load.py");pid=m["tmm_pid"]();exe="/proc/"+pid+"/exe"
digest=hashlib.sha256(pathlib.Path(exe).read_bytes()).hexdigest()
# Addresses are from the cached config/scope live receipts and catalog-probes log.
assert digest in ("05d17517531d99b26eb9e8f00f5b5326f660b5bef492226c9555368b887a9611","26e8f07b12a279e7d84f2328363db998a7dfa109a9b3c71847be408a6710a12c","a4b9e777a1daccd8c2b8c7f1aa7eba920b6040253f45f017605ea0a5f0a8afd7")
pad=m["entry_bytes"](0xccc604,5);assert pad==b"\\x90"*5,pad
print(json.dumps({"pid":pid,"starttime":pathlib.Path("/proc/"+pid+"/stat").read_text().split(") ",1)[1].split()[19],"build_id":m["elf_build_id"](exe),"sha256":digest,"parser_pad_address":"0xccc604","parser_pad":pad.hex()}))
'''
EVIDENCE_MANIFEST = '''import hashlib,json,pathlib,stat
root=pathlib.Path("/evidence");rows={}
for p in sorted(root.rglob("*")):
 mode=p.lstat().st_mode
 if stat.S_ISDIR(mode):continue
 assert stat.S_ISREG(mode),str(p)
 assert p.suffix.lower() not in (".pem",".key",".p12",".pfx"),str(p)
 data=p.read_bytes()
 assert b"PRIVATE KEY-----" not in data and b"BEGIN CERTIFICATE" not in data,str(p)
 rows[str(p.relative_to(root))]={"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
print(json.dumps(rows))
'''
HOST_SCAN = '''import json,os,pathlib
rows=[]
for p in pathlib.Path("/proc").iterdir():
 if not p.name.isdigit() or int(p.name)==os.getpid(): continue
 try:
  name=(p/"comm").read_text().strip()
  if any(s in name.lower() for s in ("python","tmm","kubectl","tcpdump","drain","tao","icap")):
   args=(p/"cmdline").read_bytes().split(b"\\0")
   markers=[s for s in ("ai-traffic", "attribution", "request_scope", "scope-live", "config_live", "template_suite", "icap_suite", "port-forward", "ls-drain", "ls_drain") if any(s.encode() in a for a in args)]
   rows.append({"pid":int(p.name),"comm":name,"test_markers":markers})
 except (FileNotFoundError,PermissionError,ProcessLookupError): pass
files=[]
for parent in (pathlib.Path("/tmp"),pathlib.Path("/home/starin")):
 for p in parent.iterdir():
  if p.name.startswith(("eob-","ai-traffic","scope-","template-","observability-","config-","tmm")):
   s=p.lstat();files.append({"path":str(p),"bytes":s.st_size,"directory":p.is_dir(),"mtime":s.st_mtime})
print(json.dumps({"processes":rows,"candidate_paths":files}))
'''
POD_VIEW = '''import json,sys
doc=json.load(sys.stdin)
print(json.dumps([{"name":p["metadata"]["name"],"uid":p["metadata"]["uid"],"node":p["spec"].get("nodeName"),"containers":[{k:s.get(k) for k in ("name","containerID","imageID","restartCount","ready")} for s in p["status"].get("containerStatuses",[])]} for p in doc["items"]]))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=HOSTS)
    parser.add_argument("action", choices=("inventory", "cleanup"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    record = {"role": args.role, "action": args.action, "host": HOSTS[args.role],
              "started": time.time(), "passed": False, "commands": [],
              "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "driver_source": Path(__file__).read_text()}
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=12", "-o",
           "IdentitiesOnly=yes", "-i", "/home/claude/.ssh/id_ed25519",
           "starin@" + HOSTS[args.role]]

    def run(*argv, check=True):
        result = subprocess.run(ssh + [shlex.join(argv)], text=True,
                                capture_output=True, timeout=300, check=False)
        record["commands"].append({"argv": argv, "rc": result.returncode,
                                   "stdout": result.stdout, "stderr": result.stderr})
        if check:
            result.check_returncode()
        return result.stdout

    def kube(*argv):
        return run("kubectl", "--context=kind-vs", "-n", "default", *argv)

    def snapshot():
        result = {}
        ids = run("docker", "ps", "-aq").split()
        result["containers"] = [json.loads(line) for line in run(
            "docker", "inspect", "--format", INSPECT, *ids).splitlines()] if ids else []
        result["networks"] = run("docker", "network", "ls", "--format", "{{json .}}")
        result["volumes"] = run("docker", "volume", "ls", "--format", "{{json .}}")
        result["host_scan"] = json.loads(run("python3", "-c", HOST_SCAN))
        result["disk"] = run("df", "-B1", "/")
        result["listeners"] = run("ss", "-ltnp")
        if args.role == "build":
            result["compose"] = json.loads(run("docker", "compose", "ls", "--format", "json"))
            result["probes"] = {}
            result["runtime"] = {}
            for item in result["containers"]:
                if item["project"] in PROJECTS and item["name"].endswith("-tmm-1"):
                    result["probes"][item["name"]] = json.loads(run(
                        "docker", "exec", item["id"], "python3", "-c", PROBES))
                    result["runtime"][item["name"]] = json.loads(run(
                        "docker", "exec", item["id"], "python3", "-c", RUNTIME))
                if item["project"] in PROJECTS and item["name"].endswith("-fixture-1"):
                    run("docker", "exec", item["id"], "du", "-sh", "/evidence")
            for project in PROJECTS:
                names = [json.loads(line)["Name"] for line in result["volumes"].splitlines()
                         if json.loads(line)["Name"].startswith(project + "_")]
                if names:
                    run("docker", "volume", "inspect", *names)
        else:
            # Record identity/status only. Do not export pod environment or secrets.
            script = "import subprocess;" + "d=subprocess.check_output(" + repr([
                "kubectl", "--context=kind-vs", "-n", "default", "get", "pods", "-o", "json"]) + ");" + "subprocess.run(['python3','-c'," + repr(POD_VIEW) + "],input=d,check=True)"
            result["pods"] = json.loads(run("python3", "-c", script))
            result["owned"] = json.loads(kube("get", RESOURCE_TYPES, "-l", LABEL, "-o", "json"))
            result["routes"] = json.loads(kube("get", "f5-big-cne-pools,f5-virtualservers", "-o", "json"))
            result["probes"] = {}
            result["runtime"] = {}
            for pod in result["pods"]:
                if any(c["name"] == "f5-tmm" for c in pod["containers"]):
                    result["probes"][pod["name"]] = json.loads(kube(
                        "exec", pod["name"], "-c", "f5-tmm", "--", "python3", "-c", PROBES))
                    result["runtime"][pod["name"]] = json.loads(kube(
                        "exec", pod["name"], "-c", "f5-tmm", "--", "python3", "-c", RUNTIME))
            run("sha256sum", "/home/starin/ai-traffic-jig/jig.py",
                "/home/starin/ai-traffic-jig/backend.py", "/home/starin/ai-traffic-jig/client.py")
        return result

    def archive_evidence(container, project):
        manifest = json.loads(run("docker", "exec", container, "python3", "-c", EVIDENCE_MANIFEST))
        path = args.output.parent / (project + "-evidence-20260928.tar.gz")
        argv = ["docker", "exec", container, "tar", "-czf", "-", "-C", "/evidence", "."]
        if not path.exists():
            with path.open("xb") as archive:
                result = subprocess.run(ssh + [shlex.join(argv)], stdout=archive,
                                        stderr=subprocess.PIPE, timeout=120, check=False)
            record["commands"].append({"argv": argv, "rc": result.returncode,
                                       "stdout_file": str(path), "stderr": result.stderr.decode()})
            result.check_returncode()
        else:
            record.setdefault("reused_archives", []).append(str(path))
        actual = {}
        with tarfile.open(path) as archive:
            for member in archive:
                if member.isdir():
                    continue
                assert member.isfile(), member.name
                name = member.name.removeprefix("./")
                assert name not in actual and name in manifest, name
                data = archive.extractfile(member).read()
                actual[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        assert actual == manifest, "evidence archive differs from source manifest"
        record.setdefault("archives", []).append({"path": str(path), "files": manifest,
            "bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})

    def cleanup(before):
        for slots in before["probes"].values():
            assert all(s.startswith("OK ") and ("armed=0 " in s or "mode=0 " in s)
                       for s in slots.values()), "active program needs explicit investigation"
        if args.role == "build":
            owned = [c for c in before["containers"] if c["project"] in PROJECTS]
            assert len(owned) == 6
            commands = []
            for project in PROJECTS:
                selected = [c for c in owned if c["project"] == project]
                assert {c["name"] for c in selected} == {"/"+project+"-tmm-1", "/"+project+"-fixture-1"}
                root = "/home/starin/" + (project if "dlp" in project else "eob-config-20260925")
                files = ["icap-compose.yaml"]
                if "dlp" not in project:
                    files.append("config-compose.yaml")
                if "template" in project:
                    files.append("observability-compose.yaml")
                expected = ",".join(root + "/" + f for f in files)
                assert next(c for c in before["compose"] if c["Name"] == project)["ConfigFiles"] == expected
                argv = ["docker", "compose", "--project-name", project]
                if "dlp" not in project:
                    env = "template-fixture.env" if "template" in project else "config-fixture.env"
                    files.append(env)
                    argv += ["--env-file", root + "/" + env]
                hashes = run("sha256sum", *(root + "/" + f for f in files))
                for line, name in zip(hashes.splitlines(), files):
                    expected_hash = hashlib.sha256((ROOT / "env/ai-traffic" / name).read_bytes()).hexdigest()
                    if project == "eob-dlp-20260924" and name == "icap-compose.yaml":
                        # Reviewed older source: fixed fixture IPs, before env-variable support.
                        expected_hash = "18660f6fbe5d41d0b9218d394d173203ae0841776f3fc8ead312513ba6fd3dc1"
                    assert line.split()[0] == expected_hash, name
                for name in expected.split(","):
                    argv += ["-f", name]
                for item in selected:
                    for mount in item["mounts"]:
                        if mount["Type"] == "volume":
                            volume = json.loads(run("docker", "volume", "inspect", mount["Name"]))[0]
                            assert volume["Labels"]["com.docker.compose.project"] == project
                        else:
                            assert mount["Type"] == "bind" and mount["Destination"] == "/work" and mount["Source"] == root and not mount["RW"]
                networks = json.loads(run("docker", "network", "inspect", project+"_data", project+"_management"))
                for network in networks:
                    assert network["Labels"]["com.docker.compose.project"] == project
                    assert set(network["Containers"]) <= {c["id"] for c in selected}
                archive_evidence(next(c["id"] for c in selected if c["name"].endswith("-fixture-1")), project)
                commands.append(argv + ["down", "--volumes", "--timeout", "20"])
            # All three evidence archives must pass before any project is removed.
            for argv in commands:
                run(*argv)
        else:
            assert {(r["kind"], r["metadata"]["name"]) for r in before["owned"]["items"]} == {
                ("ConfigMap", "ai-traffic"), ("Pod", "ai-traffic-client"),
                ("Pod", "ai-traffic-backend"), ("F5BigCnePool", "ai-traffic"),
                ("F5VirtualServer", "ai-traffic")}
            for name in ("jig.py", "backend.py", "client.py"):
                digest = run("sha256sum", "/home/starin/ai-traffic-jig/" + name).split()[0]
                assert digest == hashlib.sha256((ROOT / "env/ai-traffic" / name).read_bytes()).hexdigest(), name
            record["backend_final_log"] = kube("logs", "ai-traffic-backend")
            run("python3", "/home/starin/ai-traffic-jig/jig.py", "down")

    def verify(before, after):
        def stable_containers(state):
            return [{k: c[k] for k in ("id", "name", "image", "state", "restarts", "mounts")}
                    for c in state["containers"] if c["project"] not in PROJECTS]
        assert stable_containers(before) == stable_containers(after)
        assert not any(p["test_markers"] for p in after["host_scan"]["processes"])
        if args.role == "build":
            assert not any(c["project"] in PROJECTS for c in after["containers"])
            assert not after["compose"]
            assert not any(p["comm"].startswith("tmm.") for p in after["host_scan"]["processes"])
            for kind in ("networks", "volumes"):
                assert not any(project in after[kind] for project in PROJECTS)
        else:
            assert not after["owned"]["items"]
            assert [p for p in before["pods"] if p["name"] not in ("ai-traffic-client", "ai-traffic-backend")] == after["pods"]
            assert before["runtime"] == after["runtime"]
            assert before["probes"] == after["probes"]
            def routes(state):
                return [{"uid": r["metadata"]["uid"], "spec": r["spec"]}
                        for r in state["routes"]["items"] if r["metadata"]["name"] != "ai-traffic"]
            assert routes(before) == routes(after)

    with args.output.open("x") as receipt:
        try:
            record["before"] = snapshot()
            if args.action == "cleanup":
                cleanup(record["before"])
                record["after"] = snapshot()
                verify(record["before"], record["after"])
            record["passed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            record["finished"] = time.time()
            json.dump(record, receipt, indent=2)
            receipt.write("\n")
    print(json.dumps({"role": args.role, "action": args.action, "passed": True,
                      "receipt": str(args.output)}))


if __name__ == "__main__":
    main()
