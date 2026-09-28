#!/usr/bin/env python3
"""P21 pinned-toolchain bench and Unix-socket checks; NOT live TMM evidence.

Optional --receipt writes an exclusive JSON record even when a check fails.
Run on the build box with UBPF/PREVAIL pointing at the pinned installations.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
RECORD = {"scope": "P21 build-box bench and socket harness; no live TMM", "commands": [],
          "checks": [], "passed": False}


def run(*args, check=True, env=None):
    p = subprocess.run([str(a) for a in args], text=True, capture_output=True,
                       timeout=180, env=env)
    RECORD["commands"].append({"argv": [str(a) for a in args], "rc": p.returncode,
                               "stdout": p.stdout, "stderr": p.stderr})
    print(p.stdout, end="", flush=True)
    print(p.stderr, end="", file=sys.stderr, flush=True)
    if check:
        p.check_returncode()
    return p


def checked(name):
    RECORD["checks"].append(name)
    print("PASS", name, flush=True)


def sockets(server_binary, directory):
    client_path = HERE.parent / "env/scripts/ls-load.py"
    spec = importlib.util.spec_from_file_location("config_client", client_path)
    client = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(client)
    path = directory / "loader.sock"
    server = subprocess.Popen([str(server_binary), str(path)], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)
    try:
        assert select.select([server.stdout], [], [], 10)[0], "socket harness startup timeout"
        assert server.stdout.readline().strip() == "READY"

        def send(payload, fragmented=False):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect(str(path))
                if fragmented:
                    for offset in range(0, len(payload), 13):
                        s.sendall(payload[offset:offset + 13])
                        time.sleep(0.0005)
                else:
                    s.sendall(payload)
                s.shutdown(socket.SHUT_WR)
                answer = b""
                while True:
                    data = s.recv(4096)
                    if not data:
                        return answer.decode().strip()
                    answer += data

        status = send(client.msg(client.OP_CONFIG_STATUS, slot=5), True)
        assert status.startswith("OK config "), status
        identity = json.loads(status[len("OK config "):])
        document = {"abi": 1, "schema": 1, "session": identity["session"],
                    "instance": identity["instance"], "expected_revision": 0, "revision": 1,
                    "program_sha256": identity["program_sha256"],
                    "rows": [struct.pack("<QQQQ", 100, 1, 0, 0).hex()]}
        body = client.config_body(document)
        response = send(client.msg(client.OP_CONFIG_PUBLISH, slot=5, prog=body), True)
        assert response == "OK config published slot=5 revision=1", response
        assert "revision conflict" in send(client.msg(client.OP_CONFIG_PUBLISH, slot=5, prog=body))
        checked("fragmented headers/bodies accepted; stale replay refused by actual handler")
        updated = copy.deepcopy(document)
        updated.update(expected_revision=1, revision=2)
        raw = client.msg(client.OP_CONFIG_PUBLISH, slot=5, prog=client.config_body(updated))
        assert "trailing bytes" in send(raw + b"x")
        assert "exceeds received payload" in send(raw[:-1])
        assert "short message" in send(raw[:20])
        assert "takes no payload" in send(client.msg(client.OP_CONFIG_STATUS, slot=5, prog=b"x"))
        assert "no loaded instance" in send(client.msg(client.OP_CONFIG_STATUS, slot=6))
        assert json.loads(send(client.msg(client.OP_CONFIG_STATUS, slot=5))[10:])["revision"] == 1
        checked("truncated/trailing/status payloads rejected without changing published revision")

        for field, value in (("abi", 2), ("schema", 0), ("revision", True),
                             ("session", "0" * 16), ("instance", "0" * 16),
                             ("rows", ["00"]), ("rows", ["00" * 32] * 17),
                             ("unexpected", 1)):
            bad = copy.deepcopy(updated)
            bad[field] = value
            try:
                client.config_body(bad)
            except ValueError:
                continue
            raise AssertionError("client accepted " + field)
        checked("client rejects malformed schema, numbers, records and unknown fields")

        env = dict(os.environ, LS_LOAD_SOCKET=str(path), PYTHONDONTWRITEBYTECODE="1")
        snapshot = directory / "snapshot.json"
        snapshot.write_text(json.dumps(updated))
        run(sys.executable, client_path, "config-publish", 5, snapshot, env=env)
        p = run(sys.executable, client_path, "config-publish", 5, snapshot, env=env, check=False)
        assert p.returncode != 0 and "revision conflict" in p.stderr
        p = run(sys.executable, client_path, "config-status", 5, env=env)
        assert json.loads(p.stdout)["revision"] == 2
        snapshot.write_text('{"abi":1,"abi":1}')
        p = run(sys.executable, client_path, "config-publish", 5, snapshot, env=env, check=False)
        assert p.returncode and "duplicate" in p.stderr
        for response in ("", "ERR denied", "OK config published\n<timed out waiting for a reply>"):
            client.send = lambda payload, response=response: response
            try:
                client.config_send(b"")
            except ValueError:
                continue
            raise AssertionError("ambiguous response accepted")
        checked("CLI publish/status round trip; refusal, duplicate JSON, empty/timeout replies fail")
    finally:
        server.terminate()
        stdout, stderr = server.communicate(timeout=10)
        RECORD["socket_server"] = {"stdout": stdout, "stderr": stderr, "exit": server.returncode,
                                   "terminated_by_test": True}
        assert not stderr, stderr


def main():
    clang = os.environ.get("CLANG", "clang-18")
    ubpf = Path(os.environ.get("UBPF", str(HERE.parent / "ubpf"))).resolve()
    prevail = Path(os.environ.get("PREVAIL", str(HERE.parent / "ebpf-verifier/bin/prevail"))).resolve()
    objcopy = os.environ.get("OBJCOPY", "/usr/lib/llvm-18/bin/llvm-objcopy")
    assert "18.1.3" in run(clang, "--version").stdout
    run("gcc", "--version")
    assert run("git", "-C", ubpf, "rev-parse", "HEAD").stdout.strip() == "c900ed9faf1d41358a7ea9217ccd0b64a4ee8d5d"
    assert run("git", "-C", prevail.parent.parent, "rev-parse", "HEAD").stdout.strip() == "06769f7b508214e63b97905d275920f7e90182fa"
    sources = ["ls_config.h", "config_snapshot.bpf.h", "ls_map.h", "ls_map_glue.h",
               "ls_vm.c", "ls_vm_load.c", "shield_abi.h", "ls_audit.c", "check_config.c",
               "check_config_socket.c", "check_config.py", "check_glue_owner.c",
               "check_glue_user.c", "check_glue_stubs.c", "surfaces/config_threshold.bpf.c",
               "../env/scripts/ls-load.py"]
    RECORD["source_sha256"] = {s: hashlib.sha256((HERE / s).read_bytes()).hexdigest() for s in sources}
    RECORD["tool_sha256"] = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                              for p in (prevail, ubpf / "build/lib/libubpf.a")}
    with tempfile.TemporaryDirectory(prefix="ls-config-") as temporary:
        d = Path(temporary)
        includes = ["-I" + str(HERE), "-I" + str(ubpf / "vm/inc"), "-I" + str(ubpf / "build/vm")]
        flags = ["-O2", "-Wall", "-Wextra", "-Werror"]
        obj = d / "config.bpf.o"
        run(clang, "-O2", "-g", "-target", "bpf", "-c", HERE / "surfaces/config_threshold.bpf.c", "-o", obj)
        run(objcopy, "--remove-section=.BTF", "--remove-section=.BTF.ext", "--remove-section=.rel.BTF.ext", obj)
        verified = run(prevail, obj, "fentry/config_fixture", "--termination", "--strict", "--no-division-by-zero", "--stack-size", "256")
        assert verified.stdout.startswith("PASS:"), "verifier returned no explicit PASS"
        RECORD["object_sha256"] = hashlib.sha256(obj.read_bytes()).hexdigest()
        run("gcc", *flags, *includes, "-pthread", HERE / "check_config.c", ubpf / "build/lib/libubpf.a", "-lm", "-o", d / "check-config")
        run(d / "check-config", obj)
        run("gcc", *flags, *includes, HERE / "check_glue_owner.c", HERE / "check_glue_user.c",
            HERE / "check_glue_stubs.c", "-o", d / "check-glue")
        run(d / "check-glue")
        run("gcc", *flags, *includes, "-ffunction-sections", "-fdata-sections",
            HERE / "check_config_socket.c", "-Wl,--gc-sections", "-pthread", "-o", d / "config-socket")
        sockets(d / "config-socket", d)
        for source in ("ls_vm.c", "ls_vm_load.c", "ls_audit.c"):
            run("gcc", *flags, *includes, "-fsyntax-only", HERE / source)
        checked("changed TMM translation units syntax-check with pinned uBPF headers")
    RECORD["passed"] = True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    if args.receipt and args.receipt.exists():
        parser.error("receipt exists; preserve it and use a new filename")
    try:
        main()
    except BaseException as exc:
        RECORD["error"] = str(exc)
        raise
    finally:
        if args.receipt:
            with args.receipt.open("x") as f:
                json.dump(RECORD, f, indent=2)
                f.write("\n")
