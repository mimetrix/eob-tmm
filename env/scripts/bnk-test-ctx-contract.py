#!/usr/bin/env python3
"""Datkube: test signed context probes on one pinned, stable TMM pod.

Usage: bnk-test-ctx-contract.py POD PROGDIR EXPECTED_BUILD_ID
Requires the 96-byte allocation fix, LS_VM_SAMPLES=1, LS_VM_JIT=1,
LS_VM_VERBOSE=1, a disabled slot 0, and a working HTTP/1 listener.
VIP_URL defaults to http://11.11.11.99:18081/ (ctx-contract-test.yaml).
Verdict 1 is a test result in MONITOR
mode; it is never evidence that a request was blocked. No timing is measured.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def run(args, quiet=False, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, timeout=120, **kwargs)
    if not quiet:
        print(result.stdout, end="", flush=True)
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr, flush=True)
    result.check_returncode()
    return result.stdout


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    pod, progdir, build = sys.argv[1:]
    url = os.environ.get("VIP_URL", "http://11.11.11.99:18081/")
    k = ["kubectl", "exec", pod, "-c", "f5-tmm", "--"]
    hook = "http_parse_client_headers"

    def identity():
        data = json.loads(run(["kubectl", "get", "pod", pod, "-o", "json"], quiet=True))
        status = next(c for c in data["status"]["containerStatuses"] if c["name"] == "f5-tmm")
        assert status["ready"], "TMM is not Ready"
        return data["metadata"]["uid"], status["containerID"], status["restartCount"], status["imageID"]

    initial = identity()
    print("pinned pod identity:", initial, flush=True)
    # Read the EXECUTING ELF, not merely a path in the image. Verify it against
    # both the caller's expected build and the baked arming index.
    observed = run(k + ["python3", "-c", '''
import glob, hashlib, os, subprocess, struct
paths = []
for p in glob.glob("/proc/[0-9]*/exe"):
    try:
        if os.readlink(p).endswith("/tmm64.no_pgo"): paths.append(p)
    except OSError: pass
assert len(paths) == 1, paths
p = paths[0]
bid = subprocess.check_output(["python3", "/usr/share/ls/ls_buildid.py", p], text=True).strip()
index = next(l for l in open("/usr/share/ls/hook-index.tsv") if l.startswith("#build_id\\t")).strip().split("\\t")
assert index == ["#build_id", bid], index
b = open(p, "rb").read()
off, = struct.unpack_from("<Q", b, 0x28)
ent, num, stridx = struct.unpack_from("<HHH", b, 0x3a)
sh = lambda i: struct.unpack_from("<IIQQQQ", b, off + i*ent)
_, _, _, _, so, sz = sh(stridx)
names = b[so:so+sz]
assert not any(names[sh(i)[0]:].split(b"\\0", 1)[0].startswith(b".BTF") for i in range(num))
print("EXECUTING", p, bid, "BTF=absent", "sha256=" + hashlib.sha256(b).hexdigest())
'''])
    assert f" {build} BTF=absent" in observed, "wrong executing build"
    pid = re.search(r"EXECUTING /proc/(\d+)/exe", observed).group(1)
    sock = run(k + ["python3", "-c", 'import glob; s=glob.glob("/tmp/ls_load.sock.*"); assert len(s)==1,s; print(s[0])']).strip()

    def pad():
        out = run(k + ["python3", "-c", '''
import sys
row = next(l.split("\\t") for l in open("/usr/share/ls/hook-index.tsv")
           if l.startswith(sys.argv[2] + "\\t"))
assert row[2] == "pad", row
with open("/proc/" + sys.argv[1] + "/mem", "rb", buffering=0) as f:
    f.seek(int(row[1], 16))
    print("PAD", row[1], f.read(5).hex())
''', pid, hook])
        return bytes.fromhex(out.split()[-1])

    def loader(*args):
        out = run(k + ["env", f"LS_LOAD_SOCKET={sock}", "python3", "/usr/bin/ls-load.py", *args])
        assert "ERR " not in out, out
        return out

    def status():
        out = loader("status", "0")
        values = {key: int(value) for key, value in re.findall(r"(\w+)=(\d+)", out)}
        assert {"armed", "mode", "gen", "fired", "safe_returns", "errors"} <= values.keys(), out
        return values

    def requests(count):
        script = 'for i in $(seq 1 "$1"); do curl -x "" --http1.1 --fail --silent --show-error --max-time 8 -H "Connection: close" -o /dev/null -w "%{http_code}\\n" "$2" || exit; done'
        out = run(["kubectl", "exec", "client", "--", "sh", "-c", script, "ctx-test", str(count), url])
        assert out.splitlines() == ["200"] * count, out

    assert status()["mode"] == 0, "slot 0 has an enabled program"
    assert pad() == b"\x90" * 5, "hook is already patched"
    requests(4)
    deliver = str(Path(__file__).with_name("bnk-deliver-program.py"))
    for kind in ("fentry", "fexit"):
        assert identity() == initial, "pod changed before test"
        obj = str(Path(progdir) / f"ctx96-{kind}.bpf.o")
        out = run(["python3", deliver, obj, "0", "1", hook], env={**os.environ, "POD": pod})
        assert "signature=verified" in out, out
        armed = False
        try:
            armed = True
            assert "ARMED LIVE" in loader("arm", "0", hook)
            assert pad()[0] in (0xe8, 0xe9), "entry was not patched"
            before = status()
            assert before["mode"] == 1 and before["armed"] == 1, before
            requests(32)
            after = status()
            assert after["gen"] == before["gen"], "program changed during test"
            delta = {key: after[key] - before[key] for key in ("fired", "safe_returns", "errors")}
            assert delta == {"fired": 32, "safe_returns": 32, "errors": 0}, delta
            samples = loader("samples", "0")
            matches = re.findall(r"sample seq=(\d+) len=(\d+) verdict=(\d+) ctx=([0-9a-f]+)", samples)
            assert len(matches) == 8, samples
            for seq, length, verdict, ctx in matches:
                assert int(seq) > before["fired"] and (length, verdict) == ("96", "1"), samples
                raw = bytes.fromhex(ctx)
                assert len(raw) == 48 and int.from_bytes(raw[:8], "little") != 0, samples
                if kind == "fentry":
                    assert int.from_bytes(raw[40:48], "little") == 0x6374783936746169, samples
            assert "DISARMED LIVE" in loader("disarm", hook)
            armed = False
            assert pad() == b"\x90" * 5, "disarm did not restore the pad"
            stopped = status()
            requests(8)
            final = status()
            assert final["fired"] == stopped["fired"], final
            assert identity() == initial, "pod changed during test"
            print(f"PASS {kind}: {delta}; len=96; 8 post-disarm HTTP 200s, no fires", flush=True)
        finally:
            if armed:
                loader("disarm", hook)
            loader("revoke", "0")
    logs = run(["kubectl", "logs", pod, "-c", "f5-tmm", "--since=10m"], quiet=True)
    print("\n".join(line for line in logs.splitlines() if "ls_vm:" in line), flush=True)
    for kind in ("fentry", "fexit"):
        # Reload JITs in a spare slot, then publishes that VM/jit_fn into slot 0.
        assert re.search(rf"ls_vm:.*slot=\d+ section={kind}/{hook} function=check_ctx_live .*jit=1", logs), "missing JIT load witness"
    print("PASS live entry/exit context contract; stable pod, no new restarts", flush=True)


if __name__ == "__main__":
    main()
