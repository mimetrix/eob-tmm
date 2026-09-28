"""Build-box P17 real-metadata check; retained with the evidence log."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

HOME = Path.home()
SUB = HOME / "eob-tmm-staged/substrate"
DATA = HOME / "lstools"
OUT = HOME / "embedded-p17-20260924"
OUT.mkdir(exist_ok=True)
sys.path.insert(0, str(SUB))
import gen_type_catalog
import tmmtrace


def run(*args):
    print("COMMAND", *args, flush=True)
    return subprocess.run([str(a) for a in args], check=True)


def digest(p):
    print("SHA256", hashlib.sha256(p.read_bytes()).hexdigest(), p, flush=True)


receipt = json.loads((DATA / "runtime-identity.json").read_text())
print("RUNTIME RECEIPT", json.dumps(receipt), flush=True)
assert receipt["build_id"] == "c3b81927dfdcc31137cd8212b5e23bb85677a06c"
for p in (DATA / "tmm.btf", DATA / "signatures.tsv", DATA / "hook-index.tsv",
          SUB / "gen_type_catalog.py", SUB / "tmmtrace.py", Path(__file__)):
    digest(p)
cat = gen_type_catalog.build(str(DATA / "tmm.btf"))
old = json.loads((DATA / "types.json").read_text())
assert all(cat.get(k) == v for k, v in old.items() if k != "__embedded__")
print("PASS all existing catalog keys unchanged; embedded owner types", len(cat["__embedded__"]), flush=True)
(OUT / "types.json").write_text(json.dumps(cat))
digest(OUT / "types.json")
tmmtrace._types_cache = cat
cases = {
    "nested": "fexit/http_parse_client_headers /args.cache.cur_entries > 0/ { count() }",
    "nested-control": "fexit/http_parse_client_headers /args.cache.cur_entries == 0/ { count() }",
    "embedded-pointer": "fentry/http_parse_client_headers /args.xfrag_head.tqh_first.len > 0/ { count() }",
    "pointer-embedded": "fentry/http2_http_data_to_frames /arg0.http_data.ci.http.cache.cur_entries > 0/ { count() }",
}
programs = []
for name, expr in cases.items():
    print("CASE", name, expr, flush=True)
    obj, fn, section, hook = tmmtrace.build_prog(expr, str(OUT))
    programs.append((name, Path(obj), fn, section, hook))
run("gcc", "-O2", "-DLS_CORE_RELO_TEST", SUB / "ls_core_relo.c", "-o", OUT / "relo")
run("python3", SUB / "check_relo_baked.py", DATA / "tmm.btf",
    *(p[1] for p in programs), "--relo", OUT / "relo")
target = OUT / "target"
target.mkdir(exist_ok=True)
debs = HOME / "code/tmm/docker_build/DEBS/amd64"
for pat in ("tmm_*.deb", "tmm-debuginfo_*.deb"):
    matches = list(debs.glob(pat))
    assert len(matches) == 1, matches
    run("dpkg-deb", "-x", matches[0], target)
rt = target / "usr/bin/tmm64.no_pgo"
dbg, = target.rglob("tmm64.no_pgo.debug")
assert hashlib.sha256(rt.read_bytes()).hexdigest() == receipt["sha256"]
objcopy = "/usr/lib/llvm-18/bin/llvm-objcopy"
manifest = []
for name, obj, fn, section, hook in programs:
    final = OUT / (name + ".bpf.o")
    run(OUT / "relo", obj, DATA / "tmm.btf", final)
    run(objcopy, "--remove-section=.BTF", "--remove-section=.BTF.ext", "--remove-section=.rel.BTF.ext", final)
    run("python3", SUB / "bind_target.py", "--prog", final, "--binary", rt,
        "--debug", dbg, "--index", DATA / "hook-index.tsv", "--objcopy", objcopy)
    run(tmmtrace.PREVAIL, final, section, "--termination", "--strict", "--no-division-by-zero", "--stack-size", "256")
    sig = OUT / (name + ".bpf.sig")
    run("python3", SUB / "sign_shield.py", "--key", HOME / ".ls-signing/shield_sk.pem",
        "--prog", final, "--hook", hook, "--mode-ceiling", "monitor", "--build-min",
        "0xc3b81927", "--build-max", "0xc3b81927", "-o", sig)
    digest(final)
    digest(sig)
    manifest.append({"name": name, "fn": fn, "hook": hook, "expr": cases[name]})
(OUT / "programs.json").write_text(json.dumps(manifest, indent=2))
backup = DATA / "types.json.pre-embedded-20260924"
if not backup.exists():
    backup.write_bytes((DATA / "types.json").read_bytes())
pending = DATA / "types.json.pending"
pending.write_bytes((OUT / "types.json").read_bytes())
os.replace(pending, DATA / "types.json")
print("PASS real-TMM authoring: independent relocation check, bind, final PREVAIL, sign; not live execution", flush=True)
