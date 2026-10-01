#!/usr/bin/env python3
"""Verify retained native void-completion evidence, not live TMM coverage."""
import argparse
import hashlib
import json
from pathlib import Path


PINS = {
    "void-completion-build-01.json": "2cae2546c1e2d9559bd71b04efcca51190d37133764df611b6c9a283e4f49bbc",
    "void-completion-build-02.json": "05d7cbaf045180bb43a66a3e2c56ee362b3f54a11a8c01e1d5b6247ebc16a09e",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify(cache, source, substrate, fixture):
    records = []
    snapshots = 0
    for name, expected in PINS.items():
        raw = (cache / name).read_bytes()
        require(sha(raw) == expected, "receipt changed: " + name)
        r = json.loads(raw)
        for path, item in r["sources"].items():
            require(sha(item["text"].encode()) == item["sha256"], "source mismatch: " + path)
            snapshots += 1
        require(r["discovery_sha256"] ==
                "787a96e8d860640f509a4143ff380530ef2708ad3ee01e16c24c9699c7c6b2f0",
                "qualification source changed")
        records.append(r)
    failed, result = records
    require(failed["passed"] is False and
            failed["error"] == "FileNotFoundError(2, 'No such file or directory')",
            "lost preflight failure")
    require(result["passed"] is True and "error" not in result, "native test did not pass")
    require(result["scope"] == "native_void_completion_adapter_only", "wrong evidence scope")
    require(result["compilers"] == 2 and result["cases_per_compiler"] == 24 and
            result["observed_returns_per_compiler"] == 1100, "unexpected counts")
    commands = result["commands"]
    require(all(c["rc"] == 0 for c in commands), "failed command in passing receipt")
    require(any(c["argv"] == ["uname", "-m"] and c["stdout"].strip() == "x86_64"
                for c in commands), "wrong machine")
    for compiler, version in (("gcc", "13.3.0"), ("clang-18", "18.1.3")):
        require(any(c["argv"] == [compiler, "--version"] and version in c["stdout"]
                    for c in commands), "wrong compiler: " + compiler)
        builds = [c for c in commands if c["argv"][0] == compiler and "--version" not in c["argv"]
                  and "-Wl,--wrap=ls_fexit_enter" in c["argv"]]
        require(len(builds) == 1 and "-Werror" in builds[0]["argv"] and
                not any("NDEBUG" in arg for arg in builds[0]["argv"]), "wrong native build")
        runs = [c for c in commands if c["argv"][0].endswith("/void-" + compiler)]
        require(len(runs) == 1 and all(f"PASS noise={n} cases=12 observed_returns=550" in runs[0]["stdout"]
                                      for n in (0, 1)), "missing native outcomes")
    for name, expected in (("fexit-regression", "exit trampoline validated:"),
                           ("context-regression", "context contract: entry + exit, 96 bytes")):
        runs = [c for c in commands if c["argv"][0].endswith("/" + name)]
        require(len(runs) == 1 and expected in runs[0]["stdout"], "regression missing: " + name)
    for path, item in result["sources"].items():
        name = Path(path).name
        if name.endswith(".md"):
            continue
        local = source / name if name == "void_completion_build.py" else substrate / name
        if name in ("check_void_fexit.c", "void_fexit_victim.S"):
            local = fixture / name
        require(sha(local.read_bytes()) == item["sha256"], "current source changed: " + name)
    for flag in ("production_entry_capture_implemented", "live_initialization_validated", "lifecycle_validated"):
        require(result[flag] is False, "unsupported claim: " + flag)
    return dict(passed=True, evidence_tier="MEASURED", scope=result["scope"],
                witnesses=["SELF", "TOOL"], checked_source_snapshots=snapshots,
                compiler_variants=2, cases_per_compiler=24, observed_returns_per_compiler=1100,
                regressions=["ordinary_return_hooks", "96_byte_context_contract"],
                production_entry_capture_implemented=False, live_initialization_validated=False,
                lifecycle_validated=False, receipts=PINS)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parents[2]
    parser.add_argument("--cache", type=Path, default=root / "evidence/cache")
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--substrate-root", type=Path, default=root / "substrate")
    parser.add_argument("--fixture-root", type=Path, default=root / "substrate")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = verify(args.cache, args.source_root, args.substrate_root, args.fixture_root)
    if args.output:
        data = Path(__file__).read_bytes()
        with args.output.open("x") as output:
            json.dump(dict(result=result, verifier=dict(text=data.decode(), sha256=sha(data))), output, indent=2)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
