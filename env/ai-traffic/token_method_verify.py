#!/usr/bin/env python3
"""Verify saved token-method evidence and optionally export captured values."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import tarfile
import xml.etree.ElementTree as ET
from token_method_decode import decode

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / "evidence/cache"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify():
    manifest = dict((name, sha) for sha, name in
                    (line.split() for line in (CACHE / "MANIFEST.sha256").read_text().splitlines()
                     if line and not line.startswith("#")))
    receipts = {}
    checked_sources = 0
    for path in sorted(CACHE.glob("token-method-*")):
        data = path.read_bytes()
        assert digest(data) == manifest[path.name], path.name
        if path.suffix != ".json":
            continue
        doc = json.loads(data)
        receipts[path.stem] = doc
        sources = doc.get("sources", doc.get("files", {}))
        for name, source in sources.items():
            if isinstance(source, dict) and "text" in source:
                assert digest(source["text"].encode()) == source["sha256"], name
                checked_sources += 1
    build = receipts["token-method-build-04"]
    live = receipts["token-method-live-02"]
    cleanup = receipts["token-method-cleanup-01"]
    discovery = receipts["token-method-discovery-02"]
    assert build["passed"] and live["passed"] and cleanup["passed"] and discovery["completed"]
    assert not receipts["token-method-build-01"]["passed"]
    assert not receipts["token-method-live-01"]["passed"]
    assert build == live["program_build"]
    assert build["discovery_sha256"] == manifest["token-method-discovery-02.json"]
    assert cleanup["live_sha256"] == manifest["token-method-live-02.json"]
    assert cleanup["archive"]["sha256"] == manifest["token-method-evidence-01.tar.gz"]
    assert live["before"] == live["after"]
    assert live["image_build"]["image"] == live["collector"]["image"]
    assert live["source_binding"]["sha256"] == build["runtime"]["sha256"]
    for path in (ROOT / "substrate/surfaces/token_method.bpf.c",
                 ROOT / "substrate/surfaces/token_method_abi.h",
                 ROOT / "substrate/surfaces/json_method_abi.h",
                 ROOT / "substrate/check_token_method.c"):
        saved, = [s for name, s in build["sources"].items() if name.endswith("/" + str(path.relative_to(ROOT / "substrate")))]
        assert digest(path.read_bytes()) == saved["sha256"], path
    for name in ("token_method_suite.py", "token_method_live.py", "token_method_decode.py", "icap-run-suite.sh"):
        assert digest((ROOT / "env/ai-traffic" / name).read_bytes()) == live["sources"][name]["sha256"], name
    native = [decode(bytes.fromhex(line[7:])) for cmd in build["commands"]
              for line in cmd["stdout"].splitlines() if line.startswith("RECORD ")]
    assert native == build["native_events"] and len(native) == 68
    assert any(cmd["argv"][0].endswith("/prevail") and cmd["stdout"].startswith("PASS:")
               and cmd["argv"][-2:] == ["--stack-size", "256"] for cmd in build["commands"])
    files = {}
    with tarfile.open(CACHE / "token-method-evidence-01.tar.gz", "r:gz") as archive:
        for member in archive.getmembers():
            assert member.isdir() or member.isfile(), member.name
            if member.isfile():
                name = member.name.removeprefix("./")
                assert name not in files and ".." not in Path(name).parts
                files[name] = archive.extractfile(member).read()
    assert {name: digest(data) for name, data in files.items()} == cleanup["manifest"]
    test = json.loads(live["files"]["result.json"])
    assert files["token-method-live-02/result.json"].decode() == live["files"]["result.json"]
    xml = ET.fromstring(files["token-method-live-02/tao.xml"])
    assert not xml.findall(".//failure") and not xml.findall(".//error") and xml.findall(".//testcase")
    assert test["passed"] and not test["cleanup_errors"] and not test["backend_errors"]
    assert len(test["clients"]) == len(test["origin"]) == len(test["comparisons"]) == 13
    rows = [row for page in test["stream_pages"] for row in page["events"]]
    assert len(rows) == 28 and len({r["cursor"] for r in rows}) == len(rows)
    records = [r["event"] for r in rows if r["event"]["type"] == "record"]
    assert len(records) == len({r["event_id"] for r in records}) == 26
    assert records == [r["event"] for r in test["replay_consumer"]["events"] if r["event"]["type"] == "record"]
    events = [decode(bytes.fromhex(r["raw"]["data"])) for r in records]
    assert events == test["events"] == [e for c in test["comparisons"] for e in c["events"]]
    identity = test["instances"]["token"]
    for n, event in enumerate(events, 1):
        assert event["sequence"] == n and event["instance"] == int(identity["instance"], 16)
        assert event["revision"] == identity["revision"] and event["run"] == test["run_token"]
        assert not event["flags"] and not event["output_failures"]
    before, after = test["counter_start"]["token"], test["counter_end"]["token"]
    assert after["fired"] - before["fired"] == 26
    assert all(after[k] == before[k] for k in ("errors", "safe_returns", "gen"))
    assert not any(r["event"]["type"] == "observation_gap" for r in rows)
    health = [r["event"] for r in rows if r["event"]["type"] == "ring_health"]
    assert health and all(int(r["raw"]["drops"]) == 0 for r in health)
    for case in test["comparisons"]:
        event, response = case["events"]
        assert event["status_name"] == case["expected_status"]
        assert response["status_name"] == "no_literal_method"
        if case["expected_value_hex"] is not None:
            expected = bytes.fromhex(case["expected_value_hex"])
            assert event["value_hex"] == expected[:64].hex()
            assert event["original_length"] == len(expected)
    witness = live["witnesses"]["token"]
    assert witness["initial"]["sha256"] == build["runtime"]["sha256"]
    assert witness["initial"]["bytes"].startswith("9090909090")
    assert len([r for r in witness["changes"] if r["bytes"].startswith("e8")]) == 1
    final = witness["changes"][-1]
    assert final["final"] and final["bytes"] == witness["initial"]["bytes"]
    assert final["stat"].split()[21] == witness["initial"]["stat"].split()[21]
    journal = files["token-method-live-02/events.sqlite"]
    assert digest(journal) == live["journal_sha256"]
    db = sqlite3.connect(":memory:")
    try:
        db.deserialize(journal)
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert [json.loads(r[0]) for r in db.execute("SELECT body FROM events ORDER BY id")] == [r["event"] for r in rows]
    finally:
        db.close()
    return dict(passed=True, evidence_tier="MEASURED", value_witness="SELF",
                checked_sources=checked_sources, archive_files=len(files), native_records=len(native),
                live_requests=13, live_records=26, journal_events=28,
                source_receipt="token-method-live-02.json", source_sha256=manifest["token-method-live-02.json"],
                hook=build["programs"]["token"]["section"],
                observations=events)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export", action="store_true", help="include decoded captured records")
    args = parser.parse_args()
    result = verify()
    if not args.export:
        result.pop("observations")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
