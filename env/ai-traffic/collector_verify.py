#!/usr/bin/env python3
"""Check cached collector receipts, exact payloads and the archived journal."""
import hashlib
import json
from pathlib import Path
import sqlite3
import tarfile

from method_decode import decode
from collector_container_verify import verify as verify_container


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    cache = Path(__file__).resolve().parents[2] / "evidence/cache"
    root = cache.parent.parent
    records = {}
    sources = 0
    for path in sorted(cache.glob("collector-*-20260928.json")):
        record = json.loads(path.read_text())
        records[path.name] = record
        for source in record.get("sources", {}).values():
            assert digest(source["text"].encode()) == source["sha256"]
            sources += 1
    build = records["collector-build-03-20260928.json"]
    live = records["collector-live-02-20260928.json"]
    cleanup = records["collector-cleanup-01-20260928.json"]
    assert build["passed"] and live["passed"] and cleanup["passed"]
    assert live["collector_build"] == build
    # The old receipt stays immutable. Check current native sources against the
    # later build that adds the Unix API, then verify each saved live result.
    for path, source in records["collector-build-04-20260928.json"]["sources"].items():
        name = Path(path).name
        if name in ("ls_stream.c", "check_stream_source.c"):
            current = root / "substrate/drain" / name
        elif name in ("stream_collector.py", "check_stream_collector.py", "collector_build.py", "method_decode.py", "collector_client.py"):
            current = Path(__file__).with_name(name)
        else:
            continue
        assert digest(current.read_bytes()) == source["sha256"], name
    for name in ("collector_suite.py", "collector_session.py", "lifetime_live_run.py",
                 "metadata_suite.py", "method_suite.py"):
        assert digest(Path(__file__).with_name(name).read_bytes()) == live["sources"][name]["sha256"], name
    assert not live["collector_ready"]["segment_exists_at_start"]
    assert live["collector_stop"]["returncode"] == 0
    assert cleanup["live_sha256"] == digest((cache / "collector-live-02-20260928.json").read_bytes())
    result = json.loads(live["files"]["result.json"])
    assert result["passed"] and len(result["clients"]) == 10
    pages = [row for page in result["stream_pages"] for row in page["events"]]
    first = [row for row in pages if row["event"]["type"] == "record"]
    second = [row for row in result["second_consumer"]["events"] if row["event"]["type"] == "record"]
    assert first == second and len(first) == 8
    decoded = [decode(bytes.fromhex(row["event"]["raw"]["data"])) for row in first]
    assert decoded == result["events"]
    assert [row["sequence"] for row in decoded] == list(range(1, 9))
    assert all(not row["output_failures"] for row in decoded)
    assert not any(row["event"]["type"] == "observation_gap" for row in pages)
    source = first[0]["event"]["source"]
    witness = live["witnesses"]["method"]["initial"]
    assert source["pid"] == witness["pid"] and source["start"] == witness["stat"].split()[21]
    assert result["counter_end"]["method"]["fired"] - result["counter_start"]["method"]["fired"] == 8
    archive = cache / "collector-evidence-01-20260928.tar.gz"
    assert digest(archive.read_bytes()) == cleanup["archive"]["sha256"]
    files = {}
    database = None
    with tarfile.open(archive, "r:gz") as stream:
        for member in stream.getmembers():
            if member.isfile():
                name = member.name.removeprefix("./")
                assert name not in files
                data = stream.extractfile(member).read()
                files[name] = digest(data)
                if name == "collector-live-02/journal.sqlite":
                    database = data
    assert files == cleanup["manifest"]
    assert database is not None and digest(database) == live["journal"]["sha256"]
    db = sqlite3.connect(":memory:")
    try:
        db.deserialize(database)
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        archived = [json.loads(row[0]) for row in db.execute("SELECT body FROM events ORDER BY id")]
        assert archived == [row["event"] for row in pages]
        assert len(archived) == live["journal"]["events"]
    finally:
        db.close()
    print(json.dumps({"verified": True, "source_hashes": sources, "archive_files": len(files),
                      "separate_container": verify_container(cache),
                      "journal_events": len(archived), "method_records": len(decoded),
                      "values": [{"status": row["status_name"], "value_hex": row["value_hex"]}
                                 for row in decoded]}, indent=2))


if __name__ == "__main__":
    main()
