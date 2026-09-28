#!/usr/bin/env python3
"""Verify cached container recovery evidence without another live traffic run."""
import hashlib
import json
from pathlib import Path
import sqlite3
import tarfile
import xml.etree.ElementTree as ET

from method_decode import decode


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify(cache):
    def load(stem):
        return json.loads((cache / (stem + "-20260928.json")).read_text())

    image = load("collector-image-02")
    native = load("collector-build-04")
    original = load("collector-container-live-03")
    live = load("collector-container-recovery-01")
    cleanup = load("collector-container-cleanup-01")
    assert image["passed"] and native["passed"] and live["passed"] and cleanup["passed"]
    assert not original["passed"] and original["error"] == "KeyError('event_id')"
    assert live["retained_failure"]["sha256"] == digest((cache / "collector-container-live-03-20260928.json").read_bytes())
    assert live["image_build"] == image and image["native_build"] == native
    assert cleanup["live_sha256"] == digest((cache / "collector-container-recovery-01-20260928.json").read_bytes())
    for record in (image, native, original, live, cleanup):
        for row in record["sources"].values():
            assert digest(row["text"].encode()) == row["sha256"]
    # Core runtime/deployment sources must still match the measured image/run.
    for name in ("collector_container.py", "collector_client.py", "stream_collector.py",
                 "method_decode.py", "Dockerfile.collector", "collector-compose.yaml"):
        assert digest(Path(__file__).with_name(name).read_bytes()) == image["sources"][name]["sha256"], name
    for name in ("collector_container_suite.py", "collector_container_recover.py", "icap-run-suite.sh", "lifetime_fixture.py"):
        assert digest(Path(__file__).with_name(name).read_bytes()) == live["sources"][name]["sha256"], name
    assert live["before"] == live["after"] == original["before"] == original["after"]
    assert live["suite"]["returncode"] == 0
    assert [row["action"] for row in live["controls"]] == ["stop", "resume", "kill", "resume"]
    containers = [live["collector_initial"]] + [row["container"] for row in live["controls"] if row["action"] == "resume"]
    assert len({row["id"] for row in containers}) == 3
    assert len({row["image"] for row in containers}) == 1 and containers[0]["image"] == image["image"]
    for row in containers:
        host = row["host"]
        assert host["Memory"] == host["MemorySwap"] == 134217728
        assert host["NanoCpus"] == 500000000 and host["PidsLimit"] == 32
        assert host["CapAdd"] == ["CAP_SYS_PTRACE"] and host["CapDrop"] == ["ALL"]
        assert host["ReadonlyRootfs"] and not host["Privileged"] and host["NetworkMode"] == "none"
        assert set(m["Destination"] for m in row["mounts"]) == {"/run/ls-stream", "/journal", "/api", "/source"}
    for i in (0, 2):
        stopped, queued = live["controls"][i]["stopped_ring"][0], live["controls"][i + 1]["queued_ring"][0]
        assert stopped["consumer"] == queued["consumer"]
        assert queued["producer"] - stopped["producer"] == 184
        assert stopped["drops"] == queued["drops"] == 0
        assert live["controls"][i + 1]["api"]["journal_id"] == live["api_initial"]["journal_id"]
    for consumer in live["consumers"].values():
        assert len(consumer["mounts"]) == 1
        assert consumer["mounts"][0]["Destination"] == "/api" and not consumer["mounts"][0]["RW"]
        assert consumer["host"]["CapDrop"] == ["ALL"] and not consumer["host"]["CapAdd"]
        assert not consumer["host"]["PidMode"] and consumer["host"]["NetworkMode"] == "none"
    assert len({row["id"] for row in live["consumers"].values()}) == 2
    pages = [row for page in live["consumer_a_pages"] for row in page["events"]]
    assert pages == live["consumer_b_page"]["events"] and len(pages) == 10
    assert len({row["cursor"] for row in pages}) == 10
    values = [row for row in pages if row["event"]["type"] == "record"]
    assert len(values) == len({row["event"]["event_id"] for row in values}) == 8
    assert not any(row["event"]["type"] == "observation_gap" for row in pages)
    result = json.loads(live["files"]["result.json"])
    decoded = [decode(bytes.fromhex(row["event"]["raw"]["data"])) for row in values]
    assert decoded == result["events"] and result["passed"] and len(result["clients"]) == 10
    assert [row["sequence"] for row in decoded] == list(range(1, 9))
    assert not any(row["output_failures"] for row in decoded)
    assert [row["value_hex"] for row in decoded[:6]] == [b"SendMessage".hex(), b"future.variant".hex(), "", b"future\\u002evariant".hex(), (b"x" * 64).hex(), (b"y" * 64).hex()]
    assert [row["status_name"] for row in decoded] == ["complete"] * 5 + ["truncated", "getter_error", "budget_exhausted"]
    assert result["counter_end"]["method"]["fired"] - result["counter_start"]["method"]["fired"] == 8
    for key in ("errors", "gen", "safe_returns"):
        assert result["counter_end"]["method"][key] == result["counter_start"]["method"][key]
    assert result["comparisons"][2]["case"] == "empty" and result["comparisons"][3]["case"] == "escaped"
    witness = live["witnesses"]["method"]
    assert witness["returncode"] == 0
    assert witness["initial"]["bytes"] == witness["changes"][-1]["bytes"]
    assert len([row for row in witness["changes"] if row["bytes"].startswith("f30f1efae8")]) == 1
    assert live["source_binding"]["pid"] == witness["initial"]["pid"]
    assert live["source_binding"]["sha256"] == witness["initial"]["sha256"]
    source = values[0]["event"]["source"]
    assert all(row["event"]["source"] == source for row in pages)
    assert all(source[key] == live["source_binding"][key] for key in ("pid", "start", "boot", "pid_namespace"))
    xml = ET.fromstring(live["files"]["tao.xml"])
    assert list(xml.iter("testcase"))
    for node in xml.iter():
        assert node.tag not in ("failure", "error", "skipped")
        assert not any(int(node.get(key, "0")) for key in ("failures", "errors", "skipped"))
    archive = cache / "collector-container-evidence-01-20260928.tar.gz"
    assert digest(archive.read_bytes()) == cleanup["archive"]["sha256"]
    files, database = {}, None
    with tarfile.open(archive, "r:gz") as stream:
        for member in stream.getmembers():
            if member.isfile():
                name = member.name.removeprefix("./")
                assert name not in files
                data = stream.extractfile(member).read()
                files[name] = digest(data)
                if name == "collector-container-live-03/journal.sqlite":
                    database = data
    assert files == cleanup["manifest"] and len(files) == 9
    assert database is not None and digest(database) == live["journal"]["sha256"]
    db = sqlite3.connect(":memory:")
    try:
        db.deserialize(database)
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert [json.loads(row[0]) for row in db.execute("SELECT body FROM events ORDER BY id")] == [row["event"] for row in pages]
    finally:
        db.close()
    assert not any(row["project"] == "eob-template-20260925" for row in cleanup["after"])
    assert [row for row in cleanup["before"] if row["project"] != "eob-template-20260925"] == cleanup["after"]
    return {"verified": True, "collector_container_identities": 3, "consumer_containers": 2,
            "journal_events": 10, "method_records": 8, "archive_files": len(files),
            "live_driver_changed_after_run": digest(Path(__file__).with_name("collector_container_live.py").read_bytes()) != live["sources"]["collector_container_live.py"]["sha256"]}


if __name__ == "__main__":
    print(json.dumps(verify(Path(__file__).resolve().parents[2] / "evidence/cache"), indent=2))
