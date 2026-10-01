#!/usr/bin/env python3
"""Verify saved snapshot tests, admission refusal and fixture cleanup evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile

from json_initialization_decode import FIELDS, FORMAT, decode

PINS = {
    "entry-snapshot-preflight-01.json": "349d5516a3e0ae3554da2fba505e93dbac5a7f7c94633c2a7023523ddc56c43a",
    "entry-snapshot-build-01.json": "ccd5e2dcf5aa41370ba263fb47a30fb7e15517c99b0fe117bb86bbcd8f54bddf",
    "entry-snapshot-build-02.json": "ae34e5c82afd93e325b6bea0b99b78b81ce9a0ad0cdc826503bfc1e82426b43b",
    "entry-snapshot-integration-01.json": "2c89b2fd8163b1a9212360c6a0187e1ed84d48119a094db891ddb5e59f1d1d9d",
    "entry-snapshot-package-01.json": "92082a158f1688e6f2336b8d41c9a0189aead553bff17e9c80cd41290e59bb87",
    "json-initialization-program-01.json": "f8e599689561bda615d9b8e03bbcfd4c9653cb906760650eaaff8f5fc0ba1b0d",
    "json-initialization-program-02.json": "61b2c4fb32e9f4f7099e9eeb23a06756b0fd4d6f241a59ddbe19e80ec265be20",
    "json-initialization-create-01.json": "823bcd50d5346cecea48cd66bce91d47d1bbaaf35e991daaa7d3907da011260f",
    "json-initialization-cleanup-01.json": "0d6d7a98c54c45f44c895b4a4d2392d5c361059dbbac86051d83e8c57dfeed42",
    "json-initialization-blocked-evidence-01.tar.gz": "7520b1331236723cb9cda72a0a55d356901ecf0ce8297118891ce78a90e9de7c",
    "snapshot-unwind-audit-01.json": "a175f23a05c7ec26bb5e60ec7a4d4333e8248775331c76edd1cfb24d1c81685c",
    "snapshot-unwind-check-01.json": "85a7f9c8c8572af9aa30b6ea91d1d5f0ca5b4c79d01ca2eac45d281bd87eacfb",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify(repo, cache):
    records, snapshots = {}, set()

    def embedded(value, location):
        if isinstance(value, dict):
            # Source text is exact. PTY build logs also carry a raw-byte digest,
            # but their text field has normalized newlines; the receipt pins it.
            if "sha256" in value and "text" in value and (
                    "/sources/" in location or location.endswith("/driver")):
                assert sha(value["text"].encode()) == value["sha256"], location
                snapshots.add(value["sha256"])
            for key, item in value.items():
                embedded(item, location + "/" + str(key))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                embedded(item, location + "/" + str(index))

    for name, digest in PINS.items():
        data = (cache / name).read_bytes()
        assert sha(data) == digest, name
        if name.endswith(".json"):
            records[name] = json.loads(data)
            embedded(records[name], name)
    failed = {"entry-snapshot-build-01.json", "json-initialization-program-02.json"}
    for name, row in records.items():
        assert row["passed"] == (name not in failed), name
    engine = records["entry-snapshot-build-02.json"]
    native = records["json-initialization-program-01.json"]
    qualification = records["json-initialization-program-02.json"]
    repaired = records["snapshot-unwind-check-01.json"]
    for name in ("ls_snapshot.h", "ls_vm.c", "ls_vm.h", "ls_vm_load.c", "ls_fexit.c", "ls_target.h",
                 "check_snapshot.c", "check_snapshot.bpf.c", "check_snapshot_abi.h", "bind_snapshot.py"):
        assert sha((repo / "substrate" / name).read_bytes()) == engine["sources"][name]["sha256"], name
    for name in ("surfaces/json_initialization.bpf.c", "surfaces/json_initialization_abi.h",
                 "check_json_initialization.c", "config_snapshot.bpf.h"):
        assert sha((repo / "substrate" / name).read_bytes()) == native["sources"][name]["sha256"], name
    for name in ("exit_admit.py", "completion_admit.py", "ls_buildid.py"):
        assert sha((repo / "substrate" / name).read_bytes()) == repaired["sources"][name]["sha256"], name
    assert sha((repo / "env/ai-traffic/json_initialization_decode.py").read_bytes()) == native["sources"]["json_initialization_decode.py"]["sha256"]
    commands = engine["commands"]
    reports = [r["stdout"] for r in commands if "PASS snapshot" in r.get("stdout", "")]
    assert len(reports) == 4
    assert sum(report.count("cases=20") for report in reports) == 4
    assert sum(report.count("cases=19") for report in reports) == 4
    assert "runtime imports an unwind initiator" in qualification["error"]
    assert len(qualification["instruction_checks"]["offsets"]) == 11
    assert qualification["layout"]["events"]["HUDEVT_FLOW_INIT"] == 57
    assert qualification["programs"] == {}
    observed = [decode(bytes.fromhex(line[7:])) for row in native["commands"]
                for line in row.get("stdout", "").splitlines() if line.startswith("RECORD ")]
    assert observed == native["native_events"] and len(observed) == 44
    assert all(not row["lifecycle_validated"] for row in observed)
    good = next(row for row in observed if row["initialization_completed"])
    encode = lambda row: FORMAT.pack(*(row[key] for key in FIELDS))
    bad = [encode(good)[:-1], encode(good) + b"\0"]
    for field, value in (("magic", 0), ("abi", 2), ("reserved", 1), ("status", 7),
                         ("flags", 16), ("flow_side", 3), ("guards", 4), ("reads", 4),
                         ("source_bytes", 10), ("code", 2), ("guards", 0)):
        bad.append(encode(dict(good, **{field: value})))
    for data in bad:
        try:
            decode(data)
        except ValueError:
            pass
        else:
            raise AssertionError("malformed record accepted")
    for field, value in (("flags", 1), ("output_failures", 1), ("instance", 0), ("revision", 0),
                         ("run", 0), ("invocation", 0), ("sequence", 0), ("monotonic_ns", 0)):
        assert not decode(encode(dict(good, **{field: value})))["initialization_completed"]
    audit = records["snapshot-unwind-audit-01.json"]
    for row in audit["artifacts"].values():
        assert row["narrow_imports"] == []
        assert row["wide_imports"] == ["_Unwind_Resume", "__cxa_begin_catch", "__cxa_rethrow"]
    package = records["entry-snapshot-package-01.json"]
    assert package["runtime"]["sha256"] == audit["artifacts"]["snapshot"]["sha256"]
    cleanup = records["json-initialization-cleanup-01.json"]
    assert cleanup["blocked"]["live_program_loaded"] is False
    assert cleanup["action"] == "archive-blocked"
    assert cleanup["witness"][0]["sha256"] == package["runtime"]["sha256"]
    assert cleanup["witness"][0]["bytes"] == cleanup["witness"][-1]["bytes"]
    slots = [r for r in cleanup["commands"] if r["argv"][-2] == "status"]
    assert len(slots) == 12 and all("armed=0" in r["stdout"] and "fired=0" in r["stdout"] for r in slots)
    assert [r for r in cleanup["before"] if r["project"] != "eob-template-20260925"] == cleanup["after"]
    members = {}
    with tarfile.open(cache / "json-initialization-blocked-evidence-01.tar.gz", "r:gz") as archive:
        for member in archive.getmembers():
            assert member.isfile() or member.isdir()
            if member.isfile():
                name = member.name.removeprefix("./")
                assert name not in members and not Path(name).is_absolute() and ".." not in Path(name).parts
                members[name] = sha(archive.extractfile(member).read())
    assert members == cleanup["manifest"] and len(members) == 1
    return dict(passed=True, receipts=len(records), source_snapshots=len(snapshots),
                native_cases_per_compiler=78, json_native_records=len(observed),
                decoder_rejections=len(bad), archive_files=len(members),
                live_initialization=False, admission="refused: unwind imports")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--cache", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.repo, args.cache or args.repo / "evidence/cache"), indent=2))


if __name__ == "__main__":
    main()
