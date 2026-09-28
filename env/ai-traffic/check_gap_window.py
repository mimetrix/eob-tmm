"""Check the window guard against retained four-VM missing-boundary traces."""
import argparse
import copy
import json
from pathlib import Path

from correlation_join import join
from gap_window import ObservationWindow


def check(text):
    """The old stream looks closed even though two boundaries were omitted."""
    records = [json.loads(line) for line in text.splitlines() if line.startswith("{")]
    results = []
    instances = {name: str(i) for i, name in enumerate(("init", "parse", "fini", "candidate"), 1)}
    ledger = [
        dict(path="/mcp", nonce=letter * 32, attempt=letter, actor=actor,
             accepted=True, operation="op-" + letter, auth_evidence="synthetic-test")
        for letter, actor in (("a", "agent-A"), ("b", "agent-B"))
    ]
    for mode in (0, 1):
        life = [r for r in records if r["mode"] == mode and r["kind"] != 4]
        raw = [r for r in records if r["mode"] == mode and r["kind"] == 4]
        accounting = dict(init=1, parse=2, fini=1, candidate=2, drops=0, errors=0, selections=0)
        legacy = join(life, raw, ledger, accounting)
        assert [r["status"] for r in legacy] == ["attributed", "attributed"]
        assert [r["lifetime"] for r in legacy] == [1, 1]
        window = ObservationWindow(101 + mode, instances, fresh=True)
        assert all(r["status"] == "unknown" for r in window.match(life, raw, ledger, accounting))
        window.invalidate("missed_boundaries")
        window.close(instances)
        guarded = window.match(life, raw, ledger, accounting)
        assert all(r["status"] == "unknown" and r["actor"] is None for r in guarded)
        window.close(instances)
        assert all(r["status"] == "unknown" for r in window.match(life, raw, ledger, accounting))
        absent = ObservationWindow(101 + mode, instances)
        absent.close(instances)
        assert all(r["status"] == "unknown" for r in absent.match(life, raw, ledger, accounting))
        changed = ObservationWindow(101 + mode, instances, fresh=True)
        changed.close({**instances, "init": "replacement"})
        assert all(r["status"] == "unknown" for r in changed.match(life, raw, ledger, accounting))
        capacity = ObservationWindow(101 + mode, instances, fresh=True)
        capacity.close(instances)
        limited = copy.deepcopy(raw)
        limited[-1]["flags"] = 256
        assert all(r["status"] == "unknown" for r in capacity.match(life, limited, ledger, accounting))
        mixed = ObservationWindow(999, instances, fresh=True)
        mixed.close(instances)
        assert all(r["status"] == "unknown" for r in mixed.match(life, raw, ledger, accounting))
        results.append(dict(mode=mode, legacy=legacy, guarded=guarded,
                            checks=["unsealed", "known-gap", "no-reopen", "missing-coverage",
                                    "changed-instance", "capacity", "changed-run"]))
    return {"passed": True, "results": results}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    args = parser.parse_args()
    print(json.dumps(check(args.trace.read_text()), indent=2))
