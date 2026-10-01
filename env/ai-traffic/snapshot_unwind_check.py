#!/usr/bin/env python3
"""Check corrected return admission on the build box and test tool failures."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.source))
    import exit_admit
    import completion_admit
    root = Path("/home/starin/eob-config-20260925")
    result = dict(passed=False, commands=[], sources={}, cases=[])

    def run(argv, expected):
        argv = list(map(str, argv))
        row = subprocess.run(argv, capture_output=True, text=True, timeout=240, check=False)
        result["commands"].append(dict(argv=argv, rc=row.returncode, stdout=row.stdout, stderr=row.stderr))
        assert row.returncode == expected, result["commands"][-1]

    with args.output.open("x") as receipt:
        try:
            for name in ("exit_admit.py", "completion_admit.py", "ls_buildid.py", "snapshot_unwind_check.py"):
                path = args.source / name
                result["sources"][name] = dict(text=path.read_text(), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            for label, binary, debug in (
                ("previous", Path("/home/starin/observability-20260925/image-context/tmm64.no_pgo"),
                 Path("/home/starin/observability-20260925/debug/usr/lib/debug/usr/bin/tmm64.no_pgo.debug")),
                ("snapshot", root / "entry-snapshot-integration-01/image-context/tmm64.no_pgo",
                 root / "entry-snapshot-integration-01/debug/usr/lib/debug/usr/bin/tmm64.no_pgo.debug"),
            ):
                clear, imports = exit_admit.unwind_clear(str(binary))
                assert not clear and imports == ["_Unwind_Resume", "__cxa_begin_catch", "__cxa_rethrow"]
                run([sys.executable, args.source / "exit_admit.py", debug, binary, "tmm_json_value_get_string"], 1)
                run([sys.executable, args.source / "completion_admit.py", debug, binary, "hud_json_handler"], 1)
                result["cases"].append(dict(label=label, imports=imports, sha256=hashlib.sha256(binary.read_bytes()).hexdigest()))
            victim = root / "entry-snapshot-build-02/victim"
            run([sys.executable, args.source / "exit_admit.py", victim, victim, "integer_victim"], 0)
            run([sys.executable, args.source / "completion_admit.py", victim, victim, "snapshot_victim"], 0)
            result["cases"].append(dict(label="native positive controls", sha256=hashlib.sha256(victim.read_bytes()).hexdigest()))
            with patch.object(exit_admit, "sh", return_value=exit_admit._Miss()):
                assert not exit_admit.unwind_clear("missing")[0]
                with patch.object(exit_admit, "which_dwarfdump", return_value="failing-tool"):
                    assert exit_admit.frame_has_lsda("missing", 1) == (False, False)
            with patch.object(completion_admit.subprocess, "run", side_effect=FileNotFoundError("missing")):
                try:
                    completion_admit.checked("missing")
                except FileNotFoundError:
                    pass
                else:
                    raise AssertionError("missing tool accepted")
            result["cases"].append(dict(label="failed tools refuse"))
            result["passed"] = True
        except BaseException as error:
            result["error"] = repr(error)
            raise
        finally:
            json.dump(result, receipt, indent=2)
    print(json.dumps(dict(passed=result["passed"], cases=result["cases"])))


if __name__ == "__main__":
    main()
