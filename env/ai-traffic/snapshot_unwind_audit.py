#!/usr/bin/env python3
"""Compare full and shortened unwind symbol listings on pinned TMM artifacts."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

BASE = Path("/home/starin/eob-tmm-staged/substrate")
sys.path.insert(0, str(BASE))
from exit_admit import UNWIND_INITIATORS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path("/home/starin/eob-config-20260925")
    package = json.loads((root / "entry-snapshot-integration-01/package-result.json").read_text())
    result = dict(passed=False, commands=[], artifacts={}, sources={})

    def run(*argv):
        row = subprocess.run(list(map(str, argv)), capture_output=True, text=True, timeout=180, check=False)
        result["commands"].append(dict(argv=list(map(str, argv)), rc=row.returncode, stdout=row.stdout, stderr=row.stderr))
        row.check_returncode()
        return row.stdout

    def imports(text):
        return sorted({name for line in text.splitlines() if " UND " in line
                       for name in UNWIND_INITIATORS if re.search(r"\b" + re.escape(name) + r"\b", line)})

    with args.output.open("x") as receipt:
        try:
            for name in ("exit_admit.py", "completion_admit.py"):
                path = root / "json-initialization-source-02" / name
                result["sources"][name] = dict(text=path.read_text(), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            for label, binary, debug, expected in (
                ("previous", Path("/home/starin/observability-20260925/image-context/tmm64.no_pgo"),
                 Path("/home/starin/observability-20260925/debug/usr/lib/debug/usr/bin/tmm64.no_pgo.debug"),
                 "05d17517531d99b26eb9e8f00f5b5326f660b5bef492226c9555368b887a9611"),
                ("snapshot", root / "entry-snapshot-integration-01/image-context/tmm64.no_pgo",
                 root / "entry-snapshot-integration-01/debug/usr/lib/debug/usr/bin/tmm64.no_pgo.debug",
                 package["runtime"]["sha256"]),
            ):
                assert hashlib.sha256(binary.read_bytes()).hexdigest() == expected
                narrow = run("readelf", "--dyn-syms", binary)
                wide = run("readelf", "--wide", "--dyn-syms", binary)
                result["artifacts"][label] = dict(path=str(binary), sha256=expected,
                    narrow_imports=imports(narrow), wide_imports=imports(wide),
                    notes=run("readelf", "--notes", binary), debug_sha256=hashlib.sha256(debug.read_bytes()).hexdigest())
                run("gdb", "-nx", "-batch", debug, "-ex", "ptype hud_json_handler")
            result["passed"] = True
        except BaseException as error:
            result["error"] = repr(error)
            raise
        finally:
            json.dump(result, receipt, indent=2)
    print(json.dumps(result["artifacts"], indent=2))


if __name__ == "__main__":
    main()
