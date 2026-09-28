"""Fail closed on the fixture JSON and Tao XML, even if tao_runner exits zero."""

import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


def check(directory):
    """Both independently written test reports must identify a completed success."""
    result = json.loads((directory / "result.json").read_text(encoding="utf-8"))
    xml = ET.parse(directory / "tao.xml").getroot()
    if result.get("passed") is not True:
        raise ValueError("fixture JSON did not pass")
    if not list(xml.iter("testcase")):
        raise ValueError("Tao XML contains no test case")
    for node in xml.iter():
        if node.tag in ("failure", "error", "skipped") or any(
            int(node.get(key, "0")) for key in ("failures", "errors", "skipped")
        ):
            raise ValueError("Tao XML did not pass")
    print("Fixture JSON and Tao XML both pass")


if __name__ == "__main__":
    check(Path(sys.argv[1]))
