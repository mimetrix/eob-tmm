#!/usr/bin/env python3
"""Record application-metadata source leads and packaged hook entries.

Run on the authoritative build VM. This performs no load, attach or traffic test.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


CANDIDATES = (
    "a2a_request", "a2a_response", "a2a_lookup_method", "a2a_get_subtree",
    "hud_a2a_handler", "a2a_walk_and_replace",
    "aimcp_request", "aimcp_decrypt_and_parse_sessionid",
    "hud_aimcp_handler", "hud_aimcp_add_persist", "hud_inference_egress",
    "tmm_json_object_get", "tmm_json_value_get_string",
    "http_process_server_headers",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    tree = Path("/home/starin/code/tmm")
    package = Path("/home/starin/observability-20260925/image-context")
    binary = package / "tmm64.no_pgo"
    record = {"completed": False, "scope": "source and packaged binary only",
              "files": {}, "commands": [], "candidates": {}}

    def command(argv):
        result = subprocess.run(argv, capture_output=True, text=True,
                                timeout=120, check=False)
        record["commands"].append({"argv": argv, "rc": result.returncode,
                                   "stdout": result.stdout, "stderr": result.stderr})
        result.check_returncode()
        return result.stdout

    with args.output.open("x", encoding="utf-8") as output:
        try:
            paths = [tree / name for name in (
                "AGENTS.md", "src/compile/filelist",
                "src/modules/modules.h",
                "src/modules/hudfilter/a2a/a2a.c",
                "src/modules/hudfilter/a2a/a2a.h",
                "src/modules/hudfilter/aimcp/aimcp.c",
                "src/modules/hudfilter/aimcp/aimcp.h",
                "src/modules/hudfilter/json/json_parse.h",
                "src/modules/hudfilter/json/json_parse.c",
                "src/modules/hudfilter/json/json_filter.h",
                "src/modules/hudfilter/inference/inference.c",
                "src/modules/hudfilter/inference/inference_internal.h",
                "test/ssa_functional/persistence_profiles_tao/tests/a2a_persistence.py",
                "test/ssa_functional/aimcp_tao/tests/persist_irules.py",
            )]
            paths += [package / "hook-index.tsv", package / "runtime-identity.json",
                      Path(__file__)]
            for path in paths:
                data = path.read_bytes()
                record["files"][str(path)] = {
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "text": data.decode(),
                }
            with binary.open("rb") as stream:
                record["binary_sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
            command(["git", "-C", str(tree), "rev-parse", "HEAD"])
            command(["git", "-C", str(tree), "status", "--porcelain", "src/"])
            notes = command(["readelf", "-n", str(binary)])
            index = record["files"][str(package / "hook-index.tsv")]["text"]
            build_id = next(line.split("\t")[1] for line in index.splitlines()
                            if line.startswith("#build_id\t"))
            if f"Build ID: {build_id}" not in notes:
                raise ValueError("hook index and binary build IDs differ")
            record["build_id"] = build_id
            for name in CANDIDATES:
                rows = [line.split("\t") for line in index.splitlines()
                        if not line.startswith("#") and
                        (line.split("\t")[0] == name or
                         line.split("\t")[0].startswith(name + "."))]
                record["candidates"][name] = {"hook_index_rows": rows,
                                             "live_extraction_validated": False}
                for row in rows:
                    address = int(row[1], 16)
                    command(["objdump", "-d", f"--start-address={hex(address)}",
                             f"--stop-address={hex(address + 128)}", str(binary)])
            # This header's enum is unconditional and uses simple integer values.
            # Refuse new syntax instead of guessing its preprocessed meaning.
            header = record["files"][str(tree / "src/modules/modules.h")]["text"]
            body = header.split("typedef enum {", 1)[1].split("} hud_msg_t;", 1)[0]
            body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
            names = {}
            value = -1
            for item in body.split(","):
                if not item.strip():
                    continue
                match = re.fullmatch(r"\s*(HUD\w+)\s*(?:=\s*(0x[0-9a-fA-F]+|[0-9]+))?\s*", item)
                if match is None:
                    raise ValueError("unsupported hud_msg_t enum syntax: " + item)
                value = int(match[2], 0) if match[2] else value + 1
                names[str(value)] = match[1]
            record["event_names"] = names
            record["handler_arguments"] = {}
            for name in ("hud_a2a_handler", "hud_aimcp_handler"):
                row = next(r for r in record["candidates"][name]["hook_index_rows"]
                           if r[0] == name)
                disassembly = next(c["stdout"] for c in record["commands"]
                                   if c["argv"][0] == "objdump" and
                                   "--start-address=" + row[1] in c["argv"])
                for instruction in ("%esi,%ebp", "%rdi,%r12", "%rdx,%r14", "%rcx,%r13"):
                    if instruction not in disassembly:
                        raise ValueError(name + ": argument layout needs review")
                record["handler_arguments"][name] = {
                    "node": "arg[0] / rdi", "event_code": "low 32 bits of arg[1] / esi",
                    "flow": "arg[2] / rdx", "data": "arg[3] / rcx",
                    "scope": "entry only; no pointee lifetime qualification",
                }
            debug = Path("/home/starin/observability-20260925/debug/usr/lib/debug/usr/bin/tmm64.no_pgo.debug")
            record["json_layout"] = command([
                "gdb", "-nx", "-batch", str(debug),
                "-ex", "ptype /o struct tmm_json_value",
                "-ex", "ptype /o struct tmm_json_object",
                "-ex", "ptype /o struct json_keyval",
                "-ex", "ptype /o struct tmm_json_string",
                "-ex", "p/d JSON_TYPE_OBJECT",
                "-ex", "p/d JSON_TYPE_STRING",
            ])
            record["completed"] = True
        finally:
            json.dump(record, output, indent=2)
    print(json.dumps({key: record[key] for key in
                      ("completed", "build_id", "binary_sha256", "candidates")},
                     indent=2))


if __name__ == "__main__":
    main()
