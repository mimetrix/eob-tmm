#!/usr/bin/env python3
"""Check saved initialization qualification; do not promote it to live coverage."""
import argparse
import hashlib
import json
from pathlib import Path
import re


PINS = {
    "json-initialization-discovery-01.json":
        "dfbb050dd97fc300d9cc5fc8beba043625666d4fccc8f315b9a431f854b8e7e5",
    "json-initialization-discovery-02.json":
        "787a96e8d860640f509a4143ff380530ef2708ad3ee01e16c24c9699c7c6b2f0",
}
BUILD = "ca69b84f4f5c9e225813b2ed3997c59f18ba2a31"
BINARY = "05d17517531d99b26eb9e8f00f5b5326f660b5bef492226c9555368b887a9611"
DEBUG = "eae9765021680ea5576de28c2846a1d3d6fd67331291a1ab901bcd3d8d61e088"
TREE = "/home/starin/code/tmm/"
BASE = "/home/starin/eob-tmm-staged/substrate/"
WORK = "/home/starin/eob-config-20260925/"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify(cache, source_root, substrate_root):
    records = []
    checked_sources = 0
    for name, expected in PINS.items():
        raw = (cache / name).read_bytes()
        require(digest(raw) == expected, "receipt hash mismatch: " + name)
        record = json.loads(raw)
        require(record["completed"] is True and "error" not in record, "capture incomplete")
        require(record["runtime"] == dict(build_id=BUILD, sha256=BINARY), "runtime mismatch")
        require(record["debug_sha256"] == DEBUG, "debug companion mismatch")
        require(record["tree_head"] == "e2104734a940a099a9190eb84bfbea01fb4b81d4", "tree mismatch")
        require(record["boundary_sha256"] ==
                "bea20f4ae1fba8feef7a1688bcfa3996fcccae570cccfbb8339bcad62e088889",
                "boundary source mismatch")
        for path, row in record["sources"].items():
            require(digest(row["text"].encode()) == row["sha256"], "source hash: " + path)
            checked_sources += 1
        admitted = record["admission"]
        require(set(admitted) == {"hud_json_handler", "json_filter_reset_ingress_for_reuse",
                                  "tmm_json_value_get_string"}, "wrong candidates")
        for name in ("hud_json_handler", "json_filter_reset_ingress_for_reuse"):
            row = admitted[name]
            require(row["rc"] == 1 and "VERDICT        : REFUSE" in row["stdout"] and
                    "void return --- there is no value for the exit program to read" in row["stderr"],
                    "candidate refusal changed: " + name)
        control = admitted["tmm_json_value_get_string"]
        require(control["rc"] == 0 and "VERDICT        : ADMIT" in control["stdout"] and
                "(rax)" in control["stdout"], "positive control not admitted")
        for row in admitted.values():
            require("TMM imports no unwind initiator (P8 holds)" in row["stdout"] and
                    "no LSDA --- plain frame" in row["stdout"], "unwind check incomplete")
            require(row in record["commands"], "admission command missing")
        permitted_failures = [admitted[n] for n in admitted if n != "tmm_json_value_get_string"]
        if "xbuf_binding" in record:
            permitted_failures.append(record["xbuf_binding"])
        for command in record["commands"]:
            require(command["rc"] == 0 or command in permitted_failures,
                    "unexpected capture failure: " + str(command["argv"]))
        statuses = [c for c in record["commands"] if "status" in c["argv"]]
        require(len(statuses) == 1 and statuses[0]["stdout"] == "", "inspected source modified")
        notes = [c for c in record["commands"] if c["argv"][:2] == ["readelf", "-n"]]
        require(len(notes) == 2 and all(re.findall(r"Build ID: ([0-9a-f]+)", c["stdout"]) == [BUILD]
                                       for c in notes), "binary/debug build ID mismatch")
        records.append(record)

    record = records[-1]
    for name in ("exit_admit.py", "bind_target.py", "ls_buildid.py"):
        expected = record["sources"][BASE + name]["sha256"]
        require(digest((substrate_root / name).read_bytes()) == expected, "current tool changed: " + name)
        require(records[0]["sources"][BASE + name]["sha256"] == expected, "admission tool changed")
    name = "json_initialization_discover.py"
    require(digest((source_root / name).read_bytes()) == record["sources"][WORK + name]["sha256"],
            "current discovery script changed")

    references = []

    def source(name, fragment):
        text = record["sources"][TREE + name]["text"]
        require(text.count(fragment) == 1, "missing or ambiguous source: " + fragment)
        references.append(dict(file=name, line=text[:text.index(fragment)].count("\n") + 1,
                               text=fragment))

    json_filter = "src/modules/hudfilter/json/json_filter.c"
    source(json_filter, "xbuf_embed_init(&scb->eg_rendered, uflow_mss(uf));\n    scb->f_send_egress = TRUE;")
    source(json_filter, "if (scb->f_disabled && (msg != HUDCTL_ENABLE) && (msg != HUDEVT_TCL)) {\n"
           "        /* Flow disabled; forward immediately. */\n        goto forward;")
    source(json_filter, "case HUDEVT_FLOW_INIT:\n        hud_json_init_scb(scb, uf);\n        goto forward;")
    source(json_filter, "forward:\n    hud_orbit_handle_default(node, msg, uf, data);")
    source("src/modules/hudfilter/hudfilter.h", "struct hudnode *next = node->above;\n"
           "    if (next != NULL) {\n        hud_msg_log(\"uflow upper\", msg, uf, next, data);\n"
           "        next->h_s_handler(next, msg, uf, data);")
    source("src/modules/hudfilter/hud_orbit.c", "/* Otherwise, deliver immediately */\n"
           "    orig_state = hud_orbit_state;\n    hud_orbit_state = state;\n"
           "    orb->handler(node, msg, uf, data);\n    hud_orbit_state = orig_state;")
    source("src/base/ls_fexit.c", "memcpy(f->args, args, sizeof f->args);")

    hooks = {row[0]: row[1:] for row in record["hooks"]}
    for name in ("hud_json_init_scb", "hud_json_uninit_scb", "hud_orbit_handle_default"):
        require(name not in hooks and not any(line.split()[-1].split(".")[0] == name
                for line in record["candidate_symbols"]), "standalone candidate changed: " + name)
    require(hooks["hud_json_handler"] == ["0xd94104", "pad", "4", "5"], "handler pad changed")
    require(hooks["xbuf_embed_init"] == ["0x1480080", "displace", "-", "8"], "xbuf entry changed")
    binding = record["xbuf_binding"]
    require(binding in record["commands"] and binding["rc"] == 1 and
            "target is not a supported +0/+4 padded entry" in binding["stderr"], "xbuf refusal changed")

    disassembly = [c for c in record["commands"] if "--start-address=0xd94100" in c["argv"]]
    require(len(disassembly) == 1 and "--stop-address=0xd95680" in disassembly[0]["argv"],
            "handler range incomplete")
    symbols = [line.split() for line in record["candidate_symbols"] if line.split()[-1] == "hud_json_handler"]
    require(len(symbols) == 1 and int(symbols[0][0], 16) == 0xd94100 and
            int(symbols[0][1], 16) == 0x1579, "handler extent changed")
    instructions = []
    for address, expected in (
        (0xd94137, "48 89 fd"), (0xd9413a, "41 89 f4"),
        (0xd94169, "40 f6 c6 01"), (0xd9417c, "75 3b"),
        (0xd9419f, "3e ff 24 c5 60 e1 2a"),
        (0xd94c52, "f3 48 ab"), (0xd94c7e, "e8 fd b3 6e 00"),
        (0xd94c87, "80 8d 98 00 00 00 10"),
        (0xd94ca6, "0f 85 61 ff ff ff"), (0xd94c0d, "48 8b 45 18"),
        (0xd94c14, "0f 85 8e fc ff ff"), (0xd948b1, "48 89 c7"),
        (0xd948b4, "ff 10"), (0xd953fa, "e9 83 f9 ff ff"),
        (0xd94d90, "e9 f9 fe ff ff"),
    ):
        match = re.search(r"^\s*" + format(address, "x") +
                          r":\s+((?:[0-9a-f]{2} )*[0-9a-f]{2})\s+(.+)$", disassembly[0]["stdout"], re.M)
        require(match is not None and bytes.fromhex(match[1]) == bytes.fromhex(expected),
                "instruction changed: " + hex(address))
        instructions.append(dict(address=hex(address), bytes=expected, instruction=match[2]))
    jump = [c for c in record["commands"] if "--start-address=0x22ae328" in c["argv"]]
    require(len(jump) == 1 and "22ae328 484cd900 00000000" in jump[0]["stdout"], "init jump changed")
    layout = [c for c in record["commands"] if "ptype hud_json_handler" in c["argv"]]
    require(len(layout) == 1 and layout[0]["stdout"].endswith("$1 = 0x18\n$2 = 0x39\n"),
            "node-above offset or init event changed")
    return dict(
        passed=True, evidence_tier="MEASURED", scope="source_compiled_and_admission_only",
        witnesses=["TOOL", "SELF"], build_id=BUILD, checked_source_snapshots=checked_sources,
        receipts=PINS, admission_repetitions=2, source_references=references, instructions=instructions,
        decisions=dict(handler_fexit="refused_void", reset_fexit="refused_void",
                       return_control="admitted", standalone_init_uninit="absent",
                       xbuf_entry="binding_refused_and_precedes_final_write",
                       forwarding_entry="rejected_disabled_bypass_and_changed_node",
                       orbit_wrapper_entry="precedes_wrapped_handler",
                       post_return_storage="not_qualified"),
        tested_candidate_qualified=False, live_probe_run=False, initialization_completion_validated=False,
        lifecycle_validated=False, request_scope_validated=False, message_association_validated=False,
        authenticated_identity_validated=False,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parents[2]
    parser.add_argument("--cache", type=Path, default=root / "evidence/cache")
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--substrate-root", type=Path, default=root / "substrate")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--export", action="store_true")
    args = parser.parse_args()
    result = verify(args.cache, args.source_root, args.substrate_root)
    if args.output:
        data = Path(__file__).read_bytes()
        with args.output.open("x") as output:
            json.dump(dict(result=result, verifier=dict(text=data.decode(), sha256=digest(data))), output, indent=2)
    if not args.export:
        result = {key: value for key, value in result.items() if key not in ("source_references", "instructions")}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
