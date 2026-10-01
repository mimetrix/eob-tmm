#!/usr/bin/env python3
"""Check pinned source/compiled scope evidence; never promote it to live scope."""
import argparse
import hashlib
import json
from pathlib import Path
import re


RECEIPT_SHA256 = "80baa9981872c732936054ae9ca6f51a38fb89148ec9f02bce2916f3d3efa1a3"
BUILD_ID = "ca69b84f4f5c9e225813b2ed3997c59f18ba2a31"
BINARY_SHA256 = "05d17517531d99b26eb9e8f00f5b5326f660b5bef492226c9555368b887a9611"
TREE = "/home/starin/code/tmm/"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(path):
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == RECEIPT_SHA256, "receipt hash mismatch")
    record = json.loads(data)
    require(record["completed"] is True, "incomplete discovery")
    require(record["runtime"] == dict(build_id=BUILD_ID, sha256=BINARY_SHA256), "wrong runtime")
    require(record["binary_sha256"] == BINARY_SHA256, "wrong executable hash")
    require(record["tree_head"] == "e2104734a940a099a9190eb84bfbea01fb4b81d4", "wrong source revision")
    for name, row in record["files"].items():
        require(hashlib.sha256(row["text"].encode()).hexdigest() == row["sha256"], name)
    for command in record["commands"]:
        require(type(command["rc"]) is int and command["rc"] == 0, "failed capture command")
    statuses = [c for c in record["commands"] if "status" in c["argv"]]
    require(len(statuses) == 1 and statuses[0]["stdout"] == "", "modified inspected TMM sources")
    require(record["layout"].endswith("$1 = 64\n$2 = 44\n"), "wrong HUD context offsets")
    require("/*     37      |       1 */    UINT8 flow_type;" in record["layout"], "wrong flow-type offset")
    require("/*     24      |       8 */    struct tmm_json_cache *json;" in record["layout"], "wrong cache offset")
    require("/*     89: 4   |       4 */    BOOL f_ingress_msg_mode : 1;" in record["layout"], "wrong message-mode bit")

    references = []

    def source(name, fragment):
        text = record["files"][TREE + name]["text"]
        require(text.count(fragment) == 1, "missing or ambiguous source fragment: " + fragment)
        line = text[:text.index(fragment)].count("\n") + 1
        references.append(dict(file=name, line=line, text=fragment))

    flow = "src/base/flow_table.h"
    stream = "src/modules/hudfilter/flow_stream.h"
    json_filter = "src/modules/hudfilter/json/json_filter.c"
    for fragment in (
        "#define FLOW_CLIENTSIDE         0x40",
        "#define FLOW_SERVERSIDE         0x80",
        "#define IS_CLIENTSIDE(a) ((((a)->flow_type) & FLOW_CLIENTSIDE) != 0)",
        "(union uflow *) ((uintptr_t) sf - 33)",
    ):
        source(flow, fragment)
    for fragment in (
        "uflow_is_clientside(union uflow *uf)\n{\n    return IS_CLIENTSIDE(&uf->cf);\n}",
        "STATIC_ASSERT(offsetof(struct connflow, flow_type) ==\n        offsetof(struct streamflow, flow_type) + offsetof(union uflow, sf));",
        "return uflow_is_clientside(uf) ? uf : uflow_peer(uf);",
        "Note that the per-stream state is separate from the connection state.",
    ):
        source(stream, fragment)
    for fragment in (
        "hud_json_init_scb(struct json_scb *scb, union uflow *uf)\n{\n    memset(scb, 0, sizeof(*scb));",
        "hud_json_uninit_scb(struct json_scb *scb)\n{\n    tmm_json_cache_release(scb->json);",
        "json_filter_reset_ingress_for_reuse(struct json_scb *scb)\n{\n    hud_ref_release(scb->msg_ref);\n    scb->msg_ref = NULL;\n    tmm_json_cache_release(scb->json);\n    scb->json = NULL;",
        "case HUDEVT_FLOW_INIT:\n        hud_json_init_scb(scb, uf);",
        "case HUDCTL_ABORT:\n    case HUDCTL_TEARDOWN:\n        hud_json_uninit_scb(scb);",
        "if (scb->f_disabled && (msg != HUDCTL_ENABLE) && (msg != HUDEVT_TCL))",
        "scb->f_msg_done = TRUE;\n        } else {\n            scb->f_done = TRUE;",
        "TCLRULE_JSON_REQUEST : TCLRULE_JSON_RESPONSE), scb);",
        "scb->sse->ctx = tmm_json_cache_addref(scb->json);",
        ".scb_sz = sizeof(struct json_scb),\n    .pcb_sz = sizeof(struct json_scb),",
    ):
        source(json_filter, fragment)

    instructions = []

    def instruction(start, address, expected):
        commands = [c for c in record["commands"] if "--start-address=" + hex(start) in c["argv"]]
        require(len(commands) == 1, "missing disassembly range")
        match = re.search(r"^\s*" + format(address, "x") + r":\s+((?:[0-9a-f]{2} )*[0-9a-f]{2})\s+(.+)$",
                          commands[0]["stdout"], re.M)
        require(match is not None and bytes.fromhex(match[1]) == bytes.fromhex(expected),
                "wrong instruction at " + hex(address))
        instructions.append(dict(address=hex(address), bytes=expected, instruction=match[2]))

    for address, expected in (
        (0xd93549, "49 89 d6"), (0xd93550, "49 89 f4"),
        (0xd9370a, "41 0f b6 46 25"), (0xd93718, "83 e0 40"),
        (0xd936e4, "41 f6 44 24 59 10"),
    ):
        instruction(0xd93540, address, expected)
    instruction(0xd927c0, 0xd927fc, "48 c7 43 18 00 00 00")
    for address, expected in (
        (0xd94c4a, "b9 0c 00 00 00"), (0xd94c52, "f3 48 ab"),
        (0xd947b8, "e8 03 42 00 00"), (0xd9428f, "e8 ac f2 ff ff"),
        (0xd9551f, "e8 9c d2 ff ff"),
    ):
        instruction(0xd94100, address, expected)

    hooks = {row[0]: row[1:] for row in record["hooks"]}
    expected_hooks = {
        "json_filter_handle_json_complete": ["0xd93540", "pad", "0", "5"],
        "json_filter_reset_ingress_for_reuse": ["0xd927c0", "pad", "0", "5"],
        "hud_json_handler": ["0xd94104", "pad", "4", "5"],
    }
    for name, expected in expected_hooks.items():
        require(hooks.get(name) == expected, "wrong hook: " + name)
    require("hud_json_init_scb" not in hooks and "hud_json_uninit_scb" not in hooks,
            "recheck standalone lifecycle hooks")
    return dict(
        passed=True, evidence_tier="MEASURED", scope="source_and_compiled_inspection_only",
        witnesses=["TOOL", "SELF"], build_id=BUILD_ID,
        checked_sources=len(record["files"]), source_receipt=path.name,
        source_sha256=RECEIPT_SHA256, source_references=references,
        instructions=instructions, hooks=expected_hooks,
        decisions=dict(
            flow_side="qualified_source_candidate_not_live",
            scb_as_request_id="rejected_reused_storage",
            scb_as_shared_connection="rejected_connection_and_stream_contexts",
            lifecycle="handler_events_and_reset_need_runtime_validation",
            peer_relationship="not_a_qualified_common_lifetime",
        ),
        runtime_scope_validated=False, request_scope_validated=False,
        message_association_validated=False, authenticated_identity_validated=False,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, default=Path(__file__).resolve().parents[2] /
                        "evidence/cache/message-scope-discovery-02.json")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--export", action="store_true")
    args = parser.parse_args()
    result = verify(args.receipt)
    if args.output:
        data = Path(__file__).read_bytes()
        saved = dict(result=result, verifier=dict(text=data.decode(), sha256=hashlib.sha256(data).hexdigest()))
        with args.output.open("x") as output:
            json.dump(saved, output, indent=2)
    if not args.export:
        result = {key: value for key, value in result.items() if key not in ("source_references", "instructions")}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
