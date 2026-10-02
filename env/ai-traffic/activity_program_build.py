#!/usr/bin/env python3
"""Build and check the two-entry activity ELF on the pinned x86-64 build box."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--sign", action="store_true",
                        help="sign both hook bindings after all checks pass")
    parser.add_argument("--debug", type=Path,
                        help="matching debug ELF; required when signing")
    args = parser.parse_args()
    args.output.mkdir()
    base = args.source / "substrate"
    sys.path.insert(0, str(base))
    from bind_target import sections  # pylint: disable=import-outside-toplevel
    from ls_buildid import build_id  # pylint: disable=import-outside-toplevel
    ubpf = Path("/home/starin/code/tmm/.ubpf")
    prevail = Path("/home/starin/eob-tmm-staged/ebpf-verifier/bin/prevail")
    objcopy = "/usr/lib/llvm-18/bin/llvm-objcopy"
    record = dict(passed=False, commands=[], sources={})

    def run(*argv, expected=0):
        argv = list(map(str, argv))
        p = subprocess.run(argv, capture_output=True, text=True, timeout=240, check=False)
        record["commands"].append(dict(argv=argv, rc=p.returncode, stdout=p.stdout, stderr=p.stderr))
        if p.returncode != expected:
            raise RuntimeError(f"{argv}: rc={p.returncode}\n{p.stdout}\n{p.stderr}")
        return p.stdout

    with (args.output / "result.json").open("x") as receipt:
        try:
            for path in sorted(args.source.rglob("*")):
                if path.is_file() and "__pycache__" not in path.parts:
                    record["sources"][str(path.relative_to(args.source))] = dict(
                        sha256=sha(path), text=path.read_text())
            assert "18.1.3" in run("clang-18", "--version")
            assert "13.3.0" in run("gcc", "--version")
            assert run("git", "-C", ubpf, "rev-parse", "HEAD").strip() == "c900ed9faf1d41358a7ea9217ccd0b64a4ee8d5d"
            assert run("git", "-C", prevail.parent.parent, "rev-parse", "HEAD").strip() == "06769f7b508214e63b97905d275920f7e90182fa"
            if args.sign:
                for name in ("vm/ubpf_vm.c", "vm/ubpf_jit.c"):
                    run("git", "-C", ubpf, "show", "HEAD:" + name)
            binary = args.package / "tmm64.no_pgo"
            bid = build_id(str(binary))
            record["runtime"] = dict(path=str(binary), build_id=bid, sha256=sha(binary))
            if args.sign:
                assert args.debug and build_id(str(args.debug)) == bid
                previous = Path("/home/starin/observability-20260925/debug/usr/lib/debug/usr/bin/tmm64.no_pgo.debug")
                assert sha(previous) == "eae9765021680ea5576de28c2846a1d3d6fd67331291a1ab901bcd3d8d61e088"
                # Compare the new build's layout with the already live-tested
                # metadata build. Recurse through embedded objects, not pointers.
                script = '''import gdb,json
def layout(t):
 t=t.strip_typedefs()
 fields=[]
 if t.code in (gdb.TYPE_CODE_STRUCT,gdb.TYPE_CODE_UNION):
  fields=[(f.name,f.bitpos,f.bitsize,layout(f.type)) for f in t.fields()]
 return (str(t),t.sizeof,fields)
names=["struct tmm_json_cache","jxmntok_t","struct xfrag","struct json_scb","struct connflow","struct http_data","struct http_parse_info"]
result={n:layout(gdb.lookup_type(n)) for n in names}
for n in ["HUDCTL_RESPONSE","HUDEVT_RESPONSE","HUDCTL_RESPONSE_DONE","HUDEVT_RESPONSE_DONE","JXMN_OBJECT","JXMN_STRING"]:
 result[n]=int(gdb.parse_and_eval(n))
for n in ["json_filter_handle_json_complete","hud_aimcp_handler"]:
 result[n]=str(gdb.parse_and_eval("&"+n).type)
print(json.dumps(result,sort_keys=True))
'''
                command = "python exec(" + repr(script) + ")"
                layouts = []
                for debug in (previous, args.debug):
                    text = run("gdb", "-q", "-nx", "-batch", debug, "-ex", command)
                    layouts.append(json.loads(next(line for line in text.splitlines() if line.startswith("{"))))
                assert layouts[0] == layouts[1], "metadata layout changed since the live-qualified build"
                record["layout"] = dict(reference_sha256=sha(previous), debug_sha256=sha(args.debug), values=layouts[1])
                # Client TLS walk (TLS-MODE.md): assert every offset and bit
                # position the bytecode uses against this debug file.
                tls_script = '''import gdb,json
def at(t,path):
 t=gdb.lookup_type(t); off=0
 for name in path.split("."):
  f=[x for x in t.strip_typedefs().fields() if x.name==name][0]
  off+=f.bitpos; t=f.type
 return [off, f.bitsize]
checks={"connflow.ipproto":at("struct connflow","ipproto"),"connflow.flow_type":at("struct connflow","flow_type"),
"connflow.bottom_node":at("struct connflow","bottom_node"),"hudnode.above":at("struct hudnode","above"),
"hudnode.f_active":at("struct hudnode","f_active"),"hudnode.f_ctx":at("struct hudnode","f_ctx"),
"hudnode.private":at("struct hudnode","private"),"hudnode.ctx":at("struct hudnode","ctx"),
"hudfilter.private":at("struct hudfilter","private"),"hudfilter.base.typeid":at("struct hudfilter","base.typeid"),
"hud_typeid.name":at("struct hud_typeid","name"),
"ssl_pcb.vfyresult":at("struct ssl_pcb","vfyresult"),"ssl_pcb.pcm":at("struct ssl_pcb","pcm"),
"ssl_pcb.entity":at("struct ssl_pcb","entity"),"ssl_pcb.passthru":at("struct ssl_pcb","passthru"),
"ssl_pcb.hsok":at("struct ssl_pcb","hsok"),"ssl_pcb.st_resume":at("struct ssl_pcb","st_resume"),
"ssl_pcb.ss_resume":at("struct ssl_pcb","ss_resume"),"ssl_pcb.allow_nonssl":at("struct ssl_pcb","allow_nonssl"),
"ssl_pcb.prf":at("struct ssl_pcb","prf"),"ssl_pcb.session":at("struct ssl_pcb","session"),
"ssl_pcb.peercertchain":at("struct ssl_pcb","peercertchain"),"ssl_pcb.suite.id":at("struct ssl_pcb","suite.id"),
"ssl_pcb.suite.proto":at("struct ssl_pcb","suite.proto"),"ssl_session.certmsg":at("struct ssl_session","certmsg"),
"ssl_profile.retain_certificate":at("struct ssl_profile","retain_certificate")}
checks["values"]=[int(gdb.parse_and_eval(n)) for n in ["SSL_E_SERVER","SSL_PCM_IGNORE","SSL_PCM_REQUIRE","SSL_PCM_REQUEST","SSL_VFY_OK","SSL_PROTO_TLS1_2","SSL_PROTO_TLS1_3"]]
print(json.dumps(checks,sort_keys=True))
'''
                text = run("gdb", "-q", "-nx", "-batch", args.debug, "-ex", "python exec(" + repr(tls_script) + ")")
                tls = json.loads(next(line for line in text.splitlines() if line.startswith("{")))
                expected = {
                    "connflow.ipproto": [288, 0], "connflow.flow_type": [296, 0],
                    "connflow.bottom_node": [640, 0], "hudnode.above": [192, 0],
                    "hudnode.f_active": [374, 1], "hudnode.f_ctx": [375, 1],
                    "hudnode.private": [384, 0], "hudnode.ctx": [512, 0],
                    "hudfilter.private": [1088, 0], "hudfilter.base.typeid": [512, 0],
                    "hud_typeid.name": [0, 0],
                    "ssl_pcb.vfyresult": [22, 7], "ssl_pcb.pcm": [47, 2], "ssl_pcb.entity": [96, 1],
                    "ssl_pcb.passthru": [112, 1], "ssl_pcb.hsok": [122, 1],
                    "ssl_pcb.st_resume": [169, 1], "ssl_pcb.ss_resume": [171, 1],
                    "ssl_pcb.allow_nonssl": [340, 1], "ssl_pcb.prf": [576, 0],
                    "ssl_pcb.session": [640, 0], "ssl_pcb.peercertchain": [832, 0],
                    "ssl_pcb.suite.id": [4224, 0], "ssl_pcb.suite.proto": [4264, 4],
                    "ssl_session.certmsg": [1728, 0], "ssl_profile.retain_certificate": [5747, 1],
                    "values": [1, 0, 1, 2, 0, 5, 6],
                }
                assert tls == expected, ("client TLS layout differs", tls)
                record["tls_layout"] = tls
            obj = args.output / "agent_activity.bpf.o"
            # Keep nested calls relocatable when uBPF selects one entry.
            run("clang-18", "-target", "bpf", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
                "-ffunction-sections",
                "-mllvm", "-disable-block-placement",
                "-c", base / "surfaces/agent_activity.bpf.c", "-o", obj)
            before_strip = obj.read_bytes()
            run(objcopy, "--strip-debug", "--remove-section=.BTF", "--remove-section=.BTF.ext",
                "--remove-section=.rel.BTF.ext", obj)
            def executable_sections(data):
                return {name: data[sh[4]:sh[4] + sh[5]]
                        for name, sh in sections(data) if sh[2] & 4}
            assert executable_sections(before_strip) == executable_sections(obj.read_bytes())
            record["stripping"] = dict(before_bytes=len(before_strip), after_bytes=obj.stat().st_size,
                                       executable_sections_unchanged=True)
            run("python3", base / "bind_targets.py", "--prog", obj,
                "--binary", binary, "--index", args.package / "hook-index.tsv", "--objcopy", objcopy)
            names = [n for n, _ in sections(obj.read_bytes()) if n.startswith("fentry/")]
            assert set(names) == {"fentry/json_filter_handle_json_complete", "fentry/hud_aimcp_handler"}
            for name in names:
                assert run(prevail, obj, name, "--termination", "--strict",
                           "--no-division-by-zero", "--stack-size", "256").startswith("PASS:")
            blob = obj.read_bytes()
            assert len(blob) <= 256 * 1024, "program exceeds the accepted size ceiling"
            target = next(sh for name, sh in sections(blob) if name == ".ls.target")
            offset = target[4]
            for cc in ("gcc", "clang-18"):
                check = args.output / ("target-" + cc)
                run(cc, "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", base / "check_target.c", "-o", check)
                for name in names:
                    run(check, obj, name, bid, binary)
                run(check, obj, "fentry/wrong", bid, binary, expected=1)
                run(check, obj, names[0], bid[:8] + "0" * 32, binary, expected=1)
                mutations = {
                    "version": (offset, b"X"),
                    "count": (offset + 8, struct.pack("<I", 1)),
                    "reserved": (offset + 12, b"\1"),
                    "duplicate-section": (offset + 16 + 144, blob[offset + 16:offset + 96]),
                    "unknown-section": (offset + 16 + 7, b"X"),
                    "unterminated-section": (offset + 16, b"x" * 80),
                    "duplicate-entry": (offset + 16 + 144 + 80 + 48,
                                        blob[offset + 16 + 80 + 48:offset + 16 + 80 + 56]),
                    "exit-in-set": (offset + 16 + 80 + 56, b"\1"),
                    "wrong-build-in-other-row": (offset + 16 + 144 + 80 + 8, b"x"),
                    "record-reserved": (offset + 16 + 80 + 58, b"\1"),
                }
                for label, (at, data) in mutations.items():
                    changed = bytearray(blob)
                    changed[at:at + len(data)] = data
                    path = args.output / (label + ".o")
                    path.write_bytes(changed)
                    for name in names:
                        run(check, path, name, bid, binary, expected=1)
                native = args.output / ("native-" + cc)
                run(cc, "-O2", "-Wall", "-Wextra", "-Werror", "-I" + str(ubpf / "vm/inc"),
                    "-I" + str(ubpf / "build/vm"), base / "check_agent_activity.c",
                    ubpf / "build/lib/libubpf.a", "-lm", "-o", native)
                text = run(native, obj)
                assert "PASS JIT:" in text and "PASS interpreter:" in text
            record["artifact"] = dict(path=str(obj), sha256=sha(obj), size_bytes=len(blob), sections=names)
            if args.sign:
                run("env", "PREVAIL=" + str(prevail), "python3", base / "check_target.py")
                run("python3", base / "check_ls_load.py")
                # The pre-multi-target parser, from the activity integration's
                # preserved originals. Later packages do not carry a copy.
                old_header = Path("/home/starin/eob-config-20260925/activity-integration-01/originals/ls_target.h")
                assert sha(old_header) == "cc699a4b45ca05530fe56e897bb161638e0d2fe4d2308d66edf89f9c9401013e"
                record["old_target_parser"] = dict(sha256=sha(old_header), text=old_header.read_text())
                old_check = args.output / "old-target-check"
                run("gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-I" + str(base),
                    "-include", old_header, base / "check_target.c", "-o", old_check)
                for name in names:
                    run(old_check, obj, name, bid, binary, expected=1)
                from bind_target import resolve  # pylint: disable=import-outside-toplevel
                package = json.loads((args.package.parent / "package-result.json").read_text())
                assert package["passed"] and package["runtime"]["sha256"] == sha(binary)
                record.update(tmm_image=package["image"], event_names={}, programs={})
                for label, slot, hook in (("json", 11, "json_filter_handle_json_complete"),
                                          ("http", 9, "hud_aimcp_handler")):
                    signature = args.output / ("activity-" + label + ".sig")
                    run("python3", base / "sign_shield.py", "--key",
                        Path.home() / ".ls-signing/shield_sk.pem", "--prog", obj,
                        "--hook", hook, "--mode-ceiling", "monitor", "--build-min", "0x" + bid[:8],
                        "--build-max", "0x" + bid[:8], "-o", signature)
                    _, entry, pad = resolve(args.package / "hook-index.tsv", binary, hook)
                    record["programs"][label] = dict(slot=slot, section="fentry/" + hook,
                        entry=hex(entry), pad=pad, object=obj.name, sha256=sha(obj),
                        signature=signature.name, signature_sha256=sha(signature))
            record["passed"] = True
        except BaseException as exc:
            record["error"] = repr(exc)
            raise
        finally:
            json.dump(record, receipt, indent=2)
    if args.sign:
        with (args.output / "metadata-program-build.json").open("x") as output:
            json.dump(record, output, indent=2)
    print(json.dumps(dict(passed=True, artifact=record["artifact"])))


if __name__ == "__main__":
    main()
