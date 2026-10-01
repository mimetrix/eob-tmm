#!/usr/bin/env python3
"""Build and test the bounded JSON initialization snapshot program."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

from json_initialization_decode import decode


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def elf_read(blob, address, length):
    offset = struct.unpack_from("<Q", blob, 32)[0]
    size, count = struct.unpack_from("<HH", blob, 54)
    assert size == 56
    for index in range(count):
        kind, _, start, va, _, filesz, _, _ = struct.unpack_from(
            "<IIQQQQQQ", blob, offset + index * size)
        if kind == 1 and va <= address and address - va + length <= filesz:
            return blob[start + address - va:start + address - va + length]
    raise ValueError("address outside file-backed segment")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--package", type=Path)
    parser.add_argument("--debug", type=Path)
    args = parser.parse_args()
    args.output.mkdir()
    source = args.source.resolve()
    ubpf = Path("/home/starin/code/tmm/.ubpf")
    base = Path("/home/starin/eob-tmm-staged/substrate")
    verifier = base.parent / "ebpf-verifier/bin/prevail"
    result = dict(passed=False, sources={}, commands=[], programs={}, event_names={"57": "HUDEVT_FLOW_INIT"})

    def run(*argv, env=None):
        argv = list(map(str, argv))
        row = subprocess.run(argv, capture_output=True, text=True, timeout=240,
                             check=False, env=env)
        result["commands"].append(dict(argv=argv, rc=row.returncode,
                                       stdout=row.stdout, stderr=row.stderr))
        print(row.stdout, row.stderr, end="", flush=True)
        row.check_returncode()
        return row.stdout

    with (args.output / "metadata-program-build.json").open("x") as receipt:
        try:
            paths = [p for p in source.rglob("*") if p.is_file() and p.suffix != ".pyc"]
            for path in paths:
                result["sources"][str(path.relative_to(source))] = dict(
                    sha256=sha(path), text=path.read_text())
            assert "18.1.3" in run("clang-18", "--version")
            assert "13.3.0" in run("gcc", "--version")
            assert run("git", "-C", ubpf, "rev-parse", "HEAD").strip() == (
                "c900ed9faf1d41358a7ea9217ccd0b64a4ee8d5d")
            assert run("git", "-C", verifier.parent.parent, "rev-parse", "HEAD").strip() == (
                "06769f7b508214e63b97905d275920f7e90182fa")
            obj = args.output / "metadata-initialization.bpf.o"
            section = "fexit/snapshot/hud_json_handler"
            run("clang-18", "-target", "bpf", "-O2", "-Wall", "-Wextra", "-Werror",
                "-c", source / "surfaces/json_initialization.bpf.c", "-o", obj)
            if args.package:
                package = json.loads((args.package / "package-result.json").read_text())
                integration = json.loads((args.package / "build-result.json").read_text())
                assert package["passed"] and integration["passed"] and args.debug
                runtime = args.package / "image-context/tmm64.no_pgo"
                result["runtime"] = package["runtime"]
                result["tmm_image"] = package["image"]
                assert sha(runtime) == result["runtime"]["sha256"]
                for name, row in integration["sources"].items():
                    assert sha(source / name) == row["sha256"]
                old_path = Path("/home/starin/eob-config-20260925/json-initialization-discovery-02.json")
                assert sha(old_path) == "787a96e8d860640f509a4143ff380530ef2708ad3ee01e16c24c9699c7c6b2f0"
                old = json.loads(old_path.read_text())
                result["qualified_sources"] = {}
                for name, row in old["sources"].items():
                    if name.startswith("/home/starin/code/tmm/src/modules/"):
                        assert sha(Path(name)) == row["sha256"], name
                        result["qualified_sources"][name] = row
                assert result["qualified_sources"]
                sys.path.insert(0, str(source))
                from ls_buildid import build_id
                from bind_target import resolve
                assert build_id(str(args.debug)) == result["runtime"]["build_id"]
                _, entry, pad = resolve(args.package / "image-context/hook-index.tsv",
                                         runtime, "hud_json_handler")
                symbols = run("nm", "-S", "--defined-only", args.debug)
                table = {fields[-1]: (int(fields[0], 16), int(fields[1], 16))
                         for line in symbols.splitlines()
                         if len(fields := line.split()) == 4 and fields[2] in ("t", "T")}
                assert table["hud_json_handler"] == (entry, 0x1579)
                blob = runtime.read_bytes()
                instructions = ((0x37, "4889fd"), (0x3a, "4189f4"),
                                (0x69, "40f6c601"), (0x7c, "753b"),
                                (0xb52, "f348ab"), (0xb87, "808d9800000010"),
                                (0xb0d, "488b4518"), (0x7b1, "4889c7"),
                                (0x7b4, "ff10"), (0x12fa, "e983f9ffff"),
                                (0xc90, "e9f9feffff"))
                for offset, expected in instructions:
                    assert elf_read(blob, entry + offset, len(bytes.fromhex(expected))) == bytes.fromhex(expected)
                call = elf_read(blob, entry + 0xb7e, 5)
                assert call[0] == 0xe8
                assert entry + 0xb83 + struct.unpack("<i", call[1:])[0] == table["xbuf_embed_init"][0]
                dispatch = elf_read(blob, entry + 0x9f, 8)
                assert dispatch[:4] == bytes.fromhex("3eff24c5")
                jump_table = struct.unpack("<I", dispatch[4:])[0]
                assert struct.unpack("<Q", elf_read(blob, jump_table + 57 * 8, 8))[0] == entry + 0xb48
                result["instruction_checks"] = dict(entry=hex(entry), offsets=instructions,
                                                     init_target=hex(entry + 0xb48), jump_table=hex(jump_table))
                run("objdump", "-d", "--start-address=" + hex(entry),
                    "--stop-address=" + hex(entry + 0x1579), runtime)
                expression = ('python import gdb,json; print("LAYOUT " + json.dumps({'
                              '"types":{t:{f.name:f.bitpos for f in gdb.lookup_type(t).fields() if f.name}'
                              ' for t in ("struct hudnode","struct json_scb")},'
                              '"events":{f.name:f.enumval for f in gdb.lookup_type("hud_msg_t").fields()}}))')
                text = run("gdb", "-nx", "-batch", args.debug, "-ex", expression)
                layout = json.loads(next(line[7:] for line in text.splitlines() if line.startswith("LAYOUT ")))
                result["layout"] = layout
                assert all(layout["types"]["struct hudnode"][key] == value for key, value in
                           dict(ctx_sz=352, f_active=374, f_ctx=375, f_stream=377, ctx=512).items())
                assert layout["types"]["struct json_scb"]["f_disabled"] == 704
                assert layout["events"]["HUDEVT_FLOW_INIT"] == 57
                run(sys.executable, source / "bind_snapshot.py", "--prog", obj,
                    "--binary", runtime, "--debug", args.debug,
                    "--index", args.package / "image-context/hook-index.tsv")
                result["programs"]["initialization"] = dict(
                    slot=11, kind=1, section=section, entry=hex(entry), pad=pad, object=obj.name)
            run(verifier, obj, section, "--termination", "--strict",
                "--no-division-by-zero", "--stack-size", "256")
            native = args.output / "native"
            run("gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-I" + str(source),
                "-I" + str(ubpf / "vm/inc"), "-I" + str(ubpf / "build/vm"),
                source / "check_json_initialization.c", source / "ls_fexit.c",
                source / "ls_vm_config.c", source / "ls_core_relo.c",
                ubpf / "build/lib/libubpf.a", "-lm", "-o", native)
            result["native_events"] = []
            for jit in (0, 1):
                env = dict(os.environ, LS_VM_JIT=str(jit), LS_VM_SELFTEST="0",
                           LS_VM_VERBOSE="0", LS_VM_REPORT_EVERY="0", LS_SHIELD_ENABLE="1")
                text = run(native, obj, env=env)
                assert f"PASS JSON initialization jit={jit} cases=22" in text
                events = [decode(bytes.fromhex(line[7:])) for line in text.splitlines()
                          if line.startswith("RECORD ")]
                assert len(events) == 22
                result["native_events"].extend(events)
            if args.package:
                sig = obj.with_suffix(".sig")
                build = "0x" + result["runtime"]["build_id"][:8]
                run(sys.executable, base / "sign_shield.py", "--key",
                    Path.home() / ".ls-signing/shield_sk.pem", "--prog", obj,
                    "--hook", "hud_json_handler", "--mode-ceiling", "monitor",
                    "--build-min", build, "--build-max", build, "-o", sig)
                result["programs"]["initialization"].update(sha256=sha(obj), signature_sha256=sha(sig))
            result["passed"] = True
        except BaseException as error:
            result["error"] = repr(error)
            raise
        finally:
            json.dump(result, receipt, indent=2)


if __name__ == "__main__":
    main()
