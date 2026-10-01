#!/usr/bin/env python3
"""Integrate native-qualified program ownership into an existing TMM build tree.

This is an incremental build, not a fresh-tree installer or a live traffic test.
All host paths and the existing toolchain container are explicit inputs.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import time


FILES = (
    "ls_program.h", "ls_program_impl.h", "ls_vm.c", "ls_vm.h",
    "ls_vm_load.c", "ls_map_glue.h", "ls_target.h", "ls_arm.h",
    "ls_tramp.c", "ls_tramp_asm.c",
)
NEW = {"ls_program.h", "ls_program_impl.h"}
WHITELISTS = (
    "src/compile/default_whitelist_x86_64",
    "src/compile/debug_whitelist_x86_64",
)
FUNCTIONS = (
    "ls_program_load", "ls_program_status", "ls_program_mode",
    "ls_program_attach", "ls_program_detach", "ls_program_revoke",
    "ls_program_site_owned", "ls_program_dispatch", "ls_tramp_dispatch_at",
)
TLS = ("g_prog_stack", "g_ls_namespace", "g_ls_map_namespaces")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "tree", "staged", "native", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--native-sha256", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--container", required=True)
    parser.add_argument("--previous", type=Path,
                        help="receipt for an earlier publication into this tree")
    parser.add_argument("--previous-sha256")
    parser.add_argument("--verify-built", action="store_true",
                        help="check a previous successful make without rebuilding")
    args = parser.parse_args()
    for name in ("source", "tree", "staged", "native", "output"):
        setattr(args, name, getattr(args, name).resolve())
    args.output.mkdir()
    base = args.source / "substrate"
    tree = args.tree
    record = dict(passed=False, scope="TMM linked binary only; no package or live test",
                  started=time.time(), commands=[], sources={}, original_sources={})
    record["inputs"] = {key: str(value) for key, value in vars(args).items()}
    record["driver"] = dict(sha256=sha(Path(__file__)), text=Path(__file__).read_text())

    def run(*argv, compact=False):
        argv = list(map(str, argv))
        result = subprocess.run(argv, cwd=tree, capture_output=True, text=True,
                                timeout=120, check=False)
        row = dict(argv=argv, rc=result.returncode, stderr=result.stderr)
        if compact:
            row["stdout_sha256"] = hashlib.sha256(result.stdout.encode()).hexdigest()
        else:
            row["stdout"] = result.stdout
        record["commands"].append(row)
        result.check_returncode()
        return result.stdout

    def containers():
        return run("docker", "ps", "-a", "--no-trunc", "--format",
                   "{{.ID}} {{.Names}} {{.Image}}")

    def hashes(paths):
        return {str(path.relative_to(tree)): sha(path) for path in paths}

    with (args.output / "build-result.json").open("x") as receipt:
        try:
            previous = None
            if args.previous:
                assert args.previous_sha256 and sha(args.previous) == args.previous_sha256
                previous = json.loads(args.previous.read_text())
                assert previous["inputs"]["tree"] == str(tree)
                record["previous_sha256"] = sha(args.previous)
            if args.verify_built:
                assert previous and previous.get("returncode") == 0, "no successful make receipt"
            assert sha(args.native) == args.native_sha256, "native receipt hash"
            native = json.loads(args.native.read_text())
            assert native["passed"], "native checks did not pass"
            record["native_sha256"] = sha(args.native)
            record["instructions"] = (tree / "AGENTS.md").read_text()
            record["revision"] = run("git", "rev-parse", "HEAD").strip()
            assert record["revision"] == args.revision, "TMM revision changed"
            record["status_before"] = run("git", "status", "--porcelain")
            record["containers_before"] = containers()
            inspection = json.loads(run("docker", "inspect", "--format",
                                       "{{json .Mounts}}", args.container))
            assert any(mount["Source"] == str(tree) and mount["Destination"] == "/tmm"
                       for mount in inspection), "container does not mount selected tree"
            record["container_image"] = run("docker", "inspect", "--format",
                                            "{{.Image}}", args.container).strip()
            processes = run("docker", "top", args.container, "-eo", "pid,comm,args")
            for line in processes.splitlines()[1:]:
                fields = line.split()
                assert len(fields) < 2 or fields[1] not in (
                    "make", "gmake", "gcc", "cc1", "cc1plus", "g++", "ld"
                ), "another build is running: " + line
            record["compiler"] = run("docker", "exec", args.container, "gcc", "--version")
            assert "11.4.0" in record["compiler"], "unqualified TMM compiler"
            record["ubpf_revision"] = run("git", "-C", tree / ".ubpf",
                                           "rev-parse", "HEAD").strip()
            assert record["ubpf_revision"] == "c900ed9faf1d41358a7ea9217ccd0b64a4ee8d5d"
            record["ubpf_status"] = run("git", "-C", tree / ".ubpf", "status", "--short")

            # The wrapper is generated from the assembly checked by the native suite.
            for name in ("trampoline_x86_64.S", "mk_tramp_asm.py"):
                assert sha(base / name) == native["sources"]["substrate/" + name]["sha256"]
            spec = importlib.util.spec_from_file_location("tramp_generator", base / "mk_tramp_asm.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            assembly = (base / "trampoline_x86_64.S").read_text()
            wrapper = module.PREAMBLE + "".join(module.wrap(line) for line in assembly.split("\n")) + module.EPILOGUE
            assert (base / "ls_tramp_asm.c").read_text() == wrapper, "assembly mirror drift"
            record["assembly_sha256"] = sha(base / "trampoline_x86_64.S")
            record["generated_wrapper_matches_native_assembly"] = True

            protected = [tree / name for name in (
                "src/modules/hudfilter/http2/http2.c",
                "src/modules/hudfilter/ssl/ssl.c", "src/compile/filelist",
                "Makefile.overrides", ".ubpf/build/lib/libubpf.a",
            )]
            protected += [path for path in (tree / "src/base").glob("ls_*.[ch]")
                          if path.name not in FILES]
            protected += [tree / "src/base" / name for name in ("shield_abi.h", "vm_stack_policy.h")]
            record["protected_before"] = hashes(protected)
            if args.verify_built:
                assert record["protected_before"] == previous["protected_before"], "build inputs changed"
            originals = args.output / "originals"
            originals.mkdir()
            # Check all existing substrate dependencies available in the native receipt.
            for path in protected:
                key = "substrate/" + path.name
                if path.parent == tree / "src/base" and path.name != "ls_sig_pubkey.h" and key in native["sources"]:
                    assert sha(path) == native["sources"][key]["sha256"], "unchecked dependency: " + key
            for name in FILES:
                source = base / name
                if name != "ls_tramp_asm.c":
                    assert sha(source) == native["sources"]["substrate/" + name]["sha256"], name
                record["sources"][name] = dict(sha256=sha(source), text=source.read_text())
                target = tree / "src/base" / name
                if previous:
                    assert sha(target) == previous["sources"][name]["sha256"], "tree changed since previous publication: " + name
                    assert sha(target) == sha(args.staged / name), "tree/stage divergence: " + name
                    if args.verify_built:
                        assert sha(source) == sha(target), "new source requires rebuilding: " + name
                    record["original_sources"][name] = dict(sha256=sha(target), text=target.read_text())
                    shutil.copy2(target, originals / name)
                elif name in NEW:
                    assert not target.exists() and not (args.staged / name).exists(), name
                else:
                    assert sha(target) == sha(args.staged / name), "tree/stage divergence: " + name
                    record["original_sources"][name] = dict(sha256=sha(target), text=target.read_text())
                    shutil.copy2(target, originals / name)

            changes = {}
            for name in WHITELISTS:
                path = tree / name
                text = path.read_text()
                if previous:
                    assert sha(path) == previous["whitelist_after"][name], name
                    assert text.splitlines().count("g_programs") == 1, name
                    assert "g_prog_stack" not in text.splitlines(), name
                    changes[name] = text
                else:
                    assert text.splitlines().count("g_prog_stack") == 1, name
                    assert "g_programs" not in text.splitlines(), name
                    changes[name] = text.replace("g_prog_stack\n", "g_programs\n")
                shutil.copy2(path, originals / path.name)
            record["whitelist_before"] = hashes([tree / name for name in WHITELISTS])
            record["whitelist_delta"] = dict(removed=["g_prog_stack"], added=["g_programs"],
                                            already_applied=bool(previous),
                                            reason="program stack is TLS; program ownership is process-global")
            record["filelist_substrate"] = [line for line in (tree / "src/compile/filelist").read_text().splitlines()
                                             if line.startswith(("base/ls_", "UBPF"))]
            assert "base/ls_tramp_asm.c" in "\n".join(record["filelist_substrate"])
            assert "-fpatchable-function-entry=5,0" in (tree / "Makefile.overrides").read_text()

            if args.verify_built:
                record["build_started"] = previous["build_started"]
                record["build_command"] = previous["build_command"]
                record["returncode"] = previous["returncode"]
                record["verification_only"] = True
            else:
                # Publish only after all input and preservation checks finish.
                for name in FILES:
                    shutil.copy2(base / name, tree / "src/base" / name)
                    shutil.copy2(base / name, args.staged / name)
                for name, text in changes.items():
                    (tree / name).write_text(text)
                objects = sorted((tree / "src/compile").glob("obj_x86_64.*/ls_*.o"))
                objects += sorted((tree / "src/compile").glob("obj_x86_64.*/harness.o"))
                record["invalidated_objects"] = list(map(str, objects))
                if objects:
                    run("sudo", "rm", "--", *objects)
                assert all(not path.exists() for path in objects), "stale objects survived"
                record["build_started"] = time.time()
                command = ["script", "-qec", "make tmm", str(args.output / "build.log")]
                record["build_command"] = command
                with (args.output / "console.log").open("xb") as console:
                    result = subprocess.run(command, cwd=tree, stdout=console,
                                            stderr=subprocess.STDOUT, timeout=7200, check=False)
                record["returncode"] = result.returncode
                result.check_returncode()
            record["whitelist_after"] = hashes([tree / name for name in WHITELISTS])

            binary = tree / "src/compile/obj_x86_64.no_pgo/tmm.no_pgo"
            assert binary.stat().st_mtime >= record["build_started"], "stale linked binary"
            symbol_text = run("readelf", "--wide", "--syms", binary, compact=True)
            if args.verify_built:
                old_symbols = next(row for row in previous["commands"]
                                   if row["argv"][:3] == ["readelf", "--wide", "--syms"])
                assert hashlib.sha256(symbol_text.encode()).hexdigest() == old_symbols["stdout_sha256"]
            symbols = {line.split()[-1]: line.split() for line in symbol_text.splitlines()
                       if len(line.split()) >= 8 and line.split()[0].endswith(":")}
            for name in FUNCTIONS:
                assert symbols[name][3] == "FUNC" and symbols[name][6] != "UND", name
            for name in TLS:
                assert symbols[name][3] == "TLS", name
            assert symbols["g_programs"][3] == "OBJECT"
            record["symbols"] = {name: symbols[name] for name in FUNCTIONS + TLS + ("g_programs", "g_slots")}
            record["trampolines"] = {}
            for site in range(12):
                name = "ls_trampoline_slot" + str(site)
                # Slot zero has a public alias. Name-filtered objdump can emit
                # no instructions for that name; use the exact ELF symbol range.
                address = int(symbols[name][1], 16)
                size = int(symbols[name][2])
                assert size > 0 and symbols[name][3] == "FUNC", name
                text = run("objdump", "-d", "--start-address=" + hex(address),
                           "--stop-address=" + hex(address + size), binary)
                assert "<ls_tramp_dispatch_at>" in text and "0x50(%rsp),%rdx" in text, name
                record["trampolines"][name] = text
            run(tree / "bin/diff-globals", binary, tree / WHITELISTS[0])
            record["artifact"] = dict(path=str(binary), sha256=sha(binary),
                                       bytes=binary.stat().st_size, mtime=binary.stat().st_mtime,
                                       notes=run("readelf", "-n", binary))
            shutil.copy2(binary, args.output / "tmm.no_pgo")
            assert sha(args.output / "tmm.no_pgo") == record["artifact"]["sha256"]
            record["protected_after"] = hashes(protected)
            assert record["protected_after"] == record["protected_before"], "protected file changed"
            for name in FILES:
                assert sha(tree / "src/base" / name) == sha(base / name)
                assert sha(args.staged / name) == sha(base / name)
            record["status_after"] = run("git", "status", "--porcelain")
            record["containers_after"] = containers()
            assert record["containers_after"] == record["containers_before"]
            record["passed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            record["finished"] = time.time()
            for name in ("build.log", "console.log"):
                path = args.output / name
                if path.exists():
                    record[name] = dict(sha256=sha(path), text=path.read_text(errors="replace"))
            json.dump(record, receipt, indent=2)
    print(json.dumps(dict(passed=True, artifact=record["artifact"])), flush=True)


if __name__ == "__main__":
    main()
