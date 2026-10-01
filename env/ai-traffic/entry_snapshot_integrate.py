#!/usr/bin/env python3
"""Build the tested snapshot sources through the TMM Docker toolchain."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--activity", action="store_true",
                        help="integrate the checked multi-target/JIT-buffer change")
    args = parser.parse_args()
    args.output.mkdir()
    tree = Path("/home/starin/code/tmm")
    staged = Path("/home/starin/eob-tmm-staged/substrate")
    names = ("ls_vm.c", "ls_vm.h", "ls_vm_load.c", "ls_fexit.c",
             "ls_target.h", "ls_snapshot.h")
    if args.activity:
        names = ("ls_vm.c", "ls_vm.h", "ls_target.h")
    protected = ("src/modules/hudfilter/http2/http2.c",
                 "src/modules/hudfilter/ssl/ssl.c", "src/base/ls_sig_pubkey.h",
                 "src/compile/default_whitelist_x86_64",
                 "src/compile/debug_whitelist_x86_64", "src/compile/filelist")
    record = dict(passed=False, scope="TMM_build_only", started=time.time(),
                  commands=[], sources={}, before_sources={})
    record["driver"] = dict(sha256=sha(Path(__file__)), text=Path(__file__).read_text())

    def run(*argv):
        argv = list(map(str, argv))
        row = subprocess.run(argv, cwd=tree, capture_output=True, text=True,
                             timeout=120, check=False)
        record["commands"].append(dict(argv=argv, rc=row.returncode,
                                       stdout=row.stdout, stderr=row.stderr))
        row.check_returncode()
        return row.stdout

    with (args.output / "build-result.json").open("x") as receipt:
        try:
            expected = ("cd6840802f626ab703b13fc77f2a7647ac843859cb70ec100ed35d01ddcbef99"
                        if args.activity else
                        "ae34e5c82afd93e325b6bea0b99b78b81ce9a0ad0cdc826503bfc1e82426b43b")
            assert sha(args.native) == expected
            native = json.loads(args.native.read_text())
            assert native["passed"]
            record["native_sha256"] = sha(args.native)
            record["instructions"] = (tree / "AGENTS.md").read_text()
            record["revision"] = run("git", "rev-parse", "HEAD").strip()
            assert record["revision"] == "e2104734a940a099a9190eb84bfbea01fb4b81d4"
            record["status_before"] = run("git", "status", "--porcelain", "src/")
            record["containers_before"] = run("docker", "ps", "-a", "--no-trunc",
                                               "--format", "{{.ID}} {{.Names}} {{.Image}}")
            processes = run("docker", "top", "4d2afd1db4e764d37c1b5e751b721b537f74abce4ff0055a85919c50e2314aa0",
                            "-eo", "pid,comm,args")
            for line in processes.splitlines()[1:]:
                fields = line.split()
                assert len(fields) < 2 or fields[1] not in (
                    "make", "gmake", "gcc", "cc1", "cc1plus", "g++", "ld"), line
            record["protected_before"] = {name: sha(tree / name) for name in protected}
            assert record["protected_before"]["src/base/ls_sig_pubkey.h"] == (
                "41e7867cdb7ee5a5f4ff027b1f8b167e741bc67b0073e6ec817a2e42204290db")
            originals = args.output / "originals"
            originals.mkdir()
            for name in names:
                source = args.source / name
                source_key = "substrate/" + name if args.activity else name
                assert sha(source) == native["sources"][source_key]["sha256"]
                record["sources"][name] = dict(sha256=sha(source), text=source.read_text())
                dest = tree / "src/base" / name
                if name == "ls_snapshot.h":
                    assert not dest.exists() and not (staged / name).exists()
                else:
                    assert sha(dest) == sha(staged / name), ("unreviewed tree/stage difference", name)
                    record["before_sources"][name] = dict(sha256=sha(dest), text=dest.read_text())
                    shutil.copy2(dest, originals / name)
            # All preservation checks precede source publication.
            for name in names:
                shutil.copy2(args.source / name, tree / "src/base" / name)
                shutil.copy2(args.source / name, staged / name)
            objects = sorted((tree / "src/compile").glob("obj_x86_64.*/ls_*.o"))
            objects += sorted((tree / "src/compile").glob("obj_x86_64.*/harness.o"))
            record["invalidated_objects"] = list(map(str, objects))
            if objects:
                run("sudo", "rm", "--", *objects)
            assert all(not path.exists() for path in objects)
            record["build_started"] = time.time()
            command = ["script", "-qec", "make tmm", str(args.output / "build.log")]
            record["build_command"] = command
            with (args.output / "console.log").open("xb") as console:
                process = subprocess.run(command, cwd=tree, stdout=console,
                                         stderr=subprocess.STDOUT, timeout=7200, check=False)
            record["returncode"] = process.returncode
            process.check_returncode()
            binary = tree / "src/compile/obj_x86_64.no_pgo/tmm.no_pgo"
            assert binary.stat().st_mtime >= record["build_started"], "stale linked artifact"
            symbols = run("nm", binary)
            selected = [line for line in symbols.splitlines()
                        if line.endswith((" ls_vm_snapshot_identity", " ls_vm_snapshot_call"))]
            assert len(selected) == 2
            assert b"snapshot is observe-only" in binary.read_bytes()
            record["artifact"] = dict(path=str(binary), sha256=sha(binary),
                                       bytes=binary.stat().st_size,
                                       mtime=binary.stat().st_mtime, symbols=selected,
                                       notes=run("readelf", "-n", binary))
            record["protected_after"] = {name: sha(tree / name) for name in protected}
            assert record["protected_after"] == record["protected_before"]
            record["status_after"] = run("git", "status", "--porcelain", "src/")
            record["containers_after"] = run("docker", "ps", "-a", "--no-trunc",
                                              "--format", "{{.ID}} {{.Names}} {{.Image}}")
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


if __name__ == "__main__":
    main()
