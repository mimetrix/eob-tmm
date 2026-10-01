#!/usr/bin/env python3
"""Package the checked ownership build through the existing Docker pipeline."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "tree", "build", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    args.output.mkdir()
    record = dict(passed=False, commands=[], sources={}, started=time.time())
    env = dict(os.environ, TMM=str(args.tree), SRC=str(args.source / "substrate"),
               REPO=str(args.source), CTX=str(args.output / "image-context"),
               RECEIPT=str(args.output / "pipeline-receipt"), LS_EMBED_BTF="0")

    def run(*cmd, timeout=120):
        p = subprocess.run(list(map(str, cmd)), env=env, capture_output=True,
                           text=True, timeout=timeout, check=False)
        record["commands"].append(dict(argv=list(map(str, cmd)), rc=p.returncode,
                                       stdout=p.stdout, stderr=p.stderr))
        p.check_returncode()
        return p.stdout

    with (args.output / "package-result.json").open("x") as output:
        try:
            assert sha(args.build) == "a7fc77acdff72ee9bcfc1f574ae3a4896df652013c80ca947a244dfcec2bb6f2"
            build = json.loads(args.build.read_text())
            assert build["passed"]
            record["build_receipt_sha256"] = sha(args.build)
            assert sha(Path(build["artifact"]["path"])) == build["artifact"]["sha256"]
            for name, row in build["sources"].items():
                assert sha(args.source / "substrate" / name) == row["sha256"]
                assert sha(args.tree / "src/base" / name) == row["sha256"]
            for name, digest in build["protected_after"].items():
                assert sha(args.tree / name) == digest, name
            record["containers_before"] = run("docker", "ps", "-a", "--no-trunc", "--format", "{{.ID}} {{.Names}} {{.Image}}")
            record["tree_before"] = run("git", "-C", args.tree, "status", "--porcelain")
            for path in args.source.rglob("*"):
                if path.is_file() and "__pycache__" not in path.parts:
                    record["sources"][str(path.relative_to(args.source))] = dict(sha256=sha(path), text=path.read_text())
            for index, cmd in enumerate((
                ["sh", args.source / "env/scripts/bnk-package.sh"],
                ["sh", args.source / "env/scripts/bnk-bake-tools.sh", "tmm:local", args.image],
            )):
                log = args.output / ("step-%d.log" % index)
                with log.open("xb") as stream:
                    p = subprocess.run(list(map(str, cmd)), env=env, stdout=stream,
                                       stderr=subprocess.STDOUT, timeout=7200, check=False)
                record["commands"].append(dict(argv=list(map(str, cmd)), rc=p.returncode,
                                               stdout=log.read_text()))
                p.check_returncode()
            debs = args.tree / "docker_build/DEBS/amd64"
            saved = args.output / "debs"
            saved.mkdir()
            record["debs"] = {}
            for pattern in ("tmm_*.deb", "tmm-debuginfo_*.deb"):
                files = list(debs.glob(pattern))
                assert len(files) == 1, files
                path = files[0]
                shutil.copy2(path, saved / path.name)
                record["debs"][path.name] = sha(path)
                if pattern.startswith("tmm-debuginfo"):
                    run("dpkg-deb", "-x", path, args.output / "debug")
            debug = args.output / "debug/usr/lib/debug/usr/bin/tmm64.no_pgo.debug"
            runtime = args.output / "image-context/tmm64.no_pgo"
            record["runtime"] = json.loads((args.output / "image-context/runtime-identity.json").read_text())
            assert sha(runtime) == record["runtime"]["sha256"]
            notes = run("readelf", "-n", debug)
            assert record["runtime"]["build_id"] in notes
            symbols = run("readelf", "--wide", "--syms", debug)
            table = {row.split()[-1]: row.split() for row in symbols.splitlines()
                     if len(row.split()) >= 8 and row.split()[0].endswith(":")}
            for name, old in build["symbols"].items():
                assert table[name][3] == old[3] and table[name][6] != "UND", name
            record["symbols"] = {name: table[name] for name in build["symbols"]}
            # Keep the large symbol dump out of the receipt; preserve its hash.
            record["commands"][-1]["stdout_sha256"] = hashlib.sha256(symbols.encode()).hexdigest()
            del record["commands"][-1]["stdout"]
            record["debug"] = dict(path=str(debug), sha256=sha(debug), notes=notes)
            record["image"] = run("docker", "image", "inspect", args.image, "--format", "{{.Id}}").strip()
            record["tag"] = args.image
            record["containers_after"] = run("docker", "ps", "-a", "--no-trunc", "--format", "{{.ID}} {{.Names}} {{.Image}}")
            assert record["containers_before"] == record["containers_after"]
            for name, digest in build["protected_after"].items():
                assert sha(args.tree / name) == digest, name
            record["passed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            record["finished"] = time.time()
            json.dump(record, output, indent=2)
    print(json.dumps(dict(passed=True, image=record["image"], runtime=record["runtime"])))


if __name__ == "__main__":
    main()
