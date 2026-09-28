#!/usr/bin/env python3
"""Build a dedicated collector image; retain resolved base digest and all inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir()
    record = {"passed": False, "commands": [], "sources": {}}
    root = Path(__file__).parent

    def run(*command):
        row = subprocess.run(list(map(str, command)), capture_output=True, text=True,
                             timeout=300, check=False)
        record["commands"].append({"argv": list(map(str, command)), "rc": row.returncode,
                                   "stdout": row.stdout, "stderr": row.stderr})
        row.check_returncode()
        return row.stdout

    with (args.output / "image-build.json").open("x") as receipt:
        try:
            native = json.loads((args.native / "collector-build.json").read_text())
            assert native["passed"]
            record["native_build"] = native
            context = args.output / "context"
            context.mkdir()
            for name in ("stream_collector.py", "method_decode.py", "collector_container.py",
                         "collector_client.py", "Dockerfile.collector", "collector-compose.yaml",
                         "COLLECTOR-CONTAINER.md", "collector_image_build.py"):
                path = root / name
                record["sources"][name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                           "text": path.read_text()}
                shutil.copyfile(path, context / name)
            for name in ("stream_collector.py", "method_decode.py", "collector_client.py"):
                assert record["sources"][name]["sha256"] == native["sources"][str(root / name)]["sha256"]
            reader = args.native / "ls_stream"
            assert hashlib.sha256(reader.read_bytes()).hexdigest() == native["ls_stream_sha256"]
            shutil.copy2(reader, context / "ls_stream")
            run("docker", "pull", "python:3.12-slim")
            digests = json.loads(run("docker", "image", "inspect", "python:3.12-slim",
                                    "--format", "{{json .RepoDigests}}"))
            base = next(d for d in digests if d.startswith("python@sha256:"))
            record["base_image"] = base
            run("docker", "build", "--pull=false", "--build-arg", "PYTHON_IMAGE=" + base,
                "--iidfile", args.output / "image.id", "-f", context / "Dockerfile.collector", context)
            image = (args.output / "image.id").read_text().strip()
            record["image"] = image
            run("docker", "run", "--rm", "--network", "none", "--entrypoint", "python3", image,
                "-c", 'import hashlib,sqlite3,subprocess,sys; from pathlib import Path; '
                'assert hashlib.sha256(Path("/app/ls_stream").read_bytes()).hexdigest()==sys.argv[1]; '
                'assert subprocess.run(["/app/ls_stream"],check=False).returncode==2; '
                'print(sys.version); print(sqlite3.sqlite_version)', native["ls_stream_sha256"])
            record["passed"] = True
        except BaseException as error:
            record["error"] = repr(error)
            raise
        finally:
            json.dump(record, receipt, indent=2)
    print(json.dumps({"passed": True, "image": record["image"]}))


if __name__ == "__main__":
    main()
