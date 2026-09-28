#!/usr/bin/env python3
"""P17: actual native layout/values vs generated, relocated, verified BPF.

Run on the build box with clang-18, GCC's native BTF, and the pinned uBPF library.
UBPF defaults to ../ubpf; override to the TMM build's .ubpf if needed.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

import gen_type_catalog
import tmmtrace
from check_relo_baked import Btf, elf_sections, core_relos, baked_immediates

HERE = Path(__file__).resolve().parent


def run(*args, check=True):
    p = subprocess.run([str(a) for a in args], text=True, capture_output=True)
    print(p.stdout, end="", flush=True)
    if p.stderr:
        print(p.stderr, end="", flush=True)
    if check:
        p.check_returncode()
    return p


def oracle(original, relocated, offsets):
    """Map LOCAL field indices to names, but use native C offsetof, not target BTF."""
    secs = elf_sections(original)
    btf = Btf(secs[".BTF"][2])
    relos = core_relos(secs[".BTF.ext"][2], btf)
    actual = baked_immediates(relocated, relos)
    for sec, pos, tid, access, kind in relos:
        indices = [int(x) for x in access.split(":")]
        assert kind == 0 and indices[0] == 0, (kind, access)
        cur, want = btf.strip(tid), 0
        for index in indices[1:]:
            name, member, _, bits = btf.members(cur)[index]
            assert not bits
            want += offsets[cur["name"]][name]
            cur = btf.strip(member)
        assert actual[sec, pos] == want, (sec, access, actual[sec, pos], want)
    print("PASS native offsetof oracle:", len(relos), "relocations", flush=True)


def main():
    clang = os.environ.get("CLANG", "clang-18")
    ubpf = Path(os.environ.get("UBPF", str(HERE.parent / "ubpf"))).resolve()
    prevail = Path(os.environ.get("PREVAIL", str(HERE.parent / "ebpf-verifier/bin/prevail"))).resolve()
    objcopy = os.environ.get("OBJCOPY", "/usr/lib/llvm-18/bin/llvm-objcopy")
    run(clang, "--version")
    run("gcc", "--version")
    run("git", "-C", ubpf, "rev-parse", "HEAD")
    run("git", "-C", prevail.parent.parent, "rev-parse", "HEAD")
    for path in (HERE / "check_embedded.py", HERE / "check_embedded.c",
                 HERE / "gen_type_catalog.py", HERE / "tmmtrace.py",
                 HERE / "ls_core_relo.c", prevail, ubpf / "build/lib/libubpf.a"):
        print("SHA256", hashlib.sha256(path.read_bytes()).hexdigest(), path, flush=True)
    with tempfile.TemporaryDirectory(prefix="ls-embedded-") as tmp:
        d = Path(tmp)
        native, target, relo = d / "native", d / "target.btf", d / "relo"
        run("gcc", "-O2", "-g", "-gbtf", "-Wall", "-Wextra", "-Werror",
            "-I" + str(ubpf / "vm/inc"), "-I" + str(ubpf / "build/vm"), HERE / "check_embedded.c",
            ubpf / "build/lib/libubpf.a", "-lm", "-o", native)
        run(objcopy, "--dump-section=.BTF=" + str(target), native)
        offsets = json.loads(run(native, "--offsets").stdout)
        cat = gen_type_catalog.build(str(target))
        assert cat["__embedded__"]["root"]["nested"] == "middle"
        assert cat["__embedded__"]["middle"]["embedded"] == "leaf"
        assert cat["__ptr_targets__"]["middle"]["ptr"] == "leaf"
        assert cat["only_embedded"] == {}
        assert cat["__embedded__"]["only_embedded"]["nested"] == "middle"
        assert cat["__bitfields__"]["bit_zero"]["flag"]["shift"] == 0
        assert "flag" not in cat.get("bit_zero", {})
        assert "flag" in cat["__bitfields__"]["leaf"] and "flag" not in cat["leaf"]
        for unsupported in ("array", "unsupported", "anonymous"):
            assert unsupported not in cat["leaf"]
            assert unsupported not in cat["__embedded__"].get("leaf", {})
        print("PASS catalog: typedef/qualifiers, named embedding, unsupported aggregates", flush=True)
        tmmtrace._types_cache = cat
        tmmtrace._sigs_cache = {"fixture": "root:blob:struct root *|other:blob:struct root *"}
        run("gcc", "-O2", "-DLS_CORE_RELO_TEST", HERE / "ls_core_relo.c", "-o", relo)
        cases = [
            ("nested", "args.nested.embedded.value", 123, 1),
            ("pointer-embedded", "args.middle_ptr.embedded.value", 456, 2),
            ("embedded-pointer", "args.nested.ptr.value", 789, 2),
            ("pointer-only", "args.direct.value", 789, 2),
            ("scalar-field", "args.scalar", 55, 1),
            ("scalar-arg", "arg2", 42, 0),
            ("explicit-arg", "arg1.nested.embedded.other", 17, 1),
            ("multiple", None, 1, 2),
        ]
        for name, value, want, reads in cases:
            expr = ("fentry/fixture { " + value + " }") if value else (
                "fentry/fixture /args.nested.embedded.value == 123 && "
                "args.nested.embedded.other == 17/ { count() }")
            source, fn, section, hook = tmmtrace.codegen(expr)
            c, obj, patched = d / (name + ".c"), d / (name + ".o"), d / (name + ".baked.o")
            c.write_text(source)
            print("CASE", name, expr, flush=True)
            # Match the authoring worker; scalar-only output includes an unused helper declaration.
            run(clang, "-O2", "-g", "-target", "bpf", "-c", c, "-o", obj)
            if reads:
                run(relo, obj, target, patched)
                oracle(obj.read_bytes(), patched.read_bytes(), offsets)
            else:
                patched.write_bytes(obj.read_bytes())
            run(objcopy, "--remove-section=.BTF", "--remove-section=.BTF.ext",
                "--remove-section=.rel.BTF.ext", patched)
            run(prevail, patched, section + "/" + hook, "--termination", "--strict",
                "--no-division-by-zero", "--stack-size", "256")
            run(native, patched, fn, "ok", want, reads)
            if reads:
                run(native, patched, fn, "read-failure", 0, 1)
            if name in ("nested", "pointer-embedded", "embedded-pointer", "pointer-only"):
                run(native, patched, fn, "null-root", 0, 0)
            if name in ("pointer-embedded", "embedded-pointer", "pointer-only"):
                run(native, patched, fn, "null-pointer", 0, 1)
                run(native, patched, fn, "bad-pointer", 0, 2)
            if name == "nested":
                run(objcopy, "--remove-section=.BTF", "--remove-section=.BTF.ext",
                    "--remove-section=.rel.BTF.ext", obj)
                unrelocated = run(native, obj, fn, "ok", want, reads, check=False)
                assert unrelocated.returncode == 1 and "MISMATCH" in unrelocated.stdout
                print("PASS falsifier: unrelocated offsets return the wrong value", flush=True)
        for path in ("args.nested.embedded.flag", "args.nested.embedded.array",
                     "args.nested.embedded.unsupported.x", "args.nested.embedded.anonymous.hidden",
                     "args.nested.missing.value", "args.nested.embedded"):
            try:
                tmmtrace.codegen("fentry/fixture { " + path + " }")
            except tmmtrace.DslError as exc:
                print("PASS refusal:", path, str(exc), flush=True)
            else:
                raise AssertionError("unsupported path accepted: " + path)
        # Old catalogs must retain their exact pointer-only output and refuse embedding.
        before = tmmtrace.codegen("fentry/fixture { args.direct.value }")[0]
        legacy = copy.deepcopy(cat)
        legacy.pop("__embedded__")
        tmmtrace._types_cache = legacy
        assert tmmtrace.codegen("fentry/fixture { args.direct.value }")[0] == before
        try:
            tmmtrace.codegen("fentry/fixture { args.nested.embedded.value }")
        except tmmtrace.DslError:
            pass
        else:
            raise AssertionError("legacy catalog invented an embedded edge")
        print("PASS legacy pointer-only catalog", flush=True)
        for failure in ("ambiguous", "cycle", "conflict", "bit-zero"):
            broken = copy.deepcopy(cat)
            expression = "fentry/fixture { args.nested.embedded.value }"
            if failure == "ambiguous":
                broken["__ptr_targets__"]["root"]["nested"] = "middle"
            elif failure == "cycle":
                broken["__embedded__"]["root"]["nested"] = "root"
                expression = "fentry/fixture { args.nested.scalar }"
            elif failure == "conflict":
                broken["root"]["nested"] = "u64"
                expression = "fentry/fixture /args.nested != 0/ { args.nested.embedded.value }"
            else:
                broken["__embedded__"]["root"]["nested"] = "bit_zero"
                expression = "fentry/fixture { args.nested.flag }"
            tmmtrace._types_cache = broken
            try:
                tmmtrace.codegen(expression)
            except tmmtrace.DslError as exc:
                print("PASS", failure, "refusal:", str(exc), flush=True)
            else:
                raise AssertionError("invalid metadata accepted: " + failure)
    print("PASS P17 fixtures: native offsets/values, interpreter + JIT, pinned PREVAIL; not live TMM")


if __name__ == "__main__":
    main()
