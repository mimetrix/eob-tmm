#!/usr/bin/env python3
"""
check_hook_map.py — validate a hook-point map against hook_map.schema.json.

Uses jsonschema when available; falls back to a structural check of the schema's
own required/additionalProperties/enum/pattern rules so `make check` works on a
bare box. Also reports which product-only fields an instance still lacks — that
is informative, not a failure: the example map is deliberately a subset (see
README.md and development-scope.md item 5).

Usage:  ./check_hook_map.py [map.json ...]      (default: ./hook-point-map.json)
"""
import json
import re
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_PATH = os.path.join(HERE, "hook_map.schema.json")

PRODUCT_TOP = ("ctx_abi_version", "generated_by", "signature")
PRODUCT_HOOK = ("entry_offset", "patchable_pad_bytes", "safe_return",
                "budget_cycles", "mode_ceiling")


def structural_check(schema, inst):
    """Minimal validator: the subset of JSON Schema this file actually uses."""
    errs = []
    for k in schema["required"]:
        if k not in inst:
            errs.append("top-level: missing required %r" % k)
    for k in inst:
        if k not in schema["properties"]:
            errs.append("top-level: unexpected key %r" % k)

    hpdef = schema["$defs"]["hook_point"]
    argdef = schema["$defs"]["arg_btf"]["patternProperties"]["^arg[0-9]+$"]
    fpat = argdef["properties"]["fields"]["additionalProperties"]["pattern"]

    for i, hp in enumerate(inst.get("hook_points", [])):
        where = "hook_points[%d]" % i
        for k in hpdef["required"]:
            if k not in hp:
                errs.append("%s: missing required %r" % (where, k))
        for k in hp:
            if k not in hpdef["properties"]:
                errs.append("%s: unexpected key %r" % (where, k))
        for k in ("attach_mode", "path_class"):
            allowed = hpdef["properties"][k]["enum"]
            if k in hp and hp[k] not in allowed:
                errs.append("%s: %s=%r not in %s" % (where, k, hp[k], allowed))
        for an, a in hp.get("arg_btf", {}).items():
            if not re.match(r"^arg[0-9]+$", an):
                errs.append("%s.arg_btf: bad key %r" % (where, an))
            for k in a:
                if k not in argdef["properties"]:
                    errs.append("%s.arg_btf.%s: unexpected key %r" % (where, an, k))
            for fn, ft in a.get("fields", {}).items():
                if not re.match(fpat, ft):
                    errs.append("%s.arg_btf.%s.%s: bad type %r"
                                % (where, an, fn, ft))
    return errs


def main(argv):
    paths = argv[1:] or [os.path.join(HERE, "hook-point-map.json")]
    schema = json.load(open(SCHEMA_PATH))

    try:
        import jsonschema
        validator = "jsonschema"
    except ImportError:
        jsonschema = None
        validator = "structural fallback"

    rc = 0
    for p in paths:
        rel = os.path.relpath(p, HERE)
        inst = json.load(open(p))
        if jsonschema is not None:
            try:
                jsonschema.validate(inst, schema)
                errs = []
            except jsonschema.ValidationError as e:
                errs = ["%s: %s" % ("/".join(str(x) for x in e.path), e.message)]
        else:
            errs = structural_check(schema, inst)

        if errs:
            rc = 1
            print("FAIL  %s  (%s)" % (rel, validator))
            for e in errs:
                print("        %s" % e)
        else:
            print("ok    %s  (%s)" % (rel, validator))

        # Only for maps the generator produced with the relocatability pass. The
        # checked-in example map predates it, and failing on that would punish the
        # wrong artifact.
        if inst.get("hook_points") and "arm_method" in inst["hook_points"][0]:
            try:
                check_relocatability(inst)
            except AssertionError as e:
                rc = 1
                print("FAIL  %s  relocatability: %s" % (rel, e))

        missing_top = [k for k in PRODUCT_TOP if k not in inst]
        missing_hook = sorted({k for hp in inst.get("hook_points", [])
                               for k in PRODUCT_HOOK if k not in hp})
        if missing_top or missing_hook:
            print("      product-only fields not yet emitted (expected for the "
                  "example map):")
            if missing_top:
                print("        top level: %s" % ", ".join(missing_top))
            if missing_hook:
                print("        per hook : %s" % ", ".join(missing_hook))
    return rc



def check_relocatability(doc):
    """The offline analysis is what lets the RUNTIME stay a memcpy and a jmp. If any of
    these break, the data plane would need an instruction decoder --- which is the whole
    thing this avoids."""
    hp = doc["hook_points"]
    n = 0

    for e in hp:
        assert e["arm_method"] in ("pad", "displace"), e["name"]; n += 1

        if e["arm_method"] == "displace":
            # No pad, so the jump is written OVER real instructions. Emitting one that
            # is not relocatable would corrupt the function.
            assert e["relocatable"] is True, f'{e["name"]} displaced but not relocatable'
            # Whole instructions only, and at least the 5 a jmp rel32 needs.
            assert e["displace_bytes"] >= 5, f'{e["name"]} displaces {e["displace_bytes"]}'
            assert "pad_offset" not in e, f'{e["name"]} has both a pad and displacement'
            n += 3
        else:
            assert e["pad_offset"] in (0, 4), e["name"]
            assert e["patchable_pad_bytes"] == 5, e["name"]
            n += 2

    # The population that only displacement can reach --- OpenSSL and friends. If this
    # is zero the analysis silently stopped working and reach quietly halved.
    disp = sum(1 for e in hp if e["arm_method"] == "displace")
    assert disp > 0, "no displaceable entries: the relocatability pass produced nothing"
    n += 1

    print(f"ok    hook map relocatability  ({n} assertions: "
          f"{len(hp) - disp:,} pad, {disp:,} displace)")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
