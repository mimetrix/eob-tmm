#!/usr/bin/env python3
"""Merge Horizon-downloaded clouds.yaml files into a single multi-cloud config.

Horizon's "Download clouds.yaml" button (Identity -> Application
Credentials) emits a file with the cloud named `openstack`. We need one
entry per stack, named `sjc` / `sea`, so `OS_CLOUD=sjc` selects a stack.
This merges N such files, renames each cloud, and forces `verify: false`
(the F5 F5NET Issuing CA isn't in this sandbox's trust store).

Secrets are never printed -- output goes straight to the target file at
mode 0600, and stdout only reports which keys were found.

Usage:
    merge-clouds-yaml.py sjc=/path/to/sjc-clouds.yaml [sea=/path/to/sea-clouds.yaml]

Run with --verify-tls if a proper CA bundle ever gets provisioned.
See env/tmm-build-environment.md.
"""
import os
import sys

import yaml

TARGET = os.path.expanduser("~/.config/openstack/clouds.yaml")


def main(argv):
    verify_tls = "--verify-tls" in argv
    pairs = [a for a in argv[1:] if not a.startswith("--")]
    if not pairs:
        sys.exit(__doc__)

    merged = {}
    # Preserve any clouds already configured that we're not replacing.
    if os.path.exists(TARGET):
        with open(TARGET) as fh:
            merged = (yaml.safe_load(fh) or {}).get("clouds", {}) or {}
        print(f"existing {TARGET}: keeping clouds {sorted(merged)}")

    for pair in pairs:
        if "=" not in pair:
            sys.exit(f"expected name=path, got: {pair}")
        name, path = pair.split("=", 1)
        path = os.path.expanduser(path)
        with open(path) as fh:
            doc = yaml.safe_load(fh) or {}

        clouds = doc.get("clouds") or {}
        if len(clouds) != 1:
            sys.exit(
                f"{path}: expected exactly one cloud entry, found {len(clouds)} "
                f"({sorted(clouds)}) -- is this a Horizon clouds.yaml?"
            )
        body = dict(next(iter(clouds.values())))

        auth = body.get("auth") or {}
        if not auth.get("application_credential_secret"):
            sys.exit(
                f"{path}: no application_credential_secret found. Horizon only "
                "reveals the secret at creation time -- if you missed it, delete "
                "the credential and create a new one."
            )

        body["verify"] = bool(verify_tls)
        body.setdefault("identity_api_version", 3)
        body.setdefault("interface", "public")
        body.setdefault("auth_type", "v3applicationcredential")

        merged[name] = body
        # Report only non-secret fields so the log stays safe to paste.
        print(
            f"{name}: auth_url={auth.get('auth_url')} "
            f"region={body.get('region_name')} "
            f"app_cred_id={auth.get('application_credential_id')} "
            f"secret=<{len(auth['application_credential_secret'])} chars, not shown>"
        )

    os.makedirs(os.path.dirname(TARGET), exist_ok=True)
    # Create with 0600 from the outset -- never briefly world-readable.
    fd = os.open(TARGET, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        yaml.safe_dump({"clouds": merged}, fh, default_flow_style=False, sort_keys=True)
    os.chmod(TARGET, 0o600)

    print(f"\nwrote {TARGET} (mode 600) with clouds: {sorted(merged)}")
    print("verify:", "TLS verification ON" if verify_tls else "false (internal CA not in trust store)")
    print("\nnext: OS_CLOUD=sjc openstack project list")


if __name__ == "__main__":
    main(sys.argv)
