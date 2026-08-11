#!/usr/bin/env python3
"""Verify every relative link in env/ resolves to a file that exists.

Renaming the inherited `NN-`-prefixed docs into this repo's descriptive
convention broke every cross-reference at once, so this exists to prove the
rewrite was complete rather than assert it.

`archive-eob-bigip/*.md` is exempt: those files are preserved verbatim from the
retired eob-bigip repo, so their links intentionally still point at the old
filenames. Their README maps old names to new. The archive's own README is
*not* exempt.

Usage:  check-links.py [env_dir]
Exit 0 if all links resolve, 1 otherwise.
"""
import os
import re
import sys

# [text](target) -- skip autolinks and images are fine to check too
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")

EXEMPT_VERBATIM = {
    "archive-eob-bigip/00-project-goals.md",
    "archive-eob-bigip/01-bigip-form-factors-and-ebpf-surface.md",
}


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(__file__) + "/..")
    failures, checked = [], 0

    for dirpath, _dirs, files in os.walk(root):
        for name in sorted(files):
            if not name.endswith((".md", ".sh", ".py")):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            if rel in EXEMPT_VERBATIM:
                print(f"skip (verbatim archive): {rel}")
                continue
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            if not name.endswith(".md"):
                continue
            for target in LINK.findall(text):
                # External and in-page anchors aren't our problem here.
                if target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                filepart = target.split("#", 1)[0]
                if not filepart:
                    continue
                checked += 1
                resolved = os.path.normpath(os.path.join(dirpath, filepart))
                if not os.path.exists(resolved):
                    failures.append(f"{rel}: {target} -> missing {os.path.relpath(resolved, root)}")

    for f in failures:
        print(f"BROKEN {f}")
    print(f"\n{checked} relative links checked, {len(failures)} broken")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
