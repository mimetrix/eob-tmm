#!/usr/bin/env python3
"""Generate ls_tramp_asm.c from trampoline_x86_64.S.

The TMM filelist compiles C only, so the assembly ships wrapped in a file-scope
__asm__ block. This writes that wrapper.

WHY THIS IS A SCRIPT AND NOT A MAKEFILE ONE-LINER. It was a one-liner, and on
2026-08-17 it destroyed the file it was generating: it derived the C preamble by
splitting the OUTPUT on '__asm__(' and keeping the prefix, so the first run stripped
the '#if defined(__x86_64__)' guard and every later run preserved the damage. The
result compiled to '#endif without #if'. Nested shell/make/python quoting made the
bug invisible in the recipe text.

Generating the whole file from the .S plus constants here has no such failure mode:
there is no prior output to depend on.
"""
import sys

SRC = "trampoline_x86_64.S"
DST = "ls_tramp_asm.c"

PREAMBLE = """/* ls_tramp_asm.c --- the validated trampoline_x86_64.S, wrapped in a file-scope
   asm block because the TMM filelist compiles C only.

   GENERATED from trampoline_x86_64.S by `make tramp-asm`. Do not hand-edit: on
   2026-08-17 Phase 3 was applied to THIS file and not to the .S, so the two
   disagreed and the next regeneration would have silently reverted the change.
   check-tramp-mirror fails the build if they drift. */
#if defined(__x86_64__)
__asm__(
"""

EPILOGUE = """);
#endif /* __x86_64__ */
"""


def wrap(line):
    """One .S line as a C string literal. Backslashes first --- doing it after the
    quotes would escape the backslashes this very step introduces."""
    return '"%s\\n"\n' % line.replace("\\", "\\\\").replace('"', '\\"')


def main():
    body = open(SRC).read().split("\n")
    out = PREAMBLE + "".join(wrap(l) for l in body) + EPILOGUE
    open(DST, "w").write(out)

    # Refuse to leave behind something that cannot compile. These are the exact two
    # ways the one-liner broke it.
    txt = open(DST).read()
    if "#if defined(__x86_64__)" not in txt:
        sys.exit("*** generated %s has no #if guard --- refusing" % DST)
    if txt.count("__asm__(") != 1:
        sys.exit("*** generated %s has %d __asm__ blocks, expected 1"
                 % (DST, txt.count("__asm__(")))
    print("ok    %s regenerated from %s (%d lines wrapped)" % (DST, SRC, len(body)))


if __name__ == "__main__":
    main()
