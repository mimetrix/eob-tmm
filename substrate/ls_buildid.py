#!/usr/bin/env python3
"""Read a binary's GNU build id. THE CANONICAL IMPLEMENTATION --- everything else copies it.

    ls_buildid.py <elf-file>      -> prints the id as hex, or exits non-zero

WHY THIS FILE EXISTS AT ALL. The build id is the only thing standing between "armed the
function" and "patched five bytes 64 bytes past it". On 2026-08-17 a stale address armed a
nop pad that was not rst_why's; the patch succeeded, OK ARMED LIVE was printed, and nothing
fired across 16,000 requests, because a pad cannot distinguish itself from another pad. Every
generated artifact carries the id of the binary it describes and is refused against any other.

WHY IT READS THE SECTION AND NOT THE SEGMENT. The obvious implementation walks PT_NOTE
program headers, and three copies in this repo did. It returned a 16-byte id where readelf
reports 20 --- consistently, so nothing ever disagreed with itself and nothing complained.

TMM's binaries declare TWO adjacent PT_NOTE segments, and the build-id note straddles them:

    PT_NOTE off=0x338 size=64 p_align=8   property note (36 B, 8-aligned)
                                          + build-id note header + FIRST 16 desc bytes
    PT_NOTE off=0x378 size=36 p_align=4   the remaining 4 bytes: c2cde196

The note data is contiguous in the file; the split is a segment-table artifact. A per-segment
parser therefore stops at p_filesz and truncates the descriptor. `.note.gnu.build-id` as a
SECTION covers the whole note, so reading it by name is correct by construction rather than
correct by luck about where a segment boundary fell.

The truncated form still discriminated builds --- 16 bytes of a SHA-1 is not a collision risk
--- so no live result was wrong. It was a gate advertising more than it checked, which is the
kind of thing that stays harmless until the day it does not.

FALLBACK for a binary with no section headers: coalesce the adjacent PT_NOTE segments and
scan for the note header, rather than walking note-by-note. Walking cannot work, because
alignment is PER-NOTE --- see _parse_note.
"""
import struct
import sys


def _read(f, off, size):
    f.seek(off)
    b = f.read(size)
    if len(b) != size:
        raise ValueError("short read at %#x" % off)
    return b


def _parse_note(n):
    """First NT_GNU_BUILD_ID in a note blob as hex bytes, or None.

    A PATTERN SCAN, not a note walk, and that is deliberate.

    The obvious implementation walks note-by-note, advancing by the padded name and
    descriptor lengths. It cannot work on a real segment, because ALIGNMENT IS PER-NOTE:
    .note.gnu.property pads its name to 8 bytes on 64-bit ELF while .note.gnu.build-id pads
    to 4, and both live in the same PT_NOTE. A 4-byte stride desynchronises after the
    property note; an 8-byte stride mis-locates the build-id descriptor by 4 bytes. Trying
    one alignment for the whole blob fails whichever one is picked --- which is what the
    first version of this function did, in both directions.

    A build-id note header is 16 fully determined bytes: namesz=4, a known descsz, type=3,
    and the owner string "GNU\0". Searching for that is unambiguous and needs no assumption
    about what precedes it. The descriptor lengths accepted are the ones ld actually emits:
    20 for sha1 (the default), 16 for md5, 8 for a truncated id.
    """
    for ds in (20, 16, 8):
        pat = struct.pack("<III", 4, ds, 3) + b"GNU\x00"
        i = n.find(pat)
        if i >= 0 and i + 16 + ds <= len(n):
            return n[i + 16:i + 16 + ds]
    return None


def build_id(path):
    """-> full build id as a hex string. Raises on anything it cannot read confidently."""
    with open(path, "rb") as f:
        e = _read(f, 0, 64)
        if e[:4] != b"\x7fELF":
            raise ValueError("%s is not an ELF file" % path)
        if e[4] != 2:
            raise ValueError("%s is not 64-bit ELF" % path)

        # THE SECTION PATH, preferred. See the module docstring for why.
        shoff, = struct.unpack_from("<Q", e, 0x28)
        shes, shn = struct.unpack_from("<HH", e, 0x3a)
        shstrndx, = struct.unpack_from("<H", e, 0x3e)
        if shoff and shn and shstrndx < shn:
            sh = _read(f, shoff + shstrndx * shes, shes)
            stroff, = struct.unpack_from("<Q", sh, 0x18)
            strsz, = struct.unpack_from("<Q", sh, 0x20)
            strs = _read(f, stroff, strsz)
            for i in range(shn):
                sh = _read(f, shoff + i * shes, shes)
                nmoff, = struct.unpack_from("<I", sh, 0)
                end = strs.find(b"\x00", nmoff)
                if strs[nmoff:end] != b".note.gnu.build-id":
                    continue
                off, = struct.unpack_from("<Q", sh, 0x18)
                sz, = struct.unpack_from("<Q", sh, 0x20)
                got = _parse_note(_read(f, off, sz))
                if got:
                    return got.hex()

        # FALLBACK: no section headers (a fully stripped binary). Coalesce ADJACENT PT_NOTE
        # segments first, because the straddle above is exactly what breaks a naive walk.
        phoff, = struct.unpack_from("<Q", e, 0x20)
        pes, pn = struct.unpack_from("<HH", e, 0x36)
        spans = []
        for i in range(pn):
            ph = _read(f, phoff + i * pes, pes)
            if struct.unpack_from("<I", ph, 0)[0] != 4:      # PT_NOTE
                continue
            off, = struct.unpack_from("<Q", ph, 0x08)
            sz, = struct.unpack_from("<Q", ph, 0x20)
            spans.append((off, sz))
        spans.sort()
        merged = []
        for off, sz in spans:
            if merged and merged[-1][0] + merged[-1][1] == off:
                merged[-1] = (merged[-1][0], merged[-1][1] + sz)
            else:
                merged.append((off, sz))
        for off, sz in merged:
            got = _parse_note(_read(f, off, sz))
            if got:
                return got.hex()

    raise ValueError("no NT_GNU_BUILD_ID in %s" % path)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: ls_buildid.py <elf-file>")
    try:
        print(build_id(sys.argv[1]))
    except (OSError, ValueError) as exc:
        sys.exit("*** %s" % exc)
