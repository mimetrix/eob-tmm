#!/usr/bin/env python3
"""Speak the live-surface loader protocol over its unix socket.

WHY THIS IS IN THE REPO. Every live result so far --- including "maps work in TMM"
--- was produced by a client typed inline and then thrown away. So the exact bytes
that produced a headline number were not recoverable, which is the same class of
problem as source living only on the build box. This is that client, versioned.

RUNS INSIDE THE TMM CONTAINER. The socket is at $LS_LOAD_SOCKET in the f5-tmm
container's own filesystem; a sidecar does not share it. Invoke as:

    kubectl exec -i <pod> -c f5-tmm -- python3 - status 5 < ls-load.py

WIRE LAYOUT is struct shield_msg from substrate/shield_abi.h. The offsets below
are not remembered, they were read out of the compiler:

    op=0  epoch=4  mode=8  prog_len=12  binding.hook=48  prog=192  sizeof=192

`epoch` carries the SLOT. That field name is a wart --- three ops once hardcoded
slot 0 while reporting success, so a load landed where nothing ran.

  arm   <slot> <name|0xaddr>  0x1003  patch a live function entry
  disarm      <name|0xaddr>   0x1004  restore the nops

ARM BY NAME, NOT BY ADDRESS --- and the build-id gate is the reason this exists.
A bare hex address is still accepted, and still prints a warning, because it
cannot be checked against anything. Passing a NAME resolves it through the index
baked into the image ($LS_HOOK_INDEX, default /usr/share/ls/hook-index.tsv),
whose header carries the build id of the binary it was generated from. That is
compared against the build id of the binary THIS PROCESS IS ACTUALLY RUNNING,
read out of /proc/<pid>/exe, and a mismatch is refused.

Two real failures this closes, both of which reported success at the time:

  - A stale address armed rst_cause_match_peer instead of rst_why. It is the
    neighbouring function and it also carries a nop pad, so the patch succeeded,
    "OK ARMED LIVE" was printed, and fired stayed 0 under 16,000 requests. A pad
    cannot distinguish itself from another pad; a build id can.
  - An image shipped with /usr/bin/tmm pointing at tmm64.debug, which overrides
    CFLAGS_OPTIMIZE and therefore has NO pads at all. Reading the build id from
    /proc/<pid>/exe rather than from the /usr/bin/tmm symlink catches that,
    because it asks what is running instead of what is installed.
  load  <slot> <file> [mode]  1  load an ELF (default mode 2 = enforce)
  status <slot>               3  armed/mode/gen/fired/safe_returns
  mode  <slot> <mode>         2  0 disable, 1 monitor, 2 enforce
  revoke <slot>               4

Signature verification is NOT part of this path (scope item 4, deferred): the
loader accepts unverified programs and says so on every load. Lab only.
"""
import os
import socket
import struct
import sys

HDR = 192
OFF_OP, OFF_EPOCH, OFF_MODE, OFF_PROGLEN, OFF_HOOK = 0, 4, 8, 12, 48

# struct shield_binding sits at msg offset 16; ctx_abi_version is at binding offset
# 105, in what used to be padding between mode_ceiling (uint8 at 104) and
# expires_with (4-aligned at 108). So 16 + 105.
#
# WHAT IT IS FOR. PREVAIL verifies a program against the ctx STRUCT it was compiled
# with; the running TMM's builders produce a struct of their own shape. Nothing
# connected those until this field existed, so a program built against a different
# layout loaded and verified cleanly and read adjacent fields as its own --- which is
# exactly what happened when ls_ctx_rst went 64 -> 92 bytes and gained a flow cookie.
#
# Bump this WITH the header, in the same edit. A client that lies about it is worse
# than one that sends 0, because 0 is accepted-with-a-warning and a wrong value is
# refused outright.
OFF_CTX_ABI = 16 + 105
CTX_ABI_VERSION = 3

OP_LOAD, OP_SET_MODE, OP_STATUS, OP_REVOKE = 1, 2, 3, 4
OP_ARM, OP_DISARM = 0x1003, 0x1004

HOOK_INDEX = os.environ.get("LS_HOOK_INDEX", "/usr/share/ls/hook-index.tsv")


def elf_build_id(path):
    """Read NT_GNU_BUILD_ID out of an ELF's PT_NOTE segments.

    Pure Python on purpose: the f5-tmm container has no readelf, no objdump and no
    nm, and `strings` is absent too --- the runbook records that it silently
    returns zero for everything, which is worse than being missing. python3 IS
    present, because this script runs under it.
    """
    with open(path, "rb") as f:
        e = f.read(64)
        if e[:4] != b"\x7fELF":
            return None
        if e[4] != 2:                              # ELFCLASS64 only
            return None

        # SECTION FIRST, SEGMENT AS FALLBACK, and the order is the whole point.
        #
        # This used to walk PT_NOTE program headers only. On the binary that ships it gives
        # the right answer; on the PGO debug build in the same DEB pair it silently returns a
        # 16-BYTE id where readelf reports 20, because that binary declares two adjacent
        # PT_NOTE segments and the build-id note STRADDLES them --- the first segment's
        # p_filesz cuts the descriptor after 16 bytes and the last 4 live in the next segment.
        #
        # `.note.gnu.build-id` as a SECTION covers the whole note regardless of where a
        # segment boundary fell. substrate/ls_buildid.py is the canonical implementation and
        # substrate/check_ls_load.py asserts this copy agrees with it on real binaries --- the
        # copy exists because this file must run standalone inside a container with no readelf,
        # not because two implementations are wanted.
        shoff, = struct.unpack_from("<Q", e, 0x28)
        shentsize, shnum = struct.unpack_from("<HH", e, 0x3a)
        shstrndx, = struct.unpack_from("<H", e, 0x3e)
        if shoff and shnum and shstrndx < shnum:
            f.seek(shoff + shstrndx * shentsize)
            sh = f.read(shentsize)
            stroff, = struct.unpack_from("<Q", sh, 0x18)
            strsz, = struct.unpack_from("<Q", sh, 0x20)
            f.seek(stroff)
            strs = f.read(strsz)
            for i in range(shnum):
                f.seek(shoff + i * shentsize)
                sh = f.read(shentsize)
                nmoff, = struct.unpack_from("<I", sh, 0)
                if strs[nmoff:strs.find(b"\x00", nmoff)] != b".note.gnu.build-id":
                    continue
                off, = struct.unpack_from("<Q", sh, 0x18)
                sz, = struct.unpack_from("<Q", sh, 0x20)
                f.seek(off)
                got = _note_build_id(f.read(sz))
                if got:
                    return got

        # No section headers (fully stripped). Coalesce ADJACENT PT_NOTE segments so a
        # straddling note is whole before it is looked for.
        phoff, = struct.unpack_from("<Q", e, 0x20)
        phentsize, phnum = struct.unpack_from("<HH", e, 0x36)
        spans = []
        for i in range(phnum):
            f.seek(phoff + i * phentsize)
            ph = f.read(phentsize)
            p_type, = struct.unpack_from("<I", ph, 0)
            if p_type != 4:                        # PT_NOTE
                continue
            off, = struct.unpack_from("<Q", ph, 0x08)
            sz,  = struct.unpack_from("<Q", ph, 0x20)
            spans.append((off, sz))
        spans.sort()
        merged = []
        for off, sz in spans:
            if merged and merged[-1][0] + merged[-1][1] == off:
                merged[-1] = (merged[-1][0], merged[-1][1] + sz)
            else:
                merged.append((off, sz))
        for off, sz in merged:
            f.seek(off)
            got = _note_build_id(f.read(sz))
            if got:
                return got
    return None


def _note_build_id(note):
    """First NT_GNU_BUILD_ID in a note blob as hex, or None.

    A PATTERN SCAN rather than a note walk, because ALIGNMENT IS PER-NOTE:
    .note.gnu.property pads its name to 8 bytes on 64-bit ELF and .note.gnu.build-id pads to
    4, in the same PT_NOTE. Any single stride desynchronises --- 4 skips past the build-id
    header, 8 mis-locates its descriptor by 4 bytes. A build-id note header is 16 determined
    bytes (namesz=4, descsz, type=3, "GNU\\0"), so searching for it needs no assumption about
    what came before. Kept byte-identical in behaviour to substrate/ls_buildid.py, which
    substrate/check_ls_load.py asserts.
    """
    for dsz in (20, 16, 8):
        pat = struct.pack("<III", 4, dsz, 3) + b"GNU\x00"
        i = note.find(pat)
        if i >= 0 and i + 16 + dsz <= len(note):
            return note[i + 16: i + 16 + dsz].hex()
    return None


def running_binary():
    """The binary this container is ACTUALLY executing.

    Deliberately not readlink(/usr/bin/tmm): an image can carry both tmm64.no_pgo
    (padded) and tmm64.debug (no pads, because the debug build overrides
    CFLAGS_OPTIMIZE), and /usr/bin/tmm has pointed at the wrong one. Asking /proc
    asks the kernel what is running rather than what is installed.
    """
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            exe = os.readlink("/proc/%s/exe" % d)
        except OSError:
            continue                               # not ours, or already gone
        if os.path.basename(exe).startswith("tmm"):
            return exe
    return None


def read_index(path):
    """-> (meta dict, {name: [(arm_at, arm_method, pad_offset), ...]}).

    A LIST PER NAME, not one entry, because names are not unique. This build's index
    has 71,148 lines under 70,020 distinct names: 591 names carry between 2 and 21
    entries each. They are file-scope statics that appear in several translation units,
    .isra/.constprop clones, and assembler labels (LOne, LTwo, LThree at 21 apiece).

    Storing one entry per name silently kept whichever line came last, so arming one of
    those 591 by name would patch an arbitrary one of its homonyms and report success.
    That is the same failure as the stale address it replaced, with a nicer interface.
    """
    meta, syms = {}, {}
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#"):
                p = line[1:].split("\t")
                if len(p) >= 2 and p[0] != "name":
                    meta[p[0]] = p[1]
                continue
            p = line.split("\t")
            if len(p) >= 3:
                syms.setdefault(p[0], []).append(
                    (p[1], p[2], p[3] if len(p) > 3 else "-"))
    return meta, syms


def resolve_hook(spec):
    """A name -> a checked address. A 0x... address -> itself, with a warning.

    Refuses rather than guesses on every failure. An unresolvable name that fell
    back to *something* would reproduce the exact bug this closes.
    """
    if spec.startswith("0x") or spec.startswith("0X"):
        try:
            int(spec, 16)
        except ValueError:
            sys.exit("*** %r is not a hex address and not a symbol name" % spec)
        print("warning: raw address --- NOT checked against the running binary's "
              "build id. A stale address arms whatever is there, and a nop pad "
              "exists in plenty of wrong places.", file=sys.stderr)
        return spec

    if not os.path.exists(HOOK_INDEX):
        sys.exit("*** no hook index at %s, so %r cannot be resolved.\n"
                 "    Generate it with substrate/mk_hook_map.py --index and bake it\n"
                 "    into the image, or pass a 0x address and accept it is unchecked."
                 % (HOOK_INDEX, spec))

    meta, syms = read_index(HOOK_INDEX)

    exe = running_binary()
    if exe is None:
        sys.exit("*** cannot find the running tmm binary under /proc, so the index\n"
                 "    cannot be shown to describe it. Refusing to resolve a name.")
    live = elf_build_id(exe)
    want = meta.get("build_id")
    if live is None:
        sys.exit("*** %s carries no GNU build id, so the index cannot be matched to it."
                 % exe)
    if want is None:
        sys.exit("*** %s has no #build_id header --- regenerate it." % HOOK_INDEX)
    if live != want:
        sys.exit("*** BUILD ID MISMATCH --- refusing to arm.\n"
                 "    running   %s\n              %s\n"
                 "    index for %s\n\n"
                 "    Every address in the index is wrong for this binary. This is the\n"
                 "    check that was missing when a stale address armed the function\n"
                 "    NEXT to rst_why, reported OK ARMED LIVE, and never fired.\n"
                 "    Rebuild the index from the binary this pod actually runs."
                 % (exe, live, want))

    if spec not in syms:
        sys.exit("*** %r is not in the index (%d distinct names, build %s).\n"
                 "    Either it does not exist in this build, or it is neither padded\n"
                 "    nor safely displaceable --- the generator omits those rather than\n"
                 "    emitting an entry that cannot be armed."
                 % (spec, len(syms), want[:12]))

    cands = syms[spec]
    if len(cands) > 1:
        # AMBIGUOUS, so refuse. 591 names in this build have more than one entry ---
        # file-scope statics repeated across translation units, .isra/.constprop
        # clones, assembler labels. Picking one would patch an arbitrary homonym and
        # report success, which is exactly the failure arming-by-name exists to end.
        lines = "\n".join("      %s  (%s, pad_offset=%s)" % c for c in cands[:8])
        more = "" if len(cands) <= 8 else "\n      ... and %d more" % (len(cands) - 8)
        sys.exit("*** %r is AMBIGUOUS --- %d entries in this build:\n%s%s\n\n"
                 "    A name that resolves to several addresses cannot be armed by name.\n"
                 "    Pick one and pass it as a 0x address, accepting that it is then\n"
                 "    unchecked against the build id."
                 % (spec, len(cands), lines, more))

    arm_at, method, pad_off = cands[0]
    print("%s -> %s  (%s, pad_offset=%s, build %s)"
          % (spec, arm_at, method, pad_off, want[:12]), file=sys.stderr)
    return arm_at

def resolve_sock():
    """The loader appends the TMM instance number: LS_LOAD_SOCKET=/tmp/ls_load.sock
    becomes /tmp/ls_load.sock.24. Connecting to the unsuffixed name fails with
    ENOENT, which reads exactly like "the loader is off" and is not. So resolve it,
    and if several instances are listening say so rather than picking one --- they
    are separate processes with separate slots, and guessing would attribute a
    result to the wrong one."""
    base = os.environ.get("LS_LOAD_SOCKET", "/tmp/ls_load.sock")
    if os.path.exists(base):
        return base
    d, name = os.path.dirname(base) or ".", os.path.basename(base)
    found = sorted(os.path.join(d, f) for f in os.listdir(d)
                   if f.startswith(name + "."))
    if not found:
        sys.exit("no loader socket at %s or %s.* --- is LS_LOAD_SOCKET set, and did "
                 "the loader thread start? Check the pod log for 'LOADER LISTENING'."
                 % (base, base))
    if len(found) > 1 and not os.environ.get("LS_SOCK_PICK"):
        sys.exit("several loaders listening:\n  " + "\n  ".join(found) +
                 "\nset LS_LOAD_SOCKET to one of them (separate processes, separate slots)")
    return found[0]


# RESOLVED LAZILY, not at import. As a module-level call this exited before main()
# ran, so the script could not print its own usage without a live loader --- and
# more importantly it could not be imported by a test at all, which is why the
# build-id gate below went unexercised until it was made lazy.
_SOCK = None


def sock():
    global _SOCK
    if _SOCK is None:
        _SOCK = resolve_sock()
    return _SOCK


def msg(op, slot=0, mode=0, hook=b"", prog=b""):
    """Build one shield_msg. Zero-filled: every field this op does not use must
    read as zero, not as residue from whatever was in the buffer before."""
    b = bytearray(HDR)
    struct.pack_into("<I", b, OFF_OP, op)
    struct.pack_into("<I", b, OFF_EPOCH, slot)
    struct.pack_into("<I", b, OFF_MODE, mode)
    struct.pack_into("<I", b, OFF_PROGLEN, len(prog))
    b[OFF_CTX_ABI] = CTX_ABI_VERSION
    if hook:
        if len(hook) > 64:
            sys.exit("hook name/address longer than the 64-byte field")
        b[OFF_HOOK:OFF_HOOK + len(hook)] = hook
    return bytes(b) + prog


def send(payload):
    path = sock()
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(20)
        s.connect(path)
    except OSError as e:
        sys.exit("cannot reach %s: %s  (is LS_LOAD_SOCKET set on the pod?)" % (path, e))
    s.sendall(payload)
    try:
        s.shutdown(socket.SHUT_WR)          # tell the loader the request is complete
    except OSError:
        pass
    out = b""
    while True:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            out += b"\n<timed out waiting for a reply>"
            break
        if not chunk:
            break
        out += chunk
    s.close()
    return out.decode("utf-8", "replace").rstrip()


def main():
    a = sys.argv[1:]
    if not a:
        sys.exit(__doc__)
    cmd = a[0]

    if cmd == "arm":
        # The address goes in binding.hook AS TEXT --- the loader strtoull()s it.
        # resolve_hook turns a symbol name into that text, or exits.
        slot, addr = int(a[1]), resolve_hook(a[2])
        print(send(msg(OP_ARM, slot=slot, hook=addr.encode())))
    elif cmd == "disarm":
        # Disarm resolves the same way. It MUST, or the demo arms by name and
        # disarms by a hand-typed address --- restoring nops over whatever is at
        # that address instead, which is a write into live .text.
        print(send(msg(OP_DISARM, hook=resolve_hook(a[1]).encode())))
    elif cmd == "load":
        slot, path = int(a[1]), a[2]
        mode = int(a[3]) if len(a) > 3 else 2
        with open(path, "rb") as f:
            prog = f.read()
        # The hook name becomes "fentry/<hook>", the section uBPF selects by. It
        # must match what the program was compiled with or the load is refused
        # (finding O14 --- section and function are two separate identities).
        hook = a[4].encode() if len(a) > 4 else b""
        print(send(msg(OP_LOAD, slot=slot, mode=mode, hook=hook, prog=prog)))
    elif cmd == "status":
        print(send(msg(OP_STATUS, slot=int(a[1]))))
    elif cmd == "mode":
        print(send(msg(OP_SET_MODE, slot=int(a[1]), mode=int(a[2]))))
    elif cmd == "revoke":
        print(send(msg(OP_REVOKE, slot=int(a[1]))))
    else:
        sys.exit("unknown command %r" % cmd)


if __name__ == "__main__":
    main()
