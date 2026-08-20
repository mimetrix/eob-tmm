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
# DEVELOPMENT ops, deliberately far from the real ones. A control plane would not expose
# "benchmark this program" on the load path, and the numbering says so.
OP_BENCH = 0x1001
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


def read_program(path):
    """The bytes of a .bpf.o, or a clear refusal.

    open(path, "rb") unguarded gave a Python traceback for a path typo --- which reads as "the
    tool is broken" rather than "you named a file that is not there". Same reasoning as the
    argument checks above; a traceback is never the right answer to a user error.
    """
    try:
        with open(path, "rb") as f:
            blob = f.read()
    except OSError as exc:
        sys.exit("*** cannot read %r: %s\n"
                 "    This wants a compiled and verified object --- clang -O2 -target bpf, then\n"
                 "    PREVAIL. The image carries some at /usr/share/ls/*.bpf.o." % (path, exc.strerror))
    if not blob:
        sys.exit("*** %r is empty." % path)
    if blob[:4] != b"\x7fELF":
        sys.exit("*** %r is not an ELF object (no \\x7fELF magic). Did you pass the .bpf.c?" % path)
    return blob


def elf_fentry_hook(blob):
    """b"<hook>" from the object's fentry/<hook> section name, or b"" if it has none.

    Section headers only --- a relocatable object has no program headers to speak of. Kept
    here rather than imported so this file stays runnable standalone inside a container with
    no readelf, no objdump and no llvm tools; the same reason elf_build_id is here.
    """
    try:
        if blob[:4] != b"\x7fELF" or blob[4] != 2:
            return b""
        shoff, = struct.unpack_from("<Q", blob, 0x28)
        shentsize, shnum = struct.unpack_from("<HH", blob, 0x3a)
        shstrndx, = struct.unpack_from("<H", blob, 0x3e)
        if not shoff or not shnum or shstrndx >= shnum:
            return b""
        base = shoff + shstrndx * shentsize
        stroff, = struct.unpack_from("<Q", blob, base + 0x18)
        strsz, = struct.unpack_from("<Q", blob, base + 0x20)
        strs = blob[stroff:stroff + strsz]
        for i in range(shnum):
            nmoff, = struct.unpack_from("<I", blob, shoff + i * shentsize)
            end = strs.find(b"\x00", nmoff)
            name = strs[nmoff:end]
            if name.startswith(b"fentry/"):
                return name[len(b"fentry/"):]
    except (struct.error, IndexError):
        return b""
    return b""


def tmm_pid():
    """The pid of the running tmm, or None. Same scan as running_binary, which needs the
    path; this needs the pid. Split so neither has to return a tuple nobody wants."""
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            exe = os.readlink("/proc/%s/exe" % d)
        except OSError:
            continue
        if os.path.basename(exe).startswith("tmm"):
            return d
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


def entry_bytes(addr, n=5):
    """The n bytes at `addr` in the running tmm, or None if they cannot be read.

    None means "could not check", NOT "fine" --- every caller treats it as unknown and
    proceeds, because refusing to arm because /proc was unreadable would be worse than the
    thing being guarded against. It is readable in practice: the loader already reads
    /proc/<pid>/exe to gate on the build id.
    """
    try:
        pid = tmm_pid()
        if pid is None:
            return None
        with open("/proc/%s/mem" % pid, "rb") as m:
            m.seek(int(addr, 16) if isinstance(addr, str) else addr)
            b = m.read(n)
        return b if len(b) == n else None
    except (OSError, ValueError):
        return None


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


OFF_BINDING, OFF_SIG, BINDING_LEN, SIG_LEN = 16, 128, 112, 64


def read_signature(prog_path):
    """The signed blob beside a program: <name>.bpf.o -> <name>.bpf.sig.

    REFUSES rather than sending an unsigned request. TMM will reject it anyway now, but the
    round trip is confusing --- the reply says "signature verification failed" and the reader
    looks for a corrupted signature rather than a missing one. Say it here, where the file is.
    """
    base = prog_path[:-2] if prog_path.endswith(".o") else prog_path
    for cand in (base + ".sig", prog_path + ".sig"):
        try:
            with open(cand, "rb") as f:
                blob = f.read()
        except OSError:
            continue
        if len(blob) != BINDING_LEN + SIG_LEN:
            sys.exit("*** %s is %d bytes; a signed blob is %d (%d binding + %d signature).\n"
                     "    Regenerate it with substrate/sign_shield.py."
                     % (cand, len(blob), BINDING_LEN + SIG_LEN, BINDING_LEN, SIG_LEN))
        return blob[:BINDING_LEN], blob[BINDING_LEN:]
    sys.exit("*** no signature found for %s (looked for %s.sig).\n"
             "    Every load is signature-verified now; an unsigned program is refused by TMM,\n"
             "    so this refuses here where the reason is visible. Sign it:\n"
             "      python3 substrate/sign_shield.py --key <sk.pem> --prog %s \\\n"
             "          --hook <function> -o %s.sig"
             % (prog_path, base, prog_path, base))


def msg(op, slot=0, mode=0, hook=b"", prog=b"", epoch=None, binding=None, sig=None):
    """Build one shield_msg. Zero-filled: every field this op does not use must
    read as zero, not as residue from whatever was in the buffer before.

    `epoch` OVERRIDES the slot in that field, and the field is genuinely overloaded: the
    struct calls it the replay guard, the load and status ops carry the SLOT in it, and the
    bench op carries an ITERATION COUNT. Passing an iteration count as `slot=` would work and
    would read as a lie at the call site, so the alternative name is spelled out here rather
    than left to a comment beside each caller."""
    b = bytearray(HDR)
    struct.pack_into("<I", b, OFF_OP, op)
    struct.pack_into("<I", b, OFF_EPOCH, slot if epoch is None else epoch)
    struct.pack_into("<I", b, OFF_MODE, mode)
    struct.pack_into("<I", b, OFF_PROGLEN, len(prog))
    b[OFF_CTX_ABI] = CTX_ABI_VERSION
    if binding is not None:
        # THE SIGNED BINDING REPLACES THE HOOK FIELD, because the hook lives INSIDE it (at
        # binding+32, which is why OFF_HOOK is 48). Writing both would let a caller name one
        # hook in the signed bytes and another beside them; there is exactly one hook name on
        # the wire and it is the signed one.
        if len(binding) != BINDING_LEN or not sig or len(sig) != SIG_LEN:
            sys.exit("*** malformed signed blob: %d-byte binding, %d-byte signature"
                     % (len(binding), len(sig) if sig else 0))
        b[OFF_BINDING:OFF_BINDING + BINDING_LEN] = binding
        b[OFF_SIG:OFF_SIG + SIG_LEN] = sig
    elif hook:
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


# WHAT EACH COMMAND TAKES. Checked before dispatch, so a wrong argument list produces a usage
# line naming the command rather than a Python traceback.
#
# WHY THIS IS HERE. On 2026-08-19 five invocations of these tools were wrong in a row ---
# `status` without a slot (IndexError traceback), `disarm 5` when disarm takes a NAME (it tried
# to resolve "5" as a symbol and reported "nor safely displaceable", which reads like a fact
# about the binary), and `load` without a hook. Each cost a diagnosis of the wrong thing. A
# traceback tells the reader the tool broke; a usage line tells them what they typed wrong, and
# these two are not close to the same message when someone is mid-demo.
#
# (min, max, "usage") --- max None means unbounded.
_ARGS = {
    "arm":     (2, 2, "arm <slot> <symbol-or-0xADDR>"),
    "disarm":  (1, 1, "disarm <symbol-or-0xADDR>          # a NAME, not a slot"),
    "load":    (2, 4, "load <slot> <file.bpf.o> [mode]   # mode 1=MONITOR 2=ENFORCE.\n"
                      "               Needs <file>.sig beside it --- the hook comes from the\n"
                      "               signed binding, not from an argument"),
    "status":  (1, 1, "status <slot>"),
    "mode":    (2, 2, "mode <slot> <1|2>"),
    "revoke":  (1, 1, "revoke <slot>"),
    "bench":   (1, 3, "bench <file.bpf.o> [iters] [hook]   # measure, discard, touch no slot;\n"
                      "                                     min is the number to quote"),
}


def _check_args(cmd, rest):
    """Exit with a usage line naming the command, rather than letting an index fail."""
    if cmd not in _ARGS:
        sys.exit("*** unknown command %r. Commands: %s"
                 % (cmd, " ".join(sorted(_ARGS))))
    lo, hi, usage = _ARGS[cmd]
    n = len(rest)
    if n < lo or (hi is not None and n > hi):
        sys.exit("*** %s takes %s argument%s, got %d.\n    usage: %s"
                 % (cmd,
                    ("%d" % lo) if lo == hi else ("%d to %d" % (lo, hi)),
                    "" if lo == 1 and hi == 1 else "s", n, usage))
    # A SLOT WHERE A NAME BELONGS. `disarm 5` has the right argument COUNT, so arity cannot
    # catch it --- and it then reached resolve_hook, which reported that '5' is "not padded nor
    # safely displaceable". That reads as a fact about the binary rather than a typo, and it
    # cost a diagnosis. A C identifier cannot begin with a digit, so a bare decimal here is
    # never a symbol and the check is exact rather than a guess.
    if cmd == "disarm" and rest[0].isdigit():
        sys.exit("*** disarm takes the FUNCTION NAME, not the slot: you passed %r.\n"
                 "    usage: %s\n"
                 "    Disarm resolves the name the same way arm does, on purpose --- arming by\n"
                 "    name and disarming by a hand-typed address would restore nops over\n"
                 "    whatever is at that address instead." % (rest[0], usage))
    # A slot where a slot is expected. int() on a symbol name raises ValueError, which is a
    # traceback again.
    if cmd in ("arm", "load", "status", "mode", "revoke"):    # not bench: file comes first
        try:
            int(rest[0])
        except ValueError:
            sys.exit("*** %s expects a SLOT NUMBER first, got %r.\n    usage: %s%s"
                     % (cmd, rest[0], usage,
                        "\n    (disarm is the one that takes a name, not a slot.)"
                        if cmd != "disarm" else ""))


def main():
    a = sys.argv[1:]
    if not a:
        sys.exit(__doc__)
    cmd = a[0]
    _check_args(cmd, a[1:])

    if cmd == "arm":
        # The address goes in binding.hook AS TEXT --- the loader strtoull()s it.
        # resolve_hook turns a symbol name into that text, or exits.
        slot, addr = int(a[1]), resolve_hook(a[2])
        # LOOK AT THE ENTRY BEFORE WRITING TO IT.
        #
        # Arming an already-armed entry fails, correctly --- the pad no longer holds nops. But
        # the failure came back as "no pad, out of rel32 range, or swap refused", a catch-all
        # naming three unrelated causes, and the first of them is wrong in a way that reads
        # like a stale address. It cost a diagnosis: I went looking at the bytecode.
        #
        # More importantly this catches the case that actually hurt this project. On
        # 2026-08-17 a stale address armed a nop pad 64 bytes past rst_why: the patch
        # succeeded, OK ARMED LIVE printed, and nothing fired across 16,000 requests. The
        # index's build-id gate closes that for named lookups. This closes it for a raw
        # 0x address, which the gate cannot check --- if the five bytes are not a pad and not
        # an existing hook, do not write to them.
        pre = entry_bytes(addr)
        if pre is not None:
            if pre == b"\x90" * 5:
                pass                                   # a clean pad, as expected
            elif pre[0] == 0xe8:
                sys.exit("*** %s is ALREADY ARMED --- its entry holds %s, a call, not a pad.\n"
                         "    Disarm it first. Arming over an armed entry would overwrite the\n"
                         "    displacement to the current trampoline with another one, and the\n"
                         "    original instruction bytes would be lost."
                         % (a[2], " ".join("%02x" % x for x in pre)))
            else:
                sys.exit("*** %s (%s) does not hold a five-byte nop pad. It holds %s.\n"
                         "    REFUSING to write. This is the check that was missing when a\n"
                         "    stale address armed a pad 64 bytes past rst_why, printed OK, and\n"
                         "    fired zero times across 16,000 requests.\n"
                         "    If you are certain, disarm whatever is there rather than\n"
                         "    overwriting it."
                         % (a[2], addr, " ".join("%02x" % x for x in pre)))
        print(send(msg(OP_ARM, slot=slot, hook=addr.encode())))
    elif cmd == "disarm":
        # Disarm resolves the same way. It MUST, or the demo arms by name and
        # disarms by a hand-typed address --- restoring nops over whatever is at
        # that address instead, which is a write into live .text.
        print(send(msg(OP_DISARM, hook=resolve_hook(a[1]).encode())))
    elif cmd == "load":
        slot, path = int(a[1]), a[2]
        mode = int(a[3]) if len(a) > 3 else 2
        prog = read_program(path)
        # The hook name becomes "fentry/<hook>", the section uBPF selects by. It must match
        # what the program was compiled with or the load is refused (finding O14 --- section
        # and function are two separate identities).
        #
        # DERIVED FROM THE OBJECT when not given, instead of defaulting to empty. It used to
        # default to b"", which is not a hook and cannot be one: TMM then looks for 'shield'
        # in section 'fentry/' and refuses every load with "the verified program and the
        # loaded one may differ". A default that can only fail is worse than a required
        # argument, and it fails in a way that reads like a bad object rather than a missing
        # argument --- which is exactly how it was read.
        #
        # The object's own section header is the right source: it is what the program was
        # compiled with and what PREVAIL verified. bnk-deliver-program.py already derives it
        # this way, so the two tools now agree instead of one of them needing to be told.
        # THE HOOK NOW COMES FROM THE SIGNED BINDING, not from the object's section and not
        # from an argument. Both of those are things a caller controls; the binding is what a
        # key asserted. The ELF section is still checked by TMM against the program symbol --- a
        # separate gate on a separate identity --- but it no longer decides where this may arm.
        binding, sig = read_signature(path)
        if len(a) > 4:
            print("*** ignoring the hook argument: the signed binding names the hook, and a "
                  "second name on the wire would be a second answer to one question.",
                  file=sys.stderr)
        print(send(msg(OP_LOAD, slot=slot, mode=mode, prog=prog,
                       binding=binding, sig=sig)))
    elif cmd == "status":
        print(send(msg(OP_STATUS, slot=int(a[1]))))
    elif cmd == "mode":
        print(send(msg(OP_SET_MODE, slot=int(a[1]), mode=int(a[2]))))
    elif cmd == "revoke":
        print(send(msg(OP_REVOKE, slot=int(a[1]))))
    elif cmd == "bench":
        # THE OP EXISTED IN TMM AND HAD NO CLIENT. Every previous bench run was driven by a
        # loader typed inline and thrown away --- the exact practice this file exists to
        # replace, and the reason its results were never reproducible.
        #
        # `epoch` carries the iteration count. That is a reuse of a protocol field rather than
        # a new one on purpose: these 0x100x ops are DEVELOPMENT ops and must not grow the
        # wire format a real control plane would have to implement.
        #
        # QUOTE THE MIN. The mean is 2-3x it even on an idle box with no traffic, because a
        # single rdtsc pair spanning a context switch dominates the total --- the same effect
        # that makes the armed-hook counter mean unusable. TMM refuses an iteration count above
        # its ceiling rather than clamping, since bench runs on a TMM thread inside a poll
        # iteration and the count is a stall budget.
        path = a[1]
        iters = int(a[2]) if len(a) > 2 else 10000
        prog = read_program(path)
        hook = a[3].encode() if len(a) > 3 else elf_fentry_hook(prog)
        if not hook:
            sys.exit("*** %s carries no fentry/<hook> section, so there is nothing to identify\n"
                     "    the program against. Name the hook as the 3rd argument." % path)
        print(send(msg(OP_BENCH, slot=0, mode=0, hook=hook, prog=prog, epoch=iters)))
    else:
        sys.exit("unknown command %r" % cmd)


if __name__ == "__main__":
    main()
