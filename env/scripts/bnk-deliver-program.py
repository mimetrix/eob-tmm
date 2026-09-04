#!/usr/bin/env python3
"""Deliver a verified eBPF program into a RUNNING TMM without putting a file in the container.

THE GAP THIS CLOSES. ls-load.py reads the program with open(path, "rb"), and it runs inside
the pod --- so loading a program required the .bpf.o to already be in the container's
filesystem. In practice that meant baking it into the image (a rebuild) or copying it in
(the hack the baked-in tooling exists to avoid). Neither is what "load a new program into a
running process" should cost.

WHAT THIS DOES INSTEAD. The bytes travel on stdin. A generated, self-contained loader is
piped into `kubectl exec -i ... python3 -`; it decodes the program from a base64 literal
in its own source, builds one struct shield_msg, writes it to the loader socket, and exits.
Nothing is written to the pod's disk at any point.

THAT IS ALSO THE PRODUCTION SHAPE, which is why it is worth having rather than being a
trick: in a shipped system a control plane pushes a SIGNED program object over this same
socket.

STALE CLAIM CORRECTED 2026-09-04. This used to end "what is missing is the signature
(scope item 4, unbuilt --- the loader accepts anything and says so on every load)."
Signatures shipped on 2026-08-20: every load is verified and a build with no key refuses
all of them (GROUND_TRUTH.md, `make -C substrate check-sig`). What is missing now is
narrower and worth stating precisely: nothing authenticates the PEER on the socket, and
this script sends a zeroed binding, so it carries no signature of its own and depends on
the loader's signature enforcement being off. It is a lab delivery tool, not the
production path it resembles.

    bnk-deliver-program.py <prog.bpf.o> <slot> <mode> [hook]

      mode 1 = MONITOR (evaluate and count, apply nothing), 2 = ENFORCE
      hook   omit it and the object's own ELF section is used, which is what you want
             unless you are deliberately checking the section/function identity gate

Environment: POD (default: every Running f5-tmm pod), KUBECTL (default: kubectl).
"""
import base64
import os
import subprocess
import sys

KUBECTL = os.environ.get("KUBECTL", "kubectl")

# struct shield_msg, from substrate/shield_abi.h. These offsets are read out of the
# compiler, not remembered --- see ls-load.py, which is the reference client.
TEMPLATE = '''
import base64, glob, socket, struct, sys
PROG = base64.b64decode("{b64}")
HDR = 192
OFF_OP, OFF_EPOCH, OFF_MODE, OFF_PROGLEN, OFF_HOOK = 0, 4, 8, 12, 48
OFF_CTX_ABI, CTX_ABI_VERSION = 16 + 105, 3
# binding.build_min / build_max, at binding + 96 / +100 and the binding starts at 16.
# Asserted against shield_abi.h's static_asserts rather than remembered.
OFF_BUILD_MIN, OFF_BUILD_MAX = 16 + 96, 16 + 100
OP_LOAD = 1
b = bytearray(HDR)
struct.pack_into("<I", b, OFF_OP, OP_LOAD)
struct.pack_into("<I", b, OFF_EPOCH, {slot})
struct.pack_into("<I", b, OFF_MODE, {mode})
struct.pack_into("<I", b, OFF_PROGLEN, len(PROG))
b[OFF_CTX_ABI] = CTX_ABI_VERSION
struct.pack_into("<I", b, OFF_BUILD_MIN, {build_min})
struct.pack_into("<I", b, OFF_BUILD_MAX, {build_max})
hook = {hook!r}.encode()
if hook:
    b[OFF_HOOK:OFF_HOOK + len(hook)] = hook
# The loader appends the TMM instance number to the socket path.
cands = sorted(glob.glob("/tmp/ls_load.sock*"))
if not cands:
    sys.exit("no loader socket --- is LS_LOAD_SOCKET set and the loader thread up?")
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(20)
s.connect(cands[0])
s.sendall(bytes(b) + PROG)
try:
    s.shutdown(socket.SHUT_WR)
except OSError:
    pass
out = b""
while True:
    try:
        c = s.recv(4096)
    except socket.timeout:
        out += b"<timed out>"
        break
    if not c:
        break
    out += c
print("%d bytes delivered on stdin -> %s" % (len(PROG), out.decode("utf-8", "replace").strip()))
'''


def elf_fentry_section(blob):
    """Return the hook name from the object's own `fentry/<hook>` section, or ''.

    Walks the ELF section headers directly: no objdump, no readelf, nothing that has to be
    installed. 64-bit little-endian only, which is what clang -target bpf emits here.
    """
    import struct as st
    if len(blob) < 64 or blob[:4] != b"\x7fELF" or blob[4] != 2:
        return ""
    shoff, = st.unpack_from("<Q", blob, 0x28)
    shentsize, shnum, shstrndx = st.unpack_from("<HHH", blob, 0x3A)
    if not shnum or shstrndx >= shnum:
        return ""
    stroff, = st.unpack_from("<Q", blob, shoff + shstrndx * shentsize + 0x18)
    for i in range(shnum):
        nameoff, = st.unpack_from("<I", blob, shoff + i * shentsize)
        end = blob.index(b"\x00", stroff + nameoff)
        name = blob[stroff + nameoff:end].decode("ascii", "replace")
        if name.startswith("fentry/"):
            return name[len("fentry/"):]
    return ""


def pods():
    r = subprocess.run([KUBECTL, "get", "pods", "-l", "app=f5-tmm", "--no-headers"],
                       capture_output=True, text=True)
    return [l.split()[0] for l in r.stdout.splitlines()
            if len(l.split()) > 2 and l.split()[2] == "Running"]


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    path, slot, mode = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    hook = sys.argv[4] if len(sys.argv) > 4 else ""

    # THE BUILD RANGE, settable so the loader's build gate can be tested LIVE.
    #
    # Default 0..0 --- which is what every client sends today and what the gate reads
    # as UNDECLARED (ls_build_gate.h). Set it to exercise the gate:
    #
    #   LS_BUILD_MIN=0x11111111 LS_BUILD_MAX=0x11111111   -> must be REFUSED, MISMATCH
    #   LS_BUILD_MIN=0 LS_BUILD_MAX=0x269b5d25            -> must be REFUSED, BAD_RANGE
    #   LS_BUILD_MIN=<real> LS_BUILD_MAX=<real>           -> must PASS the gate
    #
    # WHY THIS TESTS THE GATE HONESTLY DESPITE SENDING NO SIGNATURE. The gate runs on
    # the LOADER thread, in ls_vm_load.c, while signature verification happens later on
    # a TMM thread in ls_prep_run_pending. So the gate's decision is observable on its
    # own, before any signature is looked at, which is exactly what we want to isolate.
    #
    # WHAT IT DOES NOT SHOW, and the distinction matters: an unsigned range proves the
    # gate ACTS on the field, not that the field is UNFORGEABLE. The range is only
    # meaningful because sign_shield.py puts it inside the signature; this test
    # deliberately steps around that to observe the gate alone. check-sig covers the
    # other half --- it asserts a flipped bit in build_min is detected.
    bmin = int(os.environ.get("LS_BUILD_MIN", "0"), 0)
    bmax = int(os.environ.get("LS_BUILD_MAX", "0"), 0)
    with open(path, "rb") as f:
        prog = f.read()

    # DERIVE THE HOOK FROM THE OBJECT rather than trusting the caller to supply it.
    #
    # The loader requires BOTH identities and refuses unless the named function lives in the
    # named section --- PREVAIL selects by ELF section, uBPF by function symbol, and in an
    # object carrying several functions those can denote different code (finding O14). An
    # empty hook therefore yields section "fentry/", which matches nothing, and the load is
    # refused with "identity mismatch". Observed exactly that on the first run of this tool.
    #
    # Reading the section name out of the ELF locally makes the tool impossible to call
    # wrongly, which is better than documenting the requirement.
    if not hook:
        hook = elf_fentry_section(prog)
        if not hook:
            sys.exit("*** no fentry/ section in %s --- cannot derive the hook name, and the\n"
                     "    loader will refuse a load without one." % path)
    script = TEMPLATE.format(b64=base64.b64encode(prog).decode(),
                             slot=slot, mode=mode, hook=hook,
                             build_min=bmin, build_max=bmax)
    targets = [os.environ["POD"]] if os.environ.get("POD") else pods()
    if not targets:
        sys.exit("*** no Running f5-tmm pods")
    print("  %s --- %d bytes, slot %d, mode %d%s, build 0x%08x..0x%08x%s"
          % (os.path.basename(path), len(prog), slot, mode,
             ", hook=%s" % hook if hook else ", section from the object",
             bmin, bmax, "  (UNDECLARED)" if bmin == 0 and bmax == 0 else ""))
    for p in targets:
        r = subprocess.run([KUBECTL, "exec", "-i", p, "-c", "f5-tmm", "--", "python3", "-"],
                           input=script, capture_output=True, text=True)
        out = (r.stdout + r.stderr).strip().splitlines()
        print("    %-28s %s" % (p, out[-1][:88] if out else "(no output)"))


if __name__ == "__main__":
    main()
