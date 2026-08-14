#!/usr/bin/env python3
"""Prove that DIFFERENT bytecode can be loaded into a running TMM.

B7 loaded the built-in shield --- the same 4320 bytes already compiled into the
binary and armed in slot 0 at startup. That proved the load PATH works (parse,
create, JIT, publish, no hang) but not that a different program can be loaded,
because the bytes going in matched the bytes already there.

This loads two programs that are trivially distinguishable and, crucially, uses
the loader's own identity check as the discriminator. ls_vm_load.c builds the
section from the declared hook --- snprintf(section, "fentry/%.63s",
binding.hook) --- and ls_vm_reload refuses unless the program's OWN section
matches (finding O14: PREVAIL proves a SECTION, uBPF runs a SYMBOL, and the
loader must not accept a mismatch).

    demo_block.elf   section fentry/demo_block   shield() { return 1; }  SAFE_RETURN
    demo_pass.elf    section fentry/demo_pass    shield() { return 0; }  FALLTHROUGH

So:
    1. demo_block under hook=demo_block  -> OK      (sections agree)
    2. demo_pass  under hook=demo_block  -> REFUSED (this is the real evidence:
                                                     the loader read THIS program's
                                                     section, not a cached one)
    3. demo_pass  under hook=demo_pass   -> OK      (different program, accepted)
    4. the real CVE shield restored      -> OK      (leave slot 0 as we found it)

Step 2 is what makes this a test rather than a demo. If the loader were ignoring
the bytes and reusing whatever was already resident, step 2 would succeed.
"""
import glob, socket, struct, sys

HDR = 192
sock = sorted(glob.glob("/tmp/ls_load.sock*"))[0]

def send(op, payload=b"", hook=b"", slot=0, timeout=25):
    buf = bytearray(HDR)
    struct.pack_into("<I", buf, 0, op)
    struct.pack_into("<I", buf, 4, slot)
    buf[8] = 2                                   # ENFORCE
    struct.pack_into("<I", buf, 12, len(payload))
    if hook:
        buf[48:48 + len(hook)] = hook            # binding.hook = 16 + 32
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock); s.sendall(bytes(buf) + payload)
        try:    return s.recv(4096).decode(errors="replace").strip()
        except socket.timeout: return "*** TIMEOUT"
    except Exception as e: return f"*** {e}"
    finally: s.close()

blk  = open("/tmp/demo_block.elf", "rb").read()
pss  = open("/tmp/demo_pass.elf",  "rb").read()
real = open("/tmp/shield.elf",     "rb").read()

print(f"socket      : {sock}")
print(f"demo_block  : {len(blk)} bytes   demo_pass: {len(pss)} bytes   real shield: {len(real)} bytes")
print(f"programs differ: {blk != pss}\n")

checks = []

r = send(1, blk, hook=b"demo_block")
ok = r.startswith("OK"); checks.append(ok)
print(f"1. demo_block as demo_block  -> {r}\n   expect OK      : {'PASS' if ok else 'FAIL'}\n")

r = send(1, pss, hook=b"demo_block")
ok = r.startswith("ERR"); checks.append(ok)
print(f"2. demo_pass  as demo_block  -> {r}\n   expect REFUSED : {'PASS' if ok else 'FAIL'}  <-- the real evidence\n")

r = send(1, pss, hook=b"demo_pass")
ok = r.startswith("OK"); checks.append(ok)
print(f"3. demo_pass  as demo_pass   -> {r}\n   expect OK      : {'PASS' if ok else 'FAIL'}\n")

r = send(1, real, hook=b"http_psm_profile_name_lookup")
ok = r.startswith("OK"); checks.append(ok)
print(f"4. real shield restored      -> {r}\n   expect OK      : {'PASS' if ok else 'FAIL'}\n")

print(f"RESULT: {'ALL PASS --- distinct bytecode is loaded and discriminated' if all(checks) else '*** FAILED'}")
sys.exit(0 if all(checks) else 1)
