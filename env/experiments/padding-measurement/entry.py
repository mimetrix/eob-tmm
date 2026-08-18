import subprocess, re, random
def sections(p):
    o=subprocess.check_output(['readelf','-S','-W',p]).decode()
    return [(m.group(1), int(m.group(2),16), int(m.group(3),16), int(m.group(4),16))
            for m in re.finditer(r'\[\s*\d+\]\s+(\.\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)', o)]
def reader(p):
    secs=sections(p); f=open(p,'rb')
    def get(vaddr,n):
        for name,addr,off,size in secs:
            if addr and addr <= vaddr < addr+size:
                f.seek(off + (vaddr-addr)); return f.read(n)
        return b''
    return get
for label, binp, dbgp in (
    ('baseline','/tmp/base/usr/bin/tmm64.no_pgo','/tmp/basedbg/usr/lib/debug/usr/bin/tmm64.no_pgo.debug'),
    ('flagged','/tmp/new/usr/bin/tmm64.no_pgo','/tmp/dbg2/usr/lib/debug/usr/bin/tmm64.no_pgo.debug')):
    try:
        syms=[int(l.split()[0],16) for l in subprocess.check_output(['nm','--defined-only',dbgp]).decode().splitlines()
              if len(l.split())==3 and l.split()[1] in ('t','T')]
    except Exception as e:
        print(f"{label}: no debug file ({e.__class__.__name__})"); continue
    get=reader(binp)
    random.seed(7); sample=random.sample(syms, min(400,len(syms)))
    pad=sum(1 for a in sample if get(a,5)==b'\x90'*5)
    print(f"{label:9s} functions={len(syms):>7,}  sampled={len(sample)}  entry starts with 5x nop: {pad} ({100*pad/len(sample):.1f}%)")
    ex=[a for a in sample if get(a,5)==b'\x90'*5][:1] or sample[:1]
    print(f"           example 0x{ex[0]:x}: {get(ex[0],10).hex(' ')}")
