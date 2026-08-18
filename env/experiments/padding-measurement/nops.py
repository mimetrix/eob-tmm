import subprocess, sys, re
def text_bytes(p):
    o = subprocess.check_output(['readelf','-S','-W',p]).decode()
    m = re.search(r'\[\s*\d+\]\s+\.text\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)', o)
    addr, off, size = int(m.group(1),16), int(m.group(2),16), int(m.group(3),16)
    with open(p,'rb') as f: f.seek(off); return f.read(size), size
for label, path in (('baseline','/tmp/base/usr/bin/tmm64.no_pgo'), ('flagged','/tmp/new/usr/bin/tmm64.no_pgo')):
    b, size = text_bytes(path)
    run5 = b.count(b'\x90'*5)
    run5_not6 = len(re.findall(rb'(?<!\x90)\x90{5}(?!\x90)', b))
    multi = len(re.findall(rb'\x0f\x1f\x44\x00\x00', b))   # 5-byte nopl 0x0(%rax,%rax,1)
    print(f"{label:9s} .text={size:>10,}  '90'x5 runs={run5:>7,}  exactly-5={run5_not6:>7,}  nopl5={multi:>7,}")
