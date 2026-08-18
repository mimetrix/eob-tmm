import subprocess, re, random, collections
BIN="/tmp/new/usr/bin/tmm64.no_pgo"
DBG="/tmp/dbg2/usr/lib/debug/usr/bin/tmm64.no_pgo.debug"
def reader(p):
    o=subprocess.check_output(["readelf","-S","-W",p]).decode()
    secs=[(int(m.group(2),16),int(m.group(3),16),int(m.group(4),16)) for m in
          re.finditer(r"\[\s*\d+\]\s+(\.\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)",o)]
    f=open(p,"rb")
    def get(v,n):
        for a,off,sz in secs:
            if a and a<=v<a+sz: f.seek(off+(v-a)); return f.read(n)
        return b""
    return get
g=reader(BIN); NOP=b"\x90"*5; ENDBR=b"\xf3\x0f\x1e\xfa"
syms=[int(l.split()[0],16) for l in subprocess.check_output(["nm","--defined-only",DBG]).decode().splitlines()
      if len(l.split())==3 and l.split()[1] in ("t","T")]
random.seed(11); sample=random.sample(syms, 1200)
def padded(a):
    return g(a,5)==NOP or (g(a,4)==ENDBR and g(a+4,5)==NOP)
# batch addr2line
p=subprocess.run(["addr2line","-f","-e",DBG]+[hex(a) for a in sample],
                 capture_output=True, text=True)
lines=p.stdout.splitlines()
buckets=collections.defaultdict(lambda:[0,0])
for i,a in enumerate(sample):
    fn   = lines[2*i]   if 2*i   < len(lines) else "?"
    src  = lines[2*i+1] if 2*i+1 < len(lines) else "?"
    src  = src.split(":")[0]
    if src in ("?","??"): key="(no DWARF line info)"
    else:
        parts=[x for x in src.split("/") if x and x not in (".","..")]
        key="/".join(parts[:2]) if len(parts)>1 else parts[0] if parts else "?"
    b=buckets[key]; b[1]+=1
    if padded(a): b[0]+=1
tot_p=sum(v[0] for v in buckets.values()); tot=sum(v[1] for v in buckets.values())
print(f"overall: {tot_p}/{tot} = {100*tot_p/tot:.1f}% padded\n")
print(f"{'source bucket':46s} {'padded':>7} {'total':>7} {'pct':>6}")
for k,(pc,n) in sorted(buckets.items(), key=lambda kv:-kv[1][1])[:22]:
    print(f"{k[:46]:46s} {pc:>7} {n:>7} {100*pc/n:>5.0f}%")
