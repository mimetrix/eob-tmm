#!/usr/bin/env python3
"""
budget_pass.py — the admission-time cost gate, for real.

development-scope.md item 8. This is not a sketch: it parses a genuine eBPF ELF
object, decodes the instruction stream, builds a control-flow graph, finds the
longest path, and prices it against a per-hook budget. It runs on the real
shields in ../shields/.

Writing it for real fixed three bugs that were in the illustrative version:
  * it read the whole ELF FILE as instructions — the first eight bytes are
    \\x7fELF..., which decoded as a nonsense opcode. Now it locates .text.
  * it strided 8 bytes blindly, so `lddw` (BPF_LD|BPF_IMM|BPF_DW, opcode 0x18) —
    a 16-byte pseudo-instruction — had its second half decoded as a phantom
    instruction, corrupting both the opcode stream and every branch target
    after it. Now lddw consumes 16 bytes.
  * it never treated `exit` (0x95) as a block terminator, so basic blocks ran
    past returns and the graph was wrong.

What this is NOT: a WCET bound. The cycle model is a per-opcode-class table, so
it over-counts by ignoring superscalar issue and under-counts catastrophically
by ignoring memory — one L3 miss is 200+ cycles and blows any estimate here.
Treat the output as a RELATIVE sanity check ("is this program ten instructions
or ten thousand?"), which is what makes it useful as an admission gate, and read
engine-hard-problems.md §1 for why a runtime guard is still required.

Usage:  ./budget_pass.py [--budget N] <prog.bpf.o> [...]
        ./budget_pass.py ../shields/*.bpf.o
"""
import struct
import sys
import os

INSN_SZ = 8
LDDW = 0x18                      # BPF_LD | BPF_IMM | BPF_DW — 16 bytes wide
EXIT = 0x95
CALL = 0x85
JA = 0x05

# Per-opcode-class cycle estimates. TODO(f5): calibrate per microarchitecture and
# publish the calibration — an uncalibrated table makes this gate theatre.
CYCLES = {"alu": 1, "jmp": 2, "ld": 4, "ldx": 4, "st": 4, "stx": 4,
          "call": 6, "exit": 1}

DEFAULT_BUDGET = 800             # cycles; a cold hook. Hot hooks are far tighter.


# ---------------------------------------------------------------- ELF, minimally
def elf_section(path, want=".text"):
    """Return the bytes of `want` from a 64-bit little-endian ELF. No deps."""
    with open(path, "rb") as f:
        blob = f.read()
    if blob[:4] != b"\x7fELF":
        raise ValueError("%s: not an ELF object" % path)
    if blob[4] != 2 or blob[5] != 1:
        raise ValueError("%s: expected 64-bit little-endian" % path)
    e_shoff, = struct.unpack_from("<Q", blob, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", blob, 0x3A)

    def shdr(i):
        off = e_shoff + i * e_shentsize
        name, _typ, _flags, _addr, offset, size = struct.unpack_from("<IIQQQQ", blob, off)
        return name, offset, size

    _n, stroff, _sz = shdr(e_shstrndx)
    for i in range(e_shnum):
        name, offset, size = shdr(i)
        end = blob.index(b"\0", stroff + name)
        if blob[stroff + name:end].decode() == want:
            return blob[offset:offset + size]
    raise ValueError("%s: no %s section" % (path, want))


# ------------------------------------------------------------------- the decoder
def opclass(op):
    cls = op & 0x07
    if op == EXIT:  return "exit"
    if op == CALL:  return "call"
    if cls in (0x05, 0x06): return "jmp"       # BPF_JMP, BPF_JMP32
    if cls == 0x00: return "ld"
    if cls == 0x01: return "ldx"
    if cls == 0x02: return "st"
    if cls == 0x03: return "stx"
    return "alu"                                # BPF_ALU (0x04), BPF_ALU64 (0x07)


def decode(text):
    """eBPF is fixed 8-byte instructions EXCEPT lddw, which is 16."""
    insns, off, pc = [], 0, 0
    while off + INSN_SZ <= len(text):
        op, regs, joff, imm = struct.unpack_from("<BBhi", text, off)
        wide = (op == LDDW)
        insns.append({"pc": pc, "op": op, "cls": opclass(op),
                      "off": joff, "imm": imm, "wide": wide})
        step = 2 if wide else 1                 # in instruction slots
        off += INSN_SZ * step
        pc += step
    return insns


def by_pc(insns):
    return {i["pc"]: i for i in insns}


# ----------------------------------------------------------------------- the CFG
def terminator(i):
    return i["cls"] in ("jmp", "exit") or i["op"] == EXIT


def leaders(insns, index):
    """Block leaders: entry, every branch target, every fall-through after a
    terminator. `exit` terminates a block and has no successors."""
    lead = {insns[0]["pc"]} if insns else set()
    for i in insns:
        if i["op"] == EXIT:
            nxt = i["pc"] + (2 if i["wide"] else 1)
            if nxt in index: lead.add(nxt)
        elif i["cls"] == "jmp":
            tgt = i["pc"] + 1 + i["off"]
            if tgt in index: lead.add(tgt)
            nxt = i["pc"] + 1
            if i["op"] != JA and nxt in index: lead.add(nxt)   # conditional falls through
            elif i["op"] == JA and nxt in index: lead.add(nxt) # unreachable, still a leader
    return sorted(lead)


def build_cfg(insns):
    index = by_pc(insns)
    lead = leaders(insns, index)
    blocks, edges = {}, {}
    for n, start in enumerate(lead):
        end = lead[n + 1] if n + 1 < len(lead) else None
        body = [i for i in insns if i["pc"] >= start and (end is None or i["pc"] < end)]
        blocks[start] = body
    for start, body in blocks.items():
        succ, last = [], body[-1] if body else None
        if last is None:
            pass
        elif last["op"] == EXIT:
            succ = []
        elif last["cls"] == "jmp":
            tgt = last["pc"] + 1 + last["off"]
            if tgt in blocks: succ.append(tgt)
            if last["op"] != JA:
                nxt = last["pc"] + 1
                if nxt in blocks: succ.append(nxt)
        else:
            nxt = last["pc"] + (2 if last["wide"] else 1)
            if nxt in blocks: succ.append(nxt)
        edges[start] = succ
    return blocks, edges


def block_cost(body):
    return sum(CYCLES[i["cls"]] for i in body)


def back_edges(blocks, edges):
    """DFS for edges to a block already on the stack — i.e. loops."""
    seen, stack, found = set(), [], []
    def dfs(b):
        seen.add(b); stack.append(b)
        for s in edges.get(b, []):
            if s in stack: found.append((b, s))
            elif s not in seen: dfs(s)
        stack.pop()
    if blocks: dfs(sorted(blocks)[0])
    return found


def longest_path(blocks, edges):
    """DAG longest path by memoised DFS. Assumes no back-edges (checked first)."""
    memo = {}
    def best(b):
        if b in memo: return memo[b]
        memo[b] = block_cost(blocks[b])          # guard against re-entry
        succ = [s for s in edges.get(b, []) if s in blocks]
        memo[b] = block_cost(blocks[b]) + (max((best(s) for s in succ), default=0))
        return memo[b]
    return best(sorted(blocks)[0]) if blocks else 0


# --------------------------------------------------------------------- the gate
def gate(path, budget):
    text = elf_section(path)
    insns = decode(text)
    blocks, edges = build_cfg(insns)
    loops = back_edges(blocks, edges)
    name = os.path.basename(path)

    if loops:
        # PREVAIL proves each loop terminates and reports ONE aggregate bound
        # (max_loop_count) — not a per-loop map. Without a per-loop trip count we
        # cannot price a loop soundly, so refuse rather than guess.
        print("REFUSE  %-26s loop back-edge at block %d — needs a proven trip "
              "count (PREVAIL reports only an aggregate max_loop_count)"
              % (name, loops[0][1]))
        return 1

    cycles = longest_path(blocks, edges)
    verdict = "ok    " if cycles <= budget else "REJECT"
    print("%s  %-26s %3d insn · %2d blocks · longest path ~%4d cycles  (budget %d)"
          % (verdict, name, len(insns), len(blocks), cycles, budget))
    return 0 if cycles <= budget else 1


def main(argv):
    budget = DEFAULT_BUDGET
    args = []
    it = iter(argv[1:])
    for a in it:
        if a == "--budget": budget = int(next(it))
        else: args.append(a)
    if not args:
        here = os.path.dirname(os.path.abspath(__file__))
        d = os.path.join(here, os.pardir, "shields")
        args = sorted(os.path.join(d, f) for f in os.listdir(d)
                      if f.endswith(".bpf.o")) if os.path.isdir(d) else []
    if not args:
        print("no .bpf.o inputs found"); return 0
    rc = 0
    for p in args:
        try:
            rc |= gate(p, budget)
        except Exception as e:
            print("ERROR   %-26s %s" % (os.path.basename(p), e)); rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
