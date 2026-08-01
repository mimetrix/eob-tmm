#!/usr/bin/env python3
"""
budget_pass.py — the admission-time cost gate, for real.

development-scope.md item 8. This is not a sketch: it parses a genuine eBPF ELF
object, decodes the instruction stream, builds a control-flow graph, finds the
longest path, and prices it against a per-hook budget.

Run with no arguments it executes a built-in self-test over hand-assembled eBPF
wrapped in a synthesized ELF (see the bottom of this file). Pass object files to
gate them instead.

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

Usage:  ./budget_pass.py                        run the self-test
        ./budget_pass.py [--budget N] <prog.bpf.o> [...]
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
    return elf_section_bytes(blob, want, path)


def elf_section_bytes(blob, want=".text", path="<bytes>"):
    """Same, over a buffer — so the self-test needs no files on disk."""
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


# ------------------------------------------------------------------- self-test
# The repo used to run this pass over three real clang-built shield objects. Those
# lived in a prototype that has been removed, so the pass now carries its own
# cases — hand-assembled eBPF wrapped in a minimal ELF, built in memory.
#
# That is not a downgrade. The three real shields were straight-line predicates:
# none contained a `lddw` and none contained a loop, so neither the 16-byte
# instruction form nor the loop refusal was ever actually exercised. Both are
# covered below, and both were bugs in the first version of this file.

def _elf(text):
    """Wrap a .text payload in the smallest 64-bit LE ELF this parser accepts."""
    shstr = b"\0.text\0.shstrtab\0"
    eh_sz, sh_sz = 64, 64
    text_off = eh_sz
    shstr_off = text_off + len(text)
    sh_off = shstr_off + len(shstr)

    eh = bytearray(eh_sz)
    eh[0:4] = b"\x7fELF"
    eh[4] = 2                      # ELFCLASS64 — the parser insists
    eh[5] = 1                      # little endian
    eh[6] = 1                      # EV_CURRENT
    struct.pack_into("<H", eh, 16, 1)          # ET_REL
    struct.pack_into("<H", eh, 18, 247)        # EM_BPF
    struct.pack_into("<I", eh, 20, 1)
    struct.pack_into("<Q", eh, 40, sh_off)     # e_shoff
    struct.pack_into("<H", eh, 52, eh_sz)      # e_ehsize
    struct.pack_into("<H", eh, 58, sh_sz)      # e_shentsize
    struct.pack_into("<H", eh, 60, 3)          # e_shnum: null, .text, .shstrtab
    struct.pack_into("<H", eh, 62, 2)          # e_shstrndx

    def shdr(name_off, typ, off, size):
        b = bytearray(sh_sz)
        struct.pack_into("<IIQQQQ", b, 0, name_off, typ, 0, 0, off, size)
        return bytes(b)

    return (bytes(eh) + text + shstr
            + shdr(0, 0, 0, 0)                            # SHT_NULL
            + shdr(1, 1, text_off, len(text))             # .text, PROGBITS
            + shdr(8, 3, shstr_off, len(shstr)))          # .shstrtab, STRTAB


def _i(op, dst=0, src=0, off=0, imm=0):
    return struct.pack("<BBhi", op, (src << 4) | dst, off, imm)


MOV, JEQ, LDXW = 0xb7, 0x15, 0x61

_CASES = [
    # name, .text, budget, expected (verdict, insns, blocks, cycles)
    ("straight-line",
     _i(MOV, 0, imm=0) + _i(EXIT),
     800, ("ok", 2, 1, 2)),

    # lddw is a 16-BYTE pseudo-instruction. Decoded 8 bytes at a time, its zero
    # second half becomes a phantom instruction (opcode 0x00) — so a correct
    # decoder reports 3 instructions here and the buggy one reports 4. This case
    # is the regression test for that bug, and no real shield ever had a lddw.
    ("lddw is 16 bytes",
     _i(LDDW, 1, imm=0x55667788) + _i(0, imm=0x11223344)
     + _i(MOV, 0, imm=0) + _i(EXIT),
     800, ("ok", 3, 1, 6)),

    # diamond: the conditional's taken and fall-through paths differ in cost, so
    # this exercises longest-path rather than a straight sum.
    ("branch diamond",
     _i(JEQ, 0, off=1) + _i(MOV, 0, imm=1) + _i(MOV, 0, imm=2) + _i(EXIT),
     800, ("ok", 4, 3, 5)),

    # the same program under a budget it cannot meet — the gate must fail closed.
    ("over budget rejects",
     _i(JEQ, 0, off=1) + _i(MOV, 0, imm=1) + _i(MOV, 0, imm=2) + _i(EXIT),
     3, ("REJECT", 4, 3, 5)),

    # a back-edge. PREVAIL reports one aggregate max_loop_count and not a
    # per-loop trip count, so there is nothing sound to price this with: the pass
    # must REFUSE rather than guess. Also never exercised by a real shield.
    ("loop is refused, not guessed",
     _i(MOV, 0, imm=0) + _i(JA, off=-1),
     800, ("REFUSE", 2, 2, None)),

    # a memory load costs more than an ALU op in the cost table; this pins that
    # the class mapping is actually consulted.
    ("load is priced above alu",
     _i(LDXW, 1, 2) + _i(MOV, 0, imm=0) + _i(EXIT),
     800, ("ok", 3, 1, 6)),
]


def selftest():
    fails = 0
    print("budget_pass self-test (hand-assembled eBPF in a synthesized ELF):")
    for name, text, budget, expect in _CASES:
        got = gate_text(name, elf_section_bytes(_elf(text)), budget, quiet=True)
        good = (got == expect)
        cost = "loop refused" if got[3] is None else "%d cycles" % got[3]
        print("  %-4s %-30s %-7s %2d insn · %d blocks · %s"
              % ("ok" if good else "FAIL", name, got[0], got[1], got[2], cost))
        if not good:
            print("       expected %r" % (expect,))
            fails += 1
    if fails:
        print("budget_pass self-test: %d failure(s)" % fails)
        return 1
    print("ok    budget_pass.py  (%d cases: lddw's 16-byte form, longest path, "
          "fail-closed budget, loop refusal)" % len(_CASES))
    return 0


# --------------------------------------------------------------------- the gate
def gate(path, budget):
    return gate_text(os.path.basename(path), elf_section(path), budget)


def gate_text(name, text, budget, quiet=False):
    insns = decode(text)
    blocks, edges = build_cfg(insns)
    loops = back_edges(blocks, edges)

    if loops:
        # PREVAIL proves each loop terminates and reports ONE aggregate bound
        # (max_loop_count) — not a per-loop map. Without a per-loop trip count we
        # cannot price a loop soundly, so refuse rather than guess.
        if not quiet:
            print("REFUSE  %-26s loop back-edge at block %d — needs a proven trip "
                  "count (PREVAIL reports only an aggregate max_loop_count)"
                  % (name, loops[0][1]))
        return ("REFUSE", len(insns), len(blocks), None)

    cycles = longest_path(blocks, edges)
    verdict = "ok    " if cycles <= budget else "REJECT"
    if not quiet:
        print("%s  %-26s %3d insn · %2d blocks · longest path ~%4d cycles  (budget %d)"
              % (verdict, name, len(insns), len(blocks), cycles, budget))
    return (verdict.strip(), len(insns), len(blocks), cycles)


def main(argv):
    budget = DEFAULT_BUDGET
    args = []
    it = iter(argv[1:])
    for a in it:
        if a == "--budget": budget = int(next(it))
        elif a == "--selftest": pass
        else: args.append(a)
    if not args:
        return selftest()
    rc = 0
    for p in args:
        try:
            verdict = gate(p, budget)[0]
            if verdict != "ok": rc = 1
        except Exception as e:
            print("ERROR   %-26s %s" % (os.path.basename(p), e)); rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
