# Widening the eBPF implementation — maps, helpers, exit hooks

Written 2026-08-17. The programs we can write are far weaker than kernel eBPF
programs, and that — not the runtime choice, not the verifier — is what has
limited every use case. This is the plan to fix it, in the order the risk says.

---

## What we established before planning

**The riskiest assumption was that adding maps meant verifier work.** It doesn't.
Tested directly (`shields/exp/map_probe.bpf.c`): a program declaring a standard
`SEC("maps")` hash and calling `bpf_map_lookup_elem` / `bpf_map_update_elem`
**passes PREVAIL unchanged**, with `--termination --no-division-by-zero --strict`.

PREVAIL parsed the maps section, resolved the descriptor, type-checked both
helper calls against its built-in prototypes, tracked the null check on the
returned pointer, and proved the accesses in bounds. No custom platform, no
prototype table, no patch.

**Why:** helper IDs 1/2/3 are the standard BPF map helpers, and PREVAIL's linux
platform already knows their signatures. If we implement *those IDs with those
semantics*, the verifier is already on our side — and programs stay compatible
with ordinary libbpf idioms.

That turns "teach PREVAIL about our helpers" from the hard part into a non-task,
and it changes the whole shape of this work.

**What was wrong in the record:** `LIMITATIONS.md` and several design docs
described maps and helpers as *unsupported*. They were **unimplemented**. uBPF has
`ubpf_register()`; we never used it. That is a materially different claim and it
made the ceiling look structural when it was a gap.

---

## Phase 1 — Helpers and one map type *(the big unlock)*

**Goal:** a program can keep state across invocations.

### 1.1 Host-side map storage

A fixed-size open-addressed hash, **per TMM thread**, allocated with `mmap` at
init. Per-thread for the same reason the ring is: it removes locking from the hot
path by construction, and TMM's allocator cannot be touched from threads it did
not create.

- fixed capacity, no growth, no rehash — bounded is the point
- `mmap` only; **never** `malloc`
- eviction on collision, counted, never blocking

### 1.2 Register helpers 1/2/3 through `ubpf_register`

`bpf_map_lookup_elem`, `bpf_map_update_elem`, `bpf_map_delete_elem`, with the
standard semantics PREVAIL already assumes — lookup returns a pointer or NULL,
update returns 0 or negative.

**The hazard to get right:** a helper receives a `map` pointer the *program*
supplied. The host must validate it against the registered map set before
dereferencing anything, or a verified program becomes an arbitrary-write
primitive through a forged map address. PREVAIL proves the program passed *a map
descriptor*; it cannot prove the host resolves it safely. **That validation is
ours and it is the security boundary of this phase.**

### 1.3 Exit criteria

- a program counts per-key occurrences across invocations and returns a verdict
  based on accumulated state
- `make check` gains a harness driving the host map directly: capacity, eviction,
  collision, and a forged-map-pointer rejection
- verified with all PREVAIL gates on

**Why first:** it is additive, its outcome does not depend on BNK's config surface
cooperating, and it lifts the ceiling on *every* use case — rate limiting, "has
this client done this before", correlation across requests. None of that is
expressible today.

---

## Phase 2 — Exit hooks *(fixes a recorded failure)*

**Goal:** read a function's *outputs*, not only its inputs.

The first tracepoint attempt failed precisely here: armed at
`http_parse_client_headers`' entry, it read `header_count` and the `f_invalid_*`
bits **before the function wrote them**, and every field came back zero —
correctly. `parse_watch.bpf.c` is kept as that record.

**Mechanism:** return-address hijack, which is what bpftime's uretprobe does. On
entry the trampoline saves the caller's return address and substitutes a thunk;
the thunk runs the exit program and jumps to the real address.

**Risks, priced honestly:**

- needs **per-thread, per-depth storage** for saved return addresses — a small
  stack, since a hooked function can be entered recursively
- **re-entrancy**: already on item 1's requirement list and never resolved
- a `longjmp`, an exception unwind, or a `noreturn` path abandons the frame and
  leaks a saved slot. Needs a depth cap and a give-up path, not an assumption
- interacts with TMM's own stack discipline in ways nothing here has tested

**Exit criteria:** an exit program reads a value the function wrote, on live
traffic, and disarm restores the original return path exactly.

---

## Phase 3 — Forward all six arguments *(small, already scoped)*

The trampoline saves `rdi..r9` but forwards only five, because
`ls_tramp_dispatch(slot, a0..a4)` spends `rdi` on the slot. Any six-argument
function loses its last one — `rst_why`'s `rst_cause` string is the first case
where that mattered.

**Fix:** pass a **pointer to the saved register block** rather than individual
arguments, which is what the kernel's BPF trampoline does with `pt_regs` and what
bpftime hands uprobe programs. All six arguments plus `rax`/`r10`/`r11`, and no
further asm change ever.

**Cost:** changes `ls_tramp_dispatch`'s signature and every ctx builder. Contained
— but it touches the one file where a mistake is a wrong-argument bug rather than
a crash, and the asm comments already record an earlier off-by-8 in exactly that
shuffle.

---

## Phase 4 — Ring output helper *(optional, after 1)*

A `bpf_ringbuf_output`-shaped helper so a program decides *what* to emit rather
than the host emitting a fixed record. Today the record and the program's ctx are
the same buffer, so what can be egressed is capped by what can be verified over
(LIMITATIONS §2.3). This decouples them.

Gated on Phase 1, since it is the same helper-registration machinery.

---

## Explicitly not in this plan

- **Switching to bpftime.** It has all of the above, but adopting it means
  Frida-gum and LLVM inside TMM's data plane. Frida installs its own inline
  trampolines, which collides with pad-based arming and with TMM's memory layout,
  and it trades a small auditable VM for a large TMA surface. The runtime choice
  still looks right; running it *stripped of maps and helpers* was the mistake.
- **Arbitrary-address attach** (hardware breakpoints). Real, and in
  `cve-mitigation-plan.md` Phase 2 — but it addresses *where* you can attach, not
  what a program can *express*, and expressiveness is what has actually blocked us.

---

## Order, and why

| | phase | risk | unlocks |
|---|---|---|---|
| 1 | helpers + one map | **low** — verifier already agrees | state; every use case |
| 2 | exit hooks | medium — re-entrancy, stack discipline | function outputs |
| 3 | six arguments | low, but in the asm | six-arg hooks |
| 4 | ring helper | low | program-chosen egress |

Phase 1 first because the expensive unknown turned out to be free, its value does
not depend on anything outside our control, and it is the only one that changes
what a program can *say*.
