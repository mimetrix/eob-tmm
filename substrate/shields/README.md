# `substrate/shields/` — candidate shield programs, compiled and verified

Four small eBPF programs and one generated header. They are **candidate artifacts**: they
compile, and PREVAIL reaches a verdict on each. **Nothing here is loaded into TMM, and
nothing executes a shield** — per [`../../CLAUDE.md`](../../CLAUDE.md) this repo has no
prototype, and these do not change that. What they demonstrate is that the *authoring
chain* is real end to end, and that the verifier's gates fire when they should.

## What made this possible

`ls_ctx_http_psm.h` is **generated from a real build's DWARF**, not hand-written. On
2026-08-12 TMM was built from source (`make tmm-gdb`, BNK form factor) and `pahole` read the
struct layouts straight out of `tmm64.no_pgo.debug`:

```
struct fw_log_profile_protocol_transfer {
    char *  name;          /*  0  8 */   <- the field the CVE dereferences unchecked
    ...                                  /* size: 48 */
};
struct http_psm_log_data {
    UINT64  req_id;        /*  0  8 */
    ...
    struct http_scb * scb; /* 24  8 */   /* size: 32, 4-byte hole after `block` */
};
```

That matters because a shield includes the `ctx` definition for its hook, and that layout is
**a property of one build**. Previously these programs were written against structs typed
out by hand, which can drift from the binary silently. This is
[`../../development-scope.md`](../../development-scope.md) item 6 — ctx-descriptor emission —
in miniature, and the real one is a generator, not a person running `pahole`.

**The ctx is flat and bounded on purpose.** The C code walks
`log_data->scb->uf → connflow → listener → prot_transfer_log_profile → name`. eBPF cannot
chase unbounded pointers and PREVAIL will not admit a program that tries — see
`reject_memory.bpf.c`, which fails for exactly that reason. So the trampoline resolves the
chain and hands the shield the fields it needs.

## The programs

| file | section | verdict |
|---|---|---|
| `ls_2026_http_psm.bpf.c` | `fentry/http_psm_profile_name_lookup` | **PASS** — 9 instructions, 5 blocks, ~21 cycles against a budget of 800 |
| `reject_memory.bpf.c` | `fentry/reject_memory` | **FAIL** — `Invalid type (r4.type in {ctx, stack, packet, shared})` |
| `reject_termination.bpf.c` | `fentry/reject_termination` | **FAIL** with `--termination`, **PASS** without it |
| `folded_loop.bpf.c` | `fentry/folded_loop` | **PASS** — and that is the point; see below |

`ls_2026_http_psm.bpf.c` restores the NULL check missing at
`src/modules/hudfilter/http/http_psm.c:806-808`, where `ptlp` is dereferenced without one
and every other use of that field in the tree checks it
(`listener.c:1161`, `listener.c:1519`, `fw_log_profile.c:4551`, `db_fw_log.c:1663`).

## The section name is the program type, not a label

`fentry/` is not decoration and not the design's `attach_mode`. PREVAIL derives the program
type — and with it the `ctx` descriptor it verifies against — by matching the **ELF section
name** against a compiled-in prefix table, and when nothing matches it silently falls through
to `socket_filter` (`src/linux/linux_platform.cpp:188-198`).

That fallback's descriptor is `__sk_buff`: **192 bytes with pointer slots at 76/80/140**. Any
`ctx` smaller than 192 bytes therefore verifies clean while touching none of those slots — which
demonstrates a small struct fitting inside a big one and nothing else. This is finding **O3**,
and these programs were originally written with a `filter/` prefix, which matches nothing, so
their first verdicts were obtained under exactly that fallback.

`fentry/` selects `tracing`, whose descriptor is `{96, -1, -1, -1}` — 96 bytes and **no pointer
slots at all**. That is the fentry model, and an honest description of what a TMM entry hook
is: it receives argument values, and dereferencing is the host's job, not the program's. All
four verdicts are unchanged under it, which is what makes them worth quoting.

**Keep the two vocabularies apart.** `attach_mode: filter` in the hook map describes what the
host does with the return value. The section prefix describes what the verifier models. They are
different concerns and naming them alike invites exactly the substitution that happened here.
`check_shields.py`'s `fallback_prefix_guard()` fails the build if a section name stops matching a
real prefix, or selects `socket_filter` on purpose.

## Three things these programs establish

**The two gates are independent, and one hid the other.** `reject_memory.bpf.c` was written
to test termination *and* memory safety at once; it fails on memory type at instruction 8
and never reaches the termination question. Isolating them needed a program that is
memory-safe throughout and only unbounded in its trip count. Compound negative tests report
the first gate that fires, not the one you meant to test.

**`folded_loop.bpf.c` is why "PASS" needs reading carefully.** It contains an unbounded
loop over an attacker-influenced `name_len` and passes `--termination` cleanly, reporting
*"terminates within 0 loop iterations"* — because `clang -O2` recognised the body as
`sum(i) & 1` and folded it to closed form. There is no loop left in the object. So a
termination verdict can reflect what the **compiler** did rather than what the program says,
which is a concrete argument for verifying **the object that ships**, not reasoning about
source. `reject_termination.bpf.c` uses a data-dependent hash body that `-O2` cannot fold,
and that one fails as intended: *"Loop counter is too large (pc[8] < 100000)"*.

**PREVAIL's defaults are permissive, and it says so in `--help`.** `--termination` is
*"Default: ignore"*; `--allow-division-by-zero` is *"Default: allow"*; `--strict` is off.
`reject_termination.bpf.c` **passes** under the defaults and **fails** when the flags are
asked for. This is [`../../development-scope.md`](../../development-scope.md) item 3a, and
it is why `substrate/check_vm_geometry.py` treats the defaults as a finding.

## Reproducing

Compile on a machine with a BPF-capable clang (the TMM build box has clang 18.1.3; the
toolchain container has no clang at all, which is why shields build on the host):

```bash
clang -O2 -g -target bpf -c ls_2026_http_psm.bpf.c -o ls_2026_http_psm.bpf.o
```

Then verify and price. Both gates explicit — the defaults are not enough:

```bash
../../ebpf-verifier/bin/prevail ls_2026_http_psm.bpf.o \
    fentry/http_psm_profile_name_lookup --termination --no-division-by-zero --strict
python3 ../budget_pass.py --section fentry/http_psm_profile_name_lookup ls_2026_http_psm.bpf.o
```

Pass `--section` explicitly. clang leaves a **present but zero-length `.text`** alongside
the real `SEC()` section, which is the shape that produced a fail-open in `budget_pass.py`
— it priced 0 instructions and returned "under budget" for a program it never read, in the
one component whose job is to fail closed. It now locates the executable section and refuses
when there is none or several.

`budget_pass.py` independently **REFUSES** `reject_termination.bpf.c`: *"loop back-edge at
block 8 — needs a proven trip count."* Two components, two reasons, same conclusion.
