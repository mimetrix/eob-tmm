# uBPF fork patches

The uBPF clone is vendored and **gitignored**, so changes F5 owns live here as patches rather than as
a forked tree. Applied against the pinned revision (see
[`../../bnk-integration-map.md`](../../bnk-integration-map.md) for current uBPF / PREVAIL pins).

**A fork was always coming.** `development-scope.md` item 15 — back-edge fuel for time safety — is a
uBPF JIT patch marked day one. So the question was never *fork or not*; it is **how many patches, and
does each one have a way out.**

| Patch | What it does | Upstreamable? |
|---|---|---|
| `0001-jit-scratch-rightsize.patch` | Size the JIT's scratch to the program being compiled instead of to `UBPF_MAX_INSTS` | **Yes — this is an upstream bug.** Fixing it there deletes this patch |
| *(item 15, not yet written)* | Back-edge fuel in the JIT, for a time bound under `ENFORCE` | Intended to be, per `engine-hard-problems.md` §1 |

## `0001` — what and why

`initialize_jit_state_result()` allocates five scratch arrays sized by `UBPF_MAX_INSTS` = **65,536**
— the largest program uBPF permits — **regardless of the program actually being compiled**:

```
pc_locs                              65537 x  4      =  256 KB
jumps / loads / leas / local_calls   65536 x 20 x 4  = 5120 KB
                                                       -------
                                                       5.25 MB per compile
```

A 4 KB shield uses a fraction of a percent of that. The `calloc` itself is free — measured at
**0.0 us**, because it is lazily mapped zero pages — so the cost is the **demand faults as the JIT
walks the arrays**, measured independently at 272 us mean / 2115 us max. That accounted for ~90% of
`ubpf_compile_ex`.

The instruction count is already available: `ubpf_translate_x86_64()` / `_arm64()` both receive `vm`,
and `vm->num_insts` is set by `ubpf_load()`. The arrays are indexed by instruction during
translation, so `num_insts` is the **exact** bound — at most one jump / load / lea / local_call per
instruction. `pc_locs` keeps its `+1`, as upstream has it.

### Measured

50 iterations of the real `ls_vm.c:484-522` sequence against the real 4320-byte shield, on the build
box in the toolchain container:

| Stage | before | after |
|---|---|---|
| `ubpf_create` | 28.6 us | **4.8 us** |
| `ubpf_load_elf_ex` | 5.4 us | 5.3 us |
| `ubpf_compile_ex` | 311.1 us | **9.0 us** |
| **total, median** | **348.6 us** | **19.5 us** |
| total, p95 | 544.0 us | **28.5 us** |
| **total, max** | **3226.8 us** | **58.3 us** |

The **max** is the figure that decides whether this can run on a TMM poll thread, and it improves
55x. There is no first-compile penalty, because nothing large is ever allocated.

### Why this shape, and not scratch reuse

The first version of this patch kept a process-global scratch set and reused it across compiles. It
worked (21.0 us median) but was the wrong shape: process-global mutable state, a non-atomic busy
flag, and 5.25 MB retained for the process lifetime after a single compile. Upstream would reject
that, and correctly — which would have made it a **permanent** fork.

Right-sizing is smaller, faster on every percentile, has no global state, no thread-safety question,
nothing retained after the compile, and leaves `release_jit_state_result()` untouched. It is also
the actual bug rather than a workaround for it, so it has a credible path upstream — and when it
lands there, this patch disappears.

## Applying

Plain unified diffs (the vendored clone is not a git repo we control). From the uBPF clone root
(`~/code/tmm/.ubpf` on the build box):

```bash
patch -p0 --dry-run < .../0001-jit-scratch-rightsize.patch   # check first
patch -p0           < .../0001-jit-scratch-rightsize.patch
# rebuild in the toolchain container so libc matches TMM's:
#   cmake --build build -j8      ->  build/lib/libubpf.a
```

Touches three files: `vm/ubpf_jit_support.c`, `vm/ubpf_jit_support.h`, `vm/ubpf_jit_x86_64.c`, plus
the same one-line call-site change in `vm/ubpf_jit_arm64.c` (**apply that one by hand** — it is not
in the diff, and aarch64 is a supported target per `development-scope.md`).

**Re-apply after any pin bump**, and re-run both programs below before trusting the result.

## Verifying

```bash
gcc -O2 -I vm/inc -I build/vm -o /tmp/bench bench_jit_cost.c       build/lib/libubpf.a -lm
gcc -O2 -I vm/inc -I build/vm -o /tmp/verif verify_scratch_reuse.c build/lib/libubpf.a -lm
/tmp/bench shield.elf shield     # timings, per stage
/tmp/verif shield.elf shield     # correctness
```

`verify_scratch_reuse.c` is the one that matters. A speedup that silently miscompiles is worse than
no speedup, so it checks compiled **behaviour**, not that compilation returned success:

1. **JIT vs interpreter.** `ubpf_exec` runs the same bytecode without touching the JIT scratch, so it
   is an oracle this patch cannot influence.
2. **Compile drift.** The same program is compiled 40 times and every result must agree with the
   first.

Both ctx cases are exercised, so a shield that degenerated into a constant is caught rather than
passing:

```
round 0 baseline:  null-ctx -> 1   live-ctx -> 0
interpreter says:  null-ctx -> 1   live-ctx -> 0
RESULT: PASS --- JIT matches interpreter, and every compile agrees
```

That `1`/`0` split is also the shield's own logic confirmed end to end: a null
`prot_transfer_log_profile` returns the safe value, a live one falls through to the normal path.

*(The filename says `scratch_reuse` for history's sake; it tests whatever `0001` currently is.)*
