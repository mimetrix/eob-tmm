# uBPF fork patches

The uBPF clone itself is vendored and **gitignored**, so the changes F5 owns live here as patches
rather than as a forked tree. Applied against the pinned revision (see
[`../../bnk-integration-map.md`](../../bnk-integration-map.md) for the current uBPF / PREVAIL pins).

The fork is not a new cost introduced by these patches: `development-scope.md` item 15 (back-edge
fuel for time safety) already requires F5 to own and carry a uBPF fork. These sit alongside it.

| Patch | What it does | Why |
|---|---|---|
| `0001-jit-scratch-reuse.patch` | Allocate the JIT's fixed scratch once per process and reuse it, instead of `calloc`ing 5.25 MB on every compile | Cuts prepare cost **17×**, which is what makes it affordable to compile on a TMM thread. See `../../load-path-scope.md` §3a/§3b |

## Applying

These are plain unified diffs, not git-format patches — the vendored clone is not a git repo we
control. From the uBPF clone root (`~/code/tmm/.ubpf` on the build box):

```bash
patch -p0 --dry-run < .../0001-jit-scratch-reuse.patch   # check first
patch -p0           < .../0001-jit-scratch-reuse.patch
# rebuild in the toolchain container, so libc matches TMM's:
#   cmake --build build -j8      ->  build/lib/libubpf.a
```

The paths in the diff header are absolute build-box paths; `-p0` with the file present at
`vm/ubpf_jit_support.c` is the reliable way, or apply by hand — the patch is three small hunks.
**Re-apply after any uBPF pin bump**, and re-run both programs in *Verifying* below before trusting
the result.

## Why `0001` exists

`initialize_jit_state_result()` allocates five buffers sized by `UBPF_MAX_INSTS` = 65,536
*regardless of the program being compiled*:

```
pc_locs                        65537 x  4      =  256 KB
jumps / loads / leas / local_calls
                               65536 x 20 x 4  = 5120 KB
                                                 -------
                                                 5.25 MB per compile
```

A 4 KB shield touches a sliver of that. `calloc` of that size measures **0.0 us** — it is lazily
mapped zero pages — so the cost is not allocation but the **demand faults as the JIT walks them**,
measured independently at 272 us mean / 2115 us max. That accounted for essentially all of
`ubpf_compile_ex`'s 311 us median; real compilation of a 4 KB program is ~40 us.

Measured on the build box, 50 iterations of the real `ls_vm.c` call sequence against the real
4320-byte shield:

| | before | after |
|---|---|---|
| `ubpf_create` | 28.6 us | **4.9 us** |
| `ubpf_load_elf_ex` | 5.4 us | 5.8 us |
| `ubpf_compile_ex` | 311.1 us | **10.1 us** |
| **total, median** | **348.6 us** | **21.0 us** |
| total, p95 | 544.0 us | **37.4 us** |
| total, max | 3226.8 us | 1109.1 us *(first compile only — see below)* |

The remaining ~1.1 ms outlier is the **first** compile, which pays the page-faulting once inside
`ls_jit_scratch_init()`. In TMM that lands at startup, because `http_psm_init()` compiles the
built-in shield during initialization. Every runtime load after that is the ~21 us figure.

## Why reuse is safe

Checked in the source rather than assumed:

- `jumps` / `loads` / `leas` / `local_calls` are written through `emit_patchable_relative()` at index
  `num_*++`, and the `num_*` counters are reset to 0 on every compile. They are read only by
  `modify_patchable_relatives_target()` iterating `0..num_*`. **No entry is read before it is
  written within a compile**, so stale contents from a previous compile are unobservable.
- `pc_locs[i]` is written for every instruction during translation and read only in the later fixup
  pass, so every index read was written by the same compile.
- A failed compile can leave stale entries, but its output is discarded.

**Concurrency:** the shared scratch serves one compile at a time (`ls_jit_scratch_busy`). A
concurrent second compile falls back to the original per-compile `calloc`, so upstream behaviour is
preserved for callers we do not control. TMM prepares on a single thread, so the fallback should not
fire in our use.

**No struct change:** `release_jit_state_result()` recognises the shared buffers by pointer
comparison instead of a new `jit_state` field, keeping the patch to one file and reducing merge
friction against upstream.

## Verifying

Both programs build against the vendored uBPF and are the acceptance evidence for the patch. From
inside the toolchain container, with the uBPF clone at `/tmm/.ubpf`:

```bash
gcc -O2 -I vm/inc -I build/vm -o /tmp/bench bench_jit_cost.c   build/lib/libubpf.a -lm
gcc -O2 -I vm/inc -I build/vm -o /tmp/verif verify_scratch_reuse.c build/lib/libubpf.a -lm
/tmp/bench shield.elf shield     # timings, per stage
/tmp/verif shield.elf shield     # correctness
```

`verify_scratch_reuse.c` is the one that matters. A speedup that silently miscompiles is worse than
no speedup, so it checks compiled **behaviour**, not that compilation returned success:

1. **JIT vs interpreter.** `ubpf_exec` runs the same bytecode without touching the JIT scratch, so it
   is an oracle this patch cannot influence.
2. **Compile drift.** The same program is compiled 40 times through the shared scratch and every
   result must agree with the first — a stale entry leaking between compiles shows up as a later
   compile disagreeing.

Both ctx cases are exercised, so a shield that degenerated into a constant is caught rather than
passing. Current result on the pinned revision:

```
round 0 baseline:  null-ctx -> 1   live-ctx -> 0
interpreter says:  null-ctx -> 1   live-ctx -> 0
40 rounds through the shared scratch
RESULT: PASS --- JIT matches interpreter, and every compile agrees
```

That `1` / `0` split is also the shield's own logic confirmed end to end: a null
`prot_transfer_log_profile` returns the safe value, a live one falls through to the normal path.
