# TMM tree delta — the symbol-level record of what the substrate changes

Companion to [`substrate/.tree-expected-delta`](substrate/.tree-expected-delta). That manifest
records the **files** the substrate adds or modifies in a clean TMM tree, by name and status;
this file records the **contents of the three modifications** at the level of *our own names* —
the filelist entries and the whitelist symbols we add, and the one compiler flag. Together they
answer "if the build box died, could the F5-tree side be reconstructed?" without copying any F5
source: everything below is either our own symbol/file or a build-config flag, never F5 code.

**Base:** `tmm/tmm` at `e2104734a9`. **Current as of** the fexit build (2026-08-27, image
`fd74821b`). Regenerate the raw state from the build box with:

```sh
ssh <build-box> 'cd ~/code/tmm/src/compile &&
  grep -nE "^base/ls_" filelist &&
  grep -nE "g_ls_" default_whitelist_x86_64 debug_whitelist_x86_64'
```

## 1. `src/compile/filelist` — the substrate sources compiled into TMM

Thirteen files under `base/`, each tagged `STDINC` (plain C against TMM's include world) or
`STDINC UBPF` (also needs uBPF's headers). No F5 line is changed; these are appended.

| file | flags | what it is |
|---|---|---|
| `base/ls_vm_config.c` | `STDINC UBPF` | env/config for the VM (`ls_vm_sig_enforce`, overrides) |
| `base/ls_core_relo.c` | `STDINC` | the CO-RE relocator (field offsets against the binary's `.BTF`) |
| `base/ls_vm_load.c` | `STDINC UBPF` | the loader socket: LOAD / ARM / STATUS / DISARM / SET_MODE / REVOKE |
| `base/ls_vm.c` | `STDINC UBPF` | the VM: slots, `ls_vm_call`, arm/reload/swap |
| `base/ls_tp_emit.c` | `STDINC UBPF` | tracepoint/ring emit |
| `base/ls_sig.c` | `STDINC UBPF` | Ed25519 signature verification of loaded programs |
| `base/ls_audit.c` | `STDINC UBPF` | the audit trail (who armed what, when, on which binary) |
| `base/ls_tramp.c` | `STDINC UBPF` | the entry trampoline's C half (per-hook dispatch) |
| `base/ls_tramp_asm.c` | `STDINC` | the trampolines, C-wrapped: **entry** (`ls_trampoline_slot*`) **and exit** (`ls_fexit_slot*` + `ls_fexit_stub` + tables), generated from `trampoline_x86_64.S` by `make tramp-asm` |
| `base/ls_fexit.c` | `STDINC` | **fexit**: the per-instance shadow stack + `ls_fexit_enter`/`ls_fexit_leave` (added 2026-08-27) |
| `base/ls_swap.c` | `STDINC` | the `text_poke_bp` safe swap |
| `base/ls_arm.c` | `STDINC` | pad find + patch; `ls_arm_live` selects the entry vs `ls_fexit_table` per the slot's kind |
| `base/ls_prep.c` | `STDINC` | the prepare handoff (VM/verify work moved off the loader thread) |

## 2. `src/compile/{default,debug}_whitelist_x86_64` — mutable-global manifest

TMM's link fails on **any** difference, in either direction, between the binary's mutable globals
and this list. Our additions (identical in both the default and debug whitelists), in the file's
alphabetical order — **14 symbols**:

```
g_ls_audit                 # ls_audit.c   — the audit ring
g_ls_btf                   # ls_vm.c      — the parsed target BTF (for CO-RE)
g_ls_fexit_desync          # ls_fexit.c   — the 9 fexit shadow-stack + counter globals
g_ls_fexit_exits           #   (added 2026-08-27; exact set from `nm ls_fexit.o`)
g_ls_fexit_log
g_ls_fexit_log_n
g_ls_fexit_overflow
g_ls_fexit_reclaimed
g_ls_fexit_seq
g_ls_fexit_stack
g_ls_fexit_top
g_ls_names                 # ls_vm.c      — hook-name table
g_ls_nshapes               # ls_vm.c
g_ls_shapes                # ls_vm.c
```

They sort between the base tree's `g_loader_running` and `g_origin`; the nine `g_ls_fexit_*` sit
between `g_ls_btf` and `g_ls_names`.

## 3. Compiler flag — `Makefile.overrides`

```make
CFLAGS_OPTIMIZE += -fpatchable-function-entry=5,0
```

The 5-byte entry pad on every function (`endbr64` then five nops), so arming can overwrite the pad
with a `call rel32` to a trampoline at runtime. This is what makes "attach to any function on a
running TMM" possible; it is orthogonal to CO-RE. See `docs/TMM-BUILD.md`.

## 4. `ssl.c` — NOT modified

Listed as modified in an older manifest because the tree once carried a deliberate revert of an
ALPN bounds check (a vulnerable build for a shield demo). That was restored 2026-08-18 — the tree
is **not** vulnerable — and `ssl.c` is no longer in the delta. Recorded here so its absence is a
statement, not an omission.

---

*No F5 source appears above. `ls_sig_pubkey.h` is generated per build box from that box's signing
key and must never travel between trees — it is listed in `.tree-expected-delta` as added, but its
content is machine-specific.*
