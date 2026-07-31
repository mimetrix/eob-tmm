# `substrate/` — the parts of the scope that are real files

These are the parts of [`../../development-scope.md`](../../development-scope.md) worth having as
**real files rather than illustrative blocks**, because their value is precisely that they compile,
validate, and run — and because writing them for real has already caught four defects the prose
versions carried unnoticed. Each is listed below.

| File | What it is | Verified by |
|---|---|---|
| [`shield_abi.h`](shield_abi.h) | The substrate ABI: the loader message (`struct shield_msg`), the signed binding, the safe-return policy, the hook slot, and the host-side entry points. Items **3, 4, 7, 9, 10**. | compiles standalone; include-guard clean; 15 `_Static_assert`s pin the wire layout of `struct shield_msg` *and* `struct shield_binding` |
| [`check_sr_gates.c`](check_sr_gates.c) | Five cases asserting the safe-return **two-gate** rule — an unanalysed body is never enforce-capable, whatever its return type. Item **7**. | compiled and run; fails the build on regression |
| [`budget_pass.py`](budget_pass.py) | The admission-time cost gate: parses a real eBPF ELF, decodes the instruction stream, builds the CFG, prices the longest path. Item **8**. | run against the repo's own shield objects |
| [`check_offsets.py`](check_offsets.py) | Compiles a hook map's declared `ctx` offsets against the real header and fails on mismatch. Item **5**. | run; catches the live `mode`-field bug this repo had |
| [`hook_map.schema.json`](hook_map.schema.json) | JSON Schema for the per-build hook map the generator emits. Item **5** (and the input to item **6**). | valid JSON; [`../hook-point-map.json`](../hook-point-map.json) validates against it |

```bash
make check      # all of the above
```

`check` needs only a C compiler and Python 3. If `jsonschema` is installed it is used; otherwise
[`check_hook_map.py`](check_hook_map.py) falls back to a structural check of the same rules.

## What is real, and what is not

**Real:** the C in `shield_abi.h` is valid C11 and its assertions genuinely hold — `struct
shield_msg` is `op@0, epoch@4, mode@8, prog_len@12, binding@16, sig@128`, 192 bytes of header before
`prog[]`, with `struct shield_binding` pinned at `prog_sha256@0, hook@32, build_min@96,
build_max@100, mode_ceiling@104, expires_with@108`, 112 bytes. `shield_jit_fn` matches **uBPF's actual JIT signature** (`uint64_t (*)(void *mem,
size_t mem_len)`), not the one-argument shorthand the explainer uses. The schema genuinely validates
the prototype's existing hook map.

**What writing them for real has already caught** — this is the argument for these files existing at
all:

1. **A field the signature was said to cover but the message could not carry.** `sig` was documented
   as committing to the program hash, hook, build range, mode ceiling and expiry — three of which were
   nowhere in `struct shield_msg`, so the accessor the loader skeleton called could not be written.
   The binding is now embedded and asserted.
2. **A replay that defeats the kill switch.** Only `LOAD` was authenticated, and with no nonce a
   captured `LOAD` replays after a `REVOKE`. Hence `epoch`, and a signature covering `op` and `mode`.
3. **The safe-return model was inverted.** It classified by return type, which made `void` look like
   the trivial case when it is the hardest — a void function is called entirely for its side effects,
   so skipping it discards all of them. Skippability is now gate 1, closed by default, and
   `check_sr_gates.c` fails the build if that regresses.
4. **A hook map declaring the wrong `ctx` offsets.** `check_offsets.py` was written after finding a
   live one in this repo, and it still catches that bug when reintroduced.

**Not real:** every function declared in `shield_abi.h` is a **stub** — there are no bodies in this
repo, and there is no TMM here to attach to. `sig_verify`, `hook_map_lookup`, `trampoline_arm`,
`trampoline_disarm` and `shield_msg_handle` name F5-internal work that does not exist yet. The
skeletons that *use* this ABI live in [`../../development-scope-code.md`](../../development-scope-code.md)
and are candidates for review, not production code.

**Deliberately a subset:** the schema's `required` list is scoped to what the prototype's hand-written
[`../hook-point-map.json`](../hook-point-map.json) already carries, so that instance stays valid. The
fields a real generator must start emitting — `entry_offset`, `patchable_pad_bytes`, `safe_return`
(which now requires its gate-1 `skippable` verdict, not just a return `kind`),
`budget_cycles`, `mode_ceiling`, `ctx_abi_version`, `generated_by`, `signature` — are marked
`"$comment": "required in product"`, and `make check` lists which ones an instance is missing.

## Relationship to the rest of the prototype

[`../minimm/ls_shield.h`](../minimm/ls_shield.h) is the **prototype's** ABI: `ls_ctx`, `ls_verdict`,
`ls_mode`, `ls_shared` — small, runnable, and exercised by a working relay. This header is the
**product-side** ABI for the same ideas: it adds everything the prototype has no analog for (the
signed binding, patchable-entry slots, per-core evidence, the loader message family). The two use
different prefixes on purpose — `ls_*` is what runs today, `shield_*` is what is being proposed. The
naming-reconciliation table in
[`../../development-scope-code.md`](../../development-scope-code.md) maps between them, and between
both and the spellings already committed in the explainers.
