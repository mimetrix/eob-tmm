# `substrate/` — the two candidate ABI artifacts

These are the parts of [`../../development-scope.md`](../../development-scope.md) that are worth
having as **real files rather than illustrative blocks**, because their value is precisely that they
compile and validate:

| File | What it is | Verified by |
|---|---|---|
| [`shield_abi.h`](shield_abi.h) | The substrate ABI: the loader message (`struct shield_msg`), the signed binding, the safe-return policy, the hook slot, and the host-side entry points. Items **3, 4, 7, 9, 10**. | compiles standalone; include-guard clean; `_Static_assert`s pin `struct shield_msg`'s wire layout |
| [`hook_map.schema.json`](hook_map.schema.json) | JSON Schema for the per-build hook map the generator emits. Item **5** (and the input to item **6**). | valid JSON; [`../hook-point-map.json`](../hook-point-map.json) validates against it |

```bash
make check      # both of the above
```

`check` needs only a C compiler and Python 3. If `jsonschema` is installed it is used; otherwise
[`check_hook_map.py`](check_hook_map.py) falls back to a structural check of the same rules.

## What is real, and what is not

**Real:** the C in `shield_abi.h` is valid C11 and its assertions genuinely hold — `struct
shield_msg` is `op@0, hook@4, mode@68, expires_with@72, prog_len@76, sig@80`, 144 bytes of header
before `prog[]`. `shield_jit_fn` matches **uBPF's actual JIT signature** (`uint64_t (*)(void *mem,
size_t mem_len)`), not the one-argument shorthand the explainer uses. The schema genuinely validates
the prototype's existing hook map.

**Not real:** every function declared in `shield_abi.h` is a **stub** — there are no bodies in this
repo, and there is no TMM here to attach to. `sig_verify`, `hook_map_lookup`, `trampoline_arm`,
`trampoline_disarm` and `shield_msg_handle` name F5-internal work that does not exist yet. The
skeletons that *use* this ABI live in [`../../development-scope-code.md`](../../development-scope-code.md)
and are candidates for review, not production code.

**Deliberately a subset:** the schema's `required` list is scoped to what the prototype's hand-written
[`../hook-point-map.json`](../hook-point-map.json) already carries, so that instance stays valid. The
fields a real generator must start emitting — `entry_offset`, `patchable_pad_bytes`, `safe_return`,
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
