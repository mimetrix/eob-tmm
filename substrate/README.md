# `substrate/` — the sources that are compiled into TMM, and the checks that gate them

This directory holds two different kinds of thing, and the distinction matters more than any
other line in this file:

1. **Sources that are built into TMM.** `ls_vm.c`, `ls_vm_load.c`, `ls_prep.c`, `ls_arm.c`,
   `ls_swap.c`, `ls_tramp.c`, `ls_vm_config.c`, `ls_sig.c`, `ls_audit.c`, the six `ls_ctx_reg*.c`
   and `trampoline_x86_64.S` are compiled into the TMM binary in a different tree. They are the running mechanism, not illustrations of it.
   [`TMM-TREE-DELTA.md`](TMM-TREE-DELTA.md) is what that other tree needs.
2. **Candidate artifacts and checks**, kept as real files rather than illustrative blocks so they
   compile, validate and run — which caught four defects the prose versions carried unnoticed.

**This repo is still not self-contained.** `make check` exercises bench harnesses, not a data
plane; reproducing the live results needs the TMM build tree and the cluster. And two limits stand
throughout: **no CVE has been mitigated on live traffic**, and the **per-call cost of an armed hook
is unmeasured**.

## Compiled into TMM

| File | What it is |
|---|---|
| [`ls_vm.c`](ls_vm.c), [`ls_vm.h`](ls_vm.h) | The VM wrapper: create, load ELF, JIT-compile, publish into a slot, and the O14 section/symbol identity check. Item **3**. |
| [`ls_vm_load.c`](ls_vm_load.c) | The runtime load path — the socket loader thread, the `shield_msg` dispatch, and the prepare handoff onto a TMM poll thread (preparation cannot run on a thread we create; TMM aliases `malloc` to a per-core allocator whose spinlock is never initialized there). Item **3**. |
| [`ls_prep.c`](ls_prep.c) | The TMM-side glue: the periodic timer that drains the handoff, and the `INIT_FUNC(INIT_LATE, …)` registration that is **why nothing is spliced into TMM's own logic**. The one file without `STDINC` — see `TMM-TREE-DELTA.md` §5. |
| [`ls_arm.c`](ls_arm.c), [`ls_arm.h`](ls_arm.h) | Writing the patch into live code and taking it back out. Item **2**. |
| [`ls_swap.c`](ls_swap.c) | The `text_poke_bp` protocol in userspace: INT3, `membarrier(SYNC_CORE)`, tail, sync, real opcode. Item **0b**. |
| [`ls_tramp.c`](ls_tramp.c), [`trampoline_x86_64.S`](trampoline_x86_64.S) | The trampoline — one of them, shared by every armed hook. Item **1**. |
| [`ls_vm_config.c`](ls_vm_config.c) | Environment overrides, so program source and names are a restart rather than a rebuild. |
| [`ls_sig.c`](ls_sig.c), [`ls_sig.h`](ls_sig.h) | Ed25519 verification of the signed binding, before a program is admitted. The header is the one to read: it says what is signed, and why that deviates from `shield_abi.h`'s comment on purpose. Item **4**. |
| [`ls_audit.c`](ls_audit.c), [`ls_audit.h`](ls_audit.h) | One record per control-plane operation, with the caller's kernel-attested pid/uid and the verdict quoted verbatim. Read the header first: most of it is what this **cannot** do — no operator identity, no tamper evidence in the format, and an address rather than a symbol on an ARM record. Item **12**. |
| [`ls_ctx_reg.c`](ls_ctx_reg.c) + `ls_ctx_reg_*.c` | Which context builder a hook gets, resolved by symbol name through a linker set rather than by slot number — see `CONTESTED-PREMISES.md` #1 for what the slot-number version did. |
| [`mk_shield_blob.py`](mk_shield_blob.py) | Generates `ls_shield_blob.h`, the built-in shield TMM arms at startup. Generated, so gitignored; `make check-vm` depends on it. |

## Driving a live TMM

[`loader-client/`](loader-client/) — the client half of the load path: the wire protocol, the
measurement drivers, and `check_load_distinct.py`, which proves distinct bytecode is loaded and
discriminated. Not the operator front-end; that is item **11** and is unwritten.

## Candidate artifacts and checks

| File | What it is | Verified by |
|---|---|---|
| [`shield_abi.h`](shield_abi.h) | The substrate ABI: the loader message (`struct shield_msg`), the signed binding, the safe-return policy, the hook slot, and the host-side entry points. Items **3, 4, 7, 9, 10**. | compiles standalone; include-guard clean; 15 `_Static_assert`s pin the wire layout of `struct shield_msg` *and* `struct shield_binding` |
| [`check_sr_gates.c`](check_sr_gates.c) | Five cases asserting the safe-return **two-gate** rule — an unanalysed body is never enforce-capable, whatever its return type. Item **7**. | compiled and run; fails the build on regression |
| [`platform_stub.h`](platform_stub.h) | The gaps that stopped `../development-scope-code.md`'s skeletons from being readable by a compiler — two control-plane types, one bound, and the helpers no block declares. Deliberately minimal: it restates nothing `shield_abi.h` or the blocks themselves already declare, because a second declaration that disagreed would be a defect this file introduced rather than one it found. Every symbol is a declaration only; nothing is linked. | compiled by `make check-skeletons`; declarations only, never linked |
| [`check_skeletons.py`](check_skeletons.py) | Hands each ```c block in that document to a compiler. They are the exemplar an engineer reads for the shape of each item, and before this nothing had ever compiled them — which is how the JIT typedef came to be uBPF's 2-argument basic form while the design needs the 4-argument extended one. A block may opt out with a `not-compiled:` reason; opting out is **reported**, never silent. A pass means the skeletons agree with the ABI header and with each other on types, fields, arity and signatures. It does not mean they run. | run by `make check-skeletons`: 7 of 8 blocks compile, 1 opted out and reported |
| [`check_vm_geometry.py`](check_vm_geometry.py) | **Item 6a**, and it fails today. PREVAIL proves against a *declared* machine; uBPF provides an *actual* one; nothing enforces that they match, and a divergence is silent because the artifact is still authentic and the theorem still valid — just about different hardware. Parses the constants out of both vendored trees at run time rather than transcribing them. Reports under `make check`; `make gate` is the same check with the exit code a build pipeline needs. | run by `make check-geometry`; **reports a real divergence today** — `make gate` fails on it |
| [`budget_pass.py`](budget_pass.py) | The admission-time cost gate: parses a real eBPF ELF, decodes the instruction stream, builds the CFG, prices the longest path. Item **8**. | run against a six-case self-test (hand-assembled eBPF in a synthesized ELF) |
| [`check_offsets.py`](check_offsets.py) | Compiles a hook map's declared `ctx` offsets against the real header and fails on mismatch. Item **5**. | run; catches the live `mode`-field bug this repo had |
| [`hook_map.schema.json`](hook_map.schema.json) | JSON Schema for the per-build hook map the generator emits. Item **5** (and the input to item **6**). | valid JSON; [`hook-point-map.json`](hook-point-map.json) validates against it |

```bash
make check      # all of the above
```

`check` needs only a C compiler and Python 3. If `jsonschema` is installed it is used; otherwise
[`check_hook_map.py`](check_hook_map.py) falls back to a structural check of the same rules.

## What is real, and what is not

**Real:** the C in `shield_abi.h` is valid C11 and its assertions hold — `struct
shield_msg` is `op@0, epoch@4, mode@8, prog_len@12, binding@16, sig@128`, 192 bytes of header before
`prog[]`, with `struct shield_binding` pinned at `prog_sha256@0, hook@32, build_min@96,
build_max@100, mode_ceiling@104, expires_with@108`, 112 bytes. `shield_jit_fn` is **uBPF's
EXTENDED JIT signature**, `ubpf_jit_ex_fn` — `uint64_t (*)(void *mem, size_t mem_len, uint8_t *stack,
size_t stack_len)`, obtained from `ubpf_compile_ex(vm, &err, ExtendedJitMode)` — not the two-argument
basic form, whose prologue takes an unprobed 4 KiB stack frame, and not the one-argument shorthand the
explainer uses. The schema validates the example hook map that ships beside it.

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

**Not real — and this paragraph used to overstate it.** It said "there are no bodies in this repo,
and there is no TMM here to attach to." Both were true when written and neither is now: `ls_arm.c`,
`ls_tramp.c` and `ls_vm_load.c` are bodies, and they are compiled into a TMM that runs.

What genuinely remains a stub is narrower, and it is the part that matters for a security review:

- **`sig_verify` — built, and the perimeter is now narrower rather than closed.** Item 4 verifies
  an Ed25519 signature over the binding before admitting a program, on a live TMM. What remains
  open: the key is baked into the binary at build time with no revocation path, nothing records
  who armed what, and a build compiled with no key refuses everything (fail-closed, which is
  right, but means key handling is a build-time concern rather than an operational one).
- **`hook_map_lookup` — there is no hook map.** Item 5 is unbuilt; entry addresses are supplied by
  hand and move with every rebuild.
- The `shield_abi.h` entry points remain the *proposed product* ABI. The in-TMM sources above are a
  working implementation of the mechanism, not of that ABI, and the two have not been reconciled.

The skeletons that *use* the proposed ABI live in
`../development-scope-code.md` and are candidates for review, not
production code.

**Deliberately a subset:** the schema's `required` list is scoped to what the hand-written
[`hook-point-map.json`](hook-point-map.json) beside it already carries, so that instance stays valid. The
fields a real generator must start emitting — `entry_offset`, `patchable_pad_bytes`, `safe_return`
(which now requires its gate-1 `skippable` verdict, not just a return `kind`),
`budget_cycles`, `mode_ceiling`, `ctx_abi_version`, `generated_by`, `signature` — are marked
`"$comment": "required in product"`, and `make check` lists which ones an instance is missing.

## The two prefixes

[`example_hook_ctx.h`](example_hook_ctx.h) carries one example `ctx` — `struct ls_ctx`,
`ls_mode`, `ls_shared` — deliberately small and dull, and used only to give the offset check
something concrete to compile against. [`shield_abi.h`](shield_abi.h) is the
**product-side** ABI: it adds what that example has no analog for (the
signed binding, patchable-entry slots, per-core evidence, the loader message family). The two use
different prefixes on purpose — `ls_*` names the worked example's types, `shield_*` names the proposed
product ABI. Neither *header* is attached to anything, but the `ls_*` **sources** in this directory
are: they are compiled into TMM and they do execute a shield. The
naming-reconciliation table in
`../development-scope-code.md` maps between them, and between
both and the spellings already committed in the explainers.
