# Candidate code — what each development-scope item looks like

### Skeletons for the day-one work items, so "hundreds of lines, not subsystems" can be checked rather than taken on faith.

**Status:** Candidate code for review — **not TMM source**
**Companion:** [`development-scope.md`](development-scope.md) (the item list this follows, 1:1) ·
[`explainers/cve-shield-walkthrough.html`](explainers/cve-shield-walkthrough.html) (the canon; step
numbers below refer to its build steps 1–4 and CVE-day steps 5–13) ·
[`prototype/substrate/`](prototype/substrate/) (the two artifacts here that are real files) ·
[`engine-hard-problems.md`](engine-hard-problems.md) (why the flagged items are hard)
**Audience:** TMM core engineering — the people who would have to write this

---

## How to read this

Every section is one item from [`development-scope.md`](development-scope.md), in its order, with:

- an **identity line** — item number · name · walkthrough steps · where it runs · size class from
  that doc's §6 table;
- a **skeleton**, scaled to that size class (a "small" item stays small — padding it out would
  misrepresent the scope);
- a **Real / Stubbed / TODO(f5)** note, so the build-vs-reuse line is drawn in the code itself and
  not just asserted.

Three standing rules for everything below:

1. **The `ubpf_*`, `clang`, DWARF/BTF and crypto calls are real APIs.** Everything named `tmm_*`,
   `f5_*`, or marked `TODO(f5):` is a stub for work that does not exist in this repo.
2. **Nothing here is production TMM code**, and none of it can be: there is no TMM to attach to.
   These are candidates — the shape of the work, written down so it can be argued with.
3. **No skeleton claims more safety than the design does.** A verified program is memory-safe and
   terminating; its *cost* is bounded by the admission budget pass (item 8) and, for hot-path hooks,
   a runtime deadline (item 15). Termination is not a time bound.

Two of these artifacts are worth having as **real files** rather than blocks, because their value is
that they compile and validate — they live in [`prototype/substrate/`](prototype/substrate/) and are
*referenced* here rather than re-printed, so the two can't drift:

- [`prototype/substrate/shield_abi.h`](prototype/substrate/shield_abi.h) — `struct shield_msg`,
  `struct shield_binding`, `struct shield_sr_policy`, `struct hook_slot`, `shield_jit_fn`, the
  `SHIELD_ERR_*` codes, the mode/verdict/disposition enums. Compiles; its `_Static_assert`s pin the
  message's wire layout.
- [`prototype/substrate/hook_map.schema.json`](prototype/substrate/hook_map.schema.json) — the hook
  map item 5 emits and items 6–8 consume. The prototype's existing
  [`hook-point-map.json`](prototype/hook-point-map.json) validates against it.

```bash
make -C prototype/substrate check
```

## Naming reconciliation

These skeletons are the first place all twelve items share one namespace, so the spellings already
committed across the docs and the prototype have to be reconciled once, here. **Nothing committed
was rewritten to produce this table** — where a divergence exists, this is the resolution used
below, and the small doc tidies that would unify things are listed at the end for separate
approval.

| Concept | Already committed as | Used below |
|---|---|---|
| program result | `verdict` (walkthrough trampoline), `ret`/`r` (egress §5.3), `&ret` out-param (`ubpf_exec`) | **`verdict`** |
| modes | `MONITOR`/`ENFORCE` bare, `MODE_MONITOR` (in `trampoline_arm`), lowercase `monitor` (CLI/JSON), `LS_MONITOR` (prototype) | **`MODE_DISABLE`/`MODE_MONITOR`/`MODE_ENFORCE`**; lowercase stays CLI/JSON only |
| skip-the-body | `SAFE_RETURN` (block), `SAFE-RETURN` (substrate prose) | **`SAFE_RETURN`** = `TRAMP_SAFE_RETURN` |
| hook cost class | `path_class` (hook map, USDT catalog), `perf_class` (shield-object JSON) | **`path_class`** |
| bytecode load | `ubpf_load` (walkthrough: raw bytecode), `ubpf_load_elf` (prototype: ELF object) | **both** — different calls; item 3 uses `ubpf_load_elf` because the signed artifact is an ELF, and says so |
| JIT'd program | `jit_fn(&ctx)` (walkthrough, one arg) | **`slot->fn(ctx, ctx_len)`** — uBPF's real signature is `uint64_t (*)(void *mem, size_t mem_len)`; the canon block elides `mem_len` |
| loader ops | `LOAD · SET_MODE · STATUS · REVOKE` (bare) | **`SHIELD_OP_*`** — prefixed for C namespace hygiene; the bare names are the wire vocabulary |
| the shield program | `int shield(struct ctx *c)` (walkthrough), `SEC("filter/…") int ls_2026_22548(…)` (design §14), `uint64_t ls_decision(void *data)` (prototype, what actually verifies today) | **walkthrough form** as the product shape, with the prototype form given alongside — see the last section |

---

## Contents

**§1 In-TMM data-plane code** — [1 trampoline](#item-1--the-trampoline) ·
[2 arm/disarm](#item-2--armdisarm) · [3 safe-point loader handler](#item-3--the-safe-point-loader-handler) ·
[4 signature verification](#item-4--signature-verification-in-tmm)
**§2 Build-pipeline tooling** — [5 hook-map generator](#item-5--hook-map-generator) ·
[6 ctx descriptors for PREVAIL](#item-6--ctx-descriptor-emission-for-prevail) ·
[7 safe-return policy table](#item-7--safe-return-policy-table)
**§3 Control plane** — [8 budget pass](#item-8--budget-pass) ·
[9 signing integration](#item-9--signing-service-integration) ·
[10 loader daemon](#item-10--loader-daemon-side) ·
[11 operator front-end](#item-11--operator-front-end) · [12 audit trail](#item-12--audit-trail)
**§5 Per CVE** — [the shield program](#the-shield-program--the-only-per-cve-code)
**§4 Staged tiers 13–17** — [noted, not coded](#staged-tiers-1317--deliberately-not-coded)

---

# §1 · In-TMM data-plane code

Ships in the substrate build. Small, delicate, and the only code here that ever touches the hot
path.

## Item 1 · The trampoline

> **step 2** · runs in **TMM, at the hooked function's entry (when armed)** · written **once per CPU
> architecture** · **≈ a page**

The armed dispatch. One copy, generic across every hook — the per-hook variation lives in data (the
slot), never in code.

```c
/*
 * substrate/trampoline.c — the armed dispatch at a patchable function entry.
 *
 * Sketch: tramp_dispatch() below is reviewable C. The entry stub that calls it
 * is per-architecture assembly that can only exist in a TMM build.
 */
#include "shield_abi.h"

/* ---------------------------------------------------------------------------
 * What the per-arch entry stub must do — TODO(f5): tramp_x86_64.S, tramp_aarch64.S
 *
 * The nop pad at the function's entry has been overwritten (item 2) with a jump
 * to tramp_<arch>_entry, which:
 *
 *   1. saves the argument registers the ABI defines, plus anything the dispatch
 *      clobbers   (x86-64 SysV: rdi rsi rdx rcx r8 r9;  AAPCS64: x0–x7)
 *   2. forms the program's ctx over those saved registers, laid out per this
 *      hook's arg_btf in the signed hook map — the ctx IS the saved frame, so
 *      there is no copy on the hot path
 *   3. calls tramp_dispatch(slot, ctx, ctx_len)
 *   4. TRAMP_FALLTHROUGH  -> restore registers, execute the instructions the
 *                            pad displaced, jump to entry + pad_bytes
 *      TRAMP_SAFE_RETURN  -> load slot->sr's value into the ABI return register
 *                            and return to the CALLER: the body never runs
 *
 * ≈ a page per architecture, and the only assembly in the whole substrate.
 * ------------------------------------------------------------------------- */

/* TODO(f5): TMM already knows its own core index — use that, not a syscall. */
static inline unsigned this_core(void);

/*
 * Runs with the hooked function's arguments in hand and nothing else. No
 * allocation, no locks, no syscalls: this is inside someone else's prologue.
 */
int tramp_dispatch(struct hook_slot *slot, void *ctx, size_t ctx_len)
{
    /* Raced with a disarm, or armed-but-inert: cost is this branch. */
    if (!slot->armed || slot->mode == MODE_DISABLE)
        return TRAMP_FALLTHROUGH;

    /*
     * The verified program. JIT'd once at load (item 3) — never per invocation.
     * It cannot fault, loop forever, or reach memory outside ctx: that is what
     * PREVAIL proved before this bytecode was ever signed. What it may COST is
     * a separate question, settled at admission by item 8.
     */
    uint64_t verdict = slot->fn(ctx, ctx_len);

    if (verdict != MATCH)
        return TRAMP_FALLTHROUGH;

    /*
     * The record: this hook is firing. Counted in BOTH modes — in monitor that
     * is the whole point (item 3's STATUS read-back, item 12's audit trail).
     * TMM is core-pinned, so each core only ever touches its own slot: no
     * atomics, no lock. TODO(f5): pad fired[] to a cache line per core; as
     * declared in shield_abi.h the array invites false sharing under CMP.
     */
    slot->fired[this_core()]++;

    if (slot->mode != MODE_ENFORCE)
        return TRAMP_FALLTHROUGH;                /* MODE_MONITOR: watch only */

    /*
     * Enforce. The host — not the program — decides what this means, and its
     * only options here are the ones the signed safe-return policy allows.
     * A program cannot inject a value or invent a branch; it selected an
     * outcome, and this is the outcome being applied.
     */
    return TRAMP_SAFE_RETURN;
}
```

**Real:** the control flow, and the fact that `slot->fn` is uBPF's JIT'd entry point with uBPF's
actual two-argument signature.
**Stubbed:** `this_core()`.
**TODO(f5):** both `.S` entry stubs; cache-line padding for `fired[]`; the decision of which
registers each arch's stub must preserve for a *hooked* function (stricter than a normal call, since
the body still has to run after a fall-through).
**Cost when dark:** nothing — an unarmed entry is nop bytes the CPU falls straight through. **Cost
when armed and not matching:** the stub's register save/restore plus one predicate. That is the
number the budget pass gates on, and the number to measure first.
**TODO(f5) — burst form for hot hooks:** `tramp_dispatch()` above is one invocation per call, which
fits TMM's run-to-completion loop. Where a hot path processes a receive burst, the per-invocation
overhead wants amortizing over the batch — DPDK's `rte_bpf_exec_burst()` is the precedent, and the
budget pass (item 8) would then reason per burst rather than per packet. Honest limit: a burst form
amortizes the call, but each packet is still a separate invocation with its own `ctx` — the program
cannot reason across the batch (`engine-hard-problems.md` §5).

## Item 2 · Arm/disarm

> **step 2** · runs in **TMM, at the safe point** · written **once** · **small**

Overwrite the nop pad with a jump to the trampoline; restore the nops to detach. Same discipline
ftrace has used on live kernel text for years — the difference here is that the pads are in **our own
build at named symbols**, not guessed offsets in a foreign binary.

```c
/*
 * substrate/arm.c — patch a compiler-reserved entry pad, in a live process.
 *
 * Called only from the safe point between poll-loop iterations (item 3), so no
 * core is executing inside the target function's prologue while it is patched.
 */
#include "shield_abi.h"

/* TODO(f5): TMM's own barriers/IPI primitives — do not invent new ones here. */
extern void tmm_broadcast_isb(void);        /* i-cache sync across cores       */
extern int  tmm_text_make_writable(void *addr, size_t len, int rw);

/*
 * Encode "jump to trampoline" into the reserved pad. The pad size came from the
 * hook map (patchable_pad_bytes) and is checked, not assumed: too small and we
 * refuse rather than clobber the first real instruction.
 *
 * TODO(f5): per-arch encoder. x86-64: 5-byte rel32 JMP (E9 + disp32), so a
 * 5-byte pad minimum. aarch64: one 4-byte B with a ±128 MiB range — beyond that
 * the trampoline needs a veneer.
 */
static int encode_jump(void *pad, size_t pad_len, void *target);

int trampoline_arm(struct hook_slot *slot, shield_jit_fn fn, int mode)
{
    if (!slot || !fn)
        return SHIELD_ERR_HOOK;
    if (mode > slot->mode_ceiling)               /* binding says no (item 4) */
        return SHIELD_ERR_CEILING;

    /* Publish the payload BEFORE the hook can reach it: a core that executes
     * the new jump must find a complete slot. */
    slot->fn   = fn;
    slot->mode = (uint8_t)mode;

    if (tmm_text_make_writable(slot->entry, SHIELD_PAD_MAX, 1) != 0)
        return SHIELD_ERR_HOOK;

    int rc = encode_jump(slot->entry, slot->pad_len, (void *)tramp_entry_for(slot));

    tmm_text_make_writable(slot->entry, SHIELD_PAD_MAX, 0);

    if (rc != 0) {
        slot->fn = NULL;                        /* leave it DARK — never half-armed */
        return SHIELD_ERR_HOOK;
    }

    tmm_broadcast_isb();                        /* every core sees the new text */
    slot->armed = 1;
    return SHIELD_OK;
}

int trampoline_disarm(struct hook_slot *slot)
{
    if (!slot || !slot->armed)
        return SHIELD_OK;                       /* idempotent: REVOKE is a kill switch */

    slot->armed = 0;                            /* stop new dispatches first */

    if (tmm_text_make_writable(slot->entry, SHIELD_PAD_MAX, 1) != 0)
        return SHIELD_ERR_HOOK;
    restore_nops(slot->entry, slot->pad_len);   /* TODO(f5): per-arch nop fill */
    tmm_text_make_writable(slot->entry, SHIELD_PAD_MAX, 0);

    tmm_broadcast_isb();
    slot->fn = NULL;
    /* fired[] is deliberately NOT cleared: the evidence outlives the shield. */
    return SHIELD_OK;
}
```

**Real:** the ordering discipline (publish payload → patch → sync → mark armed; and its exact
reverse), and the fail-dark rule.
**Stubbed:** `tmm_broadcast_isb`, `tmm_text_make_writable`, `tramp_entry_for`, `restore_nops`.
**TODO(f5):** the per-arch encoders, and calibrating `SHIELD_PAD_MAX` — it is declared in
`shield_abi.h` with a placeholder, and the per-hook truth is `patchable_pad_bytes` in the signed hook
map. Whether W^X can be relaxed
per-page in TMM's memory manager at all is a **TMA question**, not an implementation detail —
`engine-hard-problems.md` §5 carries it.
**The honest hard part:** this is the item where "proven in kernels" stops being an argument and
becomes work. The safe point makes it far easier than ftrace's general case (no core is mid-prologue),
but it is still live text in the crown-jewel process.

## Item 3 · The safe-point loader handler

> **steps 4, 10, 13** · runs in **TMM, at the safe point** · written **once** · **hundreds of lines**

The biggest in-TMM item, and the one whose unglamorous half is the actual work: not the happy path,
but every error path leaving the hook dark, plus expiry, teardown, and per-shield state.

```c
/*
 * substrate/loader.c — handle one shield_msg, between poll-loop iterations.
 *
 * Sketch over uBPF's real API. Extends the prototype's ls_ubpf_init()
 * (prototype/minimm/minimm.c:156) with everything the prototype has no analog
 * for: signature, binding, hook map, arming, expiry, teardown.
 */
#include "shield_abi.h"
#include "ubpf.h"                                /* the real library           */

extern const void *f5_pubkey;                     /* baked in at build (step 3) */
extern uint32_t    tmm_build_id(void);
extern void        audit_emit(const struct shield_msg *m, int rc); /* item 12   */

struct shield_state {                             /* one per loaded shield      */
    char             hook[SHIELD_HOOK_NAME_MAX];
    struct ubpf_vm  *vm;
    shield_jit_fn    fn;
    struct hook_slot *slot;
    uint32_t         expires_with;
    uint8_t          mode_ceiling;
};
static struct shield_state g_shields[SHIELD_MAX_SHIELDS];

static void shield_teardown(struct shield_state *s)
{
    if (s->slot) trampoline_disarm(s->slot);      /* dark first, always        */
    if (s->vm)   ubpf_destroy(s->vm);             /* frees the JIT'd page too  */
    *s = (struct shield_state){0};
}

static int do_load(const struct shield_msg *msg)
{
    char *err = NULL;
    struct shield_state *s = shield_slot_alloc(msg->hook);
    if (!s) return SHIELD_ERR_NOMEM;

    /* 1. The perimeter, before anything else touches the bytes (item 4). */
    if (!sig_verify(msg, f5_pubkey))       { shield_teardown(s); return SHIELD_ERR_SIG; }

    /* 2. The binding pins this program to THIS build and THIS hook. A signed
     *    shield replayed elsewhere dies here, not at the hook. */
    const struct shield_binding *b = shield_binding_of(msg);
    uint32_t build = tmm_build_id();
    if (build < b->build_min || build > b->build_max)
                                           { shield_teardown(s); return SHIELD_ERR_BUILD; }
    if (build >= b->expires_with)          { shield_teardown(s); return SHIELD_ERR_EXPIRED; }
    if (msg->mode > b->mode_ceiling)       { shield_teardown(s); return SHIELD_ERR_CEILING; }

    /* 3. Resolve the target in this build's signed hook map (item 5). */
    s->slot = hook_map_lookup(msg->hook);
    if (!s->slot)                          { shield_teardown(s); return SHIELD_ERR_HOOK; }

    /* 4. Instantiate. Base tier: no helpers are registered, so there is no
     *    helper ABI to secure and PREVAIL ran stock (engine-hard-problems §2). */
    s->vm = ubpf_create();
    if (!s->vm)                            { shield_teardown(s); return SHIELD_ERR_NOMEM; }

    /* The signed artifact is an ELF object, so this is ubpf_load_elf() — the
     * walkthrough's ubpf_load() is the raw-bytecode variant of the same step. */
    if (ubpf_load_elf(s->vm, msg->prog, msg->prog_len, &err) < 0)
                                           { shield_teardown(s); return SHIELD_ERR_LOAD; }

    /* 5. JIT once, here, at load — never per invocation. */
    s->fn = (shield_jit_fn)ubpf_compile(s->vm, &err);
    if (!s->fn)                            { shield_teardown(s); return SHIELD_ERR_JIT; }

    /* 6. Arm. LOAD always arms in monitor; promotion is a separate, separately
     *    authorized SET_MODE (step 11), never implied by a load. */
    if (trampoline_arm(s->slot, s->fn, MODE_MONITOR) != SHIELD_OK)
                                           { shield_teardown(s); return SHIELD_ERR_HOOK; }

    s->expires_with = b->expires_with;
    s->mode_ceiling = b->mode_ceiling;
    return SHIELD_OK;
}

/* Entry point. One message, one verdict, and on ANY failure the hook is dark:
 * there is no partially-armed state to reason about. */
int shield_msg_handle(const struct shield_msg *msg)
{
    int rc;
    switch (msg->op) {
    case SHIELD_OP_LOAD:     rc = do_load(msg);                    break;
    case SHIELD_OP_SET_MODE: rc = do_set_mode(msg);                break;
    case SHIELD_OP_STATUS:   rc = do_status(msg);                  break;
    case SHIELD_OP_REVOKE:   rc = do_revoke(msg);                  break;   /* kill switch */
    default:                 rc = SHIELD_ERR_SIG;                  break;
    }
    audit_emit(msg, rc);                          /* every op, success or not  */
    return rc;
}

/*
 * Auto-retirement (step 13). Called once per build transition — an installed
 * shield does not outlive the fix it was standing in for.
 * TODO(f5): hook this into TMOS's upgrade/ISSU path.
 */
void shield_expire_all(uint32_t new_build)
{
    for (unsigned i = 0; i < SHIELD_MAX_SHIELDS; i++)
        if (g_shields[i].vm && new_build >= g_shields[i].expires_with)
            shield_teardown(&g_shields[i]);
}
```

**Real:** `ubpf_create`, `ubpf_load_elf`, `ubpf_compile`, `ubpf_destroy` — and the JIT-once-at-load
property, which is the load-bearing performance claim.
**Stubbed:** `sig_verify` (item 4), `hook_map_lookup` (item 5), `shield_binding_of`,
`shield_slot_alloc`, `tmm_build_id`, `audit_emit` (item 12), `do_set_mode`/`do_status`/`do_revoke`
(shown by name; each is a dozen lines over `g_shields`).
**TODO(f5):** the ISSU/upgrade hook for expiry; `SHIELD_MAX_SHIELDS`; and the real message plumbing
(item 10) that gets a `shield_msg` here on every core.
**Why this is "hundreds of lines":** the eleven error returns above are the item. The prototype's
equivalent is ~25 lines because it has no signature, no binding, no map, and no arming to get wrong.

## Item 4 · Signature verification in TMM

> **steps 3, 10** · runs in **TMM, at load** · written **once (or reused)** · **small**

The perimeter. Not a safety check — PREVAIL already did that, at F5, before signing — but the reason
attacker-controlled bytes never reach the JIT at all.

```c
/*
 * substrate/sigverify.c — check the signature over the BINDING, not just bytes.
 *
 * Sketch. TMM carries only the public half; the private key never leaves F5's
 * HSM-backed release-signing infrastructure (item 9).
 */
#include "shield_abi.h"

/* TODO(f5): reuse TMOS's existing signed-artifact verification rather than
 * introducing a second crypto path. FIPS boundary applies. */
extern int  f5_verify_detached(const uint8_t *msg, size_t len,
                               const uint8_t *sig, size_t siglen,
                               const void *pubkey);
extern void f5_sha256(const uint8_t *in, size_t len, uint8_t out[32]);

/*
 * The canonical serialization that gets signed: the binding's fields in a fixed
 * order, then the program hash. Byte-identical to item 9's signer — if these two
 * ever disagree, every load fails closed, which is the correct direction to fail.
 */
static size_t binding_serialize(const struct shield_binding *b,
                                uint8_t *out, size_t cap);

int sig_verify(const struct shield_msg *msg, const void *pubkey)
{
    if (!msg || !pubkey) return 0;

    const struct shield_binding *b = shield_binding_of(msg);

    /* 1. The program must be the program that was verified and signed. */
    uint8_t h[SHIELD_SHA256_LEN];
    f5_sha256(msg->prog, msg->prog_len, h);
    if (!ct_equal(h, b->prog_sha256, sizeof h))
        return 0;

    /* 2. The binding must be internally consistent with the message: a signed
     *    shield cannot be re-pointed at another hook by editing the header. */
    if (strncmp(b->hook, msg->hook, SHIELD_HOOK_NAME_MAX) != 0)
        return 0;
    if (b->expires_with != msg->expires_with)
        return 0;

    /* 3. And the signature must cover all of it. */
    uint8_t buf[SHIELD_BINDING_WIRE_MAX];
    size_t  n = binding_serialize(b, buf, sizeof buf);
    if (n == 0)
        return 0;

    return f5_verify_detached(buf, n, msg->sig, SHIELD_SIG_MAX, pubkey) == 0;
}
```

**Real:** the check order — hash the program, cross-check the binding against the message, *then*
verify the signature over the canonical form. Constant-time comparison for the digest.
**Stubbed:** `f5_verify_detached`, `f5_sha256`, `ct_equal`, `binding_serialize`,
`shield_binding_of`.
**TODO(f5):** decide reuse-vs-new for the crypto path (strong preference: reuse); pin the algorithm
and `SHIELD_SIG_MAX` accordingly — `shield_abi.h` currently sizes it for Ed25519 and says so;
FIPS/Common-Criteria implications are in `engine-hard-problems.md` §5.
**Small, but load-bearing:** this function is the entire reason a verifier-soundness bug is a
supply-chain risk rather than a traffic-borne one.

---

# §2 · Build-pipeline tooling

Runs at F5, once per TMOS build. Written once; the *outputs* regenerate every build, which is what
makes them maintenance-free rather than a growing pile of hand-maintained metadata.

## Item 5 · Hook-map generator

> **step 3** · runs in the **build pipeline** · written **once** · **tool**

Debug info in, signed hook map out. The schema it must satisfy is a real file:
[`prototype/substrate/hook_map.schema.json`](prototype/substrate/hook_map.schema.json).

```python
#!/usr/bin/env python3
"""
hookmap_gen.py — emit this build's signed hook map from its debug info.

Sketch. pyelftools and DWARF are real; every f5_* call is a stub.
Output validates against prototype/substrate/hook_map.schema.json.
"""
import json, subprocess, sys
from elftools.elf.elffile import ELFFile          # real: pyelftools

CTX_ABI_VERSION = 1     # bump whenever ANY hook's arg_btf changes shape

SCALAR = {  # DWARF base type -> the schema's scalar vocabulary
    ("unsigned char", 1): "u8",  ("short unsigned int", 2): "u16",
    ("unsigned int", 4): "u32",  ("long unsigned int", 8): "u64",
    ("signed char", 1): "i8",    ("short int", 2): "i16",
    ("int", 4): "i32",           ("long int", 8): "i64",
    ("_Bool", 1): "bool",
}

def hookable(die):
    """A candidate boundary: a named subprogram with a definition in this build."""
    return (die.tag == "DW_TAG_subprogram"
            and "DW_AT_name" in die.attributes
            and "DW_AT_low_pc" in die.attributes)

def arg_btf(die, cu):
    """Type each argument the trampoline can hand to a program as ctx.

    The rule that keeps PREVAIL stock: only fixed-width scalars and small fixed
    byte arrays cross the boundary. A pointer argument is walked ONE level to the
    struct it names and that struct's scalar fields are exposed; anything else
    (unions, nested pointers, variable arrays) is omitted, and the hook is marked
    observe-only rather than silently exposing something unprovable.
    """
    args, ok = {}, True
    for i, p in enumerate(d for d in die.iter_children()
                          if d.tag == "DW_TAG_formal_parameter"):
        decl, fields, clean = resolve_type(p, cu)      # TODO(f5)
        if not clean:
            ok = False
        if fields:
            args["arg%d" % i] = {"type": decl, "fields": fields}
    return args, ok

def emit(elf_path, build_id, tmos_version, allowlist):
    hooks = []
    with open(elf_path, "rb") as f:
        dwarf = ELFFile(f).get_dwarf_info()
        for cu in dwarf.iter_CUs():
            for die in cu.iter_DIEs():
                if not hookable(die):
                    continue
                name = die.attributes["DW_AT_name"].value.decode()
                if name not in allowlist:      # curated, not "every symbol"
                    continue
                fields, clean = arg_btf(die, cu)
                hooks.append({
                    "name": name,
                    "symbol": name,
                    "attach_mode": "filter" if clean else "observe",
                    "path_class": allowlist[name]["path_class"],
                    "enumerated_outcomes": allowlist[name]["outcomes"],
                    "arg_btf": fields,
                    # product fields the prototype map does not carry yet:
                    "entry_offset": 0,                        # pad sits at +0
                    "patchable_pad_bytes": pad_bytes(elf_path, name),   # TODO(f5)
                    "budget_cycles": allowlist[name]["budget_cycles"],
                    "mode_ceiling": allowlist[name]["mode_ceiling"],
                    "safe_return": safe_return_for(die, cu),  # item 7
                })

    doc = {"tmos_version": tmos_version, "build_id": build_id,
           "ctx_abi_version": CTX_ABI_VERSION,
           "generated_by": "hookmap_gen.py 0.1",
           "hook_points": sorted(hooks, key=lambda h: h["name"])}

    blob = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    doc["signature"] = f5_sign_detached(blob)      # TODO(f5): item 9's service
    return doc

if __name__ == "__main__":
    json.dump(emit(*sys.argv[1:]), sys.stdout, indent=2)
```

**Real:** pyelftools, DWARF traversal, and the canonical-JSON-then-sign pattern.
**Stubbed:** `resolve_type`, `pad_bytes`, `safe_return_for`, `f5_sign_detached`.
**TODO(f5):** the allowlist's source of truth (a per-subsystem annotation in the build, not a file
maintained by hand off to the side); reading the actual pad size the compiler reserved; deciding
whether to key on DWARF or BTF if TMM's build produces both.
**The design decision hiding in here:** `attach_mode` is derived, not declared — a hook whose
arguments cannot be fully typed becomes **observe-only automatically**. That is the mechanism that
keeps "we couldn't prove this one" from silently becoming an enforce-capable surface.

## Item 6 · ctx-descriptor emission for PREVAIL

> **steps 3, 7** · runs in the **build pipeline** · written **once + ongoing discipline** · **tool +
> process**

Turn each hook's typed argument layout into the program-type descriptor stock PREVAIL verifies
against. Mechanically small. **This is `engine-hard-problems.md` §2 — the ctx/helper/program-type ABI
is the real 90% of the work**, and the reason is in the note below the code, not the code.

```python
#!/usr/bin/env python3
"""
ctxdesc_gen.py — hook map -> one PREVAIL program-type descriptor per hook.

The verifier task is "write the program-type descriptor", NOT "modify the
verifier" — so PREVAIL stays stock and unforked in the trust path.
"""
import json

SIZEOF = {"u8": 1, "i8": 1, "bool": 1, "u16": 2, "i16": 2,
          "u32": 4, "i32": 4, "u64": 8, "i64": 8}

def layout(fields):
    """Offsets a program may load from, with natural alignment and NO padding
    exposed. PREVAIL proves accesses land inside a declared region; anything not
    listed here is simply not addressable by a verified program."""
    off, out = 0, []
    for name, ty in fields.items():
        base, count = (ty[:-1].split("[") + ["1"])[:2] if "[" in ty else (ty, "1")
        size, n = SIZEOF[base], int(count)
        off += (-off) % size                       # align
        out.append({"name": name, "offset": off, "size": size * n,
                    "type": base, "count": n})
        off += size * n
    return out, off

def descriptor(hook, ctx_abi_version):
    regions, total = layout(hook["arg_btf"]["arg0"]["fields"])
    return {
        "name": hook["name"],
        "ctx_abi_version": ctx_abi_version,
        # The single memory region a base-tier program may touch: its ctx.
        "context_descriptor": {"size": total, "readable": regions,
                              "writable": []},          # read-only, always
        "helper_prototypes": [],   # base tier: NONE. This is what keeps it stock.
        "expected_return": {"type": "u64", "meaning": "0 = no match, 1 = MATCH"},
    }

def main(map_path, out_path):
    m = json.load(open(map_path))
    descs = [descriptor(h, m["ctx_abi_version"])
             for h in m["hook_points"] if "arg0" in h.get("arg_btf", {})]
    json.dump({"build_id": m["build_id"], "descriptors": descs},
              open(out_path, "w"), indent=2)
    # Admission (step 7) then runs, per program:
    #   prevail -q --section .text --program-type <name> shield.bpf.o
    # exactly as the prototype's ls_verify() invokes it today, fail-closed.
```

**Real:** PREVAIL's stock invocation and the fact that a descriptor — not a verifier patch — is what
teaches it a new program type. The prototype already runs this gate
([`prototype/minimm/minimm.c:137`](prototype/minimm/minimm.c)).
**Stubbed:** the descriptor's exact serialization (PREVAIL's own program-type registration format;
this shows the *content*, not its file syntax).
**TODO(f5):** wire `--program-type` per hook into the admission pipeline; decide how a descriptor
change forces a `ctx_abi_version` bump and what that does to already-signed shields (answer: their
binding's build range stops matching, so they stop loading — by design).
**Why this item is the real 90% and this file is only 40 lines:** the *code* is a layout walk. The
*work* is deciding, per hook, which fields belong in the ctx at all — too few and no useful shield can
be written, too many and the surface is over-exposed and versioning it becomes a permanent tax. Every
field added here is a contract F5 carries for as long as the hook exists. That judgement is not
automatable, and it is the substrate's largest ongoing engineering surface.

## Item 7 · Safe-return policy table

> **steps 3, 12** · runs in the **build pipeline** · written **once + annotations** · **tool +
> process**

What a skipped body hands back. The tool triages by return type; a human decides whether skipping is
*semantically* safe, and only the trivial cases are enforce-capable in a v1.

```python
#!/usr/bin/env python3
"""
safe_return.py — classify each hookable function's return, for the hook map.

Mirrors enum shield_sr_kind in prototype/substrate/shield_abi.h:
    none  = not enforce-capable (observe only)   void = nothing to synthesize
    zero  = 0/NULL is the benign no-op           const = an enumerated benign value
"""
TRIVIAL_VOID = {"void"}
ZERO_OK = {"int", "long", "unsigned int", "_Bool"}      # 0 = "did nothing, fine"

def classify(fn):
    """Automatic part: what CAN be returned. Conservative by construction."""
    rt = fn["return_type"]

    if rt in TRIVIAL_VOID:
        return {"kind": "void"}

    # A function whose caller checks for NULL already has a "nothing here" path.
    if fn["returns_pointer"] and fn["caller_null_checked"]:
        return {"kind": "zero"}

    # A status-code return where 0 means success is the classic trap: skipping
    # the body and reporting success is a LIE to the caller. Refuse it.
    if rt in ZERO_OK and not fn["zero_means_success"]:
        return {"kind": "zero"}

    if fn.get("annotated_benign_value") is not None:     # human, reviewed
        return {"kind": "const", "value": fn["annotated_benign_value"],
                "rationale": fn["annotation_rationale"]}

    return {"kind": "none"}          # default: observe-only. Fail closed.

def v1_gate(policy, path_class):
    """A sane first release: only arm enforce where the skip is unambiguous."""
    if policy["kind"] not in ("void", "zero"):
        return "observe"
    if path_class == "hot":          # hot-path enforce waits for item 15
        return "monitor"
    return "enforce"
```

**Real:** the classification logic and — more importantly — the two refusals: a status-code return
where zero means success is **not** safe-returnable, and anything unannotated defaults to
observe-only.
**Stubbed:** the `fn` dict's provenance (`returns_pointer`, `caller_null_checked`,
`zero_means_success` come from DWARF plus call-site analysis).
**TODO(f5):** the annotation mechanism for `const` cases — a source attribute next to the function is
right, a spreadsheet is not; and the call-site analysis for `caller_null_checked`, which is the only
genuinely non-trivial static analysis in this whole item list.
**The honest boundary:** this table is where "skip the body" stops being free. Skipping *this*
function loses its benign work — for the worked CVE, one log record. The `rationale` field exists so
that loss is written down per function, reviewed, and visible to whoever flips enforce.

---

# §3 · Control plane and F5 infrastructure

Conventional engineering — no novel machinery, and none of it on the data path.

## Item 8 · Budget pass

> **step 8** · runs at **admission, at F5** · written **once** · **tool**

Longest-path instruction count over the verified bytecode → a cycle estimate → compare against the
hook's budget → **fail closed**. A build artifact, off the data path. This is the layer that answers
"termination is not a time bound."

```python
#!/usr/bin/env python3
"""
budget_pass.py — admission-time cost gate for one verified program.

Runs AFTER PREVAIL (so loops are already proven bounded) and BEFORE signing, so
the signature attests that this gate ran. Off the data path entirely.
"""
import struct, sys

CYCLES = {          # TODO(f5): calibrate per target uarch, then keep honest.
    "alu": 1, "jmp": 2, "load": 4, "store": 4, "call": 6, "exit": 1,
}
INSN_SZ = 8

def decode(blob):
    """eBPF is fixed 8-byte instructions — a real decoder, not a sketch."""
    out = []
    for off in range(0, len(blob), INSN_SZ):
        op, regs, imm_off, imm = struct.unpack_from("<BBhi", blob, off)
        out.append({"pc": off // INSN_SZ, "op": op, "off": imm_off, "imm": imm})
    return out

def build_cfg(insns):
    """Basic blocks + edges. Back-edges are loops; PREVAIL has already proven
    each one has a bounded trip count, and we need that bound."""
    leaders = {0}
    for i in insns:
        if cls(i["op"]) == "jmp":
            leaders.add(i["pc"] + 1 + i["off"])       # branch target
            leaders.add(i["pc"] + 1)                  # fall-through
    # ... block construction elided ...
    return blocks, edges

def longest_path(blocks, edges, loop_bounds):
    """DAG longest path after collapsing each proven-bounded loop into
    (body_cost * max_trips). No bound => refuse: an unbounded estimate is not an
    estimate."""
    for head, bound in loop_bounds.items():
        if bound is None:
            raise Unbounded(head)
    order = topo(collapse_loops(blocks, edges, loop_bounds))
    best = {b: 0 for b in order}
    for b in order:
        best[b] = block_cost(b) + max((best[p] for p in preds(b)), default=0)
    return max(best.values())

def gate(prog_path, hook, hook_map):
    insns = decode(open(prog_path, "rb").read())
    blocks, edges = build_cfg(insns)
    try:
        cycles = longest_path(blocks, edges, prevail_loop_bounds(prog_path))
    except Unbounded as e:
        return fail("no proven trip count for the loop at pc=%d" % e.pc)

    budget = hook_map[hook]["budget_cycles"]
    if cycles > budget:
        return fail("worst case %d cycles exceeds %s's budget of %d"
                    % (cycles, hook, budget))
    return ok(cycles, budget)

# Worked example from engine-hard-problems (a bounded 64-iteration scan):
#   8 + 10*64 + 4 = 652 instructions  ~= 800 cycles
# — comfortably inside a cold hook's budget, nowhere near a hot one's.
```

**Real:** eBPF's fixed 8-byte encoding (the decoder is genuine), and the CFG-longest-path approach.
**Stubbed:** `cls`, `topo`, `collapse_loops`, `block_cost`, `prevail_loop_bounds`, `ok`/`fail`.
**TODO(f5):** per-microarchitecture cycle calibration — and publishing the calibration, because an
uncalibrated table makes this gate theatre; extracting loop trip counts from PREVAIL's own invariants
rather than re-deriving them.
**What it does and does not buy:** it bounds the *estimated* worst case at admission. It is an
estimate, not a measurement, and it says nothing about cache misses or a hostile memory state — which
is exactly why `engine-hard-problems.md` §1 keeps a runtime deadline (item 15) as the second layer
before any hot-path hook is armed.

## Item 9 · Signing-service integration

> **step 9** · runs in **F5 infrastructure** · written **once** · **integration**

New manifest, existing infrastructure. The signature is what attests that verification and the budget
pass actually ran — so signing must be the *last* gate, and unconditional on the earlier ones.

```python
#!/usr/bin/env python3
"""
sign_shield.py — sign the BINDING, not just the bytecode.

The private key never leaves F5's HSM; TMM carries only the public half, baked
in at build time. binding_serialize() here must stay byte-identical to the
in-TMM verifier's (item 4) — the two are one wire format with two readers.
"""
import hashlib, struct

HOOK_MAX, SIG_MAX = 64, 64

def binding_serialize(prog_sha256, hook, build_min, build_max,
                      mode_ceiling, expires_with):
    """Canonical, fixed-order, fixed-width. No JSON, no ambiguity: the bytes a
    signature covers must have exactly one representation."""
    return (prog_sha256                                    # 32
            + hook.encode().ljust(HOOK_MAX, b"\0")         # 64, NUL-padded
            + struct.pack("<IIBI", build_min, build_max,
                          mode_ceiling, expires_with))     # 13

def sign(prog_path, hook, build_range, mode_ceiling, expires_with,
         verify_report, budget_report):
    prog = open(prog_path, "rb").read()

    # Refuse to sign anything whose admission evidence is missing or negative.
    # This is the whole point of signing last: the signature IS the attestation.
    require(verify_report["verifier"] == "PREVAIL", "no verifier report")
    require(verify_report["result"] == "pass",      "program did not verify")
    require(verify_report["prog_sha256"] == hashlib.sha256(prog).hexdigest(),
            "verify report is for different bytes")
    require(budget_report["result"] == "pass",      "budget pass failed")
    require(budget_report["hook"] == hook,          "budget was measured elsewhere")

    # A shield that may enforce needs a second human. Monitor-only does not.
    if mode_ceiling >= MODE_ENFORCE:
        require(has_two_person_approval(verify_report["ticket"]),
                "enforce-capable shield needs two-person approval")

    binding = binding_serialize(hashlib.sha256(prog).digest(), hook,
                                *build_range, mode_ceiling, expires_with)

    sig = hsm_sign(binding)          # TODO(f5): PKCS#11 to the release HSM
    assert len(sig) <= SIG_MAX
    audit("signed", hook=hook, sha=hashlib.sha256(prog).hexdigest(),
          builds=build_range, ceiling=mode_ceiling, expires=expires_with)
    return binding, sig
```

**Real:** the canonical fixed-width serialization, SHA-256, and the ordering rule (verify → budget →
sign).
**Stubbed:** `hsm_sign`, `require`, `has_two_person_approval`, `audit`.
**TODO(f5):** PKCS#11 wiring to the existing release-signing HSM; where the verify/budget reports
live and how they are bound to a ticket; key rotation and how TMM learns a new public key (a build,
by construction).
**Cross-check that matters:** `binding_serialize` appears twice in this document on purpose — here and
in item 4. If they ever diverge, every shield fails to load. That is the correct failure direction,
but it argues for generating both from one definition.

## Item 10 · Loader daemon side

> **steps 4, 10** · runs in the **control plane** · written **once** · **conventional**

Fills the message, pushes it down the channel TMM already uses for runtime config, fans out to every
instance, collects the counters back. The transport is reused — that is why this is "conventional."

```c
/*
 * shieldd.c — control-plane side of the loader.
 *
 * Sketch. The transport is TMM's EXISTING config channel (the path profiles and
 * iRules already ride); nothing here invents a new way into the data plane.
 */
#include "shield_abi.h"

extern int tmm_instance_count(void);
extern int tmm_config_send(int inst, const void *msg, size_t len,
                           void *reply, size_t reply_cap);   /* TODO(f5): reuse */

/* Build one message. The struct IS the contract — see shield_abi.h. */
static struct shield_msg *msg_new(uint32_t op, const char *hook, uint8_t mode,
                                  uint32_t expires_with,
                                  const uint8_t *prog, uint32_t prog_len,
                                  const uint8_t *sig, size_t *out_len)
{
    size_t len = sizeof(struct shield_msg) + prog_len;
    struct shield_msg *m = calloc(1, len);
    if (!m) return NULL;
    m->op           = op;
    m->mode         = mode;
    m->expires_with = expires_with;
    m->prog_len     = prog_len;
    snprintf(m->hook, sizeof m->hook, "%s", hook);
    if (sig)  memcpy(m->sig, sig, SHIELD_SIG_MAX);
    if (prog) memcpy(m->prog, prog, prog_len);
    *out_len = len;
    return m;
}

/*
 * Fan out to every TMM instance. Each picks the message up at its own safe point
 * between poll-loop iterations — this call does not interrupt anything.
 *
 * All-or-nothing is deliberate: a shield armed on three cores out of four is a
 * worse outcome than one armed nowhere, so a partial failure revokes the rest.
 */
static int fanout(struct shield_msg *m, size_t len, struct shield_reply *replies)
{
    int n = tmm_instance_count(), failed = -1;

    for (int i = 0; i < n; i++) {
        int rc = tmm_config_send(i, m, len, &replies[i], sizeof replies[i]);
        if (rc != SHIELD_OK || replies[i].rc != SHIELD_OK) { failed = i; break; }
    }

    if (failed >= 0) {
        struct shield_msg *rv = msg_new(SHIELD_OP_REVOKE, m->hook, 0, 0,
                                        NULL, 0, NULL, &len);
        for (int i = 0; i < failed; i++)                  /* unwind the armed */
            tmm_config_send(i, rv, len, NULL, 0);
        free(rv);
        log_err("shield %s: instance %d rejected (%s); revoked all",
                m->hook, failed, shield_strerror(replies[failed].rc));
        return replies[failed].rc;
    }
    return SHIELD_OK;
}

/* STATUS: sum the per-core evidence back into one view for the operator. */
int shieldd_status(const char *hook, struct shield_status *out)
{
    size_t len;
    struct shield_msg *m = msg_new(SHIELD_OP_STATUS, hook, 0, 0, NULL, 0, NULL, &len);
    struct shield_reply replies[SHIELD_MAX_CORES];
    int n = tmm_instance_count();

    for (int i = 0; i < n; i++)
        tmm_config_send(i, m, len, &replies[i], sizeof replies[i]);
    free(m);

    out->cores = n;
    out->total = 0;
    for (int i = 0; i < n; i++) {
        out->fired[i] = replies[i].fired;
        out->total   += replies[i].fired;
        out->mode     = replies[i].mode;         /* uniform, or flag a mismatch */
    }
    return SHIELD_OK;
}
```

**Real:** the message construction against the actual `struct shield_msg`, and the all-or-nothing
fan-out with unwind.
**Stubbed:** `tmm_instance_count`, `tmm_config_send`, `struct shield_reply`/`shield_status`,
`log_err`, `shield_strerror`.
**TODO(f5):** identify the existing config-channel API and use it rather than adding one; decide
whether a mode mismatch across instances is an error or just a warning (it should be an error).
**Why all-or-nothing:** partial arming means the crash still happens on the un-armed cores while the
counters say the shield is working — the worst possible combination.

## Item 11 · Operator front-end

> **steps 10, 11, 12** · runs in the **control plane** · written **once** · **thin**

Not a new tool. A `tmsh` subcommand and its iControl REST equivalent, on the management surface
operators already use. `shieldctl` in the walkthrough is illustrative naming for exactly this.

```
tmsh grammar (proposed)
───────────────────────
  load   sys shield <name> \
             prog <path.o> sig <path.sig> \
             hook <symbol> mode { monitor | enforce } expires-with <build>
  modify sys shield <name> mode { disable | monitor | enforce }
  show   sys shield [ <name> ]
  delete sys shield <name>                      # = REVOKE, the kill switch

iControl REST
─────────────
  POST   /mgmt/tm/sys/shield            {name, prog, sig, hook, mode, expiresWith}
  PATCH  /mgmt/tm/sys/shield/<name>     {mode}
  GET    /mgmt/tm/sys/shield[/<name>]
  DELETE /mgmt/tm/sys/shield/<name>
```

```python
#!/usr/bin/env python3
"""
The command handlers behind that grammar. Thin by design: validate, hand to
shieldd (item 10), format what comes back. No policy lives here.
"""
def cmd_load(args):
    # Refuse enforce-on-arrival at the CLI. Monitor first is not a suggestion:
    # promotion is a separate, separately authorized command (step 11).
    if args.mode == "enforce":
        die("load starts in monitor; use `modify sys shield ... mode enforce` "
            "once you have confirmed what it catches")

    prog, sig = read(args.prog), read(args.sig)
    require_authz("shield-load")                      # TODO(f5): TMOS RBAC role

    rc = shieldd.load(hook=args.hook, prog=prog, sig=sig,
                      mode=MODE_MONITOR, expires_with=encode_build(args.expires_with))
    if rc != SHIELD_OK:
        die(shield_strerror(rc))                      # fail-dark: nothing armed
    print("loaded %s at %s in monitor; expires with %s"
          % (args.name, args.hook, args.expires_with))

def cmd_modify_mode(args):
    if args.mode == "enforce":
        require_authz("shield-enforce")   # STRICTER tier than shield-load
        st = shieldd.status(args.name)
        if st.total == 0:
            warn("this shield has never fired in monitor — confirm the predicate "
                 "matches the crash-bound flows before enforcing")
    rc = shieldd.set_mode(args.name, MODE[args.mode])
    die_unless_ok(rc)

def cmd_show(args):
    """The status read-back. Format mirrors the walkthrough's example exactly."""
    for s in shieldd.list(args.name):
        print("hook %s   mode %s   expires-with %s"
              % (s.hook, MODE_NAME[s.mode].upper(), decode_build(s.expires_with)))
        print(" · ".join("core%d fired %d" % (i, n) for i, n in enumerate(s.fired)))
        if s.total == 0 and s.mode == MODE_ENFORCE:
            print("      (never fired — either nothing is hitting the "
                  "precondition, or the predicate is wrong)")
```

**Real:** the grammar shape and the two-tier authorization split (loading is not enforcing).
**Stubbed:** `shieldd.*`, `require_authz`, `encode_build`/`decode_build`, output plumbing.
**TODO(f5):** the actual `tmsh` command-definition mechanism and RBAC role names; whether `sys` is
the right namespace or this belongs under `security`.
**Two deliberate frictions:** `load` refuses `mode enforce` outright, and promoting to enforce on a
shield that has never fired prints a warning. Both exist because the failure mode in the field is not
"the shield was too slow to deploy" — it is "someone enforced a predicate nobody had watched."

## Item 12 · Audit trail

> **step 4** · runs in the **control plane** · written **once** · **conventional**

Every op logged: who, what, when, and what happened. One structured record, emitted whether the
operation succeeded or failed.

```c
/*
 * audit.c — one record per shield operation. Emitted from the loader handler
 * (item 3) on every path, including every rejection.
 */
#include "shield_abi.h"

struct shield_audit {
    uint64_t timestamp_ns;
    char     actor[64];          /* authenticated operator, from the control plane */
    char     op[16];             /* LOAD | SET_MODE | STATUS | REVOKE             */
    char     hook[SHIELD_HOOK_NAME_MAX];
    char     shield[64];         /* CVE / shield name                             */
    uint8_t  prog_sha256[SHIELD_SHA256_LEN];   /* WHICH bytes — not just "a shield" */
    uint8_t  mode_from, mode_to;
    uint32_t build_id;           /* the TMM build that accepted or rejected it     */
    int32_t  result;             /* enum shield_err: 0, or exactly why it failed   */
    uint64_t fired_at_change;    /* evidence at the moment of a mode change        */
};

void audit_emit(const struct shield_msg *m, int rc)
{
    struct shield_audit a = {
        .timestamp_ns = tmm_now_ns(),
        .build_id     = tmm_build_id(),
        .result       = rc,
    };
    snprintf(a.op,   sizeof a.op,   "%s", op_name(m->op));
    snprintf(a.hook, sizeof a.hook, "%s", m->hook);
    control_plane_actor(a.actor, sizeof a.actor);      /* TODO(f5): TMOS identity */
    f5_sha256(m->prog, m->prog_len, a.prog_sha256);

    /* Structured to the existing sink, not a bespoke file: this has to land in
     * whatever already carries TMOS config-change audit, so it inherits
     * retention, forwarding and tamper-evidence rather than reinventing them. */
    tmm_audit_write(&a, sizeof a);                     /* TODO(f5): reuse        */

    /* A rejection is the interesting record, so make it legible on its own. */
    if (rc != SHIELD_OK)
        log_warn("shield %s %s at %s REJECTED: %s",
                 a.shield, a.op, a.hook, shield_strerror(rc));
}
```

**Real:** the record's contents — in particular `prog_sha256` (which bytes, not merely "a shield"),
`mode_from`/`mode_to`, and `fired_at_change`, so a later reviewer can reconstruct *what evidence
existed when someone flipped enforce*.
**Stubbed:** `tmm_now_ns`, `control_plane_actor`, `tmm_audit_write`, `op_name`, `log_warn`.
**TODO(f5):** identify the existing TMOS audit sink and write to it; retention and forwarding are then
inherited, not designed here.

---

# The shield program — the only per-CVE code

> **step 6** · runs in **TMM, via the VM** · written **per CVE** · **a few lines of C**

Everything above is written once. This is the marginal cost of each new mitigation.

```c
/*
 * cve-2026-nnnn.bpf.c — the whole shield for the worked example.
 * Compile:  clang -O2 -target bpf -c cve-2026-nnnn.bpf.c -o cve-2026-nnnn.bpf.o
 */

/* ctx = the hooked function's typed arguments, from this build's hook map.
 * Generated, not hand-written — see item 6. */
struct listener { struct fw_log_profile_protocol_transfer *prot_transfer_log_profile; };
struct conn_flow { struct listener *listener; };
struct ctx { struct conn_flow *cf; };

int shield(struct ctx *c)
{
    struct listener *l = c->cf ? c->cf->listener : 0;
    return !l || l->prot_transfer_log_profile == 0;   /* 1 = crash-bound */
}
```

Two lines of logic, and PREVAIL will not accept it without the guards on `c->cf` and `l` — **the
verifier will not let the shield repeat the very bug it is mitigating.**

**The form that verifies and runs today.** The prototype's VM passes the ctx as a memory argument, so
what actually compiles, passes PREVAIL, and executes in
[`prototype/`](prototype/shields/ls_shield_ubpf.bpf.c) looks like this instead — same predicate,
uBPF's calling convention:

```c
#include <stdint.h>

struct ls_ctx { uint16_t opcode; uint16_t payload_len;      /* must match ls_shield.h */
                uint32_t avail_len; uint32_t mode; uint8_t head[16]; };

uint64_t ls_decision(void *data)
{
    struct ls_ctx *ctx = data;
    return ctx->opcode >= 4;        /* the prototype's synthetic precondition */
}
```

**Real:** both blocks are real C that clang compiles to eBPF; the second is the shape the repo's
verify-gate track already exercises end to end.
**Stubbed:** the first block's `struct ctx` — its field names come from the worked example, and the
real one is generated per build by item 6.
**TODO(f5):** nothing. This is the item that needs no new tooling — which is the point of the other
twelve.

---

# Staged tiers 13–17 — deliberately not coded

These are follow-ons, not day-one work, and three of them already have a design or an implementation
elsewhere. Coding them here would imply a commitment the scope doc deliberately withholds.

- **13 · Rate-limited per-firing log line** — evidence tier 2, emitted from the trampoline (item 1).
  Needs a token bucket per shield and a decision about which sink; the counters in item 1 are the
  tier-1 answer and are already sufficient for "is this hook firing."
- **14 · Egress ring + drain agent** — already specified at code level, including the reserve/commit
  protocol and drop-and-count discipline, in
  [`data-plane-egress-primitives.md`](data-plane-egress-primitives.md) §5.3–§5.5. That document is the
  skeleton; duplicating it here would just create a second copy to keep in sync.
- **15 · Runtime watchdog / wall-clock deadline** — the second time-safety layer,
  [`engine-hard-problems.md`](engine-hard-problems.md) §1. **Gating for hot-path hooks**; the worked
  example's cold log-site hook does not need it, which is why item 8 alone suffices for day one.
- **16 · Canary auto-unload** — health-metric-driven auto-revoke, `engine-hard-problems.md` §4. The
  mechanism it needs already exists: `SHIELD_OP_REVOKE` (item 3) is the action; what is missing is the
  policy that decides to fire it.
- **17 · tmmtrace** — **already exists as working code**:
  [`prototype/tmmtrace`](prototype/tmmtrace) parses a one-liner, generates C, compiles it, runs the
  PREVAIL gate and drives the VM. It is an authoring convenience, and nothing in items 1–12 depends on
  it.

---

## Optional doc tidies — for separate approval, not applied here

Writing these skeletons surfaced a handful of one-word divergences in already-committed text. None is
an error; all would read better unified. Listed here rather than changed, per this repo's rule that
the canon is not edited as a side effect of other work:

1. **`explainers/cve-shield-walkthrough.html`** trampoline block writes bare `ENFORCE`/`MONITOR` while
   the same block's `trampoline_arm` call uses `MODE_MONITOR`. Unify on `MODE_*`.
2. **`data-plane-egress-primitives.md`** §5.3 assigns `ret = jit_fn(&ctx)` then switches on
   `host_action(hook, r)` — `ret` vs `r`. Pick one.
3. **`explainers/cve-shield-walkthrough.html`** writes `jit_fn(&ctx)`; uBPF's JIT entry point takes
   `(void *mem, size_t mem_len)`. A parenthetical would close the gap without lengthening the block.
4. **`big-ip-live-shield-design.md`** shield-object JSON uses `perf_class` where the hook map and the
   USDT catalog use `path_class`.
5. **`embedded-ebpf-substrate.md`** prose writes `SAFE-RETURN`; the code constant is `SAFE_RETURN`.

## Where this leaves the scope claim

The §6 table in [`development-scope.md`](development-scope.md) claims items 1–4 are "delicate, small,
must be exactly right," 5–7 are "tooling with one hard design decision," and 8–12 are "conventional."
Having written them out, that holds — with two honest amendments:

- **Item 2 (arm/disarm) is the riskiest item on the list**, not item 1. Patching live text in the
  crown-jewel process is a proven technique in kernels but new here, and whether TMM's memory manager
  will relax W^X per page is a TMA question before it is a coding one.
- **Item 6 is 40 lines of code and the largest ongoing commitment.** The tool is trivial; deciding what
  belongs in each hook's ctx — and then carrying that contract for the life of the hook — is the
  substrate's real engineering surface, exactly as `engine-hard-problems.md` §2 says.

Nothing in items 1–12 is a subsystem on the scale of writing a VM or a verifier. That remains the
whole point of reusing uBPF and PREVAIL.

---

*Candidate code for review — not TMM source, and not a commitment to an implementation. Detailed
method & claims are held in a separate invention disclosure.*
