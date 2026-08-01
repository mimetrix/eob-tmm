# Candidate code — what each development-scope item looks like

### Skeletons for the day-one work items, so the shape of each one can be argued with rather than taken on faith.

> An earlier framing of this file was "so 'hundreds of lines, not subsystems' can be checked." That
> claim is **retired** ([`engine-hard-problems.md`](engine-hard-problems.md) §6.1): the item *list*
> is right, the sizes were low — in several cases badly — and the subsystem being added is a code-patching,
> live-text, dynamic-code-loading facility inside the crown-jewel process — **subsystem-scale
> work, not a feature** for a defensible v1 on two architectures. What these skeletons still do,
> and all they do, is show the *shape* of each item and mark honestly where reuse ends.

**Status:** Candidate code for review — **not TMM source**
**Companion:** [`development-scope.md`](development-scope.md) (the item list this follows, 1:1) ·
[`explainers/cve-shield-walkthrough.html`](explainers/cve-shield-walkthrough.html) (the canon; step
numbers below refer to its build steps 1–4 and CVE-day steps 5–13) ·
[`substrate/`](substrate/) (the artifacts here that are real files) ·
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
3. **No skeleton claims more safety than the design does.** A verified program is memory-safe, and
   terminating **only if admission passes PREVAIL's `--termination`** (off by its default) — and then
   only within a 100,000-loop-iteration bound, itself ~300 µs. Termination is not a time bound. Its
   *cost* is *estimated* at admission by the budget pass (item 8) and *enforced* at runtime by
   back-edge fuel (item 15, a uBPF JIT patch, day one). And "memory-safe" does not mean "cannot
   write its `ctx`": PREVAIL permits ctx writes, which is why item 1's `ctx` is a per-core **copy**.

Some of these artifacts are worth having as **real files** rather than blocks, because their value is
that they compile and validate — they live in [`substrate/`](substrate/) and are *referenced* here
rather than re-printed, so the two copies can't drift:

- [`substrate/shield_abi.h`](substrate/shield_abi.h) — `struct shield_msg`,
  `struct shield_binding`, `struct shield_sr_policy`, `struct hook_slot`, `shield_jit_fn`, the
  `SHIELD_ERR_*` codes, the mode/verdict/disposition enums. Compiles; its `_Static_assert`s pin the
  message's wire layout.
- [`substrate/hook_map.schema.json`](substrate/hook_map.schema.json) — the hook
  map item 5 emits and items 6–8 consume. The example instance
  [`substrate/hook-point-map.json`](substrate/hook-point-map.json) validates against it, and
  `check_offsets.py` compiles that instance's declared `ctx` offsets against the header they describe
  ([`substrate/example_hook_ctx.h`](substrate/example_hook_ctx.h)).

```bash
make -C substrate check
```

**What this repo does and does not execute.** Everything under `substrate/` really runs, and
`make -C substrate check` is the whole of it: header and wire-layout asserts, the safe-return gate
cases, the schema, the offset check, and the budget pass over its own self-test. All of it is
**build- and admission-time** material. An earlier revision of this repo also carried a prototype — a
relay that loaded and ran a shield through uBPF and drove PREVAIL as a verify gate — and several
sections below cited it as evidence that the load-and-run path worked. **That prototype has been
removed and nothing replaces it**, so no claim of the form "this runs today" survives anywhere in this
file. Each place one used to stand now says so explicitly. The skeletons are unchanged in substance;
what changed is that they are now candidates only, with no executable counterpart.

## Naming reconciliation

These skeletons are the first place all twelve items share one namespace, so the spellings already
committed across the docs — and, while it existed, the prototype — have to be reconciled once, here.
The `ls_*` spellings below came from that prototype and are retained as **retired** entries: they
record where a divergence came from, and no longer name anything in this repo. **Nothing committed
was rewritten to produce this table** — where a divergence exists, this is the resolution used
below, and the small doc tidies that would unify things are listed at the end for separate
approval.

| Concept | Already committed as | Used below |
|---|---|---|
| program result | `verdict` (walkthrough trampoline), `ret`/`r` (egress §5.3), `&ret` out-param (`ubpf_exec`) | **`verdict`** |
| modes | `MONITOR`/`ENFORCE` bare, `MODE_MONITOR` (in `trampoline_arm`), lowercase `monitor` (CLI/JSON), `LS_MONITOR` (removed prototype — retired) | **`MODE_DISABLE`/`MODE_MONITOR`/`MODE_ENFORCE`**; lowercase stays CLI/JSON only |
| skip-the-body | `SAFE_RETURN` (block), `SAFE-RETURN` (substrate prose) | **`SAFE_RETURN`** = `TRAMP_SAFE_RETURN` |
| hook cost class | `path_class` (hook map, USDT catalog), `perf_class` (shield-object JSON) | **`path_class`** |
| bytecode load | `ubpf_load` (walkthrough: raw bytecode), `ubpf_load_elf` (uBPF's ELF-object entry point, `vm/inc/ubpf.h:458`) | **both** — different calls; item 3 uses `ubpf_load_elf` because the signed artifact is an ELF, and says so |
| JIT'd program | `jit_fn(&ctx)` (walkthrough, one arg) | **`slot->fn(ctx, ctx_len)`** — uBPF's real signature is `uint64_t (*)(void *mem, size_t mem_len)`; the canon block elides `mem_len` |
| loader ops | `LOAD · SET_MODE · STATUS · REVOKE` (bare) | **`SHIELD_OP_*`** — prefixed for C namespace hygiene; the bare names are the wire vocabulary |
| the shield program | `int shield(struct ctx *c)` returning a predicate (walkthrough) and `int ls_ptlog_nullderef(struct ctx *c)` returning `LS_SAFE_RETURN`/`LS_PASS` (design §14) — one product form, two names for the same worked bug; `uint64_t ls_decision(void *data)` (the removed prototype's spelling of the memory-argument form uBPF's own `ubpf_exec`/JIT signature imposes — **nothing in this repo verifies or runs it**) | **the product form** for the shape, with the uBPF-signature form given alongside — see the last section |
| the shield's ELF section | `SEC("tracing/…")` (design §14) | **`SEC("fentry/<hook>")`** — the section prefix *is* PREVAIL's type-selection mechanism, and `tracing/` is not one of the prefixes that selects the `tracing` type. See item 6 |

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
**Per CVE** — [the shield program](#the-shield-program--the-only-per-cve-code)
**Staged tiers 13–17** — [noted, not coded](#staged-tiers-1317--deliberately-not-coded) (item 15 is
day one)

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
 *   2. COPIES those saved registers into this core's ctx scratch buffer, laid
 *      out per this hook's arg_btf in the signed hook map, and hands the
 *      program the COPY (see "the copy is not optional" below)
 *   3. calls tramp_dispatch(slot, ctx, ctx_len)
 *   4. TRAMP_FALLTHROUGH  -> discard the scratch copy, restore the SAVED
 *                            registers (never the copy), jump to
 *                            entry + pad_bytes
 *      TRAMP_SAFE_RETURN  -> load slot->sr's value into the ABI return register
 *                            and return to the CALLER: the body never runs
 *
 * Nothing is "displaced" and nothing has to be re-executed: the pad is nops the
 * compiler reserved via -fpatchable-function-entry BEFORE the prologue, so
 * entry + pad_bytes is the first real instruction. Deleting that step is what
 * makes this design simpler than ftrace's general case.
 *
 * ≈ a page per architecture, and the only assembly in the whole substrate.
 * ------------------------------------------------------------------------- */

/* ---------------------------------------------------------------------------
 * The copy is not optional — and it is the cost to measure.
 *
 * An earlier draft of this file said "the ctx IS the saved frame, so there is
 * no copy on the hot path." That is retired, and it was the most dangerous
 * sentence in this repo. PREVAIL's context descriptor is four ints
 * (ebpf-verifier/src/spec/ebpf_base.h: size · data · end · meta) and expresses
 * NO read-only region. Its ctx-write check is gated on `desc->end >= 0`
 * (src/crab/ebpf_checker.cpp), so a descriptor with no pointer slots — which is
 * exactly what a TMM ctx of resolved scalars is — skips the check entirely:
 * a verified program may write EVERY BYTE of its ctx, and PREVAIL's own comment
 * says so ("real programs do write them").
 *
 * Compose that with "the ctx is the live register frame" and "restore registers
 * on fall-through" and a signed, verified, nominally read-only base-tier
 * program becomes an ARGUMENT-INJECTION PRIMITIVE into live TMM code paths,
 * delivered by the very mechanism sold as the safety story. So:
 *
 *   - the stub copies the argument registers into per-core scratch,
 *   - the program is handed the copy, and
 *   - the copy is DISCARDED on fall-through; the body resumes from the saved
 *     registers, which the program never had addressable.
 *
 * Read-only is therefore a property of the copy and of the discard, not of
 * anything PREVAIL enforces. The copy is the cost, and it is the number to
 * measure first — see item 8's closing note, where 6–17-cycle predicates make
 * invocation overhead the binding constraint, not program cost.
 * ------------------------------------------------------------------------- */

/* TODO(f5): per-core ctx scratch, sized to the largest hook's ctx and padded to
 * a cache line. Statically reserved at substrate init — no allocation here. */
extern void *tramp_ctx_scratch(unsigned core);

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
     * `ctx` here is this core's scratch COPY, never the live register frame.
     *
     * What PREVAIL proved, stated exactly: it cannot fault, and it cannot reach
     * memory outside ctx. It also cannot WRITE outside ctx — but it can write
     * freely INSIDE it, which is why the copy exists and is discarded. And it
     * terminates only within PREVAIL's 100,000-loop-iteration bound, and only
     * when admission passed --termination (off by PREVAIL's default). 100,000
     * iterations is itself ~300 µs at ~10 instructions each on 3 GHz, so
     * "terminates" is not "cannot stall the poll loop": that is what item 8's
     * admission budget and item 15's back-edge fuel are for.
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
     *
     * Precisely: at the base tier the program returns a PREDICATE (0/1, item
     * 6's expected_return), not an outcome. The host maps predicate -> outcome
     * from this hook's declared enumerated_outcomes in the signed map; the
     * canonical set is PASS · DROP · RESET · SAFE-RETURN · STEER · SAMPLE
     * (embedded-ebpf-substrate.md §2, "this is the one list"). At an
     * enforce-capable function boundary the mapping is the two-element case:
     * TRAMP_FALLTHROUGH *is* PASS, TRAMP_SAFE_RETURN is SAFE-RETURN. A program
     * cannot inject a value or invent a branch — it did not even select the
     * outcome, it answered a question the host's policy then acted on.
     */
    return TRAMP_SAFE_RETURN;
}
```

**Real:** the control flow, and the fact that `slot->fn` is uBPF's JIT'd entry point with uBPF's
actual two-argument signature.
**Stubbed:** `this_core()`, `tramp_ctx_scratch()`.
**TODO(f5):** both `.S` entry stubs; cache-line padding for `fired[]`; the per-core ctx scratch and
its sizing; the decision of which registers each arch's stub must preserve for a *hooked* function
(stricter than a normal call, since the body still has to run after a fall-through).
**Cost when dark:** nothing — an unarmed entry is nop bytes the CPU falls straight through. **Cost
when armed and not matching:** the stub's register save/restore, **the ctx copy into per-core
scratch**, and one predicate. That is the number the budget pass gates on, and the number to measure
first — the copy is a real cost, and paying it is what keeps a verified program from writing the
caller's arguments.
**TODO(f5) — burst form for hot hooks:** `tramp_dispatch()` above is one invocation per call, which
fits TMM's run-to-completion loop and is nearly free at a warm per-request boundary. Where a hot path
processes a receive burst, the per-invocation overhead wants amortizing over the batch, and the
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
 * Sketch over uBPF's real API — ubpf_create / ubpf_load_elf / ubpf_compile, all
 * in the library's own vm/inc/ubpf.h. An earlier revision of this file described
 * this as extending a prototype relay's working init path; that prototype has
 * been removed, so this skeleton now builds on nothing runnable in this repo.
 * It is a candidate written against uBPF's published API, and everything the
 * loader has to add around those three calls — signature, binding, hook map,
 * arming, expiry, teardown — is unwritten.
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

/*
 * LOAD runs in TWO phases, and the split is not cosmetic.
 *
 *   PREPARE — OFF the safe point. Signature, binding, hook-map lookup,
 *     ubpf_create(), ubpf_load_elf() (a full ELF parse of an attacker-supplied
 *     — though signature-gated — object) and ubpf_compile_ex() (a
 *     code-generation pass). Milliseconds, and every byte of it is work TMM
 *     must not do while it is supposed to be polling.
 *   PUBLISH — AT the safe point. Hand the finished function pointer to the slot
 *     and patch a few bytes of entry pad. Microseconds.
 *
 * An earlier draft of this sketch did all of it at the safe point, which is
 * milliseconds during which TMM is not polling — a self-inflicted outage on the
 * happy path of a mitigation.
 */
static int do_load_prepare(const struct shield_msg *msg, struct shield_state *s)
{
    char *err = NULL;

    /* 1. The binding pins this program to THIS build and THIS hook. It travels
     *    INSIDE the message at an asserted offset (shield_abi.h @16, 112 bytes),
     *    which is what makes shield_binding_of() expressible at all; the
     *    signature over it has already been checked by the caller. A signed
     *    shield replayed elsewhere dies here, not at the hook. */
    const struct shield_binding *b = shield_binding_of(msg);
    uint32_t build = tmm_build_id();
    if (build < b->build_min || build > b->build_max) return SHIELD_ERR_BUILD;
    if (build >= b->expires_with)                     return SHIELD_ERR_EXPIRED;
    if (msg->mode > b->mode_ceiling)                  return SHIELD_ERR_CEILING;

    /* 2. Resolve the target in this build's signed hook map (item 5). The hook
     *    name comes from the BINDING — there is no unsigned msg->hook to read,
     *    deliberately: a field carried both inside and outside the signature
     *    raises "which one wins?", and the answer is always the signed one. */
    s->slot = hook_map_lookup(b->hook);
    if (!s->slot)                                     return SHIELD_ERR_HOOK;

    /* 3. Instantiate. Base tier: no helpers are registered, so there is no
     *    helper ABI to secure and PREVAIL ran stock (engine-hard-problems §2). */
    s->vm = ubpf_create();
    if (!s->vm)                                       return SHIELD_ERR_NOMEM;

    /* The signed artifact is an ELF object, so this is ubpf_load_elf() — the
     * walkthrough's ubpf_load() is the raw-bytecode variant of the same step. */
    if (ubpf_load_elf(s->vm, msg->prog, msg->prog_len, &err) < 0)
                                                      return SHIELD_ERR_LOAD;

    /* 4. JIT once, here, at load — never per invocation. ExtendedJitMode, NOT
     *    ubpf_compile(): the basic JIT's prologue emits an unconditional
     *    `sub rsp, UBPF_EBPF_STACK_SIZE` (UBPF_MAX_CALL_DEPTH 8 x 512 = 4096)
     *    with NO stack probe, so a 4 KiB frame is taken at whatever depth TMM's
     *    call graph already sits at — able to step clean over a single guard
     *    page. The extended form takes the program stack as arguments, so we
     *    hand it a per-core preallocated buffer instead. */
    s->fn = ubpf_compile_ex(s->vm, &err, ExtendedJitMode);
    if (!s->fn)                                       return SHIELD_ERR_JIT;

    return SHIELD_OK;
}

/* At the safe point: publish and patch, nothing else.
 * LOAD always arms in monitor; promotion is a separate, separately authorized
 * SET_MODE (step 11), never implied by a load. */
static int do_load_publish(struct shield_state *s, const struct shield_binding *b)
{
    if (trampoline_arm(s->slot, s->fn, MODE_MONITOR) != SHIELD_OK)
        return SHIELD_ERR_HOOK;
    s->expires_with = b->expires_with;
    s->mode_ceiling = b->mode_ceiling;
    return SHIELD_OK;
}

/* Both phases, in order, with the fail-dark rule. Written as one function here
 * for readability; TODO(f5): the real split is a state machine, because only the
 * second call may run at the safe point and the first must not. */
static int do_load(const struct shield_msg *msg)
{
    const struct shield_binding *b = shield_binding_of(msg);
    struct shield_state *s = shield_slot_alloc(b->hook);
    if (!s) return SHIELD_ERR_NOMEM;

    int rc = do_load_prepare(msg, s);              /* off the safe point */
    if (rc == SHIELD_OK)
        rc = do_load_publish(s, b);                /* at the safe point  */

    if (rc != SHIELD_OK) shield_teardown(s);       /* always dark on failure */
    return rc;
}

/*
 * Entry point. One message, one verdict, and on ANY failure the hook is dark:
 * there is no partially-armed state to reason about.
 *
 * Two rules here are corrections of security defects in an earlier draft of this
 * sketch, and both are now expressible because shield_abi.h carries the fields:
 *
 *   1. LENGTH BEFORE CONTENT. msg->prog_len is attacker-influenced until the
 *      signature says otherwise, so it is validated against the length of the
 *      datagram actually received as statement one — before it reaches a hash,
 *      a parser or a memcpy. The earlier draft first consumed prog_len *inside*
 *      the authentication step.
 *   2. EVERY OP IS AUTHENTICATED, AND CARRIES AN EPOCH. The earlier draft
 *      verified only LOAD and let SET_MODE/STATUS/REVOKE dispatch with no
 *      sig_verify() at all; and with no nonce or epoch anywhere, a captured
 *      LOAD replayed after a REVOKE re-arms the hook — which DEFEATS THE KILL
 *      SWITCH. The signature now covers op, epoch, mode, prog_len, the binding
 *      and prog (shield_abi.h), and the epoch is rejected unless it strictly
 *      advances.
 */
int shield_msg_handle(const struct shield_msg *msg, size_t datagram_len)
{
    int rc;

    /* 1. Structural, first: does the message fit inside what we received? */
    if (datagram_len < sizeof *msg ||
        msg->prog_len > datagram_len - sizeof *msg)
        return SHIELD_ERR_SIG;

    /* 2. The perimeter, for EVERY op — not just LOAD (item 4). */
    if (!sig_verify(msg, datagram_len, f5_pubkey)) {
        audit_emit(msg, SHIELD_ERR_SIG);
        return SHIELD_ERR_SIG;
    }

    /* 3. Replay. msg->epoch must strictly advance for this hook, so a revoked
     *    shield cannot be resurrected by re-sending an old LOAD. REVOKE bumps
     *    it, which is what makes it a kill switch rather than a suggestion.
     *    TODO(f5): where the per-hook epoch lives across a TMM restart; and a
     *    distinct SHIELD_ERR_REPLAY code — enum shield_err has none yet, so
     *    this returns the perimeter's code. */
    if (!epoch_advance(shield_binding_of(msg)->hook, msg->epoch)) {
        audit_emit(msg, SHIELD_ERR_SIG);
        return SHIELD_ERR_SIG;
    }

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

**Real:** `ubpf_create`, `ubpf_load_elf`, `ubpf_compile_ex`, `ubpf_destroy` — and the JIT-once-at-load
property, which is the load-bearing performance claim. `ExtendedJitMode` and `ubpf_jit_ex_fn`'s
`(mem, mem_len, stack, stack_len)` signature are uBPF's real API
(`ubpf/vm/inc/ubpf.h`); so is the basic JIT's unprobed `sub rsp, 4096` prologue
(`ubpf/vm/ubpf_jit_x86_64.c`) that makes the extended form the right call here.
**Real, and checkable:** [`substrate/shield_abi.h`](substrate/shield_abi.h) now
carries the binding *inside* `struct shield_msg` (`binding` at offset 16, 112 bytes, `sizeof` 192, all
pinned by `_Static_assert` and checked by `make -C substrate check`), so
`shield_binding_of()` is a real accessor rather than a function that could not be written. `epoch` is
a top-level field at offset 4 and the signature covers `op · epoch · mode · prog_len · binding ·
prog`. Note what is deliberately *absent*: there is no top-level `msg->hook` or `msg->expires_with`
any more, because a field carried both inside and outside the signature raises "which copy wins?" and
the answer is always the signed one — so every skeleton above reads them through the accessor.
**Stubbed:** `sig_verify` (item 4), `hook_map_lookup` (item 5), `shield_slot_alloc`, `tmm_build_id`,
`epoch_advance`, `audit_emit` (item 12), `do_set_mode`/`do_status`/`do_revoke` (shown by name; each is
a dozen lines over `g_shields`).
**TODO(f5) — three ABI gaps this sketch still runs ahead of.** Called out rather than quietly written
into the header, because its `_Static_assert`s pin a wire layout other documents quote:
1. **The received datagram length is not in the ABI.** `shield_msg_handle()` and `sig_verify()` are
   declared in the header as `(msg)` and `(msg, pubkey)`; the length-before-content rule needs the
   length passed alongside, as the skeletons above assume.
2. **`SHIELD_ERR_REPLAY`** has no code in `enum shield_err`, so a rejected epoch is currently
   indistinguishable from a bad signature in the audit record.
3. **`shield_jit_fn`** is typed for the basic two-argument JIT, not `ubpf_jit_ex_fn`'s
   `(mem, mem_len, stack, stack_len)` — which the stack-probe fix above requires.
**Also TODO(f5):** the ISSU/upgrade hook for expiry; `SHIELD_MAX_SHIELDS`; the per-core program stack
handed to `ubpf_jit_ex_fn`; and the real message plumbing (item 10) that gets a `shield_msg` here on
every core, carrying the received datagram length with it.
**Why this is "hundreds of lines":** the error returns above are the item. The removed prototype's
equivalent was ~25 lines, because it had no signature, no binding, no map and no arming to get wrong
— the contrast is still the point, but it is now a recollection rather than a diff a reviewer can
run.

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
 * The canonical serialization that gets signed: op, epoch, mode and prog_len,
 * then the binding's fields in a fixed order (the binding already carries the
 * program hash). Byte-identical to item 9's signer — if these two ever disagree,
 * every load fails closed, which is the correct direction to fail.
 *
 * Covering op/epoch/mode is not decoration: it is what authenticates SET_MODE,
 * STATUS and REVOKE, and what makes REVOKE a kill switch rather than something a
 * replayed LOAD can undo.
 */
static size_t sig_payload_serialize(const struct shield_msg *msg,
                                    uint8_t *out, size_t cap);

int sig_verify(const struct shield_msg *msg, size_t datagram_len,
               const void *pubkey)
{
    if (!msg || !pubkey) return 0;

    /*
     * 1. LENGTH FIRST. prog_len is attacker-influenced until step 4 below says
     *    otherwise, so it is bounded by the datagram we actually received before
     *    it is handed to a hash. An earlier draft of this function fed
     *    msg->prog_len straight into f5_sha256() — an attacker-chosen length
     *    read inside the very step that is supposed to authenticate it.
     */
    if (datagram_len < sizeof *msg)                        return 0;
    if (msg->prog_len > datagram_len - sizeof *msg)        return 0;

    /* The binding travels inside the message at an asserted offset, which is
     * what makes this accessor expressible. It returns the SIGNED copy —
     * there is no other, by design (shield_abi.h). */
    const struct shield_binding *b = shield_binding_of(msg);

    /* 2. The program must be the program that was verified and signed. */
    uint8_t h[SHIELD_SHA256_LEN];
    f5_sha256(msg->prog, msg->prog_len, h);
    if (!ct_equal(h, b->prog_sha256, sizeof h))
        return 0;

    /*
     * 3. There is deliberately NO "is the binding consistent with the header?"
     *    step here any more, and its absence is the point. An earlier shape
     *    duplicated `hook` and `expires_with` outside the binding and then
     *    cross-checked the two copies — a check that only existed because the
     *    duplication did. With one signed copy there is nothing to disagree.
     *
     * 4. The signature covers op, epoch, mode, prog_len, the binding and the
     *    program hash, in that fixed order — so SET_MODE, STATUS and REVOKE are
     *    authenticated too, and a captured LOAD cannot be replayed after a
     *    REVOKE because its epoch no longer advances.
     */
    uint8_t buf[SHIELD_BINDING_WIRE_MAX];
    size_t  n = sig_payload_serialize(msg, buf, sizeof buf);
    if (n == 0)
        return 0;

    return f5_verify_detached(buf, n, msg->sig, SHIELD_SIG_MAX, pubkey) == 0;
}
```

**Real:** the check order — **bound the length**, hash the program, *then* verify the signature over
the canonical form. Constant-time comparison for the digest. `shield_binding_of()` and the fields it
reaches are real, `_Static_assert`-pinned members of
[`shield_abi.h`](substrate/shield_abi.h).
**Stubbed:** `f5_verify_detached`, `f5_sha256`, `ct_equal`, `sig_payload_serialize`.
**TODO(f5):** decide reuse-vs-new for the crypto path (strong preference: reuse); pin the algorithm
and `SHIELD_SIG_MAX` accordingly — `shield_abi.h` currently sizes it for Ed25519 and says so;
FIPS/Common-Criteria implications are in `engine-hard-problems.md` §5. Also the ABI gaps listed under
item 3, of which the one that bites here is that the header declares `sig_verify(msg, pubkey)` with no
place to pass the received datagram length.
**Small, but load-bearing:** this function is the entire reason a verifier-soundness bug is a
supply-chain risk rather than a traffic-borne one. Which is also why the two corrections above are
not style: a length read before authentication, and three of four ops dispatching with no
authentication at all, are both holes in the only perimeter this design has.

---

# §2 · Build-pipeline tooling

Runs at F5, once per TMOS build. Written once; the *outputs* regenerate every build, which is what
makes them maintenance-free rather than a growing pile of hand-maintained metadata.

## Item 5 · Hook-map generator

> **step 3** · runs in the **build pipeline** · written **once** · **tool**

Debug info in, signed hook map out. The schema it must satisfy is a real file:
[`substrate/hook_map.schema.json`](substrate/hook_map.schema.json).

```python
#!/usr/bin/env python3
"""
hookmap_gen.py — emit this build's signed hook map from its debug info.

Sketch. pyelftools and DWARF are real; every f5_* call is a stub.
Output validates against substrate/hook_map.schema.json.
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
                    # product fields the example map in substrate/ does not carry yet:
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
**The bug in `hookable()` above, stated plainly:** testing for `DW_AT_low_pc` accepts only functions
the build emitted out-of-line — which is correct, and is also why the generator **silently drops
every inlined static**, exactly the small leaf functions that hold the interesting state. Worse, it
says nothing about `-fipa-icf` **folds** (two source names, one pad — arming one arms both) or about
`ipa-cp`/`ipa-sra` **clones** (`foo.constprop.0`, whose argument list differs from the source, so a
`ctx` derived from the source signature is wrong). A real generator must therefore: reject or
explicitly disambiguate folded symbols; emit clones under their *emitted* name with their *emitted*
signature, or omit them; and **publish the resulting hookable set as a build artifact**, because it
is a subset of the source and nobody can predict it by reading code. See
[`engine-hard-problems.md`](engine-hard-problems.md) §5.
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
ctxdesc_gen.py — hook map -> one ctx descriptor per hook.

The task is "describe the ctx", not "modify the verifier's analysis" — but note
carefully that this does NOT come for free. PREVAIL has no --program-type option
and no descriptor file format: it deduces the type from the ELF section-name
prefix against a table compiled into the binary. So getting these descriptors in
front of it is either a patch set F5 owns (with a per-release rebase cost, on the
one component the trust story wants unforked) or a decision to reuse PREVAIL's
existing `tracing` type and live inside its 96 bytes. See the note below the code.
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
        # `readable` is what PREVAIL bounds. `writable` is NOT ENFORCED BY
        # PREVAIL and is recorded here only as documentation of intent: its
        # context descriptor is four ints (size/data/end/meta) and expresses no
        # read-only region at all, so a verified program may write every byte of
        # its ctx. Read-only is a property of the trampoline's per-core COPY and
        # of discarding it on fall-through (item 1) — never of this field.
        "context_descriptor": {"size": total, "readable": regions,
                              "writable": []},          # NOT enforced; see above
        "helper_prototypes": [],   # base tier: NONE. This is what keeps it stock.
        # Base tier: the program returns a PREDICATE, not an outcome. The host
        # maps predicate -> outcome from the hook's enumerated_outcomes; the
        # canonical set is PASS · DROP · RESET · SAFE-RETURN · STEER · SAMPLE
        # (embedded-ebpf-substrate.md §2). One bit does not select among six.
        "expected_return": {"type": "u64",
                            "meaning": "predicate: 0 = no match, 1 = MATCH"},
        "outcome_mapping": hook["enumerated_outcomes"],   # host-owned, signed
    }

def main(map_path, out_path):
    m = json.load(open(map_path))
    descs = [descriptor(h, m["ctx_abi_version"])
             for h in m["hook_points"] if "arg0" in h.get("arg_btf", {})]
    json.dump({"build_id": m["build_id"], "descriptors": descs},
              open(out_path, "w"), indent=2)
    # Admission (step 7) then runs, per program:
    #   prevail -q --section fentry/<hook> shield.bpf.o
    #
    # NOTE: there is NO --program-type option. PREVAIL deduces the program type
    # from the ELF SECTION-NAME PREFIX against a table compiled into the binary
    # (ebpf-verifier/src/linux/linux_platform.cpp), and falls back to
    # socket_filter when no prefix matches. So the section name above is not
    # decoration: it is the whole type-selection mechanism. See the note below
    # for the two honest ways to get a TMM ctx model in front of the verifier.
```

**Real:** PREVAIL's stock invocation, and the fact that what teaches it a ctx layout is a
*descriptor* rather than a change to its analysis. Both flags on the printed line are real options —
`-q,--quiet` and `--section` (`ebpf-verifier/src/main.cpp:74,65`) — so it is checkable against
PREVAIL's own source, which is the only place it can be sourced to now. Two things it is *not*: it is
not a transcript of a run in this repo, and it is not the full set of flags a product gate needs (O4:
`--termination` is off by default and must be passed explicitly). An earlier draft called this
"exactly what the prototype invokes today" and cited a prototype relay's call site. That was wrong
even then — the relay invoked only `-q [--section <s>]` — and the citation is dead now, because the
prototype has been removed. **No verify gate runs in this repo at all.**
**Not real — `--program-type` does not exist.** PREVAIL has no such option
(`ebpf-verifier/src/main.cpp`); the type comes from the section-name prefix, matched against a
compiled-in C++ table, fallback `socket_filter`. **So registering a TMM program type is a PREVAIL
patch set, not a config file** — which also retires the claim that "a descriptor, not a verifier
patch," is all this needs. There are exactly two honest options, and the choice belongs in the room:
- **Reuse PREVAIL's existing `tracing` type — free, no fork in the trust path.** It is a 96-byte
  region (`tracing_regions = 12 * 8`) with `data`/`end`/`meta` all `-1`, i.e. twelve u64 argument
  slots and nothing dereferenceable
  (`ebpf-verifier/src/linux/gpl/spec_type_descriptors.hpp`). Emit each shield into a matching section
  prefix and the ctx model has to resolve honestly, because twelve scalars is all there is. Nothing
  forked, nothing rebased.
  **The prefix is not the type name, and this is a live trap.** The prefixes that select `tracing`
  are `fentry/`, `fexit/`, `fmod_ret/`, `iter/`, `tp_btf/` and their `.s/` sleepable variants —
  **`tracing/` is not among them** (`ebpf-verifier/src/linux/linux_platform.cpp`; the string
  `"tracing"` appears there as the *type's* name, never as a section prefix). A shield emitted as
  `SEC("tracing/<hook>")` matches no prefix and therefore lands on the `socket_filter` fallback and
  its 192-byte `__sk_buff` — silently, with a green verdict. That is the trap the removed prototype's
  verify gate sat in (O3 in [`design-review-findings.md`](design-review-findings.md)), and with the
  prototype gone it is now a trap waiting for whatever gate replaces it rather than a defect anyone
  can go look at. Use `SEC("fentry/<hook>")`. The one adjacent prefix that *does*
  read like its type is `tracepoint/`, which selects `tracepoint` (a `perf_max_trace_size` region),
  not `tracing`.
- **Own a patch set** that registers a TMM program type with its own descriptor per `ctx_abi_version`
  — more expressive, and a **per-release rebase cost on the component the trust story says is
  unforked.**
**Stubbed:** the descriptor's exact serialization (whichever of the two options above is taken
determines whether it is a file at all).
**TODO(f5):** pick one of the two options above and cost it; decide how a descriptor change forces a
`ctx_abi_version` bump and what that does to already-signed shields (answer: their binding's build
range stops matching, so they stop loading — by design).
**Why this item is the real 90% and this file is only 40 lines:** the *code* is a layout walk. The
*work* is deciding, per hook, which fields belong in the ctx at all — too few and no useful shield can
be written, too many and the surface is over-exposed and versioning it becomes a permanent tax. Every
field added here is a contract F5 carries for as long as the hook exists. That judgement is not
automatable, and it is the substrate's largest ongoing engineering surface.

## Item 7 · Safe-return policy table

> **steps 3, 12** · runs in the **build pipeline** · written **once + annotations** · **tool +
> process**

What a skipped body hands back — **and, first, whether the body may be skipped at all.** Those are two
different questions, and conflating them is the most dangerous mistake available in this whole design.

```python
#!/usr/bin/env python3
"""
safe_return.py — classify each hookable function for safe-return eligibility.

Two independent gates, in this order:
  1. SIDE EFFECTS — may this body be skipped at all?   (the dangerous question)
  2. RETURN VALUE — if so, what does the caller get?   (the easy question)

Mirrors, field for field, the two enums in substrate/shield_abi.h:
    enum shield_skippable   GATE 1: unanalysed (default, observe-only) | no | yes
    enum shield_sr_kind     GATE 2: none | void | zero | const
and emits the `safe_return` object hook_map.schema.json now REQUIRES both keys of.
The rule is not documentation any more: shield_sr_enforce_capable() demands both
gates, and substrate/check_sr_gates.c asserts five cases — including
`void` + unanalysed, the case the retired return-type model accepted — so
`make -C substrate check` fails on regression.
"""
ZERO_OK = {"int", "long", "unsigned int", "_Bool"}      # 0 = "did nothing, fine"

# Side effects whose ABSENCE the caller will notice. Any one of these makes a
# function un-skippable regardless of what it returns.
DISQUALIFYING = (
    "takes_or_releases_lock",     # skip -> lock leaked, or released twice
    "adjusts_refcount",           # skip -> leak, or premature free
    "advances_state_machine",     # skip -> caller proceeds from a state never reached
    "consumes_input",             # skip -> buffer/cursor not advanced; caller re-reads
    "allocates_or_frees",         # skip -> caller holds a pointer that was never set up
    "writes_caller_visible_out",  # skip -> out-param left uninitialised
    "signals_or_wakes",           # skip -> peer waits forever
)

def skippable(fn):
    """Gate 1. Conservative and *closed by default*: a body is skippable only if
    we can show it does nothing the caller depends on. `void` proves NOTHING
    here — a void function can take a lock, advance a parser, or free a buffer.
    That is exactly the trap: the worked CVE's own vulnerable function returns
    nothing and still does something the system wanted (it emits a log)."""
    for effect in DISQUALIFYING:
        if fn.get(effect):
            return False, effect
    if not fn.get("side_effects_analysed"):
        return False, "not analysed"          # absence of evidence != evidence
    return True, None

def return_kind(fn):
    """Gate 2. Only reached for a body we already agreed may be skipped."""
    rt = fn["return_type"]

    if rt == "void":
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

    return {"kind": "none"}

def classify(fn):
    """Emit the schema's `safe_return`: gate 1's verdict is a FIELD, not just a
    reason string, so a downstream consumer cannot re-derive enforce-capability
    from `kind` alone."""
    ok, why = skippable(fn)
    if not ok:
        return {"skippable": "unanalysed" if why == "not analysed" else "no",
                "kind": "none", "rationale": "body not skippable: %s" % why}
    return dict(skippable="yes", **return_kind(fn))

def v1_gate(policy, path_class, attacker_reachable):
    """A sane first release: only arm enforce where the skip is unambiguous.

    `path_class` is NOT a purely structural label. It is
    (static structure AND adversarial reachability) — a hook that fires once per
    exceptional event is structurally `cold` and adversarially `hot` the moment
    an attacker can drive that exception, which is exactly the worked example's
    log site on a malformed-input path. The hook-map generator computes the
    conjunction; `attacker_reachable` is passed separately here to make the
    second half impossible to forget. See engine-hard-problems.md §1 and §5.
    """
    if policy["kind"] not in ("void", "zero"):
        return "observe"
    if path_class == "hot" or attacker_reachable:   # enforce here needs item 15
        return "monitor"
    return "enforce"
```

**Real, and now enforced rather than documented:** the two-gate structure, and the three refusals — a
body with any caller-visible side effect is not skippable *whatever* it returns; a status-code return
where zero means success is not safe-returnable; anything unanalysed or unannotated defaults to
observe-only. Gate 1 is `enum shield_skippable` in
[`shield_abi.h`](substrate/shield_abi.h), it sits *ahead of* `kind` in `struct
shield_sr_policy`, `shield_sr_enforce_capable()` requires both gates, and
[`check_sr_gates.c`](substrate/check_sr_gates.c) asserts five cases — `void` + unanalysed
among them — so `make -C substrate check` fails if the retired return-type model creeps
back. `hook_map.schema.json` requires `skippable` alongside `kind` for the same reason.
**Stubbed:** the `fn` dict's provenance — return type and signature come from DWARF, but every
`DISQUALIFYING` flag and `caller_null_checked` need real analysis.
**TODO(f5):** the side-effect analysis behind gate 1 — this is the genuinely hard static analysis in
the whole item list, and the honest v1 answer is probably **not to automate it**: hand-audit a
short list of candidate functions and annotate them in source, rather than trusting a tool to prove
absence of side effects across TMM. Also: the annotation mechanism for `const` cases (a source
attribute beside the function, not a spreadsheet).
**Why the two gates are separate — and why this was nearly a bug.** An earlier draft of this triage
classified by return type alone, so a `void` function went straight to *enforce-capable*. That is
wrong and it is the most dangerous mistake available here: **`void` tells you there is no return
value to fake, not that there are no side effects to lose.** A void function can take a lock, drop a
refcount, advance a parser, consume input, or fill an out-param — skip it and the caller proceeds
from a state that never happened, which is a worse failure than the crash being mitigated. The
worked CVE proves the point on its own terms: its vulnerable function returns nothing and *still*
does something the system wanted, which is why enforcing costs a log record. Gate 1 exists so that
cost is discovered before enforcement, not after.
**The honest boundary:** this table is where "skip the body" stops being free. The `rationale` field
records what is lost, per function, reviewed, and visible to whoever flips enforce.

---

# §3 · Control plane and F5 infrastructure

Conventional engineering — no novel machinery, and none of it on the data path.

## Item 8 · Budget pass

> **step 8** · runs at **admission, at F5** · written **once** · **tool**

Longest-path instruction count over the verified bytecode → a cycle estimate → compare against the
hook's budget → **fail closed**. A build artifact, off the data path. This is the layer that makes
"termination is not a time bound" *actionable at admission* — it is an estimate and a relative sanity
check, not a WCET bound, so it is the cheap half of time safety. The enforcement half is item 15's
back-edge fuel, at runtime.

**The block below is the original illustrative sketch, kept for contrast only — it has three bugs,
listed underneath, and the working implementation is a real file.** Read it as a record of what was
easy to get wrong, not as a specification.

```python
#!/usr/bin/env python3
"""
budget_pass.py — THE SKETCH (superseded; kept for contrast). The working version
is substrate/budget_pass.py.

Runs AFTER PREVAIL and BEFORE signing, so the signature attests that this gate
ran. Off the data path entirely.
"""
import struct, sys

CYCLES = {          # TODO(f5): calibrate per target uarch, then keep honest.
    "alu": 1, "jmp": 2, "load": 4, "store": 4, "call": 6, "exit": 1,
}
INSN_SZ = 8

def decode(blob):
    """BUG 1 & 2: assumes a fixed 8-byte stride over the whole FILE. eBPF's
    `lddw` is a 16-byte pseudo-instruction, and the first bytes of the file are
    \\x7fELF, not code. Both are fixed in the real version."""
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
    insns = decode(open(prog_path, "rb").read())    # BUG 1: reads the whole file
    blocks, edges = build_cfg(insns)                # BUG 3: `exit` not a terminator
    try:
        # BUG 4, and the fatal one: prevail_loop_bounds() cannot be written.
        # PREVAIL reports ONE AGGREGATE max_loop_count for the program, not a
        # per-loop trip count, so there is no per-loop bound to ask it for.
        cycles = longest_path(blocks, edges, prevail_loop_bounds(prog_path))
    except Unbounded as e:
        return fail("no proven trip count for the loop at pc=%d" % e.pc)

    budget = hook_map[hook]["budget_cycles"]
    if cycles > budget:
        return fail("worst case %d cycles exceeds %s's budget of %d"
                    % (cycles, hook, budget))
    return ok(cycles, budget)

# RETIRED ARITHMETIC — a bounded 64-iteration scan was priced here as
#   8 + 10*64 + 4 = 652 instructions  ~= 800 cycles
# and called "comfortably inside a cold hook's budget." Both halves were wrong.
# 652 instructions at 800 cycles is 1.23 cycles per instruction — below the
# cheapest entry in the CYCLES table above, and impossible for a loop whose body
# contains a load at 4. Priced honestly against that table, a 10-instruction body
# with one load and one back-edge costs ~14 cycles an iteration, so the program is
# ~900-1,100 cycles. And 800 is not "a cold hook's budget" with room to spare: it
# is DEFAULT_BUDGET in the real tool, i.e. the program EXCEEDS the cold budget it
# was claimed to fit inside. A sketch comparing a number to itself is exactly the
# failure the working implementation exists to prevent.
```

**This one is now real code, not a sketch.** [`substrate/budget_pass.py`](substrate/budget_pass.py)
parses a genuine eBPF ELF, decodes the stream, builds the CFG and prices the longest path — no
dependencies. It used to be run against three clang-built shield objects that lived in the prototype;
**those objects are gone with it, and the cycle counts they produced (6, 17 and 12) are no longer
reproducible here.** What `make -C substrate check` runs instead is the pass's own **self-test** — six
programs hand-assembled as raw eBPF and wrapped in a synthesized ELF in memory, each with an asserted
expected verdict, instruction count, block count and cost:

```
budget_pass self-test (hand-assembled eBPF in a synthesized ELF):
  ok   straight-line                  ok       2 insn · 1 blocks · 2 cycles
  ok   lddw is 16 bytes               ok       3 insn · 1 blocks · 6 cycles
  ok   branch diamond                 ok       4 insn · 3 blocks · 5 cycles
  ok   over budget rejects            REJECT   4 insn · 3 blocks · 5 cycles
  ok   loop is refused, not guessed   REFUSE   2 insn · 2 blocks · loop refused
  ok   load is priced above alu       ok       3 insn · 1 blocks · 6 cycles
```

Losing the real objects is a real loss — those were compiler output, and these are hand-written
instruction streams. But on the specific question of *whether this pass is correct* the self-test is
**better coverage than the objects ever gave**, and that is worth stating plainly rather than
conceding grudgingly: none of the three shields contained a `lddw` and none contained a loop, so the
16-byte instruction form and the loop refusal — two of the three bugs this rewrite fixed, and the two
hardest things in the decoder — **were never actually exercised by them**. Both are asserted cases
now, alongside a fail-closed over-budget rejection and a check that a load really is priced above an
ALU op. What the self-test cannot do is tell you what a real clang-emitted predicate costs; for that,
see the design conclusion below, which does not depend on the deleted objects.

Writing it for real fixed three bugs that were in the sketch above: it read the whole ELF *file* as
instructions (the first eight bytes are `\x7fELF`); it strided 8 bytes blindly, so `lddw` — a
**16-byte** pseudo-instruction — had its second half decoded as a phantom instruction, corrupting
every branch target after it; and it never treated `exit` as a block terminator, so blocks ran past
returns. It also refuses, rather than guesses, when it finds a loop back-edge: PREVAIL reports one
*aggregate* `max_loop_count`
(`ebpf-verifier/src/result.hpp`, `src/fwd_analyzer.cpp`), not a per-loop trip count, so there is
nothing sound to price a loop with.

**The design conclusion survives the loss of the measurement.** A shield of this kind is a handful of
loads, a compare and a return — single-digit to low-tens of cycles, which anyone can confirm by
counting instructions against the `CYCLES` table above without needing an object file to point at.
That is far below any plausible hook budget, and the consequence is the part worth carrying into the
design: for programs of this shape **the budget pass is not the binding constraint — the trampoline's
register save/restore is.** The thing to measure first is invocation overhead, not program cost. Note
the epistemic status honestly: this was previously stated with three measured objects behind it and is
now an instruction-count argument. The conclusion is unchanged and the support is weaker.

**Real:** eBPF's 8-byte encoding **with `lddw`'s 16-byte form**, the CFG-longest-path approach, and
the implementation in `substrate/`.
**Stubbed (in the retired sketch only):** `cls`, `topo`, `collapse_loops`, `block_cost`, `ok`/`fail`.
**Cannot exist — `prevail_loop_bounds()` is not "stubbed", it is unimplementable as specified.** The
sketch's design assumed a per-loop trip count it could ask PREVAIL for. PREVAIL exposes one
**aggregate** `max_loop_count` for the whole program (`ebpf-verifier/src/result.hpp`,
`src/fwd_analyzer.cpp`), which cannot attribute iterations to a particular back-edge, so there is
nothing sound to multiply a loop body by. The working tool therefore **refuses** any program with a
back-edge and cites the aggregate as the reason. Refusing is the correct answer, and it is a narrower
tool than the sketch promised: **loops are out of scope for admission pricing until something else
supplies per-loop bounds** — a source-level annotation the compiler preserves, or F5's own analysis
over the bytecode. Not a TODO on PREVAIL.
**TODO(f5):** per-microarchitecture cycle calibration — and publishing the calibration, because an
uncalibrated table makes this gate theatre.
**What it does and does not buy:** it bounds the *estimated* worst case at admission. It is an
estimate, not a measurement, and it says nothing about cache misses or a hostile memory state — which
is why time safety needs a runtime half. Per `engine-hard-problems.md` §1 that half is **back-edge
fuel (item 15, a uBPF JIT patch), and it is day one**, not "the second layer before any hot-path hook
is armed": a wall-clock deadline is *reporting*, not enforcement, and any hook reachable from
unauthenticated input is adversarially hot whatever its structural `path_class` says.

## Item 9 · Signing-service integration

> **step 9** · runs in **F5 infrastructure** · written **once** · **integration**

New manifest, existing infrastructure. The signature is what attests that verification and the budget
pass actually ran — so signing must be the *last* gate, and unconditional on the earlier ones.

```python
#!/usr/bin/env python3
"""
sign_shield.py — sign the BINDING, not just the bytecode.

The private key never leaves F5's HSM; TMM carries only the public half, baked
in at build time. sig_payload_serialize() here must stay byte-identical to the
in-TMM verifier's (item 4) — the two are one wire format with two readers, and
their field order is shield_abi.h's struct order.
"""
import hashlib, struct

HOOK_MAX, SIG_MAX = 64, 64

def binding_serialize(prog_sha256, hook, build_min, build_max,
                      mode_ceiling, expires_with):
    """The binding, canonical and fixed-width. No JSON, no ambiguity: the bytes a
    signature covers must have exactly one representation. Matches
    struct shield_binding's asserted offsets (0/32/96/100/104/108, sizeof 112)."""
    return (prog_sha256                                    # 32  @0
            + hook.encode().ljust(HOOK_MAX, b"\0")         # 64  @32, NUL-padded
            + struct.pack("<IIBxxxI", build_min, build_max,
                          mode_ceiling, expires_with))     # 16  @96, pad declared

def sig_payload_serialize(op, epoch, mode, prog_len, binding):
    """What the signature actually covers. The binding alone is NOT enough: op,
    epoch and mode must be inside it, or SET_MODE / STATUS / REVOKE arrive
    unauthenticated and a captured LOAD can be replayed after a REVOKE to
    re-arm a hook the operator just killed."""
    return struct.pack("<IIBxxxI", op, epoch, mode, prog_len) + binding

def sign(prog_path, op, epoch, hook, build_range, mode, mode_ceiling,
         expires_with, verify_report, budget_report):
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
    payload = sig_payload_serialize(op, epoch, mode, len(prog), binding)

    sig = hsm_sign(payload)          # TODO(f5): PKCS#11 to the release HSM
    assert len(sig) <= SIG_MAX
    audit("signed", hook=hook, op=op, epoch=epoch,
          sha=hashlib.sha256(prog).hexdigest(),
          builds=build_range, ceiling=mode_ceiling, expires=expires_with)
    return binding, sig
```

**Real:** the canonical fixed-width serialization — its field order and offsets are
[`shield_abi.h`](substrate/shield_abi.h)'s, `_Static_assert`-pinned there — SHA-256, and the
ordering rule (verify → budget → sign).
**Stubbed:** `hsm_sign`, `require`, `has_two_person_approval`, `audit`.
**TODO(f5):** PKCS#11 wiring to the existing release-signing HSM; where the verify/budget reports
live and how they are bound to a ticket; key rotation and how TMM learns a new public key (a build,
by construction); and who allocates `epoch` — it must be monotonic *per box*, which makes it a
property of the control-plane push, not of the signing run.
**Cross-check that matters:** `sig_payload_serialize` appears twice in this document on purpose — here
and in item 4. If they ever diverge, every shield fails to load. That is the correct failure direction,
but it argues for generating both from one definition, and it argues harder now that the payload is
the message preamble plus the binding rather than the binding alone.

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

/*
 * Build one message. The struct IS the contract — see shield_abi.h.
 *
 * Note what this function does NOT do: it does not set a hook name or an expiry.
 * Those live inside the signed binding, which the signing service (item 9)
 * produced and this daemon copies in whole and unmodified. There is no unsigned
 * second copy for the daemon to fill in, and that is deliberate — the daemon is
 * a courier, not an author. `epoch` is the one field it *does* own, because
 * monotonicity is a property of this box's push sequence.
 */
static struct shield_msg *msg_new(uint32_t op, uint32_t epoch, uint8_t mode,
                                  const struct shield_binding *binding,
                                  const uint8_t *prog, uint32_t prog_len,
                                  const uint8_t *sig, size_t *out_len)
{
    size_t len = sizeof(struct shield_msg) + prog_len;
    struct shield_msg *m = calloc(1, len);
    if (!m) return NULL;
    m->op       = op;
    m->epoch    = epoch;
    m->mode     = mode;
    m->prog_len = prog_len;
    m->binding  = *binding;                  /* the signed binding, verbatim */
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
        /* The unwind REVOKE has to be a SIGNED message, because TMM now
         * authenticates every op — the daemon cannot mint one. So it is
         * pre-issued alongside the LOAD it unwinds, at the next epoch, and held
         * for exactly this case. TODO(f5): pre-issued-revocation lifecycle. */
        struct shield_msg *rv = revoke_msg_for(m, &len);
        for (int i = 0; i < failed; i++)                  /* unwind the armed */
            tmm_config_send(i, rv, len, NULL, 0);
        free(rv);
        log_err("shield %s: instance %d rejected (%s); revoked all",
                shield_binding_of(m)->hook, failed,
                shield_strerror(replies[failed].rc));
        return replies[failed].rc;
    }
    return SHIELD_OK;
}

/* STATUS: sum the per-core evidence back into one view for the operator. Also a
 * signed op, for the same reason — a read-back an attacker can forge is a
 * read-back that can lie about whether a shield is armed. */
int shieldd_status(const char *hook, struct shield_status *out)
{
    size_t len;
    struct shield_msg *m = signed_status_msg_for(hook, &len);
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

**Real:** the message construction against the actual `struct shield_msg` — including `binding` copied
in whole and the absence of any writable `hook`/`expires_with` for the daemon to set — and the
all-or-nothing fan-out with unwind.
**Stubbed:** `tmm_instance_count`, `tmm_config_send`, `struct shield_reply`/`shield_status`,
`log_err`, `shield_strerror`, `revoke_msg_for`, `signed_status_msg_for`.
**TODO(f5):** identify the existing config-channel API and use it rather than adding one; decide
whether a mode mismatch across instances is an error or just a warning (it should be an error).
**The cost of authenticating every op, stated plainly.** Once `SET_MODE`, `STATUS` and `REVOKE` are
signed — and they must be, or `REVOKE` is defeatable by replay — the daemon can no longer synthesize
a control message. Every op needs a signature and an epoch from somewhere, which means either the
signing service issues an op set per shield up front (a pre-issued `REVOKE` at the next epoch, held
for the unwind path above) or the box holds a narrower operational key of its own. **That choice is a
TMA question and it is not settled here**; what is settled is that the earlier shape — one
authenticated op and three unauthenticated ones — is not an option.
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
    uint32_t epoch;              /* the replay guard's value — a rejected epoch is */
                                 /*   the record that says someone tried a replay  */
    uint32_t build_id;           /* the TMM build that accepted or rejected it     */
    int32_t  result;             /* enum shield_err: 0, or exactly why it failed   */
    uint64_t fired_at_change;    /* evidence at the moment of a mode change        */
};

void audit_emit(const struct shield_msg *m, int rc)
{
    struct shield_audit a = {
        .timestamp_ns = tmm_now_ns(),
        .build_id     = tmm_build_id(),
        .epoch        = m->epoch,
        .result       = rc,
    };
    snprintf(a.op,   sizeof a.op,   "%s", op_name(m->op));
    /* Through the accessor: the hook name exists only inside the binding. On a
     * rejection this is a CLAIMED hook — the signature is what makes it a fact,
     * and rc says whether it passed. Recording the claim is the point. */
    snprintf(a.hook, sizeof a.hook, "%s", shield_binding_of(m)->hook);
    control_plane_actor(a.actor, sizeof a.actor);      /* TODO(f5): TMOS identity */
    /* Safe on the rejection path too: prog_len was bounded against the received
     * datagram length before anything reached here (item 3, statement one). */
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
`mode_from`/`mode_to`, `epoch`, and `fired_at_change`, so a later reviewer can reconstruct *what
evidence existed when someone flipped enforce* — and, with `epoch` plus a `result` of "bad signature",
*that someone replayed a captured message*.
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
#include <stdint.h>                  /* the only include: nothing to call */

/* ctx = the hooked function's arguments AS RESOLVED SCALARS, from this build's
 * hook map. Generated, not hand-written — see item 6. Field offsets must match
 * the map's byte-for-byte; a build whose layout shifted is caught by the
 * ctx_abi_version check rather than silently mis-read. */
struct ctx {
    uint8_t  listener_present;       /* offset 0 */
    uint8_t  log_profile_present;    /* offset 1 */
    uint32_t flow_id;                /* offset 4 */
};

int shield(struct ctx *c)
{
    return !c->listener_present      /* two scalar loads, one branch, no loop */
        || !c->log_profile_present;  /* nonzero = crash-bound */
}
```

**Scalars, not pointers — and the program never sees a pointer at all.** The host's generated
ctx-builder walks the `conn_flow → listener → log profile` chain in **native C**, NULL-checked at each
step, and hands the program the answers. That is why this verifies: two loads at constant offsets
provably inside `ctx_size`, one short-circuiting branch, no back-edge, no call instruction. It is also
the same form the canon ships — `explainers/cve-shield-walkthrough.html` step 6.

> **What an earlier draft of this section printed, and why it was wrong.** It declared
> `struct ctx { struct conn_flow *cf; }` and wrote `c->cf ? c->cf->listener : 0`, then claimed
> "PREVAIL will not accept it without the guards." **That inverts what the verifier does.** A load out
> of `ctx` yields an unconstrained *number* (`ebpf-verifier/src/crab/ebpf_transformer.cpp`), and
> dereferencing a number is refused **unconditionally** — a NULL check cannot promote a number to a
> pointer. So that program is rejected **with or without** its guards, and the guards were never what
> made it acceptable. The verifier does not "stop the shield repeating the bug it is mitigating" by
> insisting on NULL checks; it refuses pointer-chasing outright, which is a stronger and much simpler
> property, and it is why the ctx-builder has to do the walking in host code.

**What this section used to claim, and cannot any more.** Printed alongside the product form above was
a second one: the prototype's own shield, cited by path under `prototype/shields/`, and described as
compiling, passing the PREVAIL gate and **executing end to end today**. That file has been removed
along with the rest of the prototype. **No shield in this repo compiles, verifies, or runs**, and this
was the single strongest piece of evidence the document had — the loss should be read as exactly that
rather than smoothed over. One qualification, in fairness to the reviewers rather than to the claim:
"passes the PREVAIL gate" was already weaker than it sounded, because that gate ran under the
`socket_filter` fallback (O3), so it never established that a TMM ctx model verifies.

Two things survive the file, because they are claims about *shapes* rather than about an artifact.
First, the signature uBPF imposes: `ubpf_exec` and the JIT both pass `(void *mem, size_t mem_len)`
(`ubpf/vm/inc/ubpf.h:510`), so any program actually run under uBPF receives its ctx as an untyped
memory pointer and casts, where the product form above takes a typed struct pointer. Second, the
mode-handling divergence noted below. The form looked like this — now **illustrative only, compiled
and verified by nothing in this repo**:

```c
uint64_t ls_decision(void *data)
{
    struct ls_ctx *ctx = data;
    if (ctx->opcode >= N_HANDLERS) {        /* the synthetic precondition */
        if (ctx->mode == LS_ENFORCE) return 2;   /* matched + drop    */
        return 1;                                /* matched + monitor */
    }
    return 0;                                    /* no match          */
}
```

**A divergence worth naming**, because it is a design point and not a property of the deleted file:
above, the *program* consults `mode` and picks among three verdict codes, whereas item 1 has the
*host* gate on `slot->mode` and the program return only a predicate. The product shape is the right
one — a program that reads its own mode is a program that can be confused about which mode it is in —
and the form above is what you get when there is no trampoline to hold the policy, which is precisely
the condition a prototype without one is in.
**Stubbed:** `struct ctx`'s field names come from the worked example, and the
real one is generated per build by item 6.
**TODO(f5):** nothing. This is the item that needs no new tooling — which is the point of the other
twelve.

---

# Staged tiers 13–17 — not coded here (except that **15 is day one**)

Items 13, 14, 16 and 17 are follow-ons. Two of them — 14 and 16 — already have a design, or the
mechanism they would be built on, elsewhere in this repo; 17 used to have a working implementation and
no longer does (see below). Coding them here would imply a commitment the scope doc deliberately
withholds. **Item 15
is not a follow-on** and is called out below.

- **13 · Rate-limited per-firing log line** — evidence tier 2, emitted from the trampoline (item 1).
  Needs a token bucket per shield and a decision about which sink; the counters in item 1 are the
  tier-1 answer and are already sufficient for "is this hook firing."
- **14 · Egress ring + drain agent** — already specified at code level, including the reserve/commit
  protocol and drop-and-count discipline, in
  [`data-plane-egress-primitives.md`](data-plane-egress-primitives.md) §5.3–§5.5. That document is the
  skeleton; duplicating it here would just create a second copy to keep in sync.
- **15 · Back-edge fuel — a uBPF JIT patch. DAY ONE, not a staged tier.**
  [`engine-hard-problems.md`](engine-hard-problems.md) §1. Three corrections to how this file used to
  file it. **(a) Fuel is the mechanism, not the optional extra.** uBPF's own API states that
  `ubpf_set_instruction_limit` *"has no effect on JIT'd programs"* (`ubpf/vm/inc/ubpf.h`), so
  enforcing a bound means **patching uBPF's JIT** — F5-owned, upstreamable, and the one place the
  "reused as-is" claim does not hold. **(b) Wall-clock is *reporting*, not enforcement**, so naming
  the deliverable "wall-clock deadline" named the unmeasurable half: on aarch64 the counter ticks at
  tens of MHz (10–40 ns granularity) against a hot hook's budget of tens of nanoseconds.
  **(c) "The worked example's cold log-site hook does not need it" was the `path_class` error** — a
  log function on a malformed-input path is the path an attacker drives, i.e. adversarially `hot`, so
  it needs fuel more than a steady-state packet hook does. Item 8 alone does **not** suffice for day
  one; it is the admission estimate, and this is the runtime enforcement. Known corner: the
  instruction limit *does* work in uBPF's **interpreter**, so an interpreter-only high-assurance build
  has enforceable fuel today with no fork.
- **16 · Canary auto-unload** — health-metric-driven auto-revoke, `engine-hard-problems.md` §4. The
  mechanism it needs already exists: `SHIELD_OP_REVOKE` (item 3) is the action; what is missing is the
  policy that decides to fire it.
- **17 · Authoring DSL** — a bpftrace-style one-liner front-end: parse a one-liner, generate C, compile
  it, run the verify gate, load it. **Proposed and unbuilt.** This entry previously read "already
  exists as working code" and cited a prototype front-end that parsed a one-liner and drove the whole
  pipeline; that tool has been removed, so item 17 is now a follow-on like 13, 14 and 16 rather than
  the one item on the list with an implementation behind it. Left deliberately unnamed here — the
  removed tool's name read as a shipped TMM component, which is what caused the confusion that removed
  it. It stays an authoring convenience either way: it emits the same bytecode the C path does, so
  nothing in items 1–12 depends on it and it adds no security surface of its own.

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
  substrate's real engineering surface, exactly as `engine-hard-problems.md` §2 says. And the 40 lines
  now sit in front of a decision they cannot make: PREVAIL has no `--program-type`, so the choice is
  reuse its `tracing` type or own a patch set with a per-release rebase cost.

**And one amendment that is not honest, it is a retraction.** This section used to close: "Nothing in
items 1–12 is a subsystem on the scale of writing a VM or a verifier. That remains the whole point of
reusing uBPF and PREVAIL." The first sentence is retired. Nobody writes a VM, a verifier or a
compiler — that reuse is real, and narrow. What is being built instead is a **code-patching,
live-text, dynamic-code-loading facility inside the crown-jewel process**, carrying a build-pipeline
toolchain and a permanent per-build ABI, and needing a fork of one of the three reused components to
get time safety at all (item 15). Sized honestly that is **subsystem-scale work** for a
defensible v1 on two architectures, plus the TMA and certification engagement
([`engine-hard-problems.md`](engine-hard-problems.md) §6.1). No month figure is offered anywhere in
this package, on purpose: it is a proposal, not a plan. The item list in
these two documents is right; the size classes are shape, not effort, and reviewed against what each
item actually requires they are low — in several cases badly, and two of the largest items were missing altogether.

---

*Candidate code for review — not TMM source, and not a commitment to an implementation. Detailed
method & claims are held in a separate invention disclosure.*
