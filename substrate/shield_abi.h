/*
 * shield_abi.h — the substrate ABI: loader message, signed binding, hook slot.
 *
 * This header is the contract between four parties:
 *   1. the control-plane loader that fills a shield_msg (walkthrough step 10),
 *   2. TMM's safe-point handler that consumes it (step 10, dev-scope item 3),
 *   3. the trampoline armed at a patchable function entry (step 2, item 1), and
 *   4. F5's signing service, which signs the binding — not just the bytes (step 9).
 *
 * It is the product-side counterpart of the prototype's ls_shield.h:
 *   - struct shield_msg      <-> the loader message family (LOAD/SET_MODE/STATUS/REVOKE)
 *   - struct shield_binding  <-> what the signature covers (step 9; design §5.3)
 *   - struct shield_sr_policy<-> the per-build safe-return table (step 3; item 7)
 *   - struct hook_slot       <-> one armable patchable entry + its per-core evidence
 *   - shield_jit_fn          <-> uBPF's compiled program (ubpf_compile_ex, step 10)
 *
 * SCOPE — this is a candidate ABI for review, not TMM source. The uBPF types it
 * names are real; every f5_* / tmm_* touchpoint it declares is a stub. See
 * ../../development-scope-code.md for the per-item skeletons that use it, and
 * README.md in this directory for what is real vs. illustrative here.
 */
#ifndef SHIELD_ABI_H
#define SHIELD_ABI_H

#include <stdint.h>
#include <stddef.h>

#define SHIELD_ABI_VERSION    1u
#define SHIELD_HOOK_NAME_MAX  64u          /* bytes, NUL-padded, in msg + binding  */
#define SHIELD_SIG_MAX        64u          /* Ed25519-sized; widen for P-384/RSA   */
#define SHIELD_SHA256_LEN     32u
#define SHIELD_MAX_CORES      128u         /* CMP fan-out ceiling for counters     */
#define SHIELD_MAX_SHIELDS     64u         /* concurrently loaded shields          */
/* Bytes the signing service serialises and signs: the message preamble through the
 * end of the binding. NOTE the arithmetic — 16 (op..prog_len) + 112 (binding) is
 * EXACTLY 128, so this leaves zero headroom: adding one field to either the preamble
 * or the binding overflows a buffer sized by this constant. The comment it replaced
 * said "32 + 64 + 13, rounded up", which described an earlier binding that no longer
 * exists. TODO(f5): derive it rather than hard-code it —
 *   sizeof(struct shield_msg) - sizeof(((struct shield_msg *)0)->sig) - 0  */
#define SHIELD_BINDING_WIRE_MAX 128u
/* Bytes of entry pad arm/disarm may touch. TODO(f5): per-arch — x86-64 needs at
 * least 5 for a rel32 JMP; aarch64 needs 4 for a B (plus a veneer past ±128 MiB).
 * The per-hook truth is patchable_pad_bytes in the signed hook map. */
#define SHIELD_PAD_MAX          8u

/* Loader operations (walkthrough step 10). The canon spells these bare —
 * LOAD · SET_MODE · STATUS · REVOKE — prefixed here to keep the C namespace
 * clean; see the naming-reconciliation table in development-scope-code.md. */
enum shield_op {
    SHIELD_OP_LOAD     = 1, /* verify sig -> load -> JIT -> arm dark, then monitor */
    SHIELD_OP_SET_MODE = 2, /* promote/demote within the binding's mode_ceiling    */
    SHIELD_OP_STATUS   = 3, /* read back per-core fire counters (step 12)          */
    SHIELD_OP_REVOKE   = 4, /* disarm every core — the kill switch                 */
};

/* Operational modes. MODE_MONITOR is the canon spelling (trampoline_arm's third
 * argument); the walkthrough's trampoline block writes bare MONITOR/ENFORCE. */
enum shield_mode {
    MODE_DISABLE = 0,       /* armed but inert: predicate not run                  */
    MODE_MONITOR = 1,       /* run predicate, count firings, touch nothing         */
    MODE_ENFORCE = 2,       /* run predicate, take the host's safe outcome         */
};

/* What a verified program returns. 1 = the crash precondition holds. */
enum shield_verdict {
    SHIELD_VERDICT_NOMATCH = 0,
    SHIELD_VERDICT_MATCH   = 1,
};
#define MATCH SHIELD_VERDICT_MATCH         /* canon spelling (trampoline block)    */

/* What the trampoline hands back to the patched function's prologue. */
enum shield_disposition {
    TRAMP_FALLTHROUGH  = 0, /* run the original body, unchanged                    */
    TRAMP_SAFE_RETURN  = 1, /* skip the body; return per the safe-return policy    */
};
#define SAFE_RETURN TRAMP_SAFE_RETURN      /* canon spelling (trampoline block)    */

/* Load-path failures. Every one leaves the hook DARK — there is no partial arm.
 * SHIELD_ERR_SIG is the canon code; the rest are the paths the sketch elides. */
enum shield_err {
    SHIELD_OK           =  0,
    SHIELD_ERR_SIG      = -1, /* signature or binding mismatch — the perimeter     */
    SHIELD_ERR_BUILD    = -2, /* this TMOS build outside binding build_min..max    */
    SHIELD_ERR_EXPIRED  = -3, /* expires_with already reached — auto-retire        */
    SHIELD_ERR_CEILING  = -4, /* requested mode exceeds the binding's ceiling      */
    SHIELD_ERR_HOOK     = -5, /* hook name absent from this build's hook map       */
    SHIELD_ERR_LOAD     = -6, /* ubpf_load rejected the bytecode                   */
    SHIELD_ERR_JIT      = -7, /* ubpf_compile failed                               */
    SHIELD_ERR_BUDGET   = -8, /* admission budget for this hook exceeded (item 8)  */
    SHIELD_ERR_NOMEM    = -9,
    SHIELD_ERR_REPLAY   = -10, /* epoch did not strictly advance — replayed op   */
    SHIELD_ERR_BUSY     = -12, /* hook already armed — see the note on hook_slot */
    SHIELD_ERR_MASKED   = -13, /* would be unreachable behind another armed hook */
    SHIELD_ERR_ARMEDCOST= -14, /* global armed-cost ceiling would be exceeded    */
    SHIELD_ERR_TRUNC    = -11, /* prog_len disagrees with the received length   */
};

/* What the signature covers — the binding, not just the bytecode (step 9). A
 * signed shield therefore cannot be replayed at another hook, on another build,
 * or escalated past the mode it was authorized for. */
struct shield_binding {
    uint8_t  prog_sha256[SHIELD_SHA256_LEN];   /* hash of the verified bytecode    */
    char     hook[SHIELD_HOOK_NAME_MAX];       /* valid at this named symbol only  */
    uint32_t build_min;                        /* on these TMOS builds only ...    */
    uint32_t build_max;                        /* ... inclusive                    */
    uint8_t  mode_ceiling;                     /* enum shield_mode: may it enforce?*/
    uint32_t expires_with;                     /* encoded build id -> auto-retire  */
};

/* The loader message.
 *
 * An earlier draft of this struct reproduced the walkthrough's field list
 * verbatim — op, hook, mode, expires_with, prog_len, sig, prog — and a review
 * caught that it therefore could not carry what its own comment said the
 * signature covered. `sig` was documented as committing to "prog + its binding"
 * (program hash + hook + build range + mode ceiling + expiry), but three of those
 * five fields were nowhere in the message, so the accessor the loader skeleton
 * called — `shield_binding_of()` — could not be written at all. Three
 * consequences make this a correctness fix rather than a tidy:
 *
 *   1. The binding is now embedded, so the signature has something to commit to
 *      and every field it covers is present to be checked.
 *   2. `hook` and `expires_with` are deliberately NOT duplicated at the top
 *      level. Carrying a field both inside and outside the signed binding raises
 *      "which one wins?", and the answer is always the signed one — so the
 *      unsigned copy is a liability with no use.
 *   3. `epoch` is new, and it is the replay guard. Without it a captured LOAD can
 *      be replayed after a REVOKE, which defeats the kill switch outright. The
 *      signature covers `op`, `mode` and `epoch` so SET_MODE, STATUS and REVOKE
 *      are authenticated too; the earlier shape authenticated only LOAD, leaving
 *      three unauthenticated control operations.
 *
 * `prog_len` is attacker-influenced until the signature checks out, so the
 * receiver's FIRST statement must validate it against the actual received
 * datagram length — before hashing `prog`, not as part of doing so. */
struct shield_msg {
    uint32_t op;                    /* LOAD · SET_MODE · STATUS · REVOKE        */
    uint32_t epoch;                 /* monotonic per box; replay guard          */
    uint8_t  mode;                  /* requested mode: MONITOR · ENFORCE        */
    uint8_t  _pad[3];               /* declared, not implicit                   */
    uint32_t prog_len;              /* UNTRUSTED until sig_verify succeeds      */
    struct shield_binding binding;  /* what the signature commits to (step 9)   */
    uint8_t  sig[SHIELD_SIG_MAX];   /* over op, epoch, mode, prog_len, binding, prog */
    uint8_t  prog[];                /* the verified bytecode                    */
};

_Static_assert(offsetof(struct shield_binding, prog_sha256)  ==   0, "binding layout");
_Static_assert(offsetof(struct shield_binding, hook)         ==  32, "binding layout");
_Static_assert(offsetof(struct shield_binding, build_min)    ==  96, "binding layout");
_Static_assert(offsetof(struct shield_binding, build_max)    == 100, "binding layout");
_Static_assert(offsetof(struct shield_binding, mode_ceiling) == 104, "binding layout");
_Static_assert(offsetof(struct shield_binding, expires_with) == 108, "binding pad");
_Static_assert(sizeof(struct shield_binding)                 == 112, "binding size");

_Static_assert(offsetof(struct shield_msg, op)       ==   0, "shield_msg layout");
_Static_assert(offsetof(struct shield_msg, epoch)    ==   4, "shield_msg layout");
_Static_assert(offsetof(struct shield_msg, mode)     ==   8, "shield_msg layout");
_Static_assert(offsetof(struct shield_msg, prog_len) ==  12, "shield_msg layout");
_Static_assert(offsetof(struct shield_msg, binding)  ==  16, "shield_msg layout");
_Static_assert(offsetof(struct shield_msg, sig)      == 128, "shield_msg layout");
_Static_assert(offsetof(struct shield_msg, prog)     == 192, "shield_msg header size");
_Static_assert(sizeof(struct shield_msg)             == 192, "shield_msg header size");

/* The accessor the loader skeleton needs. Now expressible, because the binding
 * is in the message. Returns the SIGNED copy — there is no other. */
static inline const struct shield_binding *
shield_binding_of(const struct shield_msg *msg)
{
    return &msg->binding;
}

/* Per-hookable-function: what a skipped body hands back (item 7, step 3).
 *
 * TWO GATES, IN THIS ORDER. An earlier draft of this enum classified a function
 * by its return type alone, which inverted the difficulty: by that reading
 * `void` looked trivially safe, because there is no value to fake. In fact
 * `void` is the HARDEST case — a void function is called entirely for its side
 * effects, so skipping it discards all of them and the signature tells you
 * nothing about what they were. A function returning an error code is often
 * easier, because the caller already has a path for the failure value.
 *
 * So `skippable` is gate 1, and it is decided independently of the return type:
 * does not running the body leave TMM consistent? Is a lock held across it, does
 * a refcount move, does flow state advance, is an input buffer consumed, does
 * anything downstream read an out-param the body was to fill, is memory
 * allocated? CLOSED BY DEFAULT — a body that has not been analysed is not
 * safe-returnable, and "we could not find a problem" is not "there is none".
 * Only once gate 1 passes does `kind` — gate 2, what value to synthesize —
 * matter at all. check_sr_gates.c asserts this so it cannot silently regress. */
enum shield_skippable {
    SKIP_UNANALYSED = 0,    /* default: NOT enforce-capable. Observe only.         */
    SKIP_NO         = 1,    /* analysed, and the body has effects that must run    */
    SKIP_YES        = 2,    /* analysed: no caller-visible effect is lost          */
};

enum shield_sr_kind {
    SR_NONE  = 0,           /* gate 2 not reached (see enum shield_skippable)      */
    SR_VOID  = 1,           /* void function — no value to synthesize, which says  */
                            /*   nothing about gate 1. See the comment above.      */
    SR_ZERO  = 2,           /* return 0 / NULL is the benign no-op for this fn     */
    SR_CONST = 3,           /* return an enumerated benign constant (see .value)   */
};

struct shield_sr_policy {
    uint8_t  skippable;     /* enum shield_skippable — GATE 1, checked first        */
    uint8_t  kind;          /* enum shield_sr_kind    — GATE 2                      */
    uint64_t value;         /* SR_CONST only: the benign value to return            */
};

/* A hook is enforce-capable only if BOTH gates passed. Expressed here so that no
 * caller can accidentally re-derive it from the return type alone. */
static inline int
shield_sr_enforce_capable(const struct shield_sr_policy *sr)
{
    return sr->skippable == SKIP_YES && sr->kind != SR_NONE;
}

/* uBPF's compiled program.
 *
 * This is `ubpf_jit_ex_fn`, uBPF's EXTENDED JIT signature, and the extra two
 * parameters are the whole point. uBPF offers two modes:
 *
 *   BasicJitMode    -> ubpf_jit_fn    = (void *mem, size_t mem_len)
 *   ExtendedJitMode -> ubpf_jit_ex_fn = (void *mem, size_t mem_len,
 *                                        uint8_t *stack, size_t stack_len)
 *
 * The basic form is the one whose prologue does an unconditional
 * `sub rsp, UBPF_EBPF_STACK_SIZE` with no stack probe — a 4 KiB frame taken at
 * arbitrary depth in TMM's call graph, able to step clean over a single guard
 * page. So the basic form is unusable here, and an earlier version of this
 * typedef used it anyway while a comment claimed it was "uBPF's real JIT
 * signature". It is one of two real signatures, and the wrong one.
 *
 * The extended form takes the program stack per call, which is what lets the
 * trampoline hand over a per-core preallocated stack. Obtain it from
 * `ubpf_compile_ex(vm, &err, ExtendedJitMode)`. See design-review-findings.md O7. */
typedef uint64_t (*shield_jit_fn)(void *mem, size_t mem_len,
                                  uint8_t *stack, size_t stack_len);

/* One armable patchable entry, resolved from this build's signed hook map.
 * `fired` is indexed by core: TMM is core-pinned, so each core increments only
 * its own slot — no atomics needed, but pad to a cache line in a real build to
 * avoid false sharing (see item 1's note in development-scope-code.md).
 *
 * ONE PROGRAM PER HOOK, AND THAT IS A DECISION, NOT AN ACCIDENT OF THIS STRUCT.
 * There is a single `fn`, so a second LOAD naming an armed hook must be REFUSED
 * with SHIELD_ERR_BUSY. It must not overwrite: silently replacing a live shield
 * disarms a mitigation the operator believes is running, and resets its fire
 * counter to zero, so the evidence of the swap looks exactly like "no matches."
 * Replacing a shield is REVOKE then LOAD, explicitly. Chaining several programs
 * at one hook is deferred, because the hard part is not the plumbing but
 * declaring a total order over the outcome set — without one, behaviour depends
 * on load order, and load order depends on config-sync arrival order, which is
 * not the same on two HA peers. See engine-hard-problems.md §3.1. */
struct hook_slot {
    char     hook[SHIELD_HOOK_NAME_MAX];   /* named symbol (hook-map key)          */
    void    *entry;                        /* patchable-entry address from the map */
    shield_jit_fn fn;                      /* JIT'd once at load, not per packet   */
    uint8_t  armed;                        /* nop pad currently overwritten?       */
    uint8_t  pad_len;                      /* patchable_pad_bytes for this hook    */
    uint8_t  mode;                         /* enum shield_mode                     */
    uint8_t  mode_ceiling;                 /* from the signed binding              */
    uint32_t expires_with;                 /* auto-retire build                    */
    struct shield_sr_policy sr;            /* what a skipped body returns          */
    uint8_t  masked_by_armed;              /* another armed hook's SAFE-RETURN can  */
                                           /*   skip the body containing this hook. */
                                           /*   Report STATUS as `masked`, NEVER as */
                                           /*   zero fires — zero reads as "nothing */
                                           /*   matched", which is the opposite of  */
                                           /*   the truth (§3.1).                   */
    uint32_t budget_cycles;                /* this hook's admission allowance; the  */
                                           /*   loader also tracks a GLOBAL armed   */
                                           /*   cost, because a flow pays the SUM   */
                                           /*   of the hooks it traverses (§3.1).   */
    uint64_t fired[SHIELD_MAX_CORES];      /* per-core evidence, both modes         */
};

/*
 * Host-side entry points — declarations only; every body is a stub in this repo.
 *
 * shield_msg_handle() runs at TMM's safe point between poll-loop iterations,
 * never mid-packet, and is fanned out per TMM instance/core by the loader daemon.
 * sig_verify() checks the whole binding, not just the program bytes.
 *
 * BOTH TAKE `len` — the number of bytes actually received — and that is not
 * decoration. `msg->prog_len` is attacker-influenced until the signature checks
 * out, so a receiver handed only a pointer has no way to validate it and the rule
 * "check prog_len first" is unenforceable. With `len` present the first statement
 * can be a real check, returning SHIELD_ERR_TRUNC. Likewise sig_verify() needs
 * `len` to know how many bytes of prog[] to hash.
 */
int  shield_msg_handle(const struct shield_msg *msg, size_t len);  /* item 3      */
int  sig_verify(const struct shield_msg *msg, size_t len,
                const void *pubkey);                               /* item 4      */
struct hook_slot *hook_map_lookup(const char *hook);               /* item 5 out  */
int  trampoline_arm(struct hook_slot *slot, shield_jit_fn fn, int mode); /* item 2 */
int  trampoline_disarm(struct hook_slot *slot);                    /* item 2      */

#endif /* SHIELD_ABI_H */
