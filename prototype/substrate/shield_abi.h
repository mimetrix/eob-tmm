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
 *   - shield_jit_fn          <-> uBPF's compiled program (ubpf_compile, step 10)
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
#define SHIELD_BINDING_WIRE_MAX 128u       /* 32 + 64 + 13, rounded up             */
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

/* The loader message — one struct carries the whole contract.
 * Field order, types and comments are the walkthrough's canon, verbatim.
 * NOTE: `mode` leaves 3 bytes of implicit padding before `expires_with`. Kept
 * as-is for canon fidelity; a real wire format would either declare that pad
 * explicitly or serialize field-by-field. The asserts below pin the layout. */
struct shield_msg {
    uint32_t op;            /* LOAD · SET_MODE · STATUS · REVOKE */
    char     hook[64];      /* named symbol to attach at */
    uint8_t  mode;          /* MONITOR · ENFORCE */
    uint32_t expires_with;  /* encoded build id (17.5.2 at the CLI) → auto-retire */
    uint32_t prog_len;
    uint8_t  sig[64];       /* F5 signature — covers prog + its binding (step 9) */
    uint8_t  prog[];        /* the verified bytecode */
};

_Static_assert(offsetof(struct shield_msg, op)           ==   0, "shield_msg layout");
_Static_assert(offsetof(struct shield_msg, hook)         ==   4, "shield_msg layout");
_Static_assert(offsetof(struct shield_msg, mode)         ==  68, "shield_msg layout");
_Static_assert(offsetof(struct shield_msg, expires_with) ==  72, "shield_msg pad");
_Static_assert(offsetof(struct shield_msg, prog_len)     ==  76, "shield_msg layout");
_Static_assert(offsetof(struct shield_msg, sig)          ==  80, "shield_msg layout");
_Static_assert(sizeof(struct shield_msg)                 == 144, "shield_msg header size");

/* Per-hookable-function: what a skipped body hands back (item 7, step 3). A v1
 * only arms enforce-capable boundaries whose kind is VOID or ZERO. */
enum shield_sr_kind {
    SR_NONE  = 0,           /* not enforce-capable: observe only                   */
    SR_VOID  = 1,           /* void function — nothing to synthesize              */
    SR_ZERO  = 2,           /* return 0 / NULL is the benign no-op for this fn     */
    SR_CONST = 3,           /* return an enumerated benign constant (see .value)   */
};

struct shield_sr_policy {
    uint8_t  kind;          /* enum shield_sr_kind                                 */
    uint64_t value;         /* SR_CONST only: the benign value to return           */
};

/* uBPF's compiled program. This is uBPF's real JIT signature (mem + mem_len);
 * the walkthrough's trampoline block writes jit_fn(&ctx) and elides mem_len. */
typedef uint64_t (*shield_jit_fn)(void *mem, size_t mem_len);

/* One armable patchable entry, resolved from this build's signed hook map.
 * `fired` is indexed by core: TMM is core-pinned, so each core increments only
 * its own slot — no atomics needed, but pad to a cache line in a real build to
 * avoid false sharing (see item 1's note in development-scope-code.md). */
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
    uint64_t fired[SHIELD_MAX_CORES];      /* per-core evidence, both modes         */
};

/*
 * Host-side entry points — declarations only; every body is a stub in this repo.
 *
 * shield_msg_handle() runs at TMM's safe point between poll-loop iterations,
 * never mid-packet, and is fan-out per TMM instance/core by the loader daemon.
 * sig_verify() checks the whole binding, not just the program bytes.
 */
int  shield_msg_handle(const struct shield_msg *msg);              /* item 3      */
int  sig_verify(const struct shield_msg *msg, const void *pubkey); /* item 4      */
struct hook_slot *hook_map_lookup(const char *hook);               /* item 5 out  */
int  trampoline_arm(struct hook_slot *slot, shield_jit_fn fn, int mode); /* item 2 */
int  trampoline_disarm(struct hook_slot *slot);                    /* item 2      */

#endif /* SHIELD_ABI_H */
