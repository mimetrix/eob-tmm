/*
 * ls_tramp.c --- the C half of the patched-entry trampoline.
 *
 * The assembly in trampoline_x86_64.S is generic: it saves the ABI's argument
 * registers, calls this, and acts on the verdict. Everything PER-HOOK lives
 * here, in C, because the ctx layout is generated from the build's DWARF
 * (development-scope.md item 6) and changes whenever a hooked function's
 * signature does. Putting it in assembly would mean regenerating assembly per
 * hook, which is the cost this split exists to avoid.
 *
 * Status: candidate artifact. It compiles. Nothing calls it --- arming (item 2)
 * is what would write the jump that reaches the assembly that reaches this.
 */

#include "ls_vm.h"
#include "ls_arm.h"
#include "ls_slots.h"
#include "ls_ctx_parse.h"
#include "ls_ctx_alpn_abi.h"
#include "ls_ctx_rst.h"
#include "ls_tp.h"

/* Slot numbers live in ls_slots.h, checked for collisions by the compiler. They
 * were here as a bare macro whose value (0, the shield slot) contradicted the
 * comment above it (7) --- so slot 0 got the parse ctx instead of the generic
 * register ctx. See ls_slots.h. */

#include <stdint.h>
#include <string.h>

/* What the assembly expects back. rax carries this; rdx carries the safe value
 * when it is 1. Kept as plain ints because the asm reads eax. */
#define LS_TRAMP_FALLTHROUGH 0
#define LS_TRAMP_SAFE_RETURN 1

/*
 * Called with the hooked function's first five integer arguments, exactly as
 * the ABI delivered them, before its prologue ran.
 *
 * The returned safe_value is what the hooked function's caller should see if we
 * skip the body; the assembly moves it to rax. What counts as safe is per-hook
 * and belongs to the safe-return policy table (item 7); a slot carries its own.
 *
 * Returns LS_TRAMP_SAFE_RETURN to skip the hooked function entirely.
 */
/*
 * Returned in rax:rdx by the System V ABI --- which is precisely the pair the
 * assembly reads. An earlier draft took a seventh `uint64_t *safe_out`
 * argument; the ABI puts a seventh argument on the STACK, while the call site
 * passes only six registers, so the callee would have dereferenced whatever
 * happened to be at that address. Returning the pair removes the mismatch by
 * construction rather than by both sides remembering the same convention.
 */
/* struct ls_tramp_result lives in ls_arm.h */

struct ls_tramp_result
ls_tramp_dispatch(int slot, uint64_t a0, uint64_t a1, uint64_t a2,
                  uint64_t a3, uint64_t a4)
{
    struct ls_tramp_result r = { LS_TRAMP_FALLTHROUGH, 0 };
    /*
     * The ctx is a per-invocation stack copy, never a view onto the argument
     * registers or onto TMM state. PREVAIL cannot express a read-only region,
     * so a verified program can write every byte of what it is handed
     * (finding O1); handing it the live frame would make the safety mechanism
     * an argument-injection primitive.
     *
     * Sized and shaped per hook in the real thing --- generated alongside the
     * hook map. This generic five-slot form is what an untyped `tracing`
     * program sees, and it is deliberately flat: no pointers out.
     */
    struct {
        uint64_t arg[5];
    } ctx;

    ctx.arg[0] = a0;
    ctx.arg[1] = a1;
    ctx.arg[2] = a2;
    ctx.arg[3] = a3;
    ctx.arg[4] = a4;

    /* Per-hook ctx. The generic five-register form above is what an untyped
     * program sees and is useless for most hooks, because nearly every TMM
     * function takes pointers and a verified program cannot chase one. So the
     * dereferencing happens HERE, in the host, and the program receives flat
     * scalars --- which is the canonical case PREVAIL already proves.
     *
     * Slot-selected rather than table-driven: one generated ctx, deliberately,
     * until this shape is proven end to end. LS_CTX_SLOT_PARSE is the hook
     * survey found to be the only one on this traffic's path
     * (http_parse_client_headers, 1:1 with requests). */
    if (slot == LS_CTX_SLOT_PARSE) {
        struct ls_ctx_parse pc;
        ls_ctx_build_parse(&pc, (const void *)a0, (const void *)a2);
        if (ls_vm_call(slot, &pc, sizeof pc) != LS_SAFE_RETURN)
            return r;
    } else if (slot == LS_CTX_SLOT_RST) {
        /* rst_why(uf, file, lineno, err, reason, rst_cause) --- every field is a
         * direct argument, so no derivation and nothing to snapshot before it is
         * overwritten. a5 (rst_cause) is NOT here: System V puts it in r9 and the
         * trampoline forwards only five. file:line identifies the site anyway. */
        struct ls_ctx_rst rc;
        ls_ctx_rst_build(&rc, (const char *)a1, (unsigned int)a2,
                         (unsigned int)a3, (unsigned int)a4);
        /* ls_tp_dispatch, not ls_vm_call: it runs the program AND publishes the
         * record to the shared-memory ring, so an entry-armed hook produces a
         * stream rather than only counters. The ring is off unless LS_TP_RING
         * names a segment. */
        if (ls_tp_dispatch(slot, &rc, sizeof rc, LS_TP_HOOK_RST) != LS_SAFE_RETURN)
            return r;
    } else if (slot == LS_CTX_SLOT_ALPN) {
        /* ssl_alpn_match(sc, skip_ext, skip_ext_len): the ALPN bytes are NOT an
         * argument --- the function derives them from `sc` in its first ten
         * lines. The builder repeats that derivation one step earlier, in the
         * ssl module's include world (ls_ctx_alpn.c), and hands back flat bytes.
         *
         * A zero return means there is no ALPN list to judge. Fall through
         * WITHOUT running the program: judging bytes that do not exist would
         * make the verdict noise rather than a finding. */
        unsigned char ac[LS_CTX_ALPN_SZ];
        if (ls_ctx_alpn_build_v(ac, (void *)a0) == 0)
            return r;
        if (ls_vm_call(slot, ac, sizeof ac) != LS_SAFE_RETURN)
            return r;
    } else if (ls_vm_call(slot, &ctx, sizeof ctx) != LS_SAFE_RETURN) {
        return r;
    }

    /*
     * TODO(f5): the safe value belongs to the slot, from the safe-return policy
     * table. Zero is right for a pointer-returning or BOOL-returning hook and
     * wrong for one whose caller treats 0 as success --- which is exactly why
     * item 7 exists and why v1 is restricted to trivial returns. Returning a
     * wrong "safe" value is worse than not shielding: it converts a crash into
     * silent misbehaviour.
     */
    r.verdict    = LS_TRAMP_SAFE_RETURN;
    r.safe_value = 0;
    return r;
}
