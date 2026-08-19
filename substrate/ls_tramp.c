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
 * Status: LIVE. ls_tramp_dispatch is reached from a patched function entry on every
 * armed hook, on a running TMM under traffic. This comment read "candidate artifact...
 * Nothing calls it" until 2026-08-18 --- true before arming was built, and the opposite
 * of true since.
 */

#include "ls_vm.h"
#include "ls_arm.h"
#include "ls_slots.h"
#include "ls_ctx_reg.h"
#include "ls_ctx_parse.h"
#include "ls_ctx_alpn_abi.h"
#include "ls_ctx_rst.h"
#include "ls_ctx_h2abort.h"
#include "ls_ctx_sslerr.h"
#include "ls_flow_cookie.h"
#include "ls_ssl_cookie.h"
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
ls_tramp_dispatch(int slot, const struct ls_regs *regs)
{
    struct ls_tramp_result r = { LS_TRAMP_FALLTHROUGH, 0 };

    /*
     * ALL SIX arguments, via a pointer to the block the trampoline already saved
     * (Phase 3). The named accessors in ls_arm.h exist because the block is in
     * STACK order, which is the reverse of ABI order --- indexing it by argument
     * position would silently swap arguments rather than fail.
     *
     * regs is NULL only if something other than the trampoline called this. Guard
     * rather than trust: a fall-through is always a safe answer.
     */
    uint64_t a0, a1, a2, a3, a4, a5;

    if (regs == 0)
        return r;

    a0 = LS_ARG0(regs);
    a1 = LS_ARG1(regs);
    a2 = LS_ARG2(regs);
    a3 = LS_ARG3(regs);
    a4 = LS_ARG4(regs);
    a5 = LS_ARG5(regs);
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

    /* SIX ARGUMENTS FOR A BUILDER, assembled from the NAMED accessors and not by indexing
     * regs. The saved block is in STACK order, which is the reverse of ABI order, so
     * indexing it by argument position silently swaps arguments rather than failing --- which
     * is exactly what ls_arm.h's accessors exist to prevent. Building the array here keeps
     * every builder from having to know that, and keeps the knowledge in one place. */
    const unsigned long long args[6] = { a0, a1, a2, a3, a4, a5 };

    ctx.arg[0] = a0;
    ctx.arg[1] = a1;
    ctx.arg[2] = a2;
    ctx.arg[3] = a3;
    ctx.arg[4] = a4;

    /*
     * PER-HOOK CTX, LOOKED UP RATHER THAN SWITCHED ON.
     *
     * The generic five-register form above is what an untyped program sees. It is useless for
     * a hook whose interesting fields are behind pointers, because a verified program cannot
     * chase one --- so the dereferencing happens HERE, in the host, and the program receives
     * flat scalars, which is the case PREVAIL already proves.
     *
     * WHAT THIS REPLACED, and why it had to go. This was an if-chain on the SLOT NUMBER:
     * slot 7 got the parse builder, slots 2/3/5/6 the reset builder, and so on. That is
     * correct only while every armed function is one of the handful with a builder. It stops
     * being correct the moment a probe is generated for an arbitrary function, because the
     * generated program lands in whichever slot is free. On 2026-08-19,
     * mrhttp_setup_new_serverside armed in slot 2 had its registers read as rst_why's
     * arguments: the count was exact, every field was fiction, and a1 was dereferenced as a
     * string for up to 256 bytes. mrhttp's a1 happened to be a readable pointer.
     *
     * The builder now comes from the slot, resolved AT ARM TIME from the hook the program
     * declared in its own ELF section --- so a function nobody wrote a builder for gets the
     * register block and no dereference, which is what mk_probe.py generates against. See
     * ls_ctx_reg.h.
     *
     * ONE INDIRECT CALL on the data path, not a search: the pointer was resolved when the
     * slot was armed. A string compare over the registration set per invocation would be a
     * real cost on a hook that fires per request.
     */
    {
        const struct ls_ctx_reg *reg = ls_vm_ctx_reg(slot);

        if (reg == 0) {
            /* No typed builder. The generic ctx, and nothing is dereferenced. */
            if (ls_vm_call(slot, &ctx, sizeof ctx) != LS_SAFE_RETURN)
                return r;
        } else {
            /* One buffer for every builder, bounded by LS_CTX_OUT_MAX. Sized from the
             * registration rather than from a per-hook struct so this file does not need to
             * know any hook's layout --- it did, and that coupling is what made the if-chain
             * grow a branch per hook. */
            unsigned char out[LS_CTX_OUT_MAX];
            unsigned long n;

            /* A builder may write at most LS_CTX_OUT_MAX. The registration asserts its own
             * size at compile time, so this is a belt-and-braces bound against a builder
             * whose struct grew without its _Static_assert being updated. Refusing is right:
             * a truncated record is a record with wrong fields. */
            if (reg->size > sizeof out)
                return r;

            n = reg->build(out, args);
            if (n == 0)
                return r;              /* the builder declined --- see ls_ctx_reg_alpn.c */

            if (reg->hook_id == 0u) {
                /* No ring identity, so run the program without publishing. ALPN is the case:
                 * its record is a verdict input, not telemetry. Publishing under a zero
                 * hook id would give the consumer a record it cannot decode. */
                if (ls_vm_call(slot, out, n) != LS_SAFE_RETURN)
                    return r;
            } else if (ls_tp_dispatch(slot, out, n, reg->hook_id) != LS_SAFE_RETURN) {
                /* ls_tp_dispatch runs the program AND publishes to the shared-memory ring,
                 * so an entry-armed hook produces a stream and not only counters. The ring
                 * is off unless LS_TP_RING names a segment. */
                return r;
            }
        }
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
