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
struct ls_tramp_result {
    int      verdict;
    uint64_t safe_value;
};

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

    if (ls_vm_call(slot, &ctx, sizeof ctx) != LS_SAFE_RETURN)
        return r;

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
