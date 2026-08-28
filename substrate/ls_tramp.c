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
    uint64_t a0, a1, a2, a3, a4;

    if (regs == 0)
        return r;

    a0 = LS_ARG0(regs);
    a1 = LS_ARG1(regs);
    a2 = LS_ARG2(regs);
    a3 = LS_ARG3(regs);
    a4 = LS_ARG4(regs);
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

    /*
     * ONE PATH: the generic five-register context. There are no typed, per-hook ctx builders
     * any more. A program reads whatever fields it needs from the argument pointers via CO-RE
     * relocations resolved at load against this build's own BTF (ls_core_relo.c), so the host
     * never learns any hook's layout --- which is what removed the "burns a build per data
     * source" coupling: adding a data source is writing bytecode now, not editing TMM. An
     * arbitrary armed function therefore gets exactly this: the register block, nothing
     * dereferenced.
     */
    if (ls_vm_call(slot, &ctx, sizeof ctx) != LS_SAFE_RETURN)
        return r;

    /*
     * The safe value belongs to the SLOT (item 7). v1 carries one configured
     * value per slot (ls_vm_safe_value, set from LS_SHIELD_SAFE_VALUE at arm) ---
     * not yet the full per-return-type policy table, but enough that an err_t
     * hook returns ERR_BUF instead of 0. Zero was right for a pointer/BOOL hook
     * and wrong for one whose caller treats 0 as success, which converts a crash
     * into silent misbehaviour: dtls_tx is precisely that case (0 == ERR_OK).
     */
    r.verdict    = LS_TRAMP_SAFE_RETURN;
    r.safe_value = ls_vm_safe_value(slot);
    return r;
}
