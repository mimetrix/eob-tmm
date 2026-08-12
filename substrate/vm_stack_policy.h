/*
 * vm_stack_policy.h --- item 6a, resolved the way uBPF actually supports.
 *
 * The problem: PREVAIL proves memory safety against a *declared* per-subprogram
 * stack frame (its `subprogram_stack_size`, default 512). uBPF then executes the
 * program with a frame size of its own. If those disagree the proof is valid and
 * about different hardware, which is the one failure a signing gate cannot catch.
 *
 * The fix is NOT to pick 256 or 512 and hope both sides keep it. uBPF exposes
 *
 *     ubpf_register_stack_usage_calculator(vm, calculator, cookie)
 *
 * and calls it during load for every local function, using the result to adjust
 * r10 on entry (vm/ubpf_vm.c:872 in the interpreter, ubpf_jit_x86_64.c:1827 and
 * ubpf_jit_arm64.c:1260 in the JITs). So the host can make the runtime allocate
 * *exactly what the verifier proved against*, by construction rather than by two
 * constants coincidentally agreeing.
 *
 * Two things in uBPF's contract to know before relying on it. Both are the
 * permissive direction, and both are the opposite of what its own header says:
 *
 *   ubpf.h --- "If the callback returns 0 or there is no callback registered,
 *   the eBPF interpreter/JITer assume that the local function uses the maximum
 *   stack available according to the spec (512K)."
 *
 *   (1) With no calculator registered, ubpf_stack_usage_for_local_func() returns
 *       UBPF_EBPF_LOCAL_FUNCTION_STACK_SIZE --- 256, not a maximum.
 *   (2) A calculator returning 0 is recorded as UBPF_STACK_USAGE_CUSTOM with value
 *       0, so the accessor returns 0 and the function gets a ZERO-BYTE frame. The
 *       16-byte alignment guard passes it (0 % 16 == 0) and nothing else rejects
 *       it, in the interpreter or either JIT.
 *
 * So a calculator must never return 0 to mean "I don't know" --- that is the value
 * the documentation calls safest and the code treats as smallest.
 *
 * Status: candidate artifact. It compiles and asserts its own invariants. It is
 * not wired into a VM here --- nothing in this repo instantiates or runs a shield.
 */

#ifndef VM_STACK_POLICY_H
#define VM_STACK_POLICY_H

#include <stdint.h>

/* uBPF requires every frame size to be 16-byte aligned (vm/ubpf_vm.c:2384) and
 * fails the load otherwise, so the policy rounds UP rather than discovering this
 * at load time. */
#define VM_STACK_ALIGN 16u

/* uBPF's own ceiling: UBPF_EBPF_STACK_SIZE is UBPF_MAX_CALL_DEPTH * 512 = 4096,
 * so a frame can never usefully exceed 4096 / depth. Named rather than inlined so
 * the relationship survives an upstream change. */
#define VM_STACK_TOTAL      4096u
#define VM_STACK_MAX_DEPTH     8u

/* What PREVAIL was actually told. This must be the value passed to
 * `prevail --stack-size N`, not a guess about its default --- the default is 512
 * and the runtime fallback is 256, which is exactly the divergence this removes. */
struct vm_stack_policy {
    uint16_t proven_frame;   /* bytes per subprogram, as verified   */
    uint16_t max_depth;      /* call frames, as verified            */
};

static inline uint16_t
vm_stack_align_up(uint16_t n)
{
    return (uint16_t)((n + (VM_STACK_ALIGN - 1u)) & (uint16_t)~(VM_STACK_ALIGN - 1u));
}

/* Is this a policy uBPF can honour? Checked at admission, not at load: a policy
 * that fails here means the verify step and the runtime disagree, and the program
 * must be refused rather than run under whichever bound happens to win. */
static inline int
vm_stack_policy_valid(const struct vm_stack_policy *p)
{
    if (p == 0)
        return 0;
    if (p->proven_frame == 0)               /* the zero-frame trap above */
        return 0;
    if (p->max_depth == 0 || p->max_depth > VM_STACK_MAX_DEPTH)
        return 0;
    if (vm_stack_align_up(p->proven_frame) != p->proven_frame)
        return 0;
    if ((uint32_t)p->proven_frame * (uint32_t)p->max_depth > VM_STACK_TOTAL)
        return 0;
    return 1;
}

/*
 * The calculator. uBPF's typedef is:
 *
 *     typedef int (*stack_usage_calculator_t)(const struct ubpf_vm *vm,
 *                                            uint16_t pc, void *cookie);
 *
 * This one takes `const void *` for the first parameter, because this header
 * must stay checkable without uBPF's headers present. That makes it a DIFFERENT
 * function pointer type, NOT assignable to the typedef --- the host writes a
 * one-line forwarding function (see ls_vm.c). Do not convert the pointer to fit:
 * calling through a converted incompatible function pointer is undefined
 * behaviour, and gcc will warn about exactly this if you try.
 *
 * Deliberately uniform: every local function gets the frame the verifier proved
 * against, because that is the only bound the proof covers. Per-function
 * refinement would need per-function evidence, and PREVAIL reports one bound for
 * the program.
 *
 * NEVER returns 0. Given no valid policy it returns the largest frame uBPF can
 * give at max depth --- the conservative direction the header wrongly attributes
 * to 0. A load that cannot be handed a valid policy should be refused upstream;
 * this is the backstop, not the gate.
 */
static inline int
vm_stack_usage(const void *vm_unused, uint16_t pc_unused, void *cookie)
{
    const struct vm_stack_policy *p = (const struct vm_stack_policy *)cookie;

    (void)vm_unused;
    (void)pc_unused;

    if (!vm_stack_policy_valid(p))
        return (int)(VM_STACK_TOTAL / VM_STACK_MAX_DEPTH);

    return (int)p->proven_frame;
}

/* Pinned so a change to the constants fails the build rather than silently
 * widening what is admitted. */
_Static_assert(VM_STACK_TOTAL % VM_STACK_MAX_DEPTH == 0,
               "total stack must divide evenly by max depth");
_Static_assert((VM_STACK_TOTAL / VM_STACK_MAX_DEPTH) % VM_STACK_ALIGN == 0,
               "the fallback frame must satisfy uBPF's 16-byte alignment");
_Static_assert(VM_STACK_ALIGN != 0u && (VM_STACK_ALIGN & (VM_STACK_ALIGN - 1u)) == 0u,
               "alignment must be a power of two for the round-up to be correct");

#endif /* VM_STACK_POLICY_H */
