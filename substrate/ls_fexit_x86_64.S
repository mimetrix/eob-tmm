/*
 * ls_fexit_x86_64.S --- the FUNCTION-EXIT trampoline, System V AMD64.
 *
 * ===================================================================
 *  WHAT THIS ADDS over the ENTRY trampoline (trampoline_x86_64.S)
 * ===================================================================
 *
 * The entry trampoline runs BEFORE a hooked function's body and can skip it.
 * This one runs AFTER the body, so a program can read the RETURN VALUE and the
 * function's post-execution state, and so a duration can be timed entry->exit.
 *
 * There is no pad at a function's exit --- a `ret` is one byte, and a function
 * has many of them --- so exit is done the only way it can be: HIJACK THE RETURN
 * ADDRESS, from the entry pad we already have. This is exactly how the kernel's
 * kretprobes, frida, and bpftime implement a return probe.
 *
 * ===================================================================
 *  THE STACK, STEP BY STEP  (this is the whole trick; get it wrong silently)
 * ===================================================================
 *
 * A caller does `call hooked_fn`, pushing CALLER-RETURN. hooked_fn's first bytes
 * are the 5-byte pad, now `call ls_fexit_entry`, pushing BODY-RETURN. So when we
 * arrive here:
 *
 *      [rsp]    = BODY-RETURN     (into the hooked fn's real body)
 *      [rsp+8]  = CALLER-RETURN   <-- the slot we overwrite
 *
 * ls_fexit_entry records {slot address, the real caller-return, the args} on a
 * shadow stack keyed by the SLOT ADDRESS, then overwrites [rsp+8] with the
 * address of ls_fexit_stub. It restores the args and `ret`s into the body. The
 * body runs untouched; its own final `ret` now lands in ls_fexit_stub instead of
 * the caller. The stub reads the return value, pops the matching shadow frame
 * (reclaiming any deeper frame a non-local exit skipped), runs the exit program,
 * and returns to the REAL caller with the return value intact.
 *
 * ===================================================================
 *  TWO EDGES THAT BITE, both handled below
 * ===================================================================
 *
 *   IBT.  The entry trampoline is a `call` target, so it starts with endbr64.
 *   The exit STUB is reached by a `ret` (from the body), and it returns to a
 *   POST-CALL address, which is never an endbranch. So the stub must NOT reach
 *   the caller with an indirect `jmp *reg` --- that faults on CET. It uses
 *   `push real_ret ; ret`, because RET is governed by the shadow stack (off here;
 *   the build is -fcf-protection=branch, IBT only), not by IBT.
 *
 *   16-BYTE ALIGNMENT.  The pad's `call` fires at the hooked fn's entry, where
 *   rsp % 16 == 8, so ls_fexit_entry is entered with rsp % 16 == 0. Every push
 *   count below is chosen to keep the C calls' rsp % 16 == 0, asserted by the
 *   harness rather than assumed.
 *
 * Status: candidate artifact, proven in check_fexit.c on x86-64 hardware (arms a
 * stand-in, exercises nesting, recursion, and a longjmp-skipped return). NOT yet
 * wired into TMM --- that is the (kind,slot) dispatch split, a ctx that carries
 * the return value, and the arm-time exclusion of unwind-traversable targets.
 */

    .text
    .globl  ls_fexit_entry
    .type   ls_fexit_entry, @function
ls_fexit_entry:
    .cfi_startproc
    endbr64                         /* IBT: this IS a `call` target (the pad).   */

    /*
     * Save the six integer-argument registers so the exit program can be handed
     * the function's ARGUMENTS alongside its return value, and so the body sees
     * them unchanged. Pushed so the lowest address holds rdi --- i.e. the block
     * reads as args[0]=rdi .. args[5]=r9, the order the C side expects.
     */
    pushq   %r9
    .cfi_adjust_cfa_offset 8
    pushq   %r8
    .cfi_adjust_cfa_offset 8
    pushq   %rcx
    .cfi_adjust_cfa_offset 8
    pushq   %rdx
    .cfi_adjust_cfa_offset 8
    pushq   %rsi
    .cfi_adjust_cfa_offset 8
    pushq   %rdi
    .cfi_adjust_cfa_offset 8
    /*
     * Now, from rsp upward:
     *     0  rdi  8  rsi  16 rdx  24 rcx  32 r8  40 r9
     *    48  BODY-RETURN
     *    56  CALLER-RETURN     <-- the slot ls_fexit_enter will hijack
     *
     * rsp % 16 == 0 here (entry was 0; six pushes = 48, 48 % 16 == 0), so the
     * call below is correctly aligned with no adjustment.
     */
    leaq    56(%rsp), %rdi          /* arg0: uint64_t *slot (addr of caller-ret) */
    leaq    0(%rsp),  %rsi          /* arg1: const uint64_t *args (rdi..r9)      */
    call    ls_fexit_enter          /* records the frame; writes *slot = &stub   */

    /* Restore the args and fall into the body. The `ret` targets BODY-RETURN;
     * the CALLER-RETURN slot now holds &ls_fexit_stub, so the body's own ret
     * will reach the stub. */
    popq    %rdi
    .cfi_adjust_cfa_offset -8
    popq    %rsi
    .cfi_adjust_cfa_offset -8
    popq    %rdx
    .cfi_adjust_cfa_offset -8
    popq    %rcx
    .cfi_adjust_cfa_offset -8
    popq    %r8
    .cfi_adjust_cfa_offset -8
    popq    %r9
    .cfi_adjust_cfa_offset -8
    ret                             /* -> BODY-RETURN, into the hooked fn body   */
    .cfi_endproc
    .size   ls_fexit_entry, .-ls_fexit_entry

/*
 * The stub the body returns INTO. Reached by the body's `ret`, which popped the
 * hijacked slot, so:
 *     rax(:rdx) = the hooked function's return value
 *     rsp       = (address of the hijacked slot) + 8   == "cur" below
 *     rsp % 16  == 0
 *
 * NO endbr64: a `ret` target is not IBT-checked, and this is never a call/jmp
 * target. Preserve rax:rdx (the return value) across the C call; punt on the
 * x87/SSE return registers exactly as the entry trampoline punts on FP state.
 */
    .globl  ls_fexit_stub
    .type   ls_fexit_stub, @function
ls_fexit_stub:
    .cfi_startproc
    pushq   %rax                    /* save return value (low)                   */
    pushq   %rdx                    /* save return value (high, for i128/struct) */
    /* rsp % 16 == 0 again (two pushes). "cur" = rsp at stub entry = here + 16. */
    leaq    16(%rsp), %rdi          /* arg0: uint64_t cur (SP just after the ret)*/
    movq    8(%rsp),  %rsi          /* arg1: uint64_t retval (the saved rax)     */
    call    ls_fexit_leave          /* returns the REAL caller-return in rax     */
    movq    %rax, %r11              /* stash it; r11 is dead at a return boundary */
    popq    %rdx                    /* restore return value (high)               */
    popq    %rax                    /* restore return value (low)                */
    pushq   %r11                    /* real caller-return -> stack               */
    ret                             /* -> the real caller (IBT-safe: it's a ret) */
    .cfi_endproc
    .size   ls_fexit_stub, .-ls_fexit_stub

    .section .note.GNU-stack,"",@progbits
