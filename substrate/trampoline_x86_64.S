/*
 * trampoline_x86_64.S --- the patched-entry trampoline, System V AMD64.
 *
 * ===================================================================
 *  WHY THIS EXISTS, given that the VM already works without it
 * ===================================================================
 *
 * The integration built on 2026-08-12 uses a DESIGNED-IN call site: 39 lines of
 * C added to http_psm.c, where the compiler owns the calling convention and the
 * shim is arch-generic C. That works, and it needs none of this file.
 *
 * This is for the other claim --- attaching to a function NOBODY EDITED. There
 * the compiler reserved a few bytes at the entry and arming rewrites them into a
 * CALL to here. There is no C frame to borrow, so everything the ABI says a
 * caller may rely on has to be preserved by hand. That is the whole content of
 * this file, and it is why development-scope.md calls item 1 badly understated
 * at "a page of asm per arch": the assembly is short, the ABI edge cases are not.
 *
 * ===================================================================
 *  MEASURED FACTS ABOUT THE TARGET --- not assumptions
 * ===================================================================
 *
 * From the BNK build of tmm/tmm at e2104734a9, x86-64
 * (tmm64.no_pgo, build-id verified against its own debug file):
 *
 *   1. IBT IS ON.  403 of 500 sampled functions begin with `endbr64`
 *      (f3 0f 1e fa).  Any indirect branch to a location without an endbranch
 *      faults on CET hardware, so THIS TRAMPOLINE MUST START WITH ONE, and the
 *      patch must not destroy the target's own.
 *
 *   2. THE PAD SITS AFTER endbr64.  With -fpatchable-function-entry=5,0 the
 *      nops are emitted after the entry label, and with IBT they land after the
 *      endbranch:  f3 0f 1e fa  90 90 90 90 90
 *      That is why FIVE is the right pad: `call rel32` is exactly 5 bytes
 *      (e8 xx xx xx xx), so arming replaces the nops in place and DISPLACES NO
 *      REAL INSTRUCTION.  Nothing has to be relocated or re-executed --- which
 *      removes the single largest source of complexity in this kind of hook.
 *
 *      IT MUST BE `call`, NOT `jmp`, and an earlier draft of this file said
 *      jmp.  A jmp pushes nothing, so the `ret` on the fall-through path below
 *      would return to the hooked function's CALLER --- i.e. it would silently
 *      behave as a safe return, always, and the body would never run.  `call`
 *      pushes the address of the instruction after the patch, which IS the
 *      body, so `ret` continues into it.  Verified on hardware, not reasoned:
 *      see check-tramp, which patches a stand-in function and asserts that the
 *      body runs on fall-through and does not on safe return.
 *
 *   3. ARGUMENTS MOVE IMMEDIATELY.  A real target begins
 *          mov %rcx,%r12 ; push %rbp ; mov %rdx,%rbp ; push %rbx ; sub $0x28,%rsp
 *      so the argument registers are consumed within the first few instructions.
 *      The trampoline therefore runs BEFORE the prologue and must capture them
 *      first; there is no later point at which rdi/rsi/rdx/rcx still hold the
 *      arguments.
 *
 *   4. .eh_frame IS PRESENT.  A core dump taken while a shield is running must
 *      still unwind, so this file carries CFI directives.  Without them the
 *      backtrace stops here, and "the crash we were shielding is now
 *      undebuggable" is not an acceptable trade.
 *
 * ===================================================================
 *  WHAT THIS FILE DOES NOT DO
 * ===================================================================
 *
 *   - It does not save FP/SIMD state.  See the note at ls_tramp_save_fp below:
 *     that is a real decision, not an omission, and it is wrong for any hook
 *     whose shield might touch floating point.
 *   - It does not handle varargs (%rax as the vector-register count).
 *   - It does not implement the safe-return path's value selection --- the host
 *     decides what a safe return means per hook (development-scope.md item 7);
 *     this returns the value the hook slot carries.
 *   - It is NOT re-entrant.  ls_vm.c hands every invocation the same per-instance
 *     program stack, which is safe only because TMM is run-to-completion and two
 *     invocations never overlap on a core.  A shield that re-entered its own
 *     hooked path would corrupt that stack.  Guarding it is on item 1's list.
 *   - It is not wired to anything.  Arming (item 2) writes the jump; nothing here
 *     writes code.
 *
 * Status: candidate artifact.  It assembles.  Nothing calls it.
 */

    .text
    .globl  ls_trampoline_entry
    .type   ls_trampoline_entry, @function

/*
 * Reached by the 5-byte `call rel32` written over the patch nops.  On entry the
 * stack and registers are exactly as the hooked function's caller left them,
 * except that the call has pushed the address of the instruction AFTER the
 * patch --- i.e. the hooked function's real body.
 *
 * REACH: `call rel32` spans +/-2GB from the patch site.  TMM's .text is ~30MB,
 * so a trampoline living in .text is always in range.  A trampoline in
 * mmap'd memory is NOT guaranteed to be, and five bytes cannot hold an indirect
 * call --- so either the trampoline is linked into the image, or arming must
 * allocate its trampolines within +/-2GB of .text and fail closed when it
 * cannot.  That constraint belongs to item 2 and is easy to miss until a large
 * ASLR offset makes it intermittent.
 */
ls_trampoline_entry:
    .cfi_startproc
    endbr64                         /* fact 1: IBT. Without this, the indirect
                                     * branch faults on CET hardware. */

    /*
     * Fact 3: capture the argument registers before anything else can clobber
     * them.  System V AMD64 integer arguments, in order:
     *     rdi rsi rdx rcx r8 r9
     * rax additionally carries the vector-register count for varargs calls,
     * which this file does not support --- see the header.
     */
    pushq   %rdi
    .cfi_adjust_cfa_offset 8
    pushq   %rsi
    .cfi_adjust_cfa_offset 8
    pushq   %rdx
    .cfi_adjust_cfa_offset 8
    pushq   %rcx
    .cfi_adjust_cfa_offset 8
    pushq   %r8
    .cfi_adjust_cfa_offset 8
    pushq   %r9
    .cfi_adjust_cfa_offset 8
    pushq   %rax
    .cfi_adjust_cfa_offset 8

    /*
     * Caller-saved registers the shield path may clobber.  r10 and r11 are
     * scratch under the ABI, so the hooked function cannot rely on them --- but
     * WE are running before the hooked function, on behalf of its caller, and
     * the caller cannot rely on them either.  Saved anyway: the cost is two
     * pushes, and the failure mode if this reasoning is ever wrong is a
     * miscompile-class bug that would take days to find.
     */
    pushq   %r10
    .cfi_adjust_cfa_offset 8
    pushq   %r11
    .cfi_adjust_cfa_offset 8

    /*
     * Align to 16 before the call.  Nine pushes above (72 bytes) plus the 8-byte
     * return address leaves rsp ≡ 0 (mod 16) already, but the alignment is
     * asserted rather than assumed, because getting it wrong shows up only when
     * the callee happens to use an aligned SSE move.
     */
    subq    $8, %rsp
    .cfi_adjust_cfa_offset 8

    /*
     * ls_tramp_dispatch(slot, arg0..arg5) --- plain C, in ls_tramp.c.
     *
     * The ctx build lives in C on purpose.  It is per-hook, generated from the
     * build's DWARF (item 6), and changes whenever a hook's signature does;
     * putting it in assembly would mean regenerating assembly per hook, which is
     * the thing this design is trying to avoid.  The assembly is generic; only
     * the C is per-hook.
     *
     * THE SLOT INDEX IS A PATCHED IMMEDIATE, not a register.
     *
     * An earlier draft of this file said the slot "arrives in r11".  That is
     * wrong: at hook entry r11 holds whatever the hooked function's CALLER left
     * there.  Nothing has put a slot index in it, and reading it would feed the
     * dispatcher garbage.
     *
     * This is one trampoline per armed hook, so the slot is known when the
     * trampoline is created.  `movl $imm32` puts it in the instruction stream;
     * arming (item 2) writes the four bytes at ls_tramp_slot_imm.  A single
     * SHARED trampoline is the alternative and would have to recover the slot
     * from the return address --- possible, slower, and a trade that belongs to
     * item 2 rather than here.
     */
    .globl  ls_tramp_slot_insn
ls_tramp_slot_insn:                 /* arming rewrites the 4 bytes at +1        */
    movl    $0x7fffffff, %edi       /* slot --- placeholder, patched at arm     */
    /*
     * The label sits on the INSTRUCTION, not on the immediate.  An earlier draft
     * used `ls_tramp_slot_imm = . + 1` to point straight at the four bytes;
     * the code was correct, but a symbol in the middle of an instruction makes
     * objdump restart disassembly there and render everything after it as
     * garbage --- in the one file whose whole audience is someone reading a
     * disassembler.  Arming adds the +1 itself; that is one line in item 2
     * against permanently unreadable output here.
     */
    /*
     * Stack layout at this point, from rsp upward.  Nine pushes (72 bytes) then
     * `sub $8`, so the saved registers begin at 8(%rsp):
     *
     *    0  alignment gap      40  r8
     *    8  r11                48  rcx
     *   16  r10                56  rdx
     *   24  rax                64  rsi
     *   32  r9                 72  rdi   <- the hooked function's arg0
     *   80  return address (into the hooked function's body)
     *
     * An earlier draft had every one of these eight bytes low --- it read rsi as
     * rdi, rdx as rsi, and so on.  That does not crash; it silently hands the
     * shield the wrong arguments, which is the worst way for this to be wrong.
     */
    movq    72(%rsp), %rsi          /* saved rdi = hooked function's arg0      */
    movq    64(%rsp), %rdx          /* saved rsi = arg1                        */
    movq    56(%rsp), %rcx          /* saved rdx = arg2                        */
    movq    48(%rsp), %r8           /* saved rcx = arg3                        */
    movq    40(%rsp), %r9           /* saved r8  = arg4                        */

    /*
     * Returns a {int verdict; uint64_t safe_value} pair, which System V returns
     * in rax:rdx --- exactly the registers the code below reads.  An earlier
     * draft passed a seventh `safe_out` POINTER argument, which the ABI would
     * have placed on the stack while this call site passed only six registers:
     * the callee would have dereferenced whatever happened to be there.
     */
    call    ls_tramp_dispatch       /* -> eax: 0 fall through, 1 safe return   */
                                    /*    rdx: the declared safe value          */

    addq    $8, %rsp
    .cfi_adjust_cfa_offset -8

    testl   %eax, %eax
    jnz     .Lsafe_return

    /*
     * Fall through: restore everything and continue into the hooked function's
     * real body.  Fact 2 is what makes this trivial --- the patch overwrote only
     * nops, so the body is intact and the return address already points at it.
     * `ret` therefore lands exactly where execution would have gone had nothing
     * been armed.
     */
    popq    %r11
    .cfi_adjust_cfa_offset -8
    popq    %r10
    .cfi_adjust_cfa_offset -8
    popq    %rax
    .cfi_adjust_cfa_offset -8
    popq    %r9
    .cfi_adjust_cfa_offset -8
    popq    %r8
    .cfi_adjust_cfa_offset -8
    popq    %rcx
    .cfi_adjust_cfa_offset -8
    popq    %rdx
    .cfi_adjust_cfa_offset -8
    popq    %rsi
    .cfi_adjust_cfa_offset -8
    popq    %rdi
    .cfi_adjust_cfa_offset -8
    ret

.Lsafe_return:
    /*
     * Safe return: the hooked function's body must NOT run.  Discard the saved
     * registers, drop the return address that points into the body, and return
     * to the hooked function's own caller with the declared safe value.
     *
     * ls_tramp_dispatch leaves that value in rdx --- chosen because rax already
     * carries the verdict.  What counts as safe is per-hook and belongs to the
     * safe-return policy table (item 7); this file only delivers it.
     *
     * THE LIMIT WORTH STATING: this is correct only for a return type that fits
     * in rax.  A struct returned by hidden pointer, or anything using rdx:rax or
     * the x87/SSE return registers, needs its own path.  Item 7 restricts v1 to
     * trivial returns for exactly this reason, and this file enforces nothing ---
     * admitting a shield on a hook with a non-trivial return type is an
     * admission-time error, not a runtime one.
     */
    addq    $72, %rsp               /* discard the nine saved registers        */
    .cfi_adjust_cfa_offset -72
    movq    %rdx, %rax              /* the declared safe value                 */
    addq    $8, %rsp                /* drop the return-into-body address       */
    .cfi_adjust_cfa_offset -8
    ret                             /* -> the hooked function's caller         */

    .cfi_endproc
    .size   ls_trampoline_entry, .-ls_trampoline_entry

/*
 * FP/SIMD, deliberately absent.
 *
 * Saving xmm0-15 costs ~256 bytes of stack and 16 stores/loads per invocation,
 * on a path whose whole budget is ~26 cycles (the measured JIT floor).  It would
 * dominate.  It is omitted here because uBPF's generated code does not touch
 * SSE --- but that is a property of TODAY'S uBPF, not a guarantee, and it does
 * not hold if a helper is ever added that does.
 *
 * So this is a bet, and it should be an explicit one: either the admission
 * pipeline proves the program touches no FP state, or the trampoline pays for
 * it.  Choosing silently is how a rare, data-dependent corruption gets shipped.
 */
    .section .note.GNU-stack,"",@progbits
