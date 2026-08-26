/*
 * fexit_victims.S --- stand-in functions for the exit-trampoline harness.
 *
 * Each begins exactly as an armed TMM function would: endbr64, then a 5-byte
 * `call ls_fexit_entry` where -fpatchable-function-entry left its pad, then the
 * real body. That is byte-for-byte what arming an exit hook produces, so the
 * harness exercises the true mechanism, not a model of it.
 *
 * Shapes, chosen to hit each way the shadow stack can be stressed:
 *   xv_leaf   --- one call, one exit          (return value + transparency)
 *   xv_mid    --- calls xv_leaf, both armed    (nested: exits unwind LIFO)
 *   xv_rec    --- recurses n deep, all armed    (depth + ordering)
 *   xv_jumps  --- longjmps out, skipping its exit (the reclaim path)
 *
 * Alignment: each is entered at rsp%16==8; the exit trampoline is transparent on
 * fall-through, so the body starts at rsp%16==8 too. A body that itself makes a
 * call aligns to %16==0 first (one push, or sub $8).
 */
    .text

/* ---- xv_leaf: returns 0x1EAF; no inner call --------------------------------- */
    .globl  xv_leaf
    .type   xv_leaf, @function
xv_leaf:
    .cfi_startproc
    endbr64
    call    ls_fexit_slot1          /* the 5-byte pad --- armed at slot 1 (distinct) */
    movq    $0x1EAF, %rax
    ret                             /* -> ls_fexit_stub (caller-ret was hijacked) */
    .cfi_endproc
    .size   xv_leaf, .-xv_leaf

/* ---- xv_mid: calls xv_leaf (also armed), returns leaf + 0x100 = 0x1FAF ------- */
    .globl  xv_mid
    .type   xv_mid, @function
xv_mid:
    .cfi_startproc
    endbr64
    call    ls_fexit_entry          /* the pad */
    subq    $8, %rsp                 /* align rsp%16: 8 -> 0 before the inner call */
    .cfi_adjust_cfa_offset 8
    call    xv_leaf                  /* nested armed call -> rax = 0x1EAF          */
    addq    $8, %rsp
    .cfi_adjust_cfa_offset -8
    addq    $0x100, %rax             /* rax = 0x1FAF                               */
    ret                             /* -> ls_fexit_stub                           */
    .cfi_endproc
    .size   xv_mid, .-xv_mid

/* ---- xv_rec(n): returns n; recurses n deep, every level armed --------------- */
    .globl  xv_rec
    .type   xv_rec, @function
xv_rec:
    .cfi_startproc
    endbr64
    call    ls_fexit_entry          /* the pad */
    testq   %rdi, %rdi
    jne     1f
    xorq    %rax, %rax               /* n == 0 -> return 0 */
    ret
1:
    pushq   %rdi                     /* save n; align rsp%16: 8 -> 0 */
    .cfi_adjust_cfa_offset 8
    decq    %rdi
    call    xv_rec                   /* rax = n-1 */
    popq    %rdi
    .cfi_adjust_cfa_offset -8
    incq    %rax                     /* rax = n */
    ret                             /* -> ls_fexit_stub */
    .cfi_endproc
    .size   xv_rec, .-xv_rec

/* ---- xv_jumps(jb): longjmp(jb, 1) --- never returns; its exit is SKIPPED ----- *
 * Its shadow frame is left dangling; the harness then calls an armed function and
 * ls_fexit_leave must reclaim this frame before matching. rdi = jmp_buf *.       */
    .globl  xv_jumps
    .type   xv_jumps, @function
xv_jumps:
    .cfi_startproc
    endbr64
    call    ls_fexit_entry          /* the pad --- frame pushed, caller-ret hijacked */
    subq    $8, %rsp                 /* align before the outbound call */
    .cfi_adjust_cfa_offset 8
    movl    $1, %esi                 /* longjmp value */
    call    longjmp                  /* -> unwinds past here; the exit stub never runs */
    ud2                             /* unreachable */
    .cfi_endproc
    .size   xv_jumps, .-xv_jumps

/* ---- xv_outer: armed; calls a C helper that longjmps back INTO this body ----- *
 * The longjmp target (a setjmp in mid_setjmp) sits BELOW xv_outer but ABOVE the
 * skipped xv_jumps, so when xv_outer returns its exit fires with the stale
 * xv_jumps frame ON TOP of the shadow stack --- the case reclaim exists for.
 * Returns 0x0117.                                                                */
    .globl  xv_outer
    .type   xv_outer, @function
xv_outer:
    .cfi_startproc
    endbr64
    call    ls_fexit_entry          /* the pad */
    subq    $8, %rsp                 /* align before the call */
    .cfi_adjust_cfa_offset 8
    call    mid_setjmp               /* setjmp; inner armed chain longjmps back to it */
    addq    $8, %rsp
    .cfi_adjust_cfa_offset -8
    movq    $0x0117, %rax
    ret                             /* -> ls_fexit_stub; reclaims the stale inner frame */
    .cfi_endproc
    .size   xv_outer, .-xv_outer

    .section .note.GNU-stack,"",@progbits
