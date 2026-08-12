/* A stand-in for a patched function: entry, endbr64, then the 5-byte patch,
 * then the real body. This is byte-for-byte what arming would produce. */
    .text
    .globl  victim
    .type   victim, @function
victim:
    .cfi_startproc
    endbr64
    call    ls_trampoline_entry     /* e8 rel32 --- exactly 5 bytes, the patch */
    /* ---- the body, reached only on fall-through ---- */
    movq    $0xBEEF, %rax
    movq    $1, body_ran(%rip)
    ret
    .cfi_endproc
    .size   victim, .-victim

    .data
    .globl  body_ran
body_ran:   .quad 0
