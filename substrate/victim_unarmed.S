/* The SAME function as victim.S, but UNARMED: endbr64 + five nops where the patch
 * would go, then the identical body. This is the padded function as it ships before
 * arming --- the honest baseline. The delta armed-minus-this is purely the trampoline. */
    .text
    .globl  victim_unarmed
    .type   victim_unarmed, @function
victim_unarmed:
    .cfi_startproc
    endbr64
    nop; nop; nop; nop; nop          /* the pad, unpatched --- 5 bytes, ~free */
    /* ---- identical body ---- */
    movq    $0xBEEF, %rax
    movq    $1, body_ran2(%rip)
    ret
    .cfi_endproc
    .size   victim_unarmed, .-victim_unarmed

    .data
    .globl  body_ran2
body_ran2:  .quad 0
