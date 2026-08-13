    .text
    .globl test_tramp
    .type test_tramp,@function
test_tramp:
    .cfi_startproc
    endbr64
    incl    g_tramp_hits(%rip)
    movl    g_skip_body(%rip), %eax
    testl   %eax, %eax
    jnz     .Lskip
    ret
.Lskip:
    addq    $8, %rsp
    xorq    %rax, %rax
    ret
    .cfi_endproc
    .size test_tramp,.-test_tramp
    .globl g_tramp_hits
    .globl g_skip_body
    .bss
    .align 4
g_tramp_hits: .long 0
g_skip_body:  .long 0
    .section .note.GNU-stack,"",@progbits
