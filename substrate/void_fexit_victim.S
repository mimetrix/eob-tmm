/* Native void-return fixture. Same call-pad stack geometry as production. */
    .text
    .global cv_target
    .type cv_target, @function
cv_target:
    endbr64
    call ls_fexit_slot1
    sub $8, %rsp
    call cv_body
    add $8, %rsp
    /* A void caller cannot treat this register as a return value. */
    mov cv_return_noise(%rip), %rax
    ret
    .size cv_target, .-cv_target

    .section .note.GNU-stack,"",@progbits
