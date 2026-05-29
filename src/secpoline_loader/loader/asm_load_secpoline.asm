.global asm_load_secpoline
asm_load_secpoline:
pushq %rax
pushq %rbx
pushq %rcx
pushq %rdx
pushq %rdi
pushq %rsi
pushq %r8
pushq %r9
pushq %r10
pushq %r11
pushq %r12
pushq %r13
pushq %r14
pushq %r15
pushq %rbp
lea return_from_secpoline_setup(%rip), %r8  /*pass adress to return to after secpoline setup*/
movq %rsp, rsp_holder(%rip) /*save stack pointer in global memory*/
call load_secpoline
ud2
int3


.global return_from_secpoline_setup
return_from_secpoline_setup:
movq rsp_holder(%rip), %rsp /*restore stack pointer*/
popq %rbp
popq %r15
popq %r14
popq %r13
popq %r12
popq %r11
popq %r10
popq %r9
popq %r8
popq %rsi
popq %rdi
popq %rdx
popq %rcx
popq %rbx
popq %rax
ret

.section .note.GNU-stack,"",@progbits
