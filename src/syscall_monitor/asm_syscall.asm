#include "gsreldata.h"
/*do syscall with low privileges*/
.global do_syscall_untrusted
do_syscall_untrusted:
movq $0, %gs:SUD_SELECTOR_OFFSET
/*save registers that are not caller-save*/
/*setup registers for syscall, all registers are correct except r10 and rax*/
/*save rdx and rax into temporary registers*/
movq %rcx, %r10
movq 0x8(%rsp), %r11 /*rax*/
pushq %r12
movq %rdx, %r12

#if EXCLUSIVE_MPK_POLICY
    /*inscrease privileges*/
    xorl %ecx, %ecx
    xorl %edx, %edx
    movl $REVOKE_PERMISSIONS, %eax
    wrpkru
    cmpl $REVOKE_PERMISSIONS, %eax
    je 1f
    ud2
    int3
1:
#endif

movq %r11, %rax
movq %r12, %rdx
syscall
movq %rax, %r11

#if EXCLUSIVE_MPK_POLICY
    /*inscrease privileges*/
    xorl %ecx, %ecx
    xorl %edx, %edx
    movl $GRANT_TRUSTED_PERMISSIONS, %eax
    wrpkru
    movb %gs:COMPARTMENT_ID_OFFSET, %dl
    cmpb $TS_MONITOR, %dl
    je 1f
    ud2
    int3
1:
#endif

movq %gs:COMPARTMENT_ID_OFFSET, %r12
cmpq $TS_MONITOR, %r12
jne .abort

movq %r11, %rax
popq %r12
movq $1, %gs:SUD_SELECTOR_OFFSET
ret


.global meta_syscall_hook
meta_syscall_hook:
    movq $0, %gs:SUD_SELECTOR_OFFSET
    pushq %r15
    movq 0x8(%rsp), %r15 /*rip after syscall*/
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11

    /*stack allignment*/
    pushq %rbp
    movq %rsp, %rbp
    andq $-16, %rsp

    movq %r10, %rcx
    pushq %r15 /*rip after syscall*/
    pushq %rax /*syscall no*/
    callq meta_monitor

    addq $16, %rsp /*discard pushed rax and rip after syscall*/

    movq %rbp, %rsp
    popq %rbp

    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx

    popq %r15
    movq $1, %gs:SUD_SELECTOR_OFFSET
    ret
    ud2
    int3

.abort:
    ud2
    int3

.section .note.GNU-stack,"",@progbits