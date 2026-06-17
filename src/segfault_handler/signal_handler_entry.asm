#include "gsreldata.h"
#include <linux/unistd.h>

.macro _SAFE_ENTRY_POINT_WRPKRU_
    .global safe_wrpkru_entry_point_segfault\@
    safe_wrpkru_entry_point_segfault\@:
.endmacro

/*entry point for the signal handler wrapper*/
.global asm_signal_entry
asm_signal_entry:
    /*signal handlers run with a default PKRU value which is AD for all domains except 0*/
    movq %rdx, %r8 /* back up rdx in a unused register*/
    xorq %rdx, %rdx
    xorq %rcx, %rcx /*rcx is an unused register for signal entry points*/
    movl $GRANT_TRUSTED_PERMISSIONS, %eax
_SAFE_ENTRY_POINT_WRPKRU_
    wrpkru
    cmpl $GRANT_TRUSTED_PERMISSIONS, %eax
    je 1f
    ud2
    int3
1:
    
    movq %r8, %rdx /* restore ucontext */
    /*the signal handler always enters on the trusted stack because it is the sigaltstack*/
    xorq %r8, %r8
    movb %gs:COMPARTMENT_ID_OFFSET, %r8b
    cmpb $TS_MONITOR, %r8b
    je .enter_wrapper
    /*if the signal was delivered during untrusted code execution, we need to retive the untrusted stack pointer and move it into gsreldata*/
    /*retrive the stack before signal delivery by looking into tihe signal frame*/
    movq %rsp, %r10
    addq $8, %r10 /*r10 points to start of signal frame*/
    addq $RSP_OFFSET_UCONTEXT, %r10
    movq (%r10), %r10 /*r10 is stackpointer before signal*/
    xchg %gs:SECURE_STACK_SP_OFFSET, %r10
    /*save trusted stack pointer on sigreturn stack if we came from untrusted code*/
    movq %gs:SIGRETURN_STACK_SP_OFFSET, %r8
    movq %r10, (%r8)
    addq $8, %r8
    movq %r8, %gs:SIGRETURN_STACK_SP_OFFSET


    rdfsbase %r9
    xchg %r9, %gs:FS_BASE_OFFSET
    wrfsbase %r9 /*switch TLS*/

.enter_wrapper:
    /*enforce 16-byte stack allignment*/
    pushq %rbp
    movq %rsp, %rbp
    andq $-16, %rsp

    callq signal_handler_switch
    /*rax contains permissions on entry*/

    movq %rbp, %rsp
    popq %rbp
    
    addq $8, %rsp /*discard return adress on stack*/
    movq $15, %rax /*put syscall number of sigreturn into rax*/

    /*now lets handler the sigreturn here directly*/
    /*make sure the restore_selector_trampoline is setup*/
    pushq %rdi
    movq %rsp, %rdi
    addq $8, %rdi /*rsi points to ucontext*/

    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11

    pushq %rbp
    movq %rsp, %rbp

    andq $-16, %rsp /* 16 byte stack alignment */

    movq %rdi, %rsi
    callq setup_restore_selector_trampoline 
    
    movq %rbp, %rsp
    popq %rbp

    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rax
    popq %rdi

    movq $0, %gs:SUD_SELECTOR_OFFSET    
    syscall 
    ud2
    int3

.section .note.GNU-stack,"",@progbits