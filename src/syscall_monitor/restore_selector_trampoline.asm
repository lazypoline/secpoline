#include "gsreldata.h"

/* Earlier commits (e.g. secpoline_adriaan's 1ee1122139463e94130ae8503278484bf8275f9d) 
    contain a CET-compatible version of this trampoline */

/* This is the landingpad for sigreturns from user-supplied signal handlers */
/* We just have to restore the selector value, and then jump back to where 
    the sigreturn should have actually went to (the "old RIP")
    We have to do so transparantly, without clobbering any registers */
/* `wrap_signal_handler` will have pushed the old RIP to the top of the stack here */
/* the privilege level to restore to will be on the safe stack */

/*TODO, what happens when rsp after sigreturn in pointed to trusted memory*/

/*sigreturn stack -> rcx, rdx, rax, rsp, rip, selector, thread state*/
.global restore_selector_trampoline
restore_selector_trampoline:
    /* we've intercepted all signal-handler syscalls */
    /* restore the selector to the value it had during the delivery of the signal */
    /* revoke permissions */
    xorl %edx, %edx
    xorl %ecx, %ecx
    movl $GRANT_FULL_PERMISSIONS, %eax
    wrpkru
    movb %gs:COMPARTMENT_ID_OFFSET, %dl
    cmpb $TS_MONITOR, %dl
    je 1f
    ud2
    int3
1:

    /*restore clobbert registers*/
    subq $8, %gs:SIGRETURN_STACK_SP_OFFSET
    movq %gs:SIGRETURN_STACK_SP_OFFSET, %rcx
    movq (%rcx), %rcx
    
    subq $8, %gs:SIGRETURN_STACK_SP_OFFSET
    movq %gs:SIGRETURN_STACK_SP_OFFSET, %rdx
    movq (%rdx), %rdx

    subq $8, %gs:SIGRETURN_STACK_SP_OFFSET
    movq %gs:SIGRETURN_STACK_SP_OFFSET, %rax
    movq (%rax), %rax

    subq $8, %gs:SIGRETURN_STACK_SP_OFFSET
    movq %gs:SIGRETURN_STACK_SP_OFFSET, %rsp
    movq (%rsp), %rsp

    subq $128, %rsp /*ignore redzone*/
    pushq %rax
    pushq %rdx
    pushq %rcx

    /*save the rip after sigreturn in gsrelative memory so we can still jump without using the stack or any registers*/
    subq $8, %gs:SIGRETURN_STACK_SP_OFFSET
    movq %gs:SIGRETURN_STACK_SP_OFFSET, %rax
    movq (%rax), %rax
    movq %rax, %gs:RIP_AFTER_SIGRETURN_HOLDER

    /*restore the sud selector*/
    subq $8, %gs:SIGRETURN_STACK_SP_OFFSET
    movq %gs:SIGRETURN_STACK_SP_OFFSET, %rax
    movq (%rax), %rax
    movq %rax, %gs:SUD_SELECTOR_OFFSET

    /*revoke permissions if we return to the application*/
    subq $8, %gs:SIGRETURN_STACK_SP_OFFSET
    movq %gs:SIGRETURN_STACK_SP_OFFSET, %rax
    movq (%rax), %rax
    cmpq $TS_MONITOR, %rax
    je .return_to_trusted_code

    movb $TS_APPLICATION, %gs:COMPARTMENT_ID_OFFSET
    rdfsbase %r9
    xchg %r9, %gs:FS_BASE_OFFSET
    wrfsbase %r9 /*switch TLS*/

    /*put trusted stack pointer back into gsreldata*/
    subq $8, %gs:SIGRETURN_STACK_SP_OFFSET
    movq %gs:SIGRETURN_STACK_SP_OFFSET, %rax
    movq (%rax), %rax
    movq %rax, %gs:SECURE_STACK_SP_OFFSET

    /* revoke permissions */
    xorl %ecx, %ecx
    xorl %edx, %edx
    movl $REVOKE_PERMISSIONS, %eax
    wrpkru
    cmpl $REVOKE_PERMISSIONS, %eax
    je 1f
    ud2
    int3
1:
    jmp .end_of_sigreturn


.return_to_trusted_code:
    movb $TS_MONITOR, %gs:COMPARTMENT_ID_OFFSET
    /* we enterd with full permissions, but we should have exclusive permissions */
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


.end_of_sigreturn:

    popq %rcx
    popq %rdx
    popq %rax
    addq $128, %rsp
    jmp *%gs:RIP_AFTER_SIGRETURN_HOLDER

.unsafe_state:
    ud2
    int3