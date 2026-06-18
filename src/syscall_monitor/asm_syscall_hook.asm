#include "gsreldata.h"
#include <linux/unistd.h>

.macro xsave_vector_regs_to_gsrel
#if SAVE_VECTOR_REGS
    pushq %rdx
    pushq %rax
    pushq %rsi
    xorl %edx, %edx
    movl $XSAVE_EAX, %eax
    movq %gs:XSAVE_AREA_STACK_SP_OFFSET, %rsi
    xsave (%rsi)
    addq $XSAVE_SIZE, %rsi
    movq %rsi, %gs:XSAVE_AREA_STACK_SP_OFFSET
    popq %rsi
    popq %rax
    popq %rdx
#endif
.endmacro

.macro xrstor_vector_regs_from_gsrel
#if SAVE_VECTOR_REGS
    pushq %rdx
    pushq %rax
    pushq %rsi
    xorl %edx, %edx
    movl $XSAVE_EAX, %eax
    movq %gs:XSAVE_AREA_STACK_SP_OFFSET, %rsi
    subq $XSAVE_SIZE, %rsi
    xrstor (%rsi)
    movl %eax, %edx
    bt $9, %edx  
    jnc 1f
    ud2
    int3
1:
    movq %rsi, %gs:XSAVE_AREA_STACK_SP_OFFSET
    popq %rsi
    popq %rax
    popq %rdx
#endif
.endmacro

.macro push_gp_regs
    /* rip is already at the top of the stack here */
    pushq %rsp /* pushes the value of rsp _before_ changing it */
    pushq %rcx
    pushq %rax
    pushq %rdx
    pushq %rbx
    pushq %rbp
    pushq %rsi
    pushq %rdi
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8
.endmacro

/* CANNOT MODIFY FLAGS !! 
    executes between cmp and jz !! */
.macro pop_gp_regs
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
    popq %r14
    popq %r15
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rbx
    popq %rdx
    popq %rax
    popq %rcx
    popq %rsp
.endmacro

.macro push_ccallee_clobbered_gp_regs
    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
.endmacro

.macro pop_ccallee_clobbered_gp_regs
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rax
.endmacro

/*
* for xmm register operations such as movaps
* stack is expected to be aligned to a 16 byte boundary.
*/
.macro align_rsp
    pushq %rbp
    movq %rsp, %rbp

    andq $-16, %rsp /* 16 byte stack alignment */
.endmacro

.macro restore_rsp
    movq %rbp, %rsp
    popq %rbp
.endmacro

.macro lower_privileges
    /* lower privileges */
    movb $TS_APPLICATION, %gs:COMPARTMENT_ID_OFFSET
    movb $1, %gs:SUD_SELECTOR_OFFSET

    /* shouldn't clobber these, except rcx. And the top 32 bits of r11 (the unused rflags)*/
    movq %r11, %rcx
    shl $32, %rcx

    movq %rdx, %r11
    
    movq %rax, %rdx
    shl $32, %rax
    shr $32, %rdx
    shl $32, %rdx

    orq $REVOKE_PERMISSIONS, %rax
    wrpkru
    cmpl $REVOKE_PERMISSIONS, %eax
    je 1f
    ud2
    int3
1:
    shr $32, %rax
    orq %rdx, %rax

    movq %r11, %rdx

    movq %rcx, %r11
    shr $32, %r11

    /* rip_after_syscall should be at top of stack here */
.endmacro

.macro switch_to_original_stack
    xchg %rsp, %gs:SECURE_STACK_SP_OFFSET/*switch stacks*/
.endmacro

.macro switch_to_original_TLS
    pushq %rdx
    rdfsbase %rdx
    xchg %rdx, %gs:FS_BASE_OFFSET
    wrfsbase %rdx /*switch to secure TLS*/
    popq %rdx
.endmacro

.macro restore_rflags
    pushq %r11
    popfq
.endmacro

.global asm_syscall_hook
asm_syscall_hook:
    /* app stack is unmodified cmp to before stack switch */
    /* register state is unmodified compared to pre-stackswitch, except rsp, rcx is clobbered and r11 contains the rflags */

    push_gp_regs /* preserve all GP regs */
    /* set up the argument for secpoline_syscall_handler */
    movq %rsp, %rdi /* base address of GPR array in rsp */
    xsave_vector_regs_to_gsrel /* preserve the vector regs */

    /* align the stack */

    align_rsp

    /* up to here, stack has to be 16 byte aligned */
    /*  bool secpoline_syscall_handler(long long* gp_regs) */
    callq secpoline_syscall_handler
    /* rax now contains `should_emulate` */
    /* the in-memory rax contains either the syscall number or the syscall result, 
        depending on `should_emulate` */

    /* int3 */

    /* restore the stack */
    restore_rsp
    
    /* shouldnt clobber rax */
    xrstor_vector_regs_from_gsrel

    /* gp regs are still pushed to the stack here */

    /* now, we check whether we have to emulate some special system calls */
    test %rax, %rax /* if !should_emulate: do nothing */
    pop_gp_regs /* doesnt modify flags */
    jz .do_nothing

    /* we still have full privileges here */

    /* when emulating, rax contains the syscall to emulate */
    
    /* check whether we have to clone */
    /* if so, do so & setup GS and SUD in child */
    cmpq $__NR_clone, %rax
    je .do_clone_thread_or_clone_vfork

    /* check whether we have to vfork */
    cmpq $__NR_vfork, %rax
    je .do_vfork

    /* if neither of the above, something's wrong */
    ud2
    int3

.do_nothing:
    switch_to_original_TLS
    switch_to_original_stack
    lower_privileges
    restore_rflags
    movq (%rsp), %rcx
    ret


.do_clone_thread_or_clone_vfork:
    /* push the right return address to the child's stack as well */
    pushq %r11
    movq %gs:SECURE_STACK_SP_OFFSET, %r11
    pushq %rax
    pushq %rdx
    pushq %rcx
    xorl %ecx, %ecx
    xorl %edx, %edx
    movl $REVOKE_PERMISSIONS, %eax
    wrpkru
    cmpl $REVOKE_PERMISSIONS, %eax
    je 1f
    ud2
    int3
1:
    subq $8, %rsi /* make space on the child stack */
    movq (%r11), %r11
    movq %r11, 0x0(%rsi) /* rip_after_syscall -> top of child stack */
    xorl %edx, %edx
    xorl %ecx, %ecx
    movl $GRANT_TRUSTED_PERMISSIONS, %eax
    wrpkru
    /*assert(thread statet == TS_MONITOR)*/
    movb %gs:COMPARTMENT_ID_OFFSET, %dl
    cmpb $TS_MONITOR, %dl
    je 1f
    ud2
    int3
1:
    popq %rcx
    popq %rdx
    popq %rax
    popq %r11
    
    push_ccallee_clobbered_gp_regs
    align_rsp

    callq init_tls_child /*secure stack for new thread in gs:CHILD_STACK_OFFSET*/
    /*child's secure stack contains its secure_stack_base, tid, tls*/
    restore_rsp
    pop_ccallee_clobbered_gp_regs
    
    push_ccallee_clobbered_gp_regs
    align_rsp
    /*remove this thread from the active thread list if this is a clone_vfork as the parent will be blocked which causes deadlock during hbreakpoint sync events*/
    /*rdi is still the flags*/
    callq prepare_clone_parent

    restore_rsp
    pop_ccallee_clobbered_gp_regs

    pushq %r9
    movq %gs:CHILD_STACK_OFFSET, %r9
    /*push application child stack pointer onto secure child stack*/
    subq $8, %r9
    movq %rsi, 0x0(%r9)
    movq %r9, %rsi
    popq %r9

    /*temporarly swap TLS to untrusted in case the setTLS flag was not set*/
    pushq %rdx
    rdfsbase %rdx
    xchg %rdx, %gs:FS_BASE_OFFSET
    wrfsbase %rdx
    popq %rdx

    /* all args are still set up as original*/
    movq $0, %gs:SUD_SELECTOR_OFFSET    
#if EXCLUSIVE_MPK_POLICY
    pushq %rax
    pushq %rdx
    pushq %rcx
    xorl %edx, %edx
    xorl %ecx, %ecx
    movl $GRANT_FULL_PERMISSIONS, %eax
    wrpkru
    /*assert(thread statet == TS_MONITOR)*/
    movb %gs:COMPARTMENT_ID_OFFSET, %dl
    cmpb $TS_MONITOR, %dl
    je 1f
    ud2
    int3
1:
    popq %rcx
    popq %rdx
    popq %rax
#endif

    syscall
    testq %rax, %rax
    jz .new_thread

    /*swap to secure TLS*/
    pushq %rdx
    rdfsbase %rdx
    xchg %rdx, %gs:FS_BASE_OFFSET
    wrfsbase %rdx
    popq %rdx
    /* parent here: either done, or error */
    movq $0, %gs:CHILD_STACK_OFFSET

    /*now lets add the thread back to the list of active threads*/
    push_ccallee_clobbered_gp_regs
    align_rsp
    callq restart_clone_parent
    restore_rsp
    pop_ccallee_clobbered_gp_regs


    movq $1, %gs:SUD_SELECTOR_OFFSET   

    switch_to_original_TLS
    switch_to_original_stack
    lower_privileges
    restore_rflags
    movq (%rsp), %rcx
    ret

.new_thread:
    /*the stack contains untrusted rsp, secure_stack_base, trusted tid, trusted TLS*/
    /*rsi will be restored to untrusted stack later so it can be clobbered*/
    /*switch to trusted TLS*/
    rdfsbase %rsi
    xchg %rsi, 0x18(%rsp)
    wrfsbase %rsi

    pushq %rax
    /*use gettid syscall to get the tid a update its value in the trusted tls*/
    movq $__NR_gettid, %rax
    syscall
    movq 0x18(%rsp), %rsi
    movq %rax, (%rsi) /*store tid into trusted TLS*/
    popq %rax

    movq 0x8(%rsp), %rsi /*move secure stack base into rsi*/
    push_ccallee_clobbered_gp_regs
    align_rsp   
    /* rdi clone_flags = still correct, rsi secure stack base*/
    callq setup_new_thread

    restore_rsp
    pop_ccallee_clobbered_gp_regs


    pushq %rax
    /*store the untrusted tls in gsreldata*/
    movq 0x20(%rsp), %rax
    movq %rax, %gs:FS_BASE_OFFSET

    /*put the untrusted stack in gsreldata*/
    movq 0x8(%rsp), %rax
    movq %rax, %gs:SECURE_STACK_SP_OFFSET
    popq %rax
    addq $0x20, %rsp /*discard untrusted rsp,  on stack*/

    /*now every register is still correct, the untrusted stack and tls are in gsreldata*/
    /*the trusted stack contains the pointer to start thread() and its arguments*/
    /*now we need to save every register so that they can be restored after start_thread() when returning to the application*/
    xchg %rax, (%rsp) /*start_thread() -> rax*/
    addq $8, %rsp
    xchg %rdi, (%rsp) /*arg -> rdi*/
    addq $8, %rsp
    pushq %rdx
    pushq %rbx
    pushq %rsi
    pushq %rcx
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8
    movq %rsp, %gs:THREAD_CLEANUP_RSP_OFFSET /*save this stack location so we can restore the registers before returning to the application*/

    callq *%rax /*start_thread(), we will return to the application during this function*/

    ud2
    int3


.do_vfork:
    /*TODO rewrite faster for vfork heavy applications*/
    /*currently this code is not used as it is faster to use fork instead when vfork is called*/

    /* vfork (not CLONE_VFORK) is a _really_ annoying syscall */
    /* we could handle CLONE_VFORK easily because we enforce that 
        the child runs on a different stack. We essentially treat that like
        CLONE_THREAD */
    /* we can't do this for the vfork syscall, because you cannot specify a different child stack */
    /* the problem is that the child will run first, and pop the 
        `rip_after_syscall` from the shared stack. It can then run other code
        which pushes to the stack (like CPython does), and destroy the `rip_after_syscall` */
    /* once the child execve's and the parent wants to return, it will observe a total
        garbage value on the top of the stack, and use that to return. This will crash him */

    /* to fix this, we push the rip_after_syscall to a dedicated stack in the parent's gsrel region */
    /* we don't have to do this for the child, since it will use the stack instead */

/*retrive rip after syscall from untrusted stack*/
/*rcx is clobbered by the syscall*/
    pushq %rax
    pushq %rdx
    pushq %r9
    pushq %rsi

    movq %gs:SECURE_STACK_SP_OFFSET, %r9

    /*drop privileges to access rip after syscall*/
    xorl %ecx, %ecx
    xorl %edx, %edx
    movl $REVOKE_PERMISSIONS, %eax
    wrpkru
    movb %gs:COMPARTMENT_ID_OFFSET, %dl
    cmpb $TS_MONITOR, %dl
    je 1f
    ud2
    int3
1:

    movq (%r9), %r9 /*get rip after syscall*/

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

   /*lets setup the stack of the new thread*/
    movq %gs:RIP_AFTER_SYSCALL_STACK_SP_OFFSET, %rsi
    movq %r9, (%rsi)
    addq $8, %rsi
    movq %rsi, %gs:RIP_AFTER_SYSCALL_STACK_SP_OFFSET

    popq %rsi
    popq %r9
    popq %rdx
    popq %rax
    
    /* do the syscall */
    movq $0, %gs:SUD_SELECTOR_OFFSET
    syscall
    testq %rax, %rax
    jz .vforked_child_enable_sud
    movq $1, %gs:SUD_SELECTOR_OFFSET
    /* parent here: either done or error */
    /* the vfork-ed child might have overwritten the rip_after_syscall here */
    /* but the RSP will still point to the right location */
    /* restore the saved rip_after_syscall to the stack & return */
    /*drop privileges to access rip after syscall*/
#if EXCLUSIVE_MPK_POLICY
    xorl %ecx, %ecx
    xorl %edx, %edx
    movl $GRANT_FULL_PERMISSIONS, %eax
    wrpkru
    movb %gs:COMPARTMENT_ID_OFFSET, %dl
    cmpb $TS_MONITOR, %dl
    je 1f
    ud2
    int3
1:
#endif

    pushq %rsi
    movq %gs:RIP_AFTER_SYSCALL_STACK_SP_OFFSET, %rsi
    subq $8, %rsi 
    movq (%rsi), %rcx /* rcx has to hold `rip_after_syscall` anyway */
    movq %rsi, %gs:RIP_AFTER_SYSCALL_STACK_SP_OFFSET
    popq %rsi

    switch_to_original_TLS
    switch_to_original_stack
    lower_privileges
    restore_rflags
    movq (%rsp), %rcx
    ret

.vforked_child_enable_sud:
    /* we will set up a gsrel region here that shares sigdisps with the parent */
    /* we need to re-enable SUD here anyway */
    push_ccallee_clobbered_gp_regs
    align_rsp
    callq setup_vforked_child
    restore_rsp
    pop_ccallee_clobbered_gp_regs

    /* lower privileges and return */
    switch_to_original_stack
    lower_privileges
    ret




/*the "main routine" for the start thread executed by the monitor, this will save the current state, return to the application and then return to the monitors start thread after the application called exit*/
.global fake_thread_main_routine
fake_thread_main_routine:
    /*first lets save the non-saved registers here so we can restore them later*/
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %rbx
    pushq %rbp


    /*switch stacks and tls, now we can still clobber registers*/
    rdfsbase %rax
    xchg %rax, %gs:FS_BASE_OFFSET
    wrfsbase %rax /*switch to secure TLS*/

    /*then restore the register for the application*/
    movq %gs:THREAD_CLEANUP_RSP_OFFSET, %r15
    movq 0x0(%r15), %r8
    movq 0x8(%r15), %r9
    movq 0x10(%r15), %r10
    movq 0x18(%r15), %r11
    movq 0x20(%r15), %r12
    movq 0x28(%r15), %r13
    movq 0x30(%r15), %r14
    movq 0x40(%r15), %rcx
    movq 0x48(%r15), %rsi
    movq 0x50(%r15), %rbx
    movq 0x58(%r15), %rdx
    movq 0x60(%r15), %rdi
    movq 0x68(%r15), %rax
    movq 0x38(%r15), %r15

    movq %rsp, %gs:THREAD_CLEANUP_RSP_OFFSET /*we use this rsp when returning here to cleanup the trusted parts of this thread*/

    /*NOW update the sigaltstack*/
    /*rcx can be clobbered at this point as it will be set by lower_privileges anyway*/
    movq %rsp, %rcx
    /*now we need to setup the sigaltstack*/
    pushq %rdi
    pushq %rsi
    pushq %r11
    movq %gs:SIG_ALTSTACK_BASE_OFFSET, %rdi
    subq %rdi, %rcx /*rcx contains sigaltstack size*/
    movq %rcx, %gs:SIG_ALTSTACK_SIZE_OFFSET
    movq $0, %rsi
    rdgsbase %rdi
    addq $SIG_ALTSTACK_BASE_OFFSET, %rdi /*rdi points to stack_t struct in gsreldata*/
    movq $__NR_sigaltstack, %rax
    movq %rsp, %r9
    movq $0, %rsp
    movq $0, %gs:SUD_SELECTOR_OFFSET
    syscall
    movq $1, %gs:SUD_SELECTOR_OFFSET
    movq %r9, %rsp
    cmpq $0, %rax
    jne .unsafe_state
    popq %r11
    popq %rsi
    popq %rdi

    
    xchg %gs:SECURE_STACK_SP_OFFSET, %rsp
    movq %rsp, %rsi /*rsi contains untrusted stack*/

    /* lower privileges in the child */
    lower_privileges
    restore_rflags
    movq (%rsp), %rcx
    ret
    ud2
    int3

.global cleanup_thread
cleanup_thread:
    /*first restore the context to the fake_thread_main_routine, so we can complete start_thread() */
    movq %gs:THREAD_CLEANUP_RSP_OFFSET, %rsp
    popq %rbp
    popq %rbx
    popq %r12
    popq %r13
    popq %r14
    popq %r15

    ret
    ud2
    int3

.unsafe_state:
    ud2
    int3
