#include "gsreldata.h"
#include <linux/unistd.h>


.macro _SAFE_ENTRY_POINT_WRPKRU_
    .global safe_wrpkru_entry_point\@
    safe_wrpkru_entry_point\@:
.endmacro

/*entry point for the monitor's system call hook function*/
.global syscall_hook_entry
syscall_hook_entry:
    /*perserve the rflags*/
    pushfq
    popq %rcx  
    /*rax can be clobbert as it will be restored from the stack before stack switching*/    
    movb %gs:COMPARTMENT_ID_OFFSET, %al
    cmpb $TS_APPLICATION, %al
    popq %rax
    jne meta_syscall_hook

    movq %rdx, %r11
    shl $32, %rcx
    xorl %edx, %edx
    shl $32, %rax
    orq $GRANT_TRUSTED_PERMISSIONS, %rax
_SAFE_ENTRY_POINT_WRPKRU_
    wrpkru
    cmpl $GRANT_TRUSTED_PERMISSIONS, %eax
    jne .unsafe_state
    movq %r11, %rdx
    shr $32, %rcx
    movq %rcx, %r11 
    shr $32, %rax

    /*r11 now contains the rflags on entry*/
    movb $1, %gs:SUD_SELECTOR_OFFSET
    /*switch to secure stack*/
    /*also push rip_after_syscall to top of new stack*/
    xchg %rsp, %gs:SECURE_STACK_SP_OFFSET/*switch stacks*/

    /*swap to secure TLS*/
    rdfsbase %rcx
    xchg %rcx, %gs:FS_BASE_OFFSET
    wrfsbase %rcx /*switch to secure TLS*/
    movb $TS_MONITOR, %gs:COMPARTMENT_ID_OFFSET

    jmp asm_syscall_hook /*syscall monitor*/
    ud2
    int3


/*entry point for the SIGSYS signal handler used by SUD*/
.global SUD_entry_point
SUD_entry_point:
    /*signal handlers run with a default PKRU value which is AD for all domains except 0*/
    movq %rdx, %r8 /* back up rdx in a unused register*/
    xorq %rdx, %rdx
    xorq %rcx, %rcx /*rcx is an unused register for signal entry points*/
    movl $GRANT_TRUSTED_PERMISSIONS, %eax
_SAFE_ENTRY_POINT_WRPKRU_
    wrpkru
    cmpl $GRANT_TRUSTED_PERMISSIONS, %eax
    jne .unsafe_state

    movq %r8, %rdx /* restore ucontext */
    /*the signal handler always enters on the trusted stack because it is the sigaltstack*/
    xorq %r8, %r8
    movb %gs:COMPARTMENT_ID_OFFSET, %r8b
    cmpb $TS_MONITOR, %r8b
    je .enter_SUD
    /*if the signal was delivered during untrusted code execution, we need to retive the untrusted stack pointer and move it into gsreldata*/
    /*retrive the stack before signal delivery by looking into tihe signal frame*/
    movq %rsp, %r10
    addq $8, %r10 /*r10 points to start of signal frame*/
    addq $RSP_OFFSET_UCONTEXT, %r10
    movq (%r10), %r10 /*r10 is stackpointer before signal*/
    xchg %gs:SECURE_STACK_SP_OFFSET, %r10
    pushq %r10

    rdfsbase %r9
    xchg %r9, %gs:FS_BASE_OFFSET
    wrfsbase %r9 /*switch TLS*/

.enter_SUD:
    movq %gs:COMPARTMENT_ID_OFFSET, %rcx
    movq $TS_MONITOR, %gs:COMPARTMENT_ID_OFFSET
    movq $0, %gs:SUD_SELECTOR_OFFSET
    /*enforce 16-byte stack allignment*/
    pushq %rbp
    movq %rsp, %rbp
    andq $-16, %rsp

    callq handle_sigsys

    movq %rbp, %rsp
    popq %rbp

    /*thread state has been reverted to the state on entry*/
    xorq %r8, %r8
    movb %gs:COMPARTMENT_ID_OFFSET, %r8b
    cmpb $TS_MONITOR, %r8b
    je .sigreturn_SUD
    popq %r10
    movq %r10, %gs:SECURE_STACK_SP_OFFSET

    rdfsbase %r9
    xchg %r9, %gs:FS_BASE_OFFSET
    wrfsbase %r9 /*switch TLS*/


.sigreturn_SUD:
    ret


/* The signal handler entry point is in asm_segfault_entry.asm*/

/*Exit point to call the application signal handler*/
.global call_app_handler
call_app_handler:
    /* rdi = signo, rsi = info, rdx = ucontext, rcx = sighandler function pointer,*/

    /*before switching to another stack, update the sigaltstack size to prevent nested signals from overwriting stuff already put onto the stack*/
    /*first save the current sigaltstack size*/
    movq %gs:SIG_ALTSTACK_SIZE_OFFSET, %r9
    pushq %r9
    /*then calculate the new size*/
    movq %gs:SIG_ALTSTACK_BASE_OFFSET, %r9
    movq %rsp, %r10
    subq %r9, %r10 /*new size = current sp - sigaltstack_base*/
    movq %r10, %gs:SIG_ALTSTACK_SIZE_OFFSET 

    /*finaly do the sigaltstack syscall*/
    pushq %rax
    pushq %rdi
    pushq %rsi
    pushq %rcx
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
    je 1f
    ud2
    int3
1:
    popq %rcx
    popq %rsi
    popq %rdi
    popq %rax

    xchg %rsp, %gs:SECURE_STACK_SP_OFFSET/*switch stacks*/

    /*switch to untrusted TLS*/
    rdfsbase %r9
    xchg %r9, %gs:FS_BASE_OFFSET
    wrfsbase %r9 /*switch TLS*/

    /*keep track of the amount of nested signal handlers are invoked and don't allow the return to this wrapper if we have not invoked any*/
    incq %gs:SIGNAL_HANDLER_LEVEL_OFFSET

    movb $TS_APPLICATION, %gs:COMPARTMENT_ID_OFFSET
    
    /*revoke privileges*/
    movq %rdx, %r10
    movq %rcx, %r11
    xorl %ecx, %ecx
    xorl %edx, %edx
    movl $REVOKE_PERMISSIONS, %eax
    wrpkru
    cmpl $REVOKE_PERMISSIONS, %eax
    je 1f
    ud2
    int3
1:
    movq %r10, %rdx
    movq %r11, %rcx


    /*enforce 16-byte stack allignment*/
    pushq %rbp
    movq %rsp, %rbp
    andq $-16, %rsp
    
    /*call the app handler*/
    callq *%rcx
    
    movq %rbp, %rsp
    popq %rbp

    /*inscrease privileges*/
    xorl %ecx, %ecx
    xorl %edx, %edx
    movl $GRANT_TRUSTED_PERMISSIONS, %eax
_SAFE_ENTRY_POINT_WRPKRU_
    wrpkru
    cmpl $GRANT_TRUSTED_PERMISSIONS, %eax
    jne .unsafe_state

    movb $TS_MONITOR, %gs:COMPARTMENT_ID_OFFSET

    /*make sure a signal handler was actually invoked*/
    movq %gs:SIGNAL_HANDLER_LEVEL_OFFSET, %r9
    cmpq $0, %r9
    je .unsafe_state
    decq %gs:SIGNAL_HANDLER_LEVEL_OFFSET

    /*switch to trusted TLS*/
    rdfsbase %r9
    xchg %r9, %gs:FS_BASE_OFFSET
    wrfsbase %r9 /*switch TLS*/

    xchg %rsp, %gs:SECURE_STACK_SP_OFFSET/*switch stacks*/

    /*now we need to undo the sigaltstack overwrite*/
    popq %r9 /*get old sigaltstack size*/
    movq %r9, %gs:SIG_ALTSTACK_SIZE_OFFSET
    /*do the sigaltstack syscall*/
    pushq %rax
    pushq %rdi
    pushq %rsi
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
    popq %rsi
    popq %rdi
    popq %rax

    ret

/*jump back to the loader to load in the application*/
.global jump_back_to_loader
jump_back_to_loader:
movb $1, %gs:SUD_SELECTOR_OFFSET
movb $1, %gs:COMPARTMENT_ID_OFFSET

    xorl %ecx, %ecx
    xorl %edx, %edx
    movl $REVOKE_PERMISSIONS, %eax
    wrpkru
    cmpl $REVOKE_PERMISSIONS, %eax
    je 1f
    ud2
    int3
1:

jmp *%rdi
ud2
int3

.unsafe_state:
    ud2
    int3