#include "config.h"

/* unsigned long bench_syscall(unsigned long syscall_no) */
/* rdi: syscall_no */
.global bench_syscall
bench_syscall:
/* first take the noisy syscall measurement */
    rdtsc
    movl %eax, %r9d
    shlq $32, %rdx
    orq %rdx, %r9
    movq $NUM_SYSCALLS, %rdx

.syscall_loop:
    movq %rdi, %rax
#if USE_CALL_RAX
    callq *%rax
#else
    syscall
#endif
    decq %rdx
    testq %rdx, %rdx
    jnz .syscall_loop

    rdtsc
    shlq $32, %rdx
    orq %rdx, %rax
    subq %r9, %rax

    movq %rax, %rsi

.measure_noise:
/* then measure the noise */
    rdtsc
    movl %eax, %r9d
    shlq $32, %rdx
    orq %rdx, %r9
    movq $NUM_SYSCALLS, %rdx

.noise_loop:
    movq %rdi, %rax
    decq %rdx
    testq %rdx, %rdx
    jnz .noise_loop

    rdtsc
    shlq $32, %rdx
    orq %rdx, %rax
    subq %r9, %rax

/* subtract the noise from the noisy measurement */
    subq %rax, %rsi
    movq %rsi, %rax

    ret


.section .note.GNU-stack,"",@progbits
