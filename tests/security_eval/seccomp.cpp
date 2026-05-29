#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/user.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stddef.h>
#include <pthread.h>
#include "_libattack.h"



#define syscall_arg(_n) (offsetof(struct seccomp_data, args[_n]))
#define syscall_nr (offsetof(struct seccomp_data, nr))

void* new_thread(void* args){
    disable_sud();
    sud_test();
}

int main(int argc, char **argv) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_pkey_mprotect, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO),
    };
    struct sock_fprog prog = {
        .filter = filter,
        .len = (unsigned short) (sizeof(filter)/sizeof(filter[0])),
    };

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
        perror("seccomp");
        exit(1);
    }

    pthread_t t;
    int res = pthread_create(&t, nullptr, new_thread, NULL);

    return 0;
}