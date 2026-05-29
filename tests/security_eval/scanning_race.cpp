#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <setjmp.h>
#include <atomic>
#include <thread>
#include <iostream>

const int PAGE_SIZE = 4096;
const unsigned char VALUE_A = 0x0;
const unsigned char VALUE_B = 0xef;

// Global state for signal handler
static jmp_buf jump_buffer;
static unsigned char *target_page = nullptr;
static unsigned char *target_byte = nullptr;
static volatile sig_atomic_t segfault_occurred = 0;


void exit_group(int ret_code) {
    asm volatile (
        "mov $231, %%rax\n"
        "ud2\n"
        "syscall\n"
        :
        : "D"(ret_code)
        : "rax"
    );
}

// Signal handler for SIGSEGV
void segfault_handler(int sig, siginfo_t *info, void *context) {
    printf("segfault handler invoked\n");
    if (target_byte != nullptr) {
        unsigned char current_value = *target_byte;
        if(current_value == VALUE_B){
            //success
            printf("success\n");
            void (*fn)(void) = (void(*)(void))target_page;
            fn();

            asm volatile (
                "rdgsbase %%rax\n"
                "movb $0, (%%rax)\n"
                :
                :
                : "rax", "memory"
            );

            if(pkey_mprotect(target_page, PAGE_SIZE, PROT_WRITE, 0)==0){
                printf("success**\n");
                exit_group(0);
            }else{
                printf("success, nvm %d\n", errno);
                exit_group(1);
            }
        }else{
            printf("failure\n");
            exit_group(2);
        }
    }
}

// Thread 1: Continuously makes page executable-only
void* mprotect_thread(void* arg) {
    printf("mprotect start%d\n", gettid());
    sleep(1);
    unsigned char *page = (unsigned char*)arg;
    
    printf("starting mprotect\n");
    if(mprotect(page, PAGE_SIZE, PROT_EXEC | PROT_READ) != 0){
        printf("mprotect fail\n");
        exit_group(1);
    }
    printf("mprotect success\n");
        
    sleep(1);
    exit_group(1);
    return nullptr;
}

// Thread 2: Continuously overwrites the target byte
void* write_thread(void* arg) {
    printf("write start%d\n", gettid());
    unsigned char *byte = (unsigned char*)arg;
    while (true) {
        *byte = VALUE_A;
        *byte = VALUE_B;
        *byte = VALUE_A;
        *byte = VALUE_B;
        
        // Add a small yield
        sched_yield();
    }
    return nullptr;
}

void run_child_process() {
    // Allocate a page for testing
    target_page = (unsigned char*)mmap(nullptr, PAGE_SIZE, PROT_READ | PROT_WRITE, 
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                                       
    if (target_page == MAP_FAILED) {
        perror("mmap");
        exit_group(1);
    }


    static unsigned char benign_wrpkru[] = {
        0x31, 0xc9,  // xor ecx, ecx
        0x31, 0xd2,  // xor edx, edx
        0xb8, 0x0, 0x0, 0x0, 0x0, // mov eax,0x5555555c
        0x0f, 0x01, 0xef, // wrpku
        0xc3 //ret
    };

    memcpy(target_page, benign_wrpkru, 13);
    
    // Set up the target byte last byte of wrpkru
    target_byte = target_page + 11;
    
    // Initialize with 0
    *target_byte = VALUE_B;
    
    // Set up signal handler
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = segfault_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    
    if (sigaction(SIGSEGV, &sa, nullptr) == -1) {
        perror("sigaction");
        exit_group(1);
    }
    
    // Create the two threads
    for(int i = 0;i<8;i++){
        printf("starting write thread\n");
        pthread_t t;
        int res = pthread_create(&t, nullptr, write_thread, target_byte);
        if(res != 0){
            printf("thread1 creation failed with %d\n", errno);
            exit_group(1);  // Failure - no race detected
        } 
    }

    pthread_t t1;
    printf("starting mprotect thread [%p]\n", target_page);
    int res = pthread_create(&t1, nullptr, mprotect_thread, target_page);
    if(res != 0){
        printf("thread2 creation failed with %d\n", errno);
        exit_group(1);  // Failure - no race detected
    }

    pthread_join(t1, NULL);

    fprintf(stderr, "someting when wrong\n");
    exit_group(1);  // Failure - no race detected
}

int main(int argc, char **argv) {
    run_child_process();
    return 1;
    
    int num_children = 16;  // Number of child processes to spawn
    
    if (argc > 1) {
        num_children = atoi(argv[1]);
    }
    
    fprintf(stderr, "Starting race condition tester with %d children\n", num_children);
    
    for (int i = 0; i < num_children; i++) {
        pid_t child = fork();
        
        if (child == 0) {
            // Child process
            fprintf(stderr, "Child %d: Starting race condition test\n", i);
            run_child_process();
            exit(1);  // Should not reach here
        } else if (child == -1) {
            perror("fork");
            exit(1);
        }
        
        // Parent: wait for child
        int status;
        waitpid(child, &status, 0);
        
        if (WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            if (exit_code == 0) {
                fprintf(stderr, "SUCCESS: Child %d returned safly\n", i);
                return 0;  // Stop spawning children
            }
        }
        int exit_code = WEXITSTATUS(status);
        fprintf(stderr, "Child %d: Failed or timed out with exit code %d, trying next child...\n", i, exit_code);
    }
    
    fprintf(stderr, "FAILURE: all child processes failed\n");
    return 1;
}
