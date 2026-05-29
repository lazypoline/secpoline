#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <elf.h>
#include <stdint.h>

#include "crt.h"
#include "dso.h"
#include "loader.h"
#include "dynlink.h"
#include "debug.h"
#include "libpath.h"
#include "env.h"
#include <sys/auxv.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <err.h>
#include <link.h>
<<<<<<< HEAD:secpoline_loader/loader/main.c
#include "loader_secpoline.h"
=======
#include "load_secpoline.h"
>>>>>>> lazypoline-secure:src/secpoline_loader/loader/main.c
#include "ld_malloc.h"


int main(int argc, char ** argv, char ** envp) {
    //assert(!__is_loader);
    size_t * sp = (size_t *)(argv - 1);
    size_t * auxvals = (size_t *)envp;
    while (*auxvals++);
    load_env();

<<<<<<< HEAD:secpoline_loader/loader/main.c
    struct mmapped_list_s* loader_mappings = get_mappings();
    asm_load_secpoline(argc, argv, envp, loader_mappings);
    ld_malloc_reset();
    reset_dso();
=======
    char* secpoline_env = getenv("SECPOLINE");
    if((secpoline_env == NULL) || (strcmp(secpoline_env, "DISABLE") != 0)){
        struct mmapped_list_s* loader_mappings = get_mappings();
        asm_load_secpoline(argc, argv, envp, loader_mappings);
        ld_malloc_reset();
        reset_dso();
    }

>>>>>>> lazypoline-secure:src/secpoline_loader/loader/main.c

    pthread_mutex_lock(&dso_lock);
    if (dso_load_self() == NULL) {
        ERROR(main, "Failed to create dso handle for the loader\n");
        exit(1);
    }

    if(!__is_loader){
        if (argc < 3) {
            ERROR(main, "Invalid number of parameters\n");
            ERROR(main, "Usage: %s <elf_file> [args...]\n", argc > 0 ? argv[0] : "loader");
            exit(1);
        }
    }


    char* libc_loader_name = getenv("LOADER_PATH");
    if(libc_loader_name){
        libc_loader_name = strdup(libc_loader_name);
    }else{
        libc_loader_name = strdup("/lib64/ld-linux-x86-64.so.2");
    }

    if (libc_loader_name == NULL) {
        ERROR(main, "Failed to allocate space for executable name\n");
        exit(1);
    }

    dso_t * dso_libc_loader = NULL;
    dso_libc_loader = dso_dynload(libc_loader_name, true, &base_search_path);

    if (dso_libc_loader == NULL) {
        ERROR(main, "Could not load '%s'\n", libc_loader_name);
        exit(1);
    }

    
    if(!__is_loader){
        int our_phnum = 0;
        Elf64_Phdr* our_phdrs = NULL;
        size_t* stack_end = NULL;
        for (size_t i = 0; stack_end==0; i += 2) {
            size_t* val = &auxvals[i + 1];
            switch (auxvals[i]) {
                case AT_ENTRY:
                    *val=(size_t)dso_libc_loader->entry;
                    break;
                case AT_PHDR:
                    our_phdrs = (Elf64_Phdr*) *val;
                    *val = (size_t)dso_libc_loader->base;
                    break;
                case AT_PHNUM:
                    our_phnum = *val;
                    *val = (size_t)dso_libc_loader->phdr_length;
                    break;
                case AT_BASE:
                    *val = 0;
                    break;
                case AT_EXECFN:
                    *val = (uintptr_t) libc_loader_name;
                    break;
                case AT_NULL:
                    stack_end = val;
                    break;
            }
        }
    
        //argv[0] = name of libc loader, argv[1] = name of application called by libc loader
        memcpy(&sp[1], &sp[2], (int)(stack_end-&sp[2])*sizeof(size_t)); //move stack argument one down to enfore 16byte stack allignement
        sp[1] = (size_t) libc_loader_name;
        sp[0] -= 1; //argc -= 1
        //update the application name to make it a relative path if it is not an absulote path
        char* application_name = (char*)sp[2];
        if(application_name[0] != '/' && application_name[0] != '.'){
            char* new_path = (char*)malloc(strlen(application_name)+3);
            new_path[0] = '.';
            new_path[1] = '/';
            memcpy(new_path+2, application_name, strlen(application_name)+1);
            sp[2] = (size_t)new_path;
        }
    }
/* 
    fprintf(stderr, "argc: %d -> name: %s\n", sp[0], sp[1]);
    for(int i = 1;i<sp[0];i++){
        fprintf(stderr, "%s\n", sp[i]);
    }

    fprintf(stderr, "path: %s\n", getenv("PATH"));
*/
    sp[-1] = (size_t)dso_libc_loader->entry; //push entry on stack
    pthread_mutex_unlock(&dso_lock);
    asm(
        "mov %[sp], %%rsp\n\t"
        "mov $0, %%rax\n\t"
        "mov $0, %%rbx\n\t"
        "mov $0, %%rcx\n\t"
        "mov $0, %%rdx\n\t"
        "mov $0, %%rdi\n\t"
        "mov $0, %%rsi\n\t"
        "mov $0, %%rbp\n\t"
        "mov $0, %%r8\n\t"
        "mov $0, %%r9\n\t"
        "mov $0, %%r10\n\t"
        "mov $0, %%r11\n\t"
        "mov $0, %%r12\n\t"
        "mov $0, %%r13\n\t"
        "mov $0, %%r14\n\t"
        "mov $0, %%r15\n\t"
        "ret\n\t"
        :: [sp]"r"(sp - 1)
    );
    
}