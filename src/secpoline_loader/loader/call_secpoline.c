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
#include "load_secpoline.h"


#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
size_t rsp_holder = 0;

char** update_ldpreload(char** envp, int* envp_size);
static size_t rdfsbase();

void load_secpoline(int argc, char ** argv, char ** envp, struct mmapped_list_s* loader_mappings, size_t* rip_after_setup) {
    //assert(!__is_loader);
    size_t * sp = (size_t *)(argv - 1);
    size_t * auxvals = (size_t *)envp;
    while (*auxvals++);

    pthread_mutex_lock(&dso_lock);
    if (dso_load_self() == NULL) {
        ERROR(main, "Failed to create dso handle for the loader\n");
        exit(1);
    }

    if (!__is_loader && argc < 2) {
        ERROR(main, "Invalid number of parameters\n");
        exit(1);
    }

    
    char* libc_loader_name = getenv("LOADER_PATH");
    char* secpoline_libc_loader_name = getenv("secpoline_LOADER_PATH");
    if(secpoline_libc_loader_name){
        libc_loader_name = strdup(secpoline_libc_loader_name);
    }else if(libc_loader_name){
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

    //Setup the new stack for secpoline, the current stack looks like:
    //


    size_t* stack_end = auxvals;
    while(*stack_end)stack_end+=2;
    stack_end++;

    //move everything (argv, env, aux) to new stack
    char* new_stack = (char*) mmap(0, 0x100000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(new_stack!=MAP_FAILED);
    size_t* new_sp = (size_t*)(new_stack+0x100000-8);

    int aux_size = (stack_end-auxvals);
    int envp_size = (auxvals - (size_t*)envp);
    char** new_envp = update_ldpreload(envp, &envp_size);
    //enfor 16 byte allignment
    new_sp -= envp_size;
    new_sp -= aux_size;
    if((size_t)new_sp%16) new_sp--;
    //push env varaible on new stack
    memcpy(new_sp, new_envp, envp_size*sizeof(size_t));
    //push aux vector on new stack
    memcpy(new_sp+envp_size, auxvals, aux_size*sizeof(size_t));


    //the pheaders for the application if we are invoked
    //or for the secpoline loader if we are requested
    int our_phnum = 0;
    Elf64_Phdr* our_phdrs = NULL;

    //update the aux vector    
    size_t* new_aux = new_sp+envp_size;
    for (size_t i = 0; new_aux[i] != AT_NULL; i += 2) {
        size_t* val = &new_aux[i + 1];
        switch (new_aux[i]) {
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
                if(__is_loader){
                    *val = (size_t)dso_libc_loader->base;
                }else{
                    *val = 0;
                }
                break;
            case AT_EXECFN:
                *val = (uintptr_t) libc_loader_name;
                break;
            case AT_RANDOM:
                //TODO do they need to be 16 new random bytes?
                *val = (size_t)(memcpy(malloc(16), (void*)*val, 16));
                break;
            case AT_PLATFORM:
                *val = (size_t)strdup((char*)*val);
        }
    }
    //fix_debugger(dso_libc_loader, our_phdrs, our_phnum);


    //get the path for secpoline and its loader to support execve calls later
    char* secpoline_path;
    char* secpoline_loader_path;     
    if(!__is_loader){
        secpoline_path = argv[1];
        secpoline_loader_path = argv[0];        
    }else{
        secpoline_path = getenv("SECPOLINE");
        if(secpoline_path==NULL){
            ERROR(load, "Specify the path to secpoline using \"export SECPOLINE=\"\n");
            exit(1);
        }

        Elf64_Phdr * interp_ent;
        for (size_t i = 0; i < our_phnum; i++) {
            if (our_phdrs[i].p_type == PT_INTERP) {
                interp_ent = &our_phdrs[i];
            }
        }
        Elf64_Phdr * phdr_ent;
        for (size_t i = 0; i < our_phnum; i++) {
            if (our_phdrs[i].p_type == PT_PHDR) {
                phdr_ent = &our_phdrs[i];
            }
        }
        
        if (phdr_ent == NULL) {
            ERROR(load, "Failed to get binary base (no PT_PHDR entry present)\n");
           exit(1);
        }
        char* application_base = (char *)our_phdrs - phdr_ent->p_vaddr;
        secpoline_loader_path = interp_ent->p_vaddr + application_base;
    }

    new_sp -= 8; //make place for argv
    new_sp[-1] = (size_t)dso_libc_loader->entry;
    new_sp[0] = 6; //argc = 6
    new_sp[1] = (size_t)libc_loader_name;
    new_sp[2] = (size_t)strdup(secpoline_path); //secpoline name
    new_sp[3] = (size_t)rip_after_setup;
    new_sp[4] = rdfsbase();
    new_sp[5] = (size_t)loader_mappings;
    new_sp[6] = (size_t)secpoline_loader_path;//secpoline loader name
    new_sp[7] = (size_t)0; //terminator

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
        :: [sp]"r"(new_sp - 1)
    );
}


//if secpoline_ld_preload is set, copy its value into ld_preload. If it already exists update it, otherwise make a new env variable
//Update glibc_tunalbes to disable rseq. If it already exists update it, otherwise make a new env variable
char** update_ldpreload(char** envp, int* envp_size){
    char* secpoline_preload = getenv("SECPOLINE_LD_PRELOAD");
    char* ld_preload = getenv("LD_PRELOAD");
    char* glibc_tunables = getenv("GLIBC_TUNABLES");
    int new_env_size = *envp_size;

    //This is the new value for LD_PRELOAD
    char* new_ld_preload = NULL;
    if(secpoline_preload){
        char* ld_preload_str = "LD_PRELOAD=";
        int preload_size = strlen(ld_preload_str);
        int secpoline_size = strlen(secpoline_preload);
        int new_size = secpoline_size + preload_size;
        new_ld_preload = (char*) malloc(new_size+1);
        new_ld_preload[new_size]='\0';
        memcpy(new_ld_preload, ld_preload_str, preload_size);
        memcpy(&new_ld_preload[preload_size], secpoline_preload, secpoline_size);
    }

    char** new_envp = (char**) calloc((new_env_size), sizeof(char*));

    //This is the new value for GLIBC_TUNALBES
    if(!glibc_tunables){
        //GLIBC_TUNALBES is not already set so add a new env add the end
        new_env_size++;
        new_envp = (char**) realloc(new_envp, (new_env_size)*sizeof(char*));
        new_envp[new_env_size-2] = strdup("GLIBC_TUNABLES=glibc.pthread.rseq=0");
    }

    if(!ld_preload && secpoline_preload){
        //LD_PRELOAD does not exist but secpoline_ld_preload does so add a new env ad the end
        new_env_size++;
        new_envp = (char**) realloc(new_envp, (new_env_size)*sizeof(char*));
        new_envp[new_env_size-2] = new_ld_preload;
    }


    for(int i = 0; i<*envp_size; i++){
        // split variable in name and value
        char* env_name = envp[i];
        if (env_name==NULL)
            continue;
        char* env_value = strchr(env_name, '=');
        if (env_value==NULL)
            continue;
        env_value[0] = '\0';
        env_value++;

        if(strcmp(env_name, "LD_PRELOAD") == 0){
            env_value[-1] = '=';
            if(secpoline_preload&&ld_preload)new_envp[i] = new_ld_preload; // overwrite ld_preload if it was already set
        } else if(strcmp(env_name, "GLIBC_TUNABLES") == 0){
            env_value[-1] = '=';
            if(glibc_tunables){
                char* disable_rseq_str = "glibc.pthread.rseq=0";
                char* new_glibc_tunables = (char*) malloc(strlen(envp[i])+strlen(disable_rseq_str)+1);
                strcpy(new_glibc_tunables, envp[i]);
                strcat(new_glibc_tunables, disable_rseq_str);
                new_envp[i] = new_glibc_tunables; // overwrite glibc_tunable if it was already set
            }
        } else {
            env_value[-1] = '=';
            new_envp[i] = strdup(envp[i]);
        }
    }
    
    *envp_size = new_env_size;
    return new_envp;
}

static size_t rdfsbase(){
    size_t fs_base;
    asm(
    "rdfsbase %0"
    : "=r" (fs_base)
    );
    return fs_base;
}