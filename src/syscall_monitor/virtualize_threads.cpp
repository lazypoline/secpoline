#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include "gsreldata.h"
#include "virtual_thread.h"
#include "nolibc_util.h"

extern "C" void* fake_thread_main_routine(void* arg);
extern void (*update_active_thread_list)(bool);

int virual_clone_wrapper(size_t flags, size_t* child_stack, [[maybe_unused]] size_t ptid, size_t ctid, size_t tls){
    //printf("top of child stack: %llx[%p]\n", child_stack[0], child_stack);
    child_stack = child_stack - 2; //make space for &tls and &ctid
    child_stack[0] = ptid;
    child_stack[1] = tls;
    //printf("child stack[0]: %llx[%p]\n", child_stack[0], &child_stack[0]);
    //printf("child stack[1]: %llx[%p]\n", child_stack[1], &child_stack[1]);
    gsreldata->child_stack = child_stack;
    //at this point the child stack looks like: rip after clone -> tls -> &child tid
    return gettid(); //this should just be a non -1 and non-zero value
}


extern "C" void init_tls_child(){
    assert(!gsreldata->child_stack);//prevent nested calles to clone
    gsreldata->fake_clone_flag = 1;

    pthread_t thread1;
    pthread_attr_t attr;
    //TODO can this be done with the default new thread stack?
    //void* sec_stack_base = setup_secure_stack();
    pthread_attr_init(&attr);
    //assert(pthread_attr_setstack(&attr, sec_stack_base, SECURE_STACK_SIZE)==0);
    assert(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)==0);
    auto result = pthread_create(&thread1, &attr, fake_thread_main_routine, NULL);
    assert(result==0);
    assert(gsreldata->child_stack);
    size_t child_tls = ((size_t*)gsreldata->child_stack)[1];
    gsreldata->child_stack = ((size_t*)gsreldata->child_stack) - 1;
    assert(pthread_getattr_np(child_tls, &attr)==0);

    void *stack_addr;
    size_t stack_size;
    assert(pthread_attr_getstack(&attr, &stack_addr, &stack_size)==0);

    ((size_t*)gsreldata->child_stack)[0] = (size_t)stack_addr;
    pthread_attr_destroy(&attr);

    gsreldata->fake_clone_flag = 0;
    return;
}

extern "C" void prepare_clone_parent(int flags){
    //nolibc_print_size_t("clone preprocessing", flags&CLONE_VFORK);
    //remove the thread from the active thread list, this will block all signals
    if(flags&CLONE_VFORK){
        update_active_thread_list(true);
    }
    return;
}

extern "C" void restart_clone_parent(int flags){
    //add the thread to the active thread list now it is unblocked
    //TODO restore sigproc mask correctly
    //nolibc_print_size_t("clone postprocessing", flags&CLONE_VFORK);
    if(flags&CLONE_VFORK){
        update_active_thread_list(false);
    }
    sigset_t mask;
    nolibc_sigempty_set(&mask);
    set_sud_allow();
    nolibc_assert(inline_syscall6(__NR_rt_sigprocmask, SIG_SETMASK, &mask, NULL, SIGSETSIZE, 0, 0)==0);
    set_sud_allow();
    return;
}
