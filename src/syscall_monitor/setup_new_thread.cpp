#include "gsreldata.h"
#include "nolibc_util.h"
#include "signal_handlers.h"

#include <linux/sched.h>
#include <linux/prctl.h>
#include <linux/unistd.h>
#include <linux/mman.h>

#include <asm/prctl.h>
#include <immintrin.h>

#include <errno.h>
#include <time.h>

#include <pthread.h>
#include "util.h"
#include "hardware_breakpoints.h"
#include "virt_page_manager.h"


#define PR_SET_SYSCALL_USER_DISPATCH	59
#define PR_SYS_DISPATCH_OFF	            0
#define PR_SYS_DISPATCH_ON	            1
#define SYSCALL_DISPATCH_FILTER_ALLOW	0
#define SYSCALL_DISPATCH_FILTER_BLOCK	1

extern 

// implemented in restore_selector_trampoline.asm
__attribute__ ((visibility("hidden")))
extern "C" void restore_selector_trampoline();
extern void (*update_active_thread_list)(bool);

/* Watch out with the code you call here: 
    it shouldn't do any TLS stuff, and shouldn't call glibc either
*/

#ifndef assert
#define assert(cond)        \
    do {                    \
        if (!(cond))          \
            asm ("int3");   \
    } while (0);
#endif

static void tag_as_trusted(void* addr, size_t len) {
    auto res = inline_syscall6(__NR_pkey_mprotect, addr, len, PROT_READ|PROT_WRITE, SECPOLINE_MPKEY, 0, 0);
    assert(res == 0);
}


GSRelativeData* map_gsrel_region(void* secure_stack_base) {
    auto mem = (void*) inline_syscall6(__NR_mmap, 0x0, sizeof(GSRelativeData), PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    assert(mem != (void*) -1 && mem != 0);
    tag_as_trusted(mem, sizeof(GSRelativeData));
    auto res = inline_syscall6(__NR_pkey_mprotect, mem, sizeof(GSRelativeData::readable_data), PROT_READ|PROT_WRITE, SECPOLINE_READONLY_MPKEY, 0, 0);
    assert(res == 0);
    auto gsreldata = new ((void*)mem) GSRelativeData();

    auto result = inline_syscall6(__NR_arch_prctl, ARCH_SET_GS, mem, 0, 0, 0, 0);
    assert(result == 0);

    gsreldata->secure_stack.base = secure_stack_base; 
    gsreldata->secure_stack.sp = (uint8_t*)secure_stack_base + SECURE_STACK_SIZE;

    gsreldata->readable_data.compartment_id = TS_MONITOR;

#if DEBUG
    gsreldata->readable_data.pages_head = &page_manager.pages;
#endif
    return gsreldata;
}

inline uint64_t rdgsbase() {
#ifdef __FSGSBASE__
    return _readgsbase_u64();
#else
    uint64_t gsbase = 0;
    auto result = inline_syscall6(__NR_arch_prctl, ARCH_GET_GS, &gsbase, 0, 0, 0, 0);
    assert(result == 0);
    return gsbase;
#endif
}

void* teardown_thread_metadata() {
    //kills the current thread, we'd best unmap some things
    set_sud_allow();
    //block all signals
    sigset_t new_mask;
    nolibc_assert(sigfillset(&new_mask)==0);
    nolibc_assert(inline_syscall6(__NR_rt_sigprocmask, SIG_SETMASK, &new_mask, 0, SIGSETSIZE, 0, 0)==0);

    //remove this thread from active list of threads
    nolibc_assert(update_active_thread_list);
    update_active_thread_list(true);


    // never unmap the sigdisps since it's too hard/racy to figure out if anyone is still using them
    //first make sure to remove some virtual pages before actually removing them
    assert(page_manager.remove_page((char*)rdgsbase(), __builtin_align_up(sizeof(GSRelativeData), 0x1000), TS_MONITOR)==0);
    
    // ensure the kernel won't try to access the unmapped selector
    int result = inline_syscall6(__NR_prctl, PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_OFF, 0x0, 0, 0, 0);
    assert(result == 0);
    GSRelativeData* gs = (GSRelativeData*) rdgsbase();
    volatile void* ss_base = gs->secure_stack.base;
    result = inline_syscall6(__NR_munmap, (void*)rdgsbase(), __builtin_align_up(sizeof(GSRelativeData), 0x1000), 0, 0, 0, 0);
    assert(result == 0);
    return (void*) ss_base;
}

void enable_sud() {
    volatile char* selector_addr = ((char*) rdgsbase()) + SUD_SELECTOR_OFFSET;
    long result = inline_syscall6(__NR_prctl, PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, 0x0, 0, selector_addr, 0);
	assert(result == 0);
}

SignalHandlers* map_signal_handlers() {
    auto result = inline_syscall6(__NR_mmap, 0x0, sizeof(SignalHandlers), PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    assert(result != -1 && result != 0);
    tag_as_trusted((void*) result, sizeof(SignalHandlers));
    return (SignalHandlers*) result;
}

//setup the original stack for the main thread
//all other threads use pthread_create to setup a stack
void* setup_secure_stack(){
    void* base = (void*) inline_syscall6(__NR_mmap, 0x0, SECURE_STACK_SIZE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    assert(base != (void*) -1 && base != 0);
    auto res = inline_syscall6(__NR_pkey_mprotect, base, SECURE_STACK_SIZE, PROT_READ|PROT_WRITE, SECPOLINE_MPKEY, 0, 0);
    assert(res == 0);
    res = inline_syscall6(__NR_mprotect, base, PAGE_SIZE, PROT_READ, 0, 0, 0); /*put a guard page at the bottom of the secure stack*/
    assert(res == 0);
    return base;
}

void setup_altstack(){
    stack_t altstack;
    gsreldata->altstack.sp = altstack.ss_sp = gsreldata->secure_stack.base;
    gsreldata->altstack.flags = altstack.ss_flags = 0;
    gsreldata->altstack.size = altstack.ss_size = SECURE_STACK_SIZE;
    int res = inline_syscall6(__NR_sigaltstack, &altstack, 0, 0, 0, 0, 0);
    assert(res==0);
}

extern "C" void setup_new_thread(unsigned long long clone_flags, void* secure_stack_base) {
    //block all signals before the setup
    sigset_t old_mask;
    sigset_t new_mask;
    nolibc_sigfill_set(&new_mask);
    nolibc_assert(inline_syscall6(__NR_rt_sigprocmask, SIG_SETMASK, &new_mask, &old_mask, SIGSETSIZE, 0, 0)==0);


    GSRelativeData* cloner_gsrel = (GSRelativeData*) rdgsbase();
    GSRelativeData* gsreldata = map_gsrel_region(secure_stack_base);
    
    assert(gsreldata->readable_data.compartment_id == TS_MONITOR);
    set_sud_allow();

    if (clone_flags & CLONE_SIGHAND) {
        // share sigdisps with caller
        gsreldata->signal_handlers = cloner_gsrel->signal_handlers;
    } else {
        // duplicate em
        gsreldata->signal_handlers = map_signal_handlers();
        new ((char*)gsreldata->signal_handlers) SignalHandlers(*cloner_gsrel->signal_handlers);    
    }
    //setup some parts of the sigaltstack, we set the size later before switching back to the untrusted stack
    gsreldata->altstack.sp = gsreldata->secure_stack.base;
    gsreldata->altstack.flags = 0;

    //initialise the hardware breakpoint controller and add this thread to it
    nolibc_assert(update_active_thread_list);

    // re-enable SUD
    enable_sud();

    update_active_thread_list(false);
    
    nolibc_assert(inline_syscall6(__NR_rt_sigprocmask, SIG_SETMASK, &old_mask, 0, SIGSETSIZE, 0, 0) == 0);
    nolibc_assert(page_manager.add_page((char*)gsreldata, sizeof(GSRelativeData), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, TS_MONITOR, false)==0);
    if(!(clone_flags & CLONE_SIGHAND))nolibc_assert(page_manager.add_page((char*)gsreldata->signal_handlers, sizeof(SignalHandlers), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, TS_MONITOR, false)==0);
    //nolibc_assert(inline_syscall6(__NR_tgkill, nolibc_getpid(), nolibc_gettid(), SIGSEGV, 0, 0, 0) == 0); //the signal wil have si_code SI_USER


    //here we can start calling unaware code so lets add all these new pages to the page_manager
    set_sud_block();
}

extern "C" void setup_vforked_child() {
    void* secure_base = 0;
    setup_new_thread(CLONE_VM|CLONE_VFORK|SIGCHLD, secure_base);
}

extern "C" void setup_restore_selector_trampoline(void* ucontextv, void* secure_stack_pointer){
    const auto uctxt = (ucontext_t*) ucontextv;
	const auto gregs = uctxt->uc_mcontext.gregs;

    //nolibc_print_size_t("returning to", gregs[REG_RIP]);
    
    gsreldata->sigreturn_stack.current[0] = gregs[REG_RIP];
    gsreldata->sigreturn_stack.current++;
    gregs[REG_RIP] = (uint64_t) restore_selector_trampoline;

    //TODO ?????????
    //when updating ths sigaltstack we need to move rsp out of the altstack (for some reason), however if a signal is delivered restore rsp back(the signal was probably delivered after the syscall)
    if(gregs[REG_RSP]==0){
        gregs[REG_RSP] = gregs[REG_R9];
    }
    
    //backup rsp after sigreturn and replace it with secure stack
    gsreldata->sigreturn_stack.current[0] = gregs[REG_RSP];
    gsreldata->sigreturn_stack.current++;
    gregs[REG_RSP] = (uint64_t)secure_stack_pointer;

    //backup rax, rdx and rcx as they will be clobbert when raising mpk privileges
    gsreldata->sigreturn_stack.current[0] = gregs[REG_RAX];
    gsreldata->sigreturn_stack.current++;
    gsreldata->sigreturn_stack.current[0] = gregs[REG_RDX];
    gsreldata->sigreturn_stack.current++;
    gsreldata->sigreturn_stack.current[0] = gregs[REG_RCX];
    gsreldata->sigreturn_stack.current++;


}


/*
    if(nolibc_getpid()!=nolibc_gettid()){
        set_sud_block();
        int tid2 = gettid();
        for(int i = 1;i<=32;i++){
            nolibc_print_size_t("i:", i);
            nolibc_print_size_t("sigsys handler", (size_t)nolibc_get_handler(i));
        }
        nolibc_print_size_t("sigsys blocked?", (size_t)nolibc_is_blocked(SIGSYS));
        int tid = nolibc_gettid();
        printf("gettid: %d %d\n", tid, tid2);
        set_sud_allow();
    }*/