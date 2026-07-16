#include "sud.h"

#include "secpoline.h"
#include "zpoline.h"
#include "gsreldata.h"
#include "signal_handlers.h"

#include <immintrin.h>
#include <stddef.h>
#include "hardware_breakpoints.h"
#include <sys/auxv.h>

extern "C" void SUD_entry_point(int signo, siginfo_t* info, void* ucontextv);
extern Page_group* vdso_pages;


void prepare_signal_mask(){
    sigset_t set;

    sigemptyset(&set);
    sigaddset(&set, SIGSYS);

#if SCAN_UNSAFE_INSTRUCTIONS
    sigaddset(&set, SIGSEGV);
    sigaddset(&set, SIGTRAP);
#endif

    sigprocmask(SIG_UNBLOCK, &set, NULL);
}


struct vdso_location {
    const uint8_t* const start;
    const int len;

    static vdso_location& get() {
        // this length might be too small, depending on kernel version
        static vdso_location _vdso{(uint8_t*) vdso_pages->start_address, vdso_pages->size};
        return _vdso;
    }

    bool contains(uint8_t* addr) {
        if (addr >= start && addr < start + len)
            return true;
        return false;
    }

private:
    vdso_location(uint8_t* start, int len) : 
        start{start}, len{len}
    {
        nolibc_assert(start);
        nolibc_assert(__builtin_is_aligned(start, 0x1000));
    }
};


// This handler should _only_ return after the REG_RIP has been repointed to the asm_syscall_hook
// otherwise, the selector will not be properly reset to BLOCK, and the syscall will not be properly emulated
//static?
//TODO, when this function is on an usafe page, it sometimes will clear the segfault handler for some reason????
extern "C" void handle_sigsys(int sig, siginfo_t *info, void *ucontextv, char compartment_id_on_entry) {
    nolibc_assert(gsreldata->readable_data.compartment_id == TS_MONITOR);
    // see the sigaction handling for more info
    nolibc_assert(info->si_code == SYS_USER_DISPATCH_INTERNAL && "SUD does not support safely running non-SUD SIGSYS handlers!");
    nolibc_assert(sig == SIGSYS);
	nolibc_assert(info->si_signo == SIGSYS);
	nolibc_assert(info->si_errno == 0);
    
    //unblock all signals here
    sigset_t empty_mask = {0};
    nolibc_assert(inline_syscall6(__NR_rt_sigprocmask, SIG_SETMASK, &empty_mask, 0, SIGSETSIZE, 0, 0) == 0);

#if REWRITE_TO_ZPOLINE
    auto& vdso = vdso_location::get();
    uint16_t* syscall_addr = &((uint16_t*)info->si_call_addr)[-1];
    if (!vdso.contains((uint8_t*) syscall_addr)) 
        rewrite_syscall_inst(syscall_addr, compartment_id_on_entry);
#endif
    
    // emulate the system call by invoking the asm_syscall_hook entrypoint (single entry point for syscall emulation)
    // this has the added advantage that we're not in a signal handler when handling certain system calls
    //  that has been an issue when receiving signals while in blocking system calls (e.g. waiting on socket)
    // we have to set up the stack "as if" we were coming from the rewritten `callq *%(rax)`, i.e. push our 
    // return address to the stack
    // FIXME: I think, for safety, it's better to run this handler on a different stack. Otherwise our stack pushes
    // might start overwriting our sighandler local vars
    const auto uctxt = (ucontext_t*) ucontextv;
	const auto gregs = uctxt->uc_mcontext.gregs;
	nolibc_assert(gregs[REG_RAX] == info->si_syscall);
    // push RIP and RAX: this clobbers memory beyond the end of the stack, which isnt necessary for SUD
    // but it is necessary for zpoline
    gregs[REG_RSP] -= 2 * sizeof(uint64_t);
    auto stack_bottom = ((long long*)gregs[REG_RSP]);

    //only give permissions that are needed to modify the stack_after_sigreturn
    if(compartment_id_on_entry == TS_APPLICATION)
        ACCESS_UNTRUSTED_MEMORY(
            "movq %[rip], (%[sp1])\n"
            "movq %[rax], (%[sp2])\n",
            ,
            [rip]"r"(gregs[REG_RIP]), [sp1]"r"(&stack_bottom[1]), [rax]"r"(gregs[REG_RAX]), [sp2]"r"(&stack_bottom[0])
        );
    else{
        stack_bottom[1] = gregs[REG_RIP];
        stack_bottom[0] = gregs[REG_RAX];
    }
    // we keep RAX as the syscall no here, so we can potentially detect in
    // `asm_syscall_hook` whether we came from SUD or not
    // "jmpq asm_syscall_hook". If we came from a rewritten syscall, 
    // `rax` would be the `asm_syscall_hook` address (zpoline.cpp)
    // I suppose we could also figure that out from the `sud_selector` value
    gregs[REG_RIP] = (long long) syscall_hook_entry;

    nolibc_assert(gregs[REG_RAX] == info->si_syscall);
    gsreldata->readable_data.compartment_id = compartment_id_on_entry;
    // sigreturn to the asm_syscall_hook!

}

// "shitty" globul, but its shared-ness will
// automatically be tied to CLONE_VM, which is what we want
static spinlock rewrite_lock;
void rewrite_syscall_inst(uint16_t* syscall_addr, char compartment_id_on_entry) {
    void* syscall_page = __builtin_align_down(syscall_addr, PAGE_SIZE);

    rewrite_lock.lock();
    defer(rewrite_lock.unlock());

	// page has to stay executable because other threads might be executing this page right now
    //however other threads cannot write to this pages because this may add unsafe instructions (wrpkru, xrstor, wgrgsbas), so tag the page with a new mpk key
	int perms = PROT_READ|PROT_WRITE|PROT_EXEC;
    sigset_t old_mask;
    sigset_t new_mask;

    size_t page_pkey = -1;

#if EXCLUSIVE_MPK_POLICY
    //now block all signals as we are using an unusual mpk key
    for(int i=0;i<SIGSETSIZE;i++){
        ((char*)&new_mask)[i] = 0xff;
    }
    
    //lower privileges and rewrite the syscall isntruction 
    //make sure the intruction that is being rewritten is actually the syscall instruction.
    //while we do make the page both executable and writable, it is only writable to the monitor.
    //And the syscall overwrite cannot create a unsafe instruction
    //so we do not rescann the page or update its virutal permissions
    if(compartment_id_on_entry == TS_APPLICATION){
        //if we came from the unstrusted application, make sure the syscall instruction belong to the untrusted applciation
        mpk_check_readonly(syscall_addr, GRANT_TRUSTED_PERMISSIONS);
        page_pkey = UNTRUSTED_MPKEY;
    }else{
        internal_wrpkru(GRANT_TRUSTED_PERMISSIONS);
        page_pkey = SECPOLINE_MPKEY;
    }
    nolibc_assert(inline_syscall6(__NR_rt_sigprocmask, SIG_SETMASK, &new_mask, &old_mask, SIGSETSIZE, 0, 0)==0);

    nolibc_assert(inline_syscall6(__NR_pkey_mprotect, syscall_page, 0x1000, perms, SECPOLINE_MPKEY, 0, 0) == 0);
    //only rewrite if another thread has not rewritten jet
    if(*syscall_addr==0x050F){
        *syscall_addr = 0xD0FF; 
    }
    nolibc_assert(inline_syscall6(__NR_pkey_mprotect, syscall_page, 0x1000, PROT_READ|PROT_EXEC, page_pkey, 0, 0) == 0);

    nolibc_assert(inline_syscall6(__NR_rt_sigprocmask, SIG_SETMASK, &old_mask, 0, SIGSETSIZE, 0, 0) == 0);
    
    internal_wrpkru(GRANT_TRUSTED_PERMISSIONS);
#else
    nolibc_assert(inline_syscall6(__NR_mprotect, syscall_page, 0x1000, perms, 0, 0, 0) == 0);
    if(*syscall_addr==0x050F){
        *syscall_addr = 0xD0FF; 
    }
    nolibc_assert(inline_syscall6(__NR_mprotect, syscall_page, 0x1000, PROT_READ|PROT_EXEC, 0, 0, 0) == 0);
#endif
    // fprintf(stderr, "Rewrote syscall at %p\n", syscall_addr);
}


void init_sud() {
    void* secure_stack_base = setup_secure_stack();
    map_gsrel_region(secure_stack_base);
    assert(gsreldata == 0);
    static_assert(offsetof(GSRelativeData, readable_data.sud_selector) == 0); // asm code depends on this

    set_sud_allow();
    
    gsreldata->signal_handlers = map_signal_handlers();
    new (gsreldata->signal_handlers) SignalHandlers();
    //Setup alt stack
    setup_altstack();

    struct sigaction act = {};
	act.sa_sigaction = SUD_entry_point;
	act.sa_flags = SA_SIGINFO|SA_ONSTACK|SA_NODEFER;

    ASSERT_ELSE_PERROR(sigfillset(&act.sa_mask) == 0); //block all signals at the start of the SIGSYS handler
	ASSERT_ELSE_PERROR(sigaction(SIGSYS, &act, NULL) == 0);

    assert(offsetof(ucontext_t, uc_mcontext.gregs[REG_RSP])==RSP_OFFSET_UCONTEXT);

    prepare_signal_mask();
}
