#include "gsreldata.h"
#include "nolibc_util.h"
#include "sud.h"

#include "secpoline.h"
#include "zpoline.h"
#include "gsreldata.h"
#include "signal_handlers.h"
#include "signal_handlers.h"

#include <immintrin.h>
#include <stddef.h>
#include <sys/auxv.h>
#include <linux/unistd.h>
#include "rigtorp_spinlock.h"
#include "erim.h"
#include "virtual_thread.h"
#include "virt_page_manager.h"
#include "mpk_isolation.h"

extern pthread_rwlock_t mmap_lock;
/* 
Do not use any libc or other shared library, this code should never call anthing outside of this file

*/
extern sighandler_type asm_signal_entry;

extern "C" size_t meta_monitor(size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t arg5, size_t arg6, size_t syscall_no, size_t rip_after_syscall){
    //nolibc_print_size_t("meta syscall:", syscall_no);
    if(syscall_no == __NR_rt_sigreturn){
        nolibc_assert(0); //sigreturn should never be interposed, instead it should be handled directly after the signal handler wrapper
    }

    //Tag new pages as untrusted
    //Scan new executable pages for unsafe instructions
    //Prevent pages from being writable and executable
    //TODO MAP_GROWSDOWN
    if(syscall_no == __NR_mmap){
        size_t start = arg1;
        size_t size = ((arg2 + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE; //allign the size to page_size
        size_t prot = arg3;
        size_t flags = arg4;
        size_t fd = arg5;
        size_t offset = arg6;
#if MMAP_LOCK
        nolibc_assert(pthread_rwlock_wrlock(&mmap_lock) == 0);
        size_t ret = secpoline_mmap(start, size, prot, flags, fd, offset, TS_MONITOR);
        nolibc_assert(pthread_rwlock_unlock(&mmap_lock) == 0);
#else
        size_t ret = secpoline_mmap(start, size, prot, flags, fd, offset, TS_MONITOR);
#endif
        return ret;
    }

    if(syscall_no == __NR_munmap){

#if MMAP_LOCK
        nolibc_assert(pthread_rwlock_wrlock(&mmap_lock) == 0);
#endif
        //TODO check that munmap will fail before removing the virt_pages
        if(page_manager.remove_page((char*)arg1, arg2, TS_MONITOR) == -1){
#if MMAP_LOCK
            nolibc_assert(pthread_rwlock_unlock(&mmap_lock) == 0);
#endif
            return -EINVAL;
        }

        size_t ret = inline_syscall6(syscall_no, arg1, arg2, arg3, arg4, arg5, arg6);
#if MMAP_LOCK
        nolibc_assert(pthread_rwlock_unlock(&mmap_lock) == 0);
#endif
        return ret;
    }

    if(syscall_no == __NR_mremap){

        char* end = (char*)arg1 + arg2;
        struct virt_page* rpage = page_manager.lookup_addr((char*)arg1, TS_MONITOR);
        if(rpage == NULL) return -EFAULT;
        if(end > (rpage->start+rpage->size)) return -EFAULT;
        int prot = rpage->prot;
        if(prot&PROT_EXEC){
            set_sud_block();
            char* ret = handle_mremap_exec((char*)arg1, arg2, arg3, arg4, (char*)arg5, prot, TS_MONITOR);
            set_sud_allow();
            return (size_t)ret;
        }

        set_sud_block();
        char* ret = handle_mremap((char*)arg1, arg2, arg3, arg4, (char*)arg5, TS_MONITOR);
        set_sud_allow();
        return (size_t)ret;
    }

    //just check that the page already exists and that we are not using pkeymprotect to change anything exept the pkey
    //TODO allow permissions changes aswell
    if(syscall_no == __NR_pkey_mprotect){
#if TRACK_MAPPINGS
        int cid = get_cid(arg4);
        if(cid == -1) return -EINVAL;
        struct virt_page* current_group = page_manager.lookup_addr((char*)arg1, cid);
        if((current_group->start != (char*)arg1) || (current_group->size != arg2) || (current_group->prot != (int)arg3)){
            return -EINVAL;
        } 
#endif
        return inline_syscall6(syscall_no, arg1, arg2, arg3, arg4, arg5, arg6);
    }


    //TODO prevent making non-anon pages executable
    if (syscall_no == __NR_mprotect) {
        nolibc_assert(!(arg3&MAP_HUGETLB));

        if ((!!(arg3 & PROT_EXEC)) && (!!(arg3 & PROT_WRITE))) {
            arg3 = arg3&(~PROT_EXEC);
            int res =  inline_syscall6(syscall_no, arg1, arg2, arg3, arg4, arg5, arg6);
            if(res == 0){
                page_manager.update_mprotect((char*)arg1, arg2, arg3, TS_MONITOR);
                for(char* address = (char *)arg1; address < (char*)arg1+arg2;address+=PAGE_SIZE){
                    add_unsafe_page(address, arg3, arg3|PROT_EXEC, true, NULL);
                }
            }
            return res; 
        }

        if((arg3 & PROT_EXEC)) {
            //first make the pages read only to prevent overwite during scanning
            int res = inline_syscall6(__NR_mprotect, (int64_t)arg1, arg2, PROT_READ, 0, 0, 0);
            if(res < 0){
                return res;
            }
            set_sud_block();
            scan_exec_mapping_mprotect((char*)arg1, arg2, arg3, arg3&~PROT_EXEC, TS_MONITOR, NULL);
            set_sud_allow();
            return 0;
        }

        int ret = inline_syscall6(syscall_no, arg1, arg2, arg3, arg4, arg5, arg6);
        nolibc_assert(page_manager.update_mprotect((char*)arg1, arg2, arg3, TS_MONITOR)==0);
        return ret;

    }

    if(syscall_no == __NR_rt_sigprocmask){
        sigset_t set;
        for (size_t i = 0; i < arg4; ++i) {
            ((unsigned char*)&set)[i] = ((unsigned char*)arg2)[i];
        }
        int ulong_w = sizeof(unsigned long)*8;
        set.__val[(SIGSYS-1)/ulong_w] &= ~(1UL << (((SIGSYS) - 1) % ulong_w));
        set.__val[(SIGSEGV-1)/ulong_w] &= ~(1UL << (((SIGSEGV) - 1) % ulong_w));
        set.__val[(SIGTRAP-1)/ulong_w] &= ~(1UL << (((SIGTRAP) - 1) % ulong_w));
        return inline_syscall6(syscall_no, arg1, &set, arg3, arg4, arg5, arg6);
    }

    //TODO don't allow the monitor to overwrite the signal handler wrapper, instead setup a new virual handler
    if(syscall_no == __NR_rt_sigaction){
        //only set these to signal entry
        if(arg1 == SIGSEGV || arg1 == SIGSYS || arg1 == SIGTRAP){
            struct kernel_sigaction *newact = (struct kernel_sigaction *)arg2;
            if(!newact){
                return inline_syscall6(syscall_no, arg1, arg2, arg3, arg4, arg5, arg6);
            }else if(newact->k_sa_handler!=(decltype(newact->k_sa_handler)) asm_signal_entry){
                newact->sa_flags &= ~SA_RESETHAND;
                newact->sa_flags &= ~SA_SIGINFO;
                newact->sa_flags &= ~SA_ONSTACK;
                newact->sa_flags &= ~SA_NODEFER;
                return inline_syscall6(syscall_no, arg1, NULL, arg3, arg4, arg5, arg6);
            }else{
                return inline_syscall6(syscall_no, arg1, arg2, arg3, arg4, arg5, arg6);
            }
        }
    }

    if(syscall_no == __NR_clone3) return -ENOSYS;
    if(syscall_no == __NR_sigaltstack) return -ENOSYS;

    if(syscall_no == __NR_clone){
        if(gsreldata->fake_clone_flag){
            //Don't actually create a child thread at this point, just save the location the childs tld, and it tid field in that tls
            return virual_clone_wrapper(arg1, (size_t*)arg2, arg3, arg4, arg5);
        }

        long _ret;
        register long _num  __asm__ ("rax") = (syscall_no);
        register long _arg1 __asm__ ("rdi") = (long)(arg1);
        register long _arg2 __asm__ ("rsi") = (long)(arg2);
        register long _arg3 __asm__ ("rdx") = (long)(arg3);
        register long _arg4 __asm__ ("r10") = (long)(arg4);
        register long _arg5 __asm__ ("r8")  = (long)(arg5);
        register long _arg6 __asm__ ("r9")  = (long)(arg6);

        __asm__ volatile (
            "subq $8, %%rsi\n"
            "pushq %%r15\n"
            "movq %[rip_after_syscall], %%r15\n" 
            "movq %%r15, (%%rsi)\n" 
            "popq %%r15\n"
            "syscall\n"
            "test %%rax, %%rax\n"
            "jnz 1f\n"
            "xor %%rsi, %%rsi\n"
            "callq *%[setup_thread]\n"
            "ret\n"
            "1:\n"
            : "=a"(_ret)
            : "r"(_arg1), "r"(_arg2), "r"(_arg3), "r"(_arg4), "r"(_arg5),
            "r"(_arg6), "0"(_num), [rip_after_syscall] "r"(rip_after_syscall),
            [setup_thread] "r"(setup_new_thread)
            : "rcx", "r11", "memory", "cc"
        );
        return _ret;
    }


    if(syscall_no == __NR_exit){
        //This can be the exit of a monitor thread or the exit of an application thread, in both cases we only need to unmap gsreldata
        bool is_monitor_thread = false;
        if(gsreldata->secure_stack.sp==0)is_monitor_thread = true;
        teardown_thread_metadata();

        //the child thread ID cannot be overwritten if we don't have the correct permissions
        //TODO unmap the stack of this thread
        if(is_monitor_thread){
            inline_syscall6(syscall_no, arg1, arg2, arg3, arg4, arg5, arg6);
        }else{
            asm volatile(
                "xorl %%ecx, %%ecx\n"
                "xorl %%edx, %%edx\n"
                "movl %[permissions], %%eax\n"
                "wrpkru\n"
                "cmpl %[permissions], %%eax\n"
                "je 1f\n"
                "ud2\n"
                "int3\n"
                "1:\n"
                "movq %[ret], %%rdi\n"
                "movq %[syscall_no], %%rax\n"
                "syscall\n"
                :
                :[permissions]"i"(REVOKE_PERMISSIONS),
                [compartment_id]"i"(COMPARTMENT_ID_OFFSET),
                [monitor_state]"i"(TS_MONITOR), [ret]"r"(arg1), [syscall_no]"i"(__NR_exit)
                : "rax", "rcx", "rdx"
            );   
        }
        //exit should never fail
        nolibc_assert(0);
    }

    return inline_syscall6(syscall_no, arg1, arg2, arg3, arg4, arg5, arg6);
}


