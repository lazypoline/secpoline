#include "gsreldata.h"
#include "secpoline.h"
#include "sud.h"
#include "zpoline.h"
#include "erim.h"
#include "signals.h"
#include "gsreldata.h"
#include "nolibc_util.h"
#include <libaudit.h>

#include <syscall.h>
#include <sys/signal.h>
#include <sched.h>
#include <unistd.h>
#include <immintrin.h>
#include <string.h>

#include <asm/prctl.h>

#include <openssl/rand.h>
#include <elf.h>
#include <string>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include "virtualize_files.h"
#include "virt_page_manager.h"
#include "libproxysql.h"


extern void (*add_breakpoints_after_fork_wrapper_func)(void);
extern void (*update_active_thread_list)(bool);
extern char* path_to_loader;
extern char* path_to_secpoline;
char is_multithreaded = 0;
extern fd_bitmap untrusted_fd_bitmap;
virt_page_manager page_manager;
pthread_rwlock_t mmap_lock = PTHREAD_RWLOCK_INITIALIZER;
static int connect_fd;


//TODO the return value of the actual handlers is ignored, only the gadgets return if the syscall should be emulated

//Returns -ENOSYS
SYSCALL_HANDLER(not_implemented){
    (*gprs)[REG_RAX] = -ENOSYS;
    return false;
}


SYSCALL_HANDLER(default){
    gprs->do_syscall();
    return false;
}


//Tag new pages as untrusted
//Scan new executable pages for unsafe instructions
//Prevent pages from being writable and executable
//MAP_STACK is currently not supported, but still used in case
//TODO MAP_HUGETLB
//TODO MAP_GROWSDOWN can increase in size, which should increase the size in the page_manager
SYSCALL_HANDLER(mmap){
    size_t start = gprs->arg1();
    size_t size = ((gprs->arg2() + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE; //allign the size to page_size
    size_t prot = gprs->arg3();
    size_t flags = gprs->arg4();
    int fd = gprs->arg5();
    size_t offset = gprs->arg6();
#if MMAP_LOCK
    assert(pthread_rwlock_wrlock(&mmap_lock) == 0);
    (*gprs)[REG_RAX] = secpoline_mmap(start, size, prot, flags, fd, offset, TS_APPLICATION);
    assert(pthread_rwlock_unlock(&mmap_lock)==0);
#else
    (*gprs)[REG_RAX] = secpoline_mmap(start, size, prot, flags, fd, offset, TS_APPLICATION);
#endif
    return false;
}


//Update the brk, if new pages are mapped, tag them with the correct key
SYSCALL_HANDLER(brk){
    (*gprs)[REG_RAX] = -ENOSYS;
    return false;


    int64_t old_break = (int64_t) sbrk(0); //Get current break
    int64_t result = gprs->do_syscall();

    //if the heap is expanded tag new pages as unprotected
    if((gprs->arg1() > old_break)&&(result>0)){
        int delta_size = gprs->arg1() - old_break;
        assert(page_manager.add_page((char*)old_break, delta_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, TS_APPLICATION, false)==0);
        assert(do_syscall_untrusted(old_break, delta_size, PROT_READ|PROT_WRITE, UNTRUSTED_MPKEY, 0, 0, __NR_pkey_mprotect)==0);
    }

    (*gprs)[REG_RAX] = result;
    return false;
}


//Prevent pages from being writable and executable
//Scan new executable pages for unsafe instructions
SYSCALL_HANDLER(mprotect){

/*
#if TRACK_MAPPINGS
    virt_page* current_page = page_manager.lookup_addr((char*)gprs->arg1(), TS_APPLICATION);
    if(current_page == NULL){
        asm("ud2");
        (*gprs)[REG_RAX] = -EINVAL;
        return false; 
    }

    //TODO, just check each page in the range, instead of forcing it to be one range
    if(!!(gprs->arg3() & PROT_EXEC)){
        if((current_page->start != (char*)gprs->arg1()) || (current_page->size != gprs->arg2())){
            asm("ud2");
            (*gprs)[REG_RAX] = -EINVAL;
            return false; 
        }
        if(!(current_page->flags&MAP_ANONYMOUS) && !(current_page->flags&MAP_ANON)){
            asm("ud2");
            (*gprs)[REG_RAX] = -EINVAL;
            return false; 
        }
    }
#endif
*/
    if(page_manager.lookup_range((char*)gprs->arg1(), gprs->arg2(), TS_APPLICATION) == NULL){
        (*gprs)[REG_RAX] = -EINVAL;
        return false;
    }

    assert(!(gprs->arg3() & PROT_GROWSDOWN));
    if ((!!(gprs->arg3() & PROT_EXEC)) && (!!(gprs->arg3() & PROT_WRITE))) {
        gprs->arg3() = gprs->arg3()&(~PROT_EXEC);
        int res = do_syscall_untrusted(gprs->arg1(), gprs->arg2(), gprs->arg3(), 0, 0,0,  __NR_mprotect);
        if(res == 0){
            assert(page_manager.update_mprotect((char*)gprs->arg1(), gprs->arg2(), gprs->arg3(), TS_APPLICATION)==0);
            for(char* address = (char*)gprs->arg1(); address < (char*)gprs->arg1()+gprs->arg2();address+=PAGE_SIZE){
                add_unsafe_page(address, gprs->arg3(), gprs->arg3()|PROT_EXEC, false, NULL);
            }
        }
        (*gprs)[REG_RAX] = res;
        return false; 
    }
    
    if((gprs->arg3() & PROT_EXEC)) {
        //find all instances of wrpkru, wrgsbase and xrstor. If any are found don't give this page executable privileges
        //TODO return error codes instead of asserting
        int res = do_syscall_untrusted(gprs->arg1(), gprs->arg2(), PROT_READ, 0, 0,0,  __NR_mprotect);
        if(res < 0){
            (*gprs)[REG_RAX] = res;
            return false;
        }
        scan_exec_mapping_mprotect((char*)gprs->arg1(), gprs->arg2(), gprs->arg3(), gprs->arg3()&~PROT_EXEC, TS_APPLICATION, NULL);
        (*gprs)[REG_RAX] = 0;
        return false;
    }

    gprs->do_syscall();
    assert(page_manager.update_mprotect((char*)gprs->arg1(), gprs->arg2(), gprs->arg3(), TS_APPLICATION)==0);
    return false;
}

SYSCALL_HANDLER(munmap){
#if MMAP_LOCK
        nolibc_assert(pthread_rwlock_wrlock(&mmap_lock) == 0);
#endif
    if(page_manager.remove_page((char*)gprs->arg1(), gprs->arg2(), TS_APPLICATION) == -1){
#if MMAP_LOCK
        nolibc_assert(pthread_rwlock_unlock(&mmap_lock) == 0);
#endif
        (*gprs)[REG_RAX] = -EINVAL;
        return false;
    }

    gprs->do_syscall();
#if MMAP_LOCK
    nolibc_assert(pthread_rwlock_unlock(&mmap_lock) == 0);
#endif
    return false;
}


SYSCALL_HANDLER(mremap){
#if TRACK_MAPPINGS
    char* end = (char*)gprs->arg1()+gprs->arg2();
    struct virt_page* rpage = page_manager.lookup_addr((char*)gprs->arg1(), TS_APPLICATION);
    if(rpage == NULL) return -EFAULT;
    if(end > (rpage->start+rpage->size)) return -EFAULT;
    int prot = rpage->prot;
    if(prot&PROT_EXEC){
        char* ret = handle_mremap_exec((char*)gprs->arg1(), gprs->arg2(), gprs->arg3(), gprs->arg4(), (char*)gprs->arg5(), prot, TS_APPLICATION);
        (*gprs)[REG_RAX] = (size_t)ret;
        return false;
    }
#endif
    char* ret = handle_mremap((char*)gprs->arg1(), gprs->arg2(), gprs->arg3(), gprs->arg4(), (char*)gprs->arg5(), TS_APPLICATION);
    (*gprs)[REG_RAX] = (size_t)ret;
    return false;
}


//update the arguments to use the secpoline loader instead
//also update the env variables to prevent attackers from setting secpoline_LD_PRELOAD
//TODO close all trusted file descriptors, as we provide access to all open fd at program start to the application
SYSCALL_HANDLER(execve){
    //arg1 filename
    //setup secpoline loader
    char** argv = (char**)gprs->arg2();
    int argc = 0;
    char** envp = (char**)gprs->arg3();
    int envpc = 0;
    internal_wrpkru(GRANT_FULL_PERMISSIONS);
    if(argv && argv[0]){
        //TODO rewrite in assembly to get rid of full permissions
        while(argv[++argc]);
    }else{
        argc = 1;
    }

    internal_wrpkru(GRANT_TRUSTED_PERMISSIONS);

    char** new_argv = (char**)calloc(argc+3, sizeof(char*)); //make space for loader and secpoline path
    assert(new_argv != NULL);
    new_argv[0] = (char*)path_to_loader;
    new_argv[1] = (char*)path_to_secpoline;

    //TODO rewrite in assembly
    internal_wrpkru(GRANT_FULL_PERMISSIONS);
    new_argv[2] = strdup((char*)gprs->arg1());
    internal_wrpkru(GRANT_TRUSTED_PERMISSIONS);
    //make sure we are executing a valid file
    if(access((const char*) new_argv[2], F_OK) != 0){
        (*gprs)[REG_RAX] = -ENOTDIR;
        return false;
    } 
    internal_wrpkru(GRANT_FULL_PERMISSIONS);
    for(int i = 1;i<argc;i++){
        new_argv[i+2] = strdup(argv[i]);
    }
    internal_wrpkru(GRANT_TRUSTED_PERMISSIONS);

    char** new_envp = NULL;
    if(envp != 0){
        internal_wrpkru(GRANT_FULL_PERMISSIONS);
        while(envp[++envpc]);
        internal_wrpkru(GRANT_TRUSTED_PERMISSIONS);

        new_envp = (char**)calloc(envpc+1, sizeof(char*));
        //TODO rewrite in assembly
        internal_wrpkru(GRANT_FULL_PERMISSIONS);
        for(int i = 0;i<envpc;i++){
            new_envp[i] = strdup(envp[i]);
        }
        internal_wrpkru(GRANT_TRUSTED_PERMISSIONS);

        for(int i = 0;new_envp[i] != 0;i++){
            std::string str_temp(new_envp[i]);
            size_t offset = str_temp.find('=');
            if(offset == std::string::npos) continue;
            if(str_temp.substr(0, offset) == "SECPOLINE_LD_PRELOAD")new_envp[i][offset+1] = '\0';
        }
        assert(new_envp);
    }
    internal_wrpkru(GRANT_TRUSTED_PERMISSIONS);

    //remove this thread for the active thread list in case this is a vfork/clone_vfork child, this will block all signals
    //TODO could potentially only do this for vfok children by setting a flag at creation
    //TODO the signal mask is inherited, so changing it before execve could potentially break the child if it relies on a signal mask at entry?
    nolibc_assert(update_active_thread_list);
    update_active_thread_list(true);

    uint64_t res = inline_syscall6(__NR_execve, (size_t)path_to_loader, (size_t)new_argv, (size_t)new_envp, 0, 0, 0);
    (*gprs)[REG_RAX] = res;
    return false;
}


//TODO implement
SYSCALL_HANDLER(execveat){
    //arg1 dfd
    //arg2 filename
    //arg3 argv
    //arg4 envp
    //arg5 flags
    (*gprs)[REG_RAX] = -ENOSYS;
    return false;
}


//Prevent set gs, set SUD, set PTRACE, set SECCOMP and overwrite set/get fs
SYSCALL_HANDLER(arch_prctl){
    //nolibc_print_size_t("arch arg1", gprs->arg1());
    if(gprs->arg1() == ARCH_SET_GS){
        (*gprs)[REG_RAX] = -ENOSYS;
        return false;
    }
    if(gprs->arg1() == ARCH_SET_FS){
        gsreldata->fs_base = (void*)gprs->arg2();
        (*gprs)[REG_RAX] = 0;
        return false;
    }
    if(gprs->arg1() == ARCH_GET_FS){
        *((long long*)gprs->arg2()) = (long long)gsreldata->fs_base;
        (*gprs)[REG_RAX] = 0;
        return false;
    }
    if(gprs->arg1() == PR_SET_SYSCALL_USER_DISPATCH){
        (*gprs)[REG_RAX] = -ENOSYS;
        return false;
    }
    if(gprs->arg1() == PR_SET_PTRACER){
        (*gprs)[REG_RAX] = -ENOSYS;
        return false;
    }        
    if(gprs->arg1() == PR_SET_SECCOMP){
        (*gprs)[REG_RAX] = -ENOSYS;
        return false;
    }

    gprs->do_syscall();
    return false;
}


SYSCALL_HANDLER(fork){
    /*
        The requirements put on vfork() by the standards are weaker than those put on fork(2), 
        so an implementation where the two are synonymous is compliant.
        https://man7.org/linux/man-pages/man2/vfork.2.html
    */
    // equivalent to clone (CLONE_VM | CLONE_VFORK | SIGCHLD) (cfr. https://man7.org/linux/man-pages/man2/vfork.2.html)
    // the vfork syscall does not take any args

    (*gprs)[REG_RAX] = __NR_fork;
    int result = gprs->do_syscall();
    //TODO block all signals until the breakpoints are set
    if(result==0){
        assert(add_breakpoints_after_fork_wrapper_func);
        add_breakpoints_after_fork_wrapper_func();
        enable_sud();
    }

    return false;
}


//clone handling, most of the handling is done afterwards in asm_syscall_hook.asm
SYSCALL_HANDLER(clone){
    is_multithreaded = 1; //this is never a race condition as we only set it to 1 before the second thread exists.
    auto& flags = gprs->arg1();
    auto& stack = gprs->arg2();
    // auto& parent_tid = a3;
    // auto& child_tid = a4;
    // auto& tls = a5;

    if (flags & CLONE_THREAD) {
        // thread-like handling
        assert(flags & CLONE_VM);
        assert(!(flags & CLONE_VFORK)); // weird
        assert(!(flags & CLONE_CLEAR_SIGHAND)); // dont clear SIGSYS handler

        assert(stack);

        // clone will be emulated later on
        return true;
    } else if (flags & CLONE_VFORK) {

        //TODO there seems to be an issue when calling system where the output is not shown when a debugger is used
        // vfork-like handling
        // parent won't do anything until child calls exec/quits
        // should be handled just like CLONE_THREAD: it's as if the parent just happens to not get scheduled
        // FIXME:: this stack should be disjoint from the parent stack. For posix_spawn in glibc 2.31, this is the case
        //          ideally, we check this here
        assert(stack); // we push to the child stack from the parent, later
        assert(flags & CLONE_VM);
        assert(!(flags & CLONE_THREAD));
        assert(!(flags & CLONE_CLEAR_SIGHAND)); // dont clear SIGSYS handler            

        return true;

    } else {
        // fork-like handling
        assert((void*) stack == NULL);
        assert(!(flags & CLONE_CLEAR_SIGHAND)); // dont clear SIGSYS handler
        assert(!(flags & CLONE_THREAD) && !(flags & CLONE_DETACHED)); // don't support threading
        assert(!(flags & CLONE_SIGHAND)); // our signal handler metadata assumes separate signal handler tables per process
        assert(!(flags & CLONE_VFORK)); // don't think our fork handling can deal with this
        assert(!(flags & CLONE_VM)); // don't share memory between parent and child

        syscall_handler_fork(syscall_no, gprs);

        return false;
    }

    assert(!"Unreachable");
}

//prevent the SIGSYS, SIGSEGV and SIGTRAP signals from being blocked
SYSCALL_HANDLER(rt_sigprocmask){
    int how = gprs->arg1();
    sigset_t* set = (sigset_t*) gprs->arg2();
    auto oldset [[maybe_unused]] = (sigset_t*) gprs->arg3();
    auto sigsetsize = gprs->arg4();
    assert(sigsetsize <=  (long long) sizeof(sigset_t));

    // sanity checking the sigsetsize parameter
    if(sigsetsize != SIGSETSIZE){
        (*gprs)[REG_RAX] = -EINVAL;
        return false;
    }

    char modifiable_mask[SIGSETSIZE] = { 0 };

    if (set) {
        memcpy_untrusted_to_trusted(modifiable_mask, set, sigsetsize);

        ASSERT_ELSE_PERROR(sigdelset((sigset_t*) modifiable_mask, SIGSYS) == 0);
#if SCAN_UNSAFE_INSTRUCTIONS
        ASSERT_ELSE_PERROR(sigdelset((sigset_t*) modifiable_mask, SIGSEGV) == 0);
        ASSERT_ELSE_PERROR(sigdelset((sigset_t*) modifiable_mask, SIGTRAP) == 0);
#endif
        set = (sigset_t*) modifiable_mask;
    }

    char trusted_oldset[SIGSETSIZE] = { 0 };
    if(oldset){
        oldset = (sigset_t*)trusted_oldset;
    }

    set_sud_allow();
    (*gprs)[REG_RAX] = inline_syscall6(__NR_rt_sigprocmask, how, set, oldset, sigsetsize, 0, 0);
    set_sud_block();

    if(oldset){
        memcpy_trusted_to_untrusted((void*)gprs->arg3(), trusted_oldset, sigsetsize);   

    }
    return false;
}


//Virtualize the signal handlers by wrapping them in our custom wrapper function
SYSCALL_HANDLER(rt_sigaction){
    (*gprs)[REG_RAX] = gsreldata->signal_handlers->handle_app_sigaction(gprs->arg1(), (struct kernel_sigaction*) gprs->arg2(), (struct kernel_sigaction*) gprs->arg3());
    return false;
}


SYSCALL_HANDLER(exit){
    nolibc_print_str("exiting thread");
    cleanup_thread(); //this will call exit, so the rest of the handling is for the meta monitor
    assert(0);
}


SYSCALL_HANDLER(exit_group){
    //TODO remove the thread from the active thread list (possibly int the exit group of the meta monitor) in case this is a vfork child
    //nolibc_assert(update_active_thread_list);
    //update_active_thread_list(true);
    
    //TODO unmap every non-secpoline page so we can safely remove all breakpoints and set all unsafe pages to executable
    //otherwise, a destructor could interfere with secpoline's protections
    //printf("exiting program.... %d\n", getpid());
#if DEBUG
    nolibc_print_size_t("exiting program", gprs->arg1());
#endif
    gprs->do_syscall();
    //exit(gprs->arg1());
    assert(0);
}


//pipe and pipe2 create two fd's and puts their values in the memory pointed to by arg1
SYSCALL_HANDLER(pipe){
    int fds[2];
    (*gprs)[REG_RAX] = inline_syscall6(syscall_no, &fds, gprs->arg2(), gprs->arg3(), gprs->arg4(), gprs->arg5(), gprs->arg6());

    if((*gprs)[REG_RAX] < 0)return false;
    if(fds[0] < 0 || fds[1] < 0)return false;

    untrusted_fd_bitmap.set_bit(fds[0]);
    untrusted_fd_bitmap.set_bit(fds[1]);

    memcpy_trusted_to_untrusted((void*)gprs->arg1(), &fds, 2*sizeof(int));

    return false;
}  


//socketpair create two fd's and puts their values in the memory pointed to by arg4
SYSCALL_HANDLER(socketpair){
    int fds[2];
    (*gprs)[REG_RAX] = inline_syscall6(syscall_no, gprs->arg1(), gprs->arg2(), gprs->arg3(), &fds, gprs->arg5(), gprs->arg6());

    if((*gprs)[REG_RAX] < 0)return false;
    if(fds[0] < 0 || fds[1] < 0)return false;

    untrusted_fd_bitmap.set_bit(fds[0]);
    untrusted_fd_bitmap.set_bit(fds[1]);

    memcpy_trusted_to_untrusted((void*)gprs->arg4(), &fds, 2*sizeof(int));
    return false;
}  



SYSCALL_HANDLER(pre_close_proxysql){
    if(connect_fd==gprs->arg1())connect_fd = -1;
    clear_virual_connection(gprs->arg1());
    return false;
}

SYSCALL_HANDLER(connect_proxysql){
    struct sockaddr* addr = (struct sockaddr*)malloc(gprs->arg3());
    memcpy_untrusted_to_trusted(addr, (void*)gprs->arg2(), gprs->arg3());
    int res = setup_virual_connection(gprs->arg1(), addr);
    if(res == -1){
        clear_virual_connection(gprs->arg1());
        free(addr);
        (*gprs)[REG_RAX] = -EINVAL;
        return false;
    }
    free(addr);
    connect_fd = gprs->arg1();
    gprs->do_syscall();
    return false;
}

//write, sendto
SYSCALL_HANDLER(send_package_proxysql){
    if(gprs->arg1()==connect_fd){
        char* temp_buff = (char*)malloc(gprs->arg3());
        memcpy_untrusted_to_trusted(temp_buff, (void*)gprs->arg2(), gprs->arg3());
        int res = virtual_write(gprs->arg1(), temp_buff, gprs->arg3(), true);
        free(temp_buff);
        if(res == -1){
            do{
                gprs->do_syscall(); //if the syscall is interupted by a signal (like sigsegv for the sync event) try again
            }while((*gprs)[REG_RAX] == -EINTR);
            return false;
        }
        (*gprs)[REG_RAX] = res;
        return false;
    }

    do{
        gprs->do_syscall(); //if the syscall is interupted by a signal (like sigsegv for the sync event) try again
    }while((*gprs)[REG_RAX] == -EINTR);
    return false;
}

    
//if(syscall_no == __NR_read|| syscall_no == __NR_recvfrom){
SYSCALL_HANDLER(recv_package_proxysql){
    if(gprs->arg1()==connect_fd){
        char* temp_buff = (char*)malloc(gprs->arg3());
        int res = virtual_read(gprs->arg1(), temp_buff, gprs->arg3(), true);
        memcpy_trusted_to_untrusted((void*)gprs->arg2(), temp_buff, gprs->arg3());
        free(temp_buff);
        if(res == -1){
            do{
                gprs->do_syscall(); //if the syscall is interupted by a signal (like sigsegv for the sync event) try again
            }while((*gprs)[REG_RAX] == -EINTR);
            return false;
        }
        (*gprs)[REG_RAX] = res;
        return false;
    }

    do{
        gprs->do_syscall(); //if the syscall is interupted by a signal (like sigsegv for the sync event) try again
    }while((*gprs)[REG_RAX] == -EINTR);
    return false;
}
