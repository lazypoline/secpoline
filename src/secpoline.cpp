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

void setup_global_data(char* secpoline_path, char* loader_path);
static void generate_2d_handler_list(syscall_handlers_struct table[], syscall_handler_type list[MAX_VALID_SYSCALL_NUM][MAX_SYSCALL_HANDLER_DEPTH*2+1]);
void initialise_syscall_handlers();
char* path_to_loader;
char* path_to_secpoline;
syscall_handler_type syscall_handler_list[MAX_VALID_SYSCALL_NUM][MAX_SYSCALL_HANDLER_DEPTH*2+1];


//TODO, printf breaks when passing gprs->arg() as an argument!!!!!!!!!!!!!!!!
//argv[1] = rsp_return_to_loader, argv[2] = fsbase loader, argv[3] = loader mappings, argv[4] = path to secpoline loader
int main(int argc, char* argv[]) {
    
    assert(argc == 5);
#if DEBUG
    fprintf(stderr, "Initializing secpoline! [pid=%d]\n", getpid());
#endif
    //int pkey = pkey_alloc(0, 0);
    //assert(pkey == secpoline_MPKEY);
    int pkey_readonly = pkey_alloc(0, 0);
    assert(pkey_readonly == SECPOLINE_READONLY_MPKEY);
    int pkey_untrusted = pkey_alloc(0, 0);
    assert(pkey_untrusted == UNTRUSTED_MPKEY);
    int pkey_null_ptr = pkey_alloc(0, 0);
    assert(pkey_null_ptr == NULL_PTR_MPKEY);

    setup_global_data(argv[0], argv[4]);
    initialise_syscall_handlers();
    init_sud();

#if REWRITE_TO_ZPOLINE
    init_zpoline();
#endif

    init_page_manager((mmapped_list_s*)argv[3]);
    gsreldata->fs_base = (void*)_readfsbase_u64();
    _writefsbase_u64((size_t)argv[2]);
    jump_back_to_loader((uint64_t)argv[1]);
    assert(0);
}

void setup_global_data(char* secpoline_path, char* loader_path){
    path_to_loader = strdup(loader_path);
    path_to_secpoline = strdup(secpoline_path);
}

void initialise_syscall_handlers(){
    syscall_handlers_struct syscall_handler_table[MAX_VALID_SYSCALL_NUM];

    //initialise the syscall handler table, for each valid syscall set their main handler to default and the rest to NULL
    for(int i = 0;i<MAX_VALID_SYSCALL_NUM;i++){
        syscall_handler_table[i].main_handler = syscall_handler_default;
        syscall_handler_table[i].is_emulated = 0;
        for(int j = 0;j<MAX_SYSCALL_HANDLER_DEPTH+1;j++){
            syscall_handler_table[i].posthandlers[j] = nullptr;
        }
        
        for(int j = 0;j<MAX_SYSCALL_HANDLER_DEPTH+1;j++){
            syscall_handler_table[i].prehandlers[j] = nullptr;
        }
    }


#if ISOLATE_FD
    //This is a "post handler" for each syscall that creates a new fd (or at least the most common ones, the rest have their own handler)
    #define X(syscall) ADD_POSTHANDLER(syscall_handler_table, syscall, save_untrusted_fd);
    FD_CREATORS(X);
    #undef X


    //These are "pre handlers" that makes sure these syscalls use an application owned fd (or at least the most common ones, the rest have their own handler)
    #define X(syscall) ADD_PREHANDLER(syscall_handler_table, syscall, fd_first_argument_prehandler);
    FD_USERS(X);
    #undef X

    #define X(syscall) ADD_PREHANDLER(syscall_handler_table, syscall, fd_second_argument_prehandler);
    FD_USERS_SECOND_ARGUMENT(X);
    #undef X

    #define X(syscall) ADD_PREHANDLER(syscall_handler_table, syscall, fd_first_second_argument_prehandler);
    FD_USERS_FIRST_SECOND_ARGUMENT(X);
    #undef X

    #define X(syscall) ADD_PREHANDLER(syscall_handler_table, syscall, fd_first_third_argument_prehandler);
    FD_USERS_FIRST_THIRD_ARGUMENT(X);
    #undef X


    ADD_MAIN_HANDLER(syscall_handler_table, close, close);
    ADD_MAIN_HANDLER(syscall_handler_table, close_range, close_range);

    ADD_MAIN_HANDLER(syscall_handler_table, pipe, pipe);
    ADD_MAIN_HANDLER(syscall_handler_table, pipe2, pipe);
    ADD_MAIN_HANDLER(syscall_handler_table, socketpair, socketpair);
#endif


    ADD_MAIN_HANDLER(syscall_handler_table, rt_sigreturn, not_implemented); //only allow sigreturn thourgh the signal handler wrapper function so all the post handler setup is done
    ADD_MAIN_HANDLER(syscall_handler_table, pkey_mprotect, not_implemented);
    ADD_MAIN_HANDLER(syscall_handler_table, pkey_free, not_implemented);
    ADD_MAIN_HANDLER(syscall_handler_table, rseq, not_implemented);
    ADD_MAIN_HANDLER(syscall_handler_table, bpf, not_implemented); //Mabye we can support this
    ADD_MAIN_HANDLER(syscall_handler_table, io_submit, not_implemented); //TODO, can implement, just need to verify that it is not using a monitor fd.
    ADD_MAIN_HANDLER(syscall_handler_table, process_vm_readv, not_implemented);
    ADD_MAIN_HANDLER(syscall_handler_table, process_vm_writev, not_implemented);
    ADD_MAIN_HANDLER(syscall_handler_table, seccomp, not_implemented);
    ADD_MAIN_HANDLER(syscall_handler_table, vmsplice, not_implemented);
    ADD_MAIN_HANDLER(syscall_handler_table, userfaultfd, not_implemented);
    ADD_MAIN_HANDLER(syscall_handler_table, unshare, not_implemented); //we would have to specially handle this when they unshare signal dispositions or vm
    ADD_MAIN_HANDLER(syscall_handler_table, clone3, not_implemented);
    ADD_MAIN_HANDLER(syscall_handler_table, sigaltstack, not_implemented);
    ADD_MAIN_HANDLER(syscall_handler_table, perf_event_open, not_implemented); //TODO only block hardware breakpoints

    ADD_MAIN_HANDLER(syscall_handler_table, open, open);
    ADD_MAIN_HANDLER(syscall_handler_table, openat, open);
    ADD_MAIN_HANDLER(syscall_handler_table, openat2, open);
    ADD_MAIN_HANDLER(syscall_handler_table, open_by_handle_at, open);
    ADD_MAIN_HANDLER(syscall_handler_table, fork, fork);
    ADD_MAIN_HANDLER(syscall_handler_table, vfork, fork); //TODO, this is a slower impmentation
    ADD_MAIN_HANDLER(syscall_handler_table, mmap, mmap);
    ADD_MAIN_HANDLER(syscall_handler_table, munmap, munmap);
    ADD_MAIN_HANDLER(syscall_handler_table, brk, brk);
    ADD_MAIN_HANDLER(syscall_handler_table, mprotect, mprotect);
    ADD_MAIN_HANDLER(syscall_handler_table, mremap, mremap);
    ADD_MAIN_HANDLER(syscall_handler_table, execve, execve);
    ADD_MAIN_HANDLER(syscall_handler_table, execveat, execveat);
    ADD_MAIN_HANDLER(syscall_handler_table, arch_prctl, arch_prctl);
    ADD_MAIN_HANDLER(syscall_handler_table, prctl, arch_prctl);
    ADD_MAIN_HANDLER(syscall_handler_table, rt_sigprocmask, rt_sigprocmask);
    ADD_MAIN_HANDLER(syscall_handler_table, rt_sigaction, rt_sigaction);
    ADD_MAIN_HANDLER(syscall_handler_table, exit, exit);
    ADD_MAIN_HANDLER(syscall_handler_table, exit_group, exit_group);
    ADD_HANDLER_EMULATE(syscall_handler_table, clone, clone);

    generate_2d_handler_list(syscall_handler_table, syscall_handler_list);
}

//populate the handler table, make sure each individual syscall handler list is always null terminated
void add_handler(syscall_handlers_struct table[], int syscall_no, syscall_handler_type func, handler_type_enum how){
    assert(syscall_no < MAX_VALID_SYSCALL_NUM);
    int index = 0;
    switch(how){
        case handler_type_enum::main_handler:
            assert(table[syscall_no].main_handler == syscall_handler_default&&"Second non-default main handler added"); //this prevents accidental overwrites of exiting non-default main handlers 
            table[syscall_no].main_handler = func;
            break;
        case handler_type_enum::prehandler:
            index = 0;
            while(table[syscall_no].prehandlers[index])index++;
            assert(index < MAX_SYSCALL_HANDLER_DEPTH);
            table[syscall_no].prehandlers[index] = func;
            break;
        case handler_type_enum::posthandler:
            index = 0;
            while(table[syscall_no].posthandlers[index])index++;
            assert(index < MAX_SYSCALL_HANDLER_DEPTH);
            table[syscall_no].posthandlers[index] = func;
            break;
        case handler_type_enum::emulate_later:
            table[syscall_no].is_emulated = 1;
            table[syscall_no].main_handler = func;
            assert(table[syscall_no].posthandlers[0]==nullptr);
            assert(table[syscall_no].prehandlers[0]==nullptr);
            break;
        default:
            assert(!"this handler type does not exist");
            break;

    }
}

//generate a 2d array of all handlers for each syscall
static void generate_2d_handler_list(syscall_handlers_struct table[], syscall_handler_type list[MAX_VALID_SYSCALL_NUM][MAX_SYSCALL_HANDLER_DEPTH*2+1]){
    for(int syscall_no = 0;syscall_no < MAX_VALID_SYSCALL_NUM;syscall_no++){
        int new_index = 0;
        int index = 0;
        while(table[syscall_no].prehandlers[index]){
            list[syscall_no][new_index++] = table[syscall_no].prehandlers[index++];
        }

        list[syscall_no][new_index++] = table[syscall_no].main_handler;
        
        index = 0;
        while(table[syscall_no].posthandlers[index]){
            list[syscall_no][new_index++] = table[syscall_no].posthandlers[index++];
        }
    }

}

// called from `asm_syscall_hook` with elevated privileges
// receives an array of GP regs, returns whether to emulate the syscall in asm or not
//  return type should _not_ be bool here to avoid a weird ABI issue
extern "C" uint64_t secpoline_syscall_handler(long long* gp_regs) {
    gprs_desc gprs{gp_regs};
    long long syscall_no = gprs[REG_RAX];

    #if RETURN_IMMEDIATELY
        // early return used for benchmarking the nop sled
        return 0;
    #endif
        
#if PRE_PRINT_SYSCALLS
        // common precall
    fprintf(stderr, "\e[31m[tid %d] %s(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx)\e[m\n", gettid(), audit_syscall_to_name(syscall_no, MACH_86_64), 
        gprs.arg1(), 
        gprs.arg2(), 
        gprs.arg3(), 
        gprs.arg4(), 
        gprs.arg5(), 
        gprs.arg6()
    );

#endif  

    assert(syscall_no < MAX_VALID_SYSCALL_NUM);
    int ret;
    for(int handler_index = 0;syscall_handler_list[syscall_no][handler_index]!=NULL;handler_index++){
        assert(syscall_handler_list[syscall_no][handler_index] != NULL);
        ret = syscall_handler_list[syscall_no][handler_index](syscall_no, &gprs);
    }

#if POST_PRINT_SYSCALLS
        // common precall
    fprintf(stderr, "\e[31m[tid %d] %s(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx) = 0x%llx\e[m\n", gettid(), audit_syscall_to_name(syscall_no, MACH_86_64), 
        gprs.arg1(), 
        gprs.arg2(), 
        gprs.arg3(), 
        gprs.arg4(), 
        gprs.arg5(), 
        gprs.arg6(),
        gprs[REG_RAX]
    );

#endif     

    return ret;
}
