#pragma once

// don't include too much here
#include <stdint.h>
#include "mpk_isolation.h"
#include <assert.h>
#include "syscall_grouping.h"

#define MAX_VALID_SYSCALL_NUM 463
#define MAX_SYSCALL_HANDLER_DEPTH 2 //THis number can be increased if more than 2 prehandler or post handlers are needed anywhere

enum class handler_type_enum {
    prehandler,
    main_handler,
    posthandler,
    emulate_later
};


#ifndef __NR_clone3 // the kernel may understand clone3 even if libc doesnt 
#define __NR_clone3 435
#endif
#ifndef CLONE_CLEAR_SIGHAND
#define CLONE_CLEAR_SIGHAND 0x100000000ULL
#endif

class gprs_desc {
public:
    long long* const gp_regs;
    gprs_desc(long long* gp_regs) : 
        gp_regs{gp_regs}
    {}

    long long& operator [] (int idx) {
        assert(idx >= REG_R8 && idx < REG_EFL);
        return gp_regs[idx];
    }

    long long& arg1() { return (*this)[REG_RDI]; }
    long long& arg2() { return (*this)[REG_RSI]; }
    long long& arg3() { return (*this)[REG_RDX]; }
    long long& arg4() { return (*this)[REG_R10]; }
    long long& arg5() { return (*this)[REG_R8]; }
    long long& arg6() { return (*this)[REG_R9]; }

    // performs syscall and updates rax
    long long do_syscall() {
        (*this)[REG_RAX] = do_syscall_untrusted(arg1(), arg2(), arg3(), arg4(), arg5(), arg6(), (*this)[REG_RAX]);
        return (*this)[REG_RAX];
    }
};

using syscall_handler_type = uint64_t (*)(long long, gprs_desc*);

//all handlers relevant for a specific syscall
struct syscall_handlers_struct{
    syscall_handler_type prehandlers[MAX_SYSCALL_HANDLER_DEPTH+1];
    syscall_handler_type main_handler;
    syscall_handler_type posthandlers[MAX_SYSCALL_HANDLER_DEPTH+1];
    bool is_emulated;
};

void add_handler(syscall_handlers_struct table[], int syscall_no, syscall_handler_type func, handler_type_enum how);

#define SYSCALL_HANDLER(fn_name) \
    uint64_t syscall_handler_##fn_name([[maybe_unused]] long long syscall_no, gprs_desc* gprs) \

#define ADD_MAIN_HANDLER(table, syscall, func) \
    add_handler(table, __NR_##syscall, syscall_handler_##func, handler_type_enum::main_handler)

#define ADD_PREHANDLER(table, syscall, func) \
    add_handler(table, __NR_##syscall, syscall_handler_##func, handler_type_enum::prehandler)

#define ADD_POSTHANDLER(table, syscall, func) \
    add_handler(table, __NR_##syscall, syscall_handler_##func, handler_type_enum::posthandler)

//This system call will be emulated in asssembly, this means it cannot have a pre or post handler. This also means that it does not go though a handler gadget
#define ADD_HANDLER_EMULATE(table, syscall, func) \
    add_handler(table, __NR_##syscall, syscall_handler_##func, handler_type_enum::emulate_later)

#define DECLARE_HANDLER(func) \
    uint64_t syscall_handler_##func(long long syscall_no, gprs_desc* gprs)

// two options:
//  (1) emulates the system call and returns the return value
//  (2) asks for the syscall to be emulated later on by setting *should_emulate = true. 
//      In this case, the return value should be the syscall number to emulate later on
long syscall_emulate(int64_t syscall_no, int64_t a1, int64_t a2, int64_t a3, int64_t a4, int64_t a5, int64_t a6, uint64_t* const should_emulate);
extern "C" void jump_back_to_loader(uint64_t rip_after_init);
extern "C" void secpoline_cleanup_entry();

DECLARE_HANDLER(default);
DECLARE_HANDLER(not_implemented);
DECLARE_HANDLER(mmap);
DECLARE_HANDLER(munmap);
DECLARE_HANDLER(brk);
DECLARE_HANDLER(mprotect);
DECLARE_HANDLER(mremap);
DECLARE_HANDLER(execve);
DECLARE_HANDLER(execveat);
DECLARE_HANDLER(arch_prctl);
DECLARE_HANDLER(fork);
DECLARE_HANDLER(clone);
DECLARE_HANDLER(rt_sigprocmask);
DECLARE_HANDLER(rt_sigaction);
DECLARE_HANDLER(exit);
DECLARE_HANDLER(exit_group);
DECLARE_HANDLER(open);
DECLARE_HANDLER(close);
DECLARE_HANDLER(close_range);
DECLARE_HANDLER(pipe);
DECLARE_HANDLER(socketpair);


DECLARE_HANDLER(save_untrusted_fd);
DECLARE_HANDLER(fd_first_argument_prehandler);
DECLARE_HANDLER(fd_second_argument_prehandler);
DECLARE_HANDLER(fd_first_second_argument_prehandler);
DECLARE_HANDLER(fd_first_third_argument_prehandler);


DECLARE_HANDLER(pre_close_proxysql);
DECLARE_HANDLER(connect_proxysql);
DECLARE_HANDLER(send_package_proxysql);
DECLARE_HANDLER(recv_package_proxysql);




