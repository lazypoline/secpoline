#pragma once
#include <sys/auxv.h>
#include <syscall.h>
#include "gsreldata.h"
#include "sud.h"
#include <fcntl.h>
#include <signal.h>
#include "kernel_sigaction.h"
#include <assert.h>

#if __GLIBC_MINOR__ <= 31
#define SIGSETSIZE (_NSIG / 8)
#else
#define SIGSETSIZE (8)
#endif

// taken from https://github.com/torvalds/linux/blob/master/tools/include/nolibc/arch-x86_64.h
#define inline_syscall6(num, arg1, arg2, arg3, arg4, arg5, arg6)                  \
({                                                                            \
	long _ret;                                                            \
	register long _num  __asm__ ("rax") = (num);                          \
	register long _arg1 __asm__ ("rdi") = (long)(arg1);                   \
	register long _arg2 __asm__ ("rsi") = (long)(arg2);                   \
	register long _arg3 __asm__ ("rdx") = (long)(arg3);                   \
	register long _arg4 __asm__ ("r10") = (long)(arg4);                   \
	register long _arg5 __asm__ ("r8")  = (long)(arg5);                   \
	register long _arg6 __asm__ ("r9")  = (long)(arg6);                   \
	                                                                      \
	__asm__  volatile (                                                   \
		"syscall\n"                                                   \
		: "=a"(_ret)                                                  \
		: "r"(_arg1), "r"(_arg2), "r"(_arg3), "r"(_arg4), "r"(_arg5), \
		  "r"(_arg6), "0"(_num)                                       \
		: "rcx", "r11", "memory", "cc"                                \
	);                                                                    \
	_ret;                                                                 \
})


inline size_t syscall_wrapper(size_t num, size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t arg5, size_t arg6, int cid){
    if(cid == TS_MONITOR){
        return inline_syscall6(num, arg1, arg2, arg3, arg4, arg5, arg6);
    }else{
        return do_syscall_untrusted(arg1, arg2, arg3, arg4, arg5, arg6, num);
    }
}

template<typename Func>
struct run_on_destruct {
    Func func;
    run_on_destruct(Func&& func) : func{func} {}
    ~run_on_destruct() { func(); }
};

#define CONCAT_(x,y) x##y
#define CONCAT(x,y) CONCAT_(x,y)
#define UNIQUE_VAR_NAME CONCAT(_unique_var_, __COUNTER__)
#define defer(block) run_on_destruct UNIQUE_VAR_NAME{[&] () -> void { block; }}

inline  __attribute__((always_inline)) size_t nolibc_gettid(){
    return inline_syscall6(__NR_gettid, 0, 0, 0, 0, 0, 0);
}

inline size_t nolibc_getpid(){
    return inline_syscall6(__NR_getpid, 0, 0, 0, 0, 0, 0);
}

inline void nolibc_print_size_t(const char *prefix, size_t value) {
#if DEBUG
    int selector = get_sud();
    set_sud_allow();

    char buf[256];
    char num_buf[32];
    int pos = 0;

    /* ---- Write [tid] ---- */

    buf[pos++] = '[';

    size_t tid = nolibc_gettid();
    int i = 30;

    if (tid == 0) {
        num_buf[i--] = '0';
    } else {
        size_t tmp = tid;
        while (tmp > 0) {
            num_buf[i--] = '0' + (tmp % 10);
            tmp /= 10;
        }
    }

    int tid_start = i + 1;
    int tid_len = 30 - i;

    for (int j = 0; j < tid_len; j++)
        buf[pos++] = num_buf[tid_start + j];

    buf[pos++] = ']';
    buf[pos++] = ' ';

    /* ---- Write prefix ---- */

    if (prefix) {
        const char *p = prefix;
        while (*p)
            buf[pos++] = *p++;
        buf[pos++] = ' ';
    }

    /* ---- Write value ---- */

    i = 30;

    if (value == 0) {
        num_buf[i--] = '0';
    } else {
        size_t tmp = value;
        while (tmp > 0) {
            num_buf[i--] = '0' + (tmp % 10);
            tmp /= 10;
        }
    }

    int num_start = i + 1;
    int num_len = 30 - i;

    for (int j = 0; j < num_len; j++)
        buf[pos++] = num_buf[num_start + j];

    buf[pos++] = '\n';

    /* ---- Write to stderr ---- */

    inline_syscall6(__NR_write, 2, buf, pos, 0, 0, 0);

    gsreldata->readable_data.sud_selector = selector;
#endif
}

inline void nolibc_print_size_t_hex(const char *prefix, size_t value) {
#if DEBUG
    int selector = get_sud();
    set_sud_allow();

    char buf[256];
    char num_buf[32];
    int pos = 0;

    /* ---- Write [tid] ---- */

    buf[pos++] = '[';

    size_t tid = nolibc_gettid();
    int i = 30;

    if (tid == 0) {
        num_buf[i--] = '0';
    } else {
        size_t tmp = tid;
        while (tmp > 0) {
            num_buf[i--] = '0' + (tmp % 10);
            tmp /= 10;
        }
    }

    int tid_start = i + 1;
    int tid_len = 30 - i;

    for (int j = 0; j < tid_len; j++)
        buf[pos++] = num_buf[tid_start + j];

    buf[pos++] = ']';
    buf[pos++] = ' ';

    /* ---- Write prefix ---- */

    if (prefix) {
        const char *p = prefix;
        while (*p)
            buf[pos++] = *p++;
        buf[pos++] = ' ';
    }

    /* ---- Write value (hex) ---- */

    buf[pos++] = '0';
    buf[pos++] = 'x';

    i = 30;

    if (value == 0) {
        num_buf[i--] = '0';
    } else {
        size_t tmp = value;
        while (tmp > 0) {
            int digit = tmp & 0xF;  // tmp % 16
            num_buf[i--] = (digit < 10) ? ('0' + digit) : ('a' + digit - 10);
            tmp >>= 4; // tmp /= 16
        }
    }

    int num_start = i + 1;
    int num_len = 30 - i;

    for (int j = 0; j < num_len; j++)
        buf[pos++] = num_buf[num_start + j];

    buf[pos++] = '\n';

    /* ---- Write to stderr ---- */

    inline_syscall6(__NR_write, 2, buf, pos, 0, 0, 0);

    gsreldata->readable_data.sud_selector = selector;
#endif
}


inline void nolibc_print_str(const char* s) {
#if DEBUG
    int selector = get_sud();
    set_sud_allow();

    char buf[256];
    char num_buf[32];
    int pos = 0;

    /* ---- Write [tid] ---- */

    buf[pos++] = '[';

    size_t tid = nolibc_gettid();
    int i = 30;

    if (tid == 0) {
        num_buf[i--] = '0';
    } else {
        size_t tmp = tid;
        while (tmp > 0) {
            num_buf[i--] = '0' + (tmp % 10);
            tmp /= 10;
        }
    }

    int tid_start = i + 1;
    int tid_len = 30 - i;

    for (int j = 0; j < tid_len; j++)
        buf[pos++] = num_buf[tid_start + j];

    buf[pos++] = ']';
    buf[pos++] = ' ';

    /* ---- Copy string ---- */

    const char* p = s;
    while (*p && pos < (int)(sizeof(buf) - 2)) {
        buf[pos++] = *p++;
    }

    buf[pos++] = '\n';

    /* ---- Single write ---- */

    inline_syscall6(__NR_write, 2, buf, pos, 0, 0, 0);

    gsreldata->readable_data.sud_selector = selector;
#endif
}

inline void clear_sig(sigset_t* set, int sig){
    int ulong_w = sizeof(unsigned long)*8;
    set->__val[(sig-1)/ulong_w] &= ~(1UL << (((sig) - 1) % ulong_w));
}

inline void nolibc_sigfill_set(sigset_t* new_mask){
    for(int i=0;i<SIGSETSIZE;i++){
        ((char*)new_mask)[i] = 0xff;
    }
    clear_sig(new_mask, SIGSYS);
    clear_sig(new_mask, SIGSEGV);
    clear_sig(new_mask, SIGTRAP);
}

inline void nolibc_sigfill_set_complete(sigset_t* new_mask){
    for(int i=0;i<SIGSETSIZE;i++){
        ((char*)new_mask)[i] = 0xff;
    }
}

inline void nolibc_sigempty_set(sigset_t* new_mask){
    for(int i=0;i<SIGSETSIZE;i++){
        ((char*)new_mask)[i] = 0x0;
    }
}


inline void nolibc_assert_impl(bool condition, const char* file, int line, const char* func) {
	if(!condition){
		set_sud_allow();
        nolibc_print_str("ASSERT FAILED");
        nolibc_print_str(file);
        nolibc_print_size_t("line", line);
        nolibc_print_str(func);
		asm("ud2");
	}
}

#define nolibc_assert(condition) nolibc_assert_impl(condition, __FILE__, __LINE__, __func__)

#undef assert
#define assert(condition) nolibc_assert_impl((condition), __FILE__, __LINE__, __func__)

inline void* nolibc_get_handler(int sig){
    int selector = get_sud();
    set_sud_allow();

    kernel_sigaction old_act;
    int res = inline_syscall6(__NR_rt_sigaction, sig, nullptr, &old_act, sizeof(old_act.sa_mask), 0, 0);
    if(res != 0){
        nolibc_print_size_t("could not get sighandler", -res);
        nolibc_assert(0);
    }

    gsreldata->readable_data.sud_selector = selector;

    return (void*)old_act.k_sa_handler;
}

inline int nolibc_is_blocked(int sig){
    int selector = get_sud();
    set_sud_allow();

    sigset_t current_mask;
    int res = inline_syscall6(__NR_rt_sigprocmask, SIG_SETMASK, nullptr, &current_mask, SIGSETSIZE, 0, 0);
    if(res != 0){
        nolibc_print_size_t("could not get sigmask", -res);
        nolibc_assert(0);
    }

    unsigned long *mask = (unsigned long *)&current_mask;
    int idx = (sig - 1) / (8 * sizeof(unsigned long));
    int bit = (sig - 1) % (8 * sizeof(unsigned long));
    //nolibc_print_size_t("sigprocmask", *mask);

    gsreldata->readable_data.sud_selector = selector;

    return (mask[idx] >> bit) & 1;
}