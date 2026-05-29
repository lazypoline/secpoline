#pragma once

#include "nolibc_util.h"
#include "sud.h"
#include "gsreldata.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <cstdlib>
#include <dlfcn.h>
#include <syscall.h>
#include <sys/signal.h>
#include <stdio.h>
#include <cstdlib>
#include <string.h>

#define ASSERT_ELSE_PERROR(cond) \
    do {                            \
        bool x = static_cast<bool>(cond);                \
        if (!x) {                       \
            fflush(stdout);                 \
            fflush(stderr);                     \
            fprintf(stderr,"%s:%d: %s: Assertion `%s` failed: ", __FILE__, __LINE__, __func__, #cond); \
            perror("");                                                                         \
            fflush(stderr);                                                                     \
            abort();                                                                            \
        }                                                                                       \
    } while (false)

#if __GLIBC__ != 2
#error Unknown glibc
#endif


inline long long nolibc_rt_sigaction(int signo, const struct kernel_sigaction* newact, struct kernel_sigaction* oldact) {
    return inline_syscall6(__NR_rt_sigaction, signo, newact, oldact, SIGSETSIZE, 0, 0);
}

inline long long nolibc_rt_sigprocmask(int how, const sigset_t* set, sigset_t* oset) {
    return inline_syscall6(__NR_rt_sigprocmask, how, set, oset, SIGSETSIZE, 0, 0);
}

inline void print_blocked_signals(void)
{
    sigset_t mask;

    if (sigprocmask(SIG_SETMASK, NULL, &mask) == -1) {
        perror("sigprocmask");
        return;
    }

    fprintf(stderr, "Blocked signals:\n");
    for (int sig = 1; sig < NSIG; sig++) {
        if (sigismember(&mask, sig))
            fprintf(stderr, "  %d (%s)\n", sig, strsignal(sig));
    }
}


inline void print_handled_signals(void)
{
    set_sud_block();
    struct sigaction sa;

    nolibc_print_str("Signals with non-default handlers:");

    for (int sig = 1; sig < NSIG; sig++) {

        /* Some signals (like SIGKILL, SIGSTOP) cannot be caught or handled */
        if (sig == SIGKILL || sig == SIGSTOP)
            continue;

        if (sigaction(sig, NULL, &sa) == -1)
            continue;  // Skip invalid or unsupported signals

        if (sa.sa_handler != SIG_DFL && sa.sa_handler != SIG_IGN) {
            nolibc_print_str(strsignal(sig));
        }
    }
    set_sud_allow();
}
