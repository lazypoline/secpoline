#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <string.h>

#include "_libattack.h"

#define PAGE_SIZE 4096

void handle_sigfpe(int signo, siginfo_t*, void* ucontextv) {
    const auto uctxt = (ucontext_t*) ucontextv;
	const auto gregs = uctxt->uc_mcontext.gregs;
    fprintf(stderr, "Got a SIGFPE! %d\n", gregs[REG_RAX]);
}

int main(int argc, char **argv) {
    struct sigaction act = {};
    act.sa_sigaction = handle_sigfpe;
    act.sa_flags |= SA_SIGINFO|SA_ONSTACK;
    sigaction(SIGFPE, &act, NULL);

    kill(getpid(), SIGFPE);

    return 0;
}