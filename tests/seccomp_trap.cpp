#include "config.h"
#include "util.h"
#include <stddef.h>
#include <signal.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <unistd.h>

static int seccomp(unsigned int operation, unsigned int flags, void *args) {
    return syscall(__NR_seccomp, operation, flags, args);
}

static void install_filter() {
    struct sock_filter filter[] = {
        /* Load architecture */

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                offsetof(struct seccomp_data, arch)),

        /* Kill process if the architecture is not what we expect */

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),

        /* Load system call number */

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),

        /* Kill the process if this is an x32 system call (bit 30 is set) */

#define X32_SYSCALL_BIT         0x40000000
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        /* getppid() results in SIGSYS; all other system calls are allowed */

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getppid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };

    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };

    ASSERT_ELSE_PERROR(seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog) == 0);
}

/* Handler for SIGSYS signal */
static void handle_sigsys(int) {
    printf("SIGSYS!\n");
}

int main() {
    /* Set up seccomp filter */
    ASSERT_ELSE_PERROR(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    install_filter();

    /* Establish handler for SIGSYS */
    struct sigaction sa;
    sa.sa_flags = 0;
    sa.sa_handler = handle_sigsys;
    sigemptyset(&sa.sa_mask);
    ASSERT_ELSE_PERROR(sigaction(SIGSYS, &sa, NULL) == 0);

    printf("About to call getppid()\n");

    getppid();   /* Results in SIGSYS; system call is not executed */

    /* After the SIGSYS handler returns, execution continues in main() */
    printf("Bye\n");
}
