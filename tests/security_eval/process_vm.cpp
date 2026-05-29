#include <sys/wait.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <stdint.h>
#include <ucontext.h>
#include <assert.h>
#include <fenv.h>
#include <spawn.h>
#include <xmmintrin.h>

#include <asm/prctl.h>
#include <iterator>

#include <immintrin.h>
#include <dlfcn.h>
#include <sys/uio.h>
#include <sys/uio.h>

#include "_libattack.h"


int main() {
    size_t  buf1;
    ssize_t       nread;
    struct iovec  local[1];
    struct iovec  remote[1];

    local[0].iov_base = &buf1;
    local[0].iov_len = 8;
    remote[0].iov_base = (void *)get_trusted_mem();
    remote[0].iov_len = 8;

    nread = process_vm_readv(getpid(), local, 1, remote, 1, 0);
    if (nread != 8){
        fprintf(stderr, "read failed, nread = %d [%d]\n", nread, errno);
        exit(EXIT_FAILURE);
    }

    void* sp;

    asm("mov %%rsp, %[sp]"
        :[sp]"=r"(sp));

    printf("stack addr = %p, real value = %p\n", buf1, sp);

    nread = process_vm_writev(getpid(), local, 1, remote, 1, 0);
    if (nread != 8){
        fprintf(stderr, "write failed, write = %d\n", nread);
        exit(EXIT_FAILURE);
    }

    exit(0);
}