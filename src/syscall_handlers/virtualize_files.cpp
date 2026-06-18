#include "virtualize_files.h"
#include "secpoline.h"
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <poll.h>
#include <linux/aio_abi.h> 

fd_bitmap untrusted_fd_bitmap;


//This the handler that will add any new fd used by the application, so we can limit the fd's they have access to
//it is possible that this is not the main handler, and that the syscall is already executed
SYSCALL_HANDLER(save_untrusted_fd){
    int fd = (*gprs)[REG_RAX];

    if(fd < 0)return false;

    untrusted_fd_bitmap.set_bit(fd);
    //fprintf(stderr, "[%d/%d] %d -> created fd %d\n", getpid(), gettid(), syscall_no, fd);
    return false;
}


//Closing a fd, so make sure to remove it from the bitmap
//TODO, when the close fails readd the fd
SYSCALL_HANDLER(close){
    //TODO update the locking for all fd related functions
    std::unique_lock<std::shared_mutex> lock(untrusted_fd_bitmap.mtx);
    int fd = gprs->arg1();

    if(gprs->do_syscall()){
        return false;
    }

    //fprintf(stderr, "[%d/%d] %d -> closing fd %d\n", getpid(), gettid(), syscall_no, fd);
    untrusted_fd_bitmap.unset_bit(fd);
    return false;
}


//make sure that the files used by the monitor cannot be manipulated by the application
SYSCALL_HANDLER(fd_first_argument_prehandler){
    int fd = gprs->arg1();
    if(fd < 0)return false;

    if(!untrusted_fd_bitmap.read_bit(fd)){
        (*gprs)[REG_RDI] = -1;
    }
    return false;
}

SYSCALL_HANDLER(fd_second_argument_prehandler){
    int fd = gprs->arg2();
    if(!untrusted_fd_bitmap.read_bit(fd)){
        (*gprs)[REG_RDI] = -1;
    }
    return false;
}

SYSCALL_HANDLER(fd_first_second_argument_prehandler){
    int fd1 = gprs->arg1();
    int fd2 = gprs->arg2();
    if(!untrusted_fd_bitmap.read_bit(fd1)){
        (*gprs)[REG_RDI] = -1;
    }
    if(!untrusted_fd_bitmap.read_bit(fd2)){
        (*gprs)[REG_RDI] = -1;
    }
    return false;
}

SYSCALL_HANDLER(fd_first_third_argument_prehandler){
    int fd1 = gprs->arg1();
    int fd3 = gprs->arg3();
    if(!untrusted_fd_bitmap.read_bit(fd1)){
        (*gprs)[REG_RDI] = -1;
    }
    if(!untrusted_fd_bitmap.read_bit(fd3)){
        (*gprs)[REG_RDI] = -1;
    }
    return false;
}


//Group handler for open, openat and open_by_handle_at
/* this part is adapted from endokernel https://github.com/endokernel */
static struct stat stat_mem;
static int stat_mem_init = 0;
SYSCALL_HANDLER(open){
    if (!stat_mem_init) {
        long fdx = inline_syscall6(__NR_open, "/proc/self/mem", 0, 0600, 0, 0, 0);
        inline_syscall6(__NR_fstat, fdx, &stat_mem, 0, 0, 0, 0);
        stat_mem_init = 1;
        inline_syscall6(__NR_close, fdx, 0, 0, 0, 0, 0);
    }

    // Step 2: Intercept and handle actual open
    long fd = gprs->do_syscall();

    if (fd < 0){ 
        return false;
    }

  

    // Step 3: Get stat info for the newly opened file
    struct stat stat_buf;
    if (inline_syscall6(__NR_fstat, fd, &stat_buf, 0, 0, 0, 0) < 0) {
        inline_syscall6(__NR_close, fd, 0, 0, 0, 0, 0);
        (*gprs)[REG_RAX] = -EACCES; // Deny with "Operation not permitted
        return false;
    }

    if (stat_buf.st_ino == stat_mem.st_ino &&
        stat_buf.st_dev == stat_mem.st_dev) {
        // This file is /proc/self/mem — block 
        inline_syscall6(__NR_close, fd, 0, 0, 0, 0, 0);
        (*gprs)[REG_RAX] = -EACCES; // Deny with "Operation not permitted
        return false;
    }

    return false;
}

SYSCALL_HANDLER(close_range){
    assert(0);
    //TODO this should also clear the bits.
    //TODO, if the range is big enough, than we can probably do larger compares to speed this up
    int start = gprs->arg1();
    int last = gprs->arg1();

    for(int i = start;i<=last;i++){
        if(!untrusted_fd_bitmap.read_bit(i)){
            (*gprs)[REG_RDI] = -1;
            (*gprs)[REG_RSI] = -1;
            return false;
        }
    }
    return false;
}


