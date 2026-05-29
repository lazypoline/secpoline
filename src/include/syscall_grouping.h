
//syscall returns the fd
#define FD_CREATORS(X) \
    X(open) \
    X(dup) \
    X(dup2) \
    X(dup3) \
    X(socket) \
    X(accept) \
    X(accept4) \
    X(creat) \
    X(epoll_create) \
    X(epoll_create1) \
    X(inotify_init) \
    X(inotify_init1) \
    X(openat) \
    X(openat2) \
    X(signalfd) \
    X(timerfd_create) \
    X(eventfd) \
    X(eventfd2) \
    X(perf_event_open) \
    X(fanotify_init) \
    X(memfd_create) \
    X(userfaultfd) \
    X(open_tree) \
    X(fsopen) \
    X(fsmount) \
    X(fspick) \
    X(pidfd_open) \
    X(pidfd_getfd) \
    X(landlock_create_ruleset) \
    X(memfd_secret) \
    X(open_by_handle_at) \


//the first argument is the only fd this syscall uses
#define FD_USERS(X) \
    X(dup) \
    X(read) \
    X(write) \
    X(close) \
    X(fstat) \
    X(lseek) \
    X(ioctl) \
    X(pread64) \
    X(pwrite64) \
    X(readv) \
    X(writev) \
    X(connect) \
    X(accept) \
    X(accept4) \
    X(sendto) \
    X(recvfrom) \
    X(sendmsg) \
    X(recvmsg) \
    X(bind) \
    X(listen) \
    X(getsockname) \
    X(getpeername) \
    X(fcntl) \
    X(flock) \
    X(fsync) \
    X(fdatasync) \
    X(ftruncate) \
    X(getdents) \
    X(fchdir) \
    X(fchmod) \
    X(fchown) \
    X(fstatfs) \
    X(finit_module) \
    X(readahead) \
    X(flistxattr) \
    X(fremovexattr) \
    X(fadvise64) \
    X(inotify_add_watch) \
    X(inotify_rm_watch) \
    X(openat) \
    X(openat2) \
    X(mkdirat) \
    X(mknodat) \
    X(fchownat) \
    X(futimesat) \
    X(newfstatat) \
    X(fchmodat) \
    X(fchmodat2) \
    X(faccessat) \
    X(faccessat2) \
    X(sync_file_range) \
    X(vmsplice) \
    X(utimensat) \
    X(signalfd) \
    X(signalfd4) \
    X(fallocate) \
    X(timerfd_settime) \
    X(timerfd_gettime) \
    X(preadv) \
    X(pwritev) \
    X(preadv2) \
    X(pwritev2) \
    X(fanotify_mark) \
    X(name_to_handle_at) \
    X(syncfs) \
    X(setns) \
    X(execveat) \
    X(statx) \
    X(pidfd_send_signal) \
    X(io_uring_enter) \
    X(io_uring_register) \
    X(open_tree) \
    X(fsconfig) \
    X(fsmount) \
    X(fspick) \
    X(mount_setattr) \
    X(quotactl_fd) \
    X(landlock_add_rule) \
    X(landlock_restrict_self) \
    X(process_mrelease) \
    X(cachestat) \
    X(unlinkat) \
    X(shutdown) \
    X(open_by_handle_at) \
    X(epoll_wait) \
    X(epoll_pwait) \
    X(epoll_pwait2) \
    X(setsockopt) \
    X(getsockopt) \
    X(fsetxattr) \
    X(fgetxattr) \
    X(readlinkat) \
    X(recvmmsg) \
    X(sendmmsg) \


#define FD_USERS_SPECIAL(X) \
    X(io_submit) \
    X(close_range) \

#define FD_USERS_SECOND_ARGUMENT(X) \
    X(symlinkat) \
    X(process_madvise) \


#define FD_USERS_FIRST_SECOND_ARGUMENT(X) \
    X(dup2) \
    X(dup3) \
    X(sendfile) \
    X(tee) \
    X(kexec_file_load) \
    X(move_mount) \
    X(pidfd_getfd) \

#define FD_USERS_FIRST_THIRD_ARGUMENT(X) \
    X(renameat) \
    X(renameat2) \
    X(linkat) \
    X(splice) \
    X(copy_file_range) \
    X(epoll_ctl) \





#define FD_CREATORS_SPECIAL(X) \
    X(pipe) \
    X(pipe2) \
    X(socketpair) \
    X(bpf) \