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
#include "../src/include/nolibc_util.h"

#include <asm/prctl.h>
#include <iterator>

#include <immintrin.h>
#include <dlfcn.h>
#include <sys/uio.h>

stack_t* map_sig_stack(){
    stack_t* sig_stack_ptr = new stack_t();
    sig_stack_ptr->ss_sp = (void*) malloc(0x800000);// inline_syscall6(__NR_mmap, 0x0, 0x800000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    assert(sig_stack_ptr->ss_sp  != (void*) -1 && sig_stack_ptr->ss_sp  != 0);
    sig_stack_ptr->ss_flags = 0;
    sig_stack_ptr->ss_size = 0x400000;
    //tag_as_trusted(sig_stack_ptr, SIG_STACK_SIZE);

    //*((int*)sig_stack_ptr->ss_sp) = 48;
    return sig_stack_ptr;
}

void handle_sigalarm(int signo){
    assert(signo == SIGALRM);
    fprintf(stderr, "Got a SIGALARM!\n");
    raise(SIGUSR1);
}

void handle_siguser1(int signo){
    assert(signo == SIGUSR1);
    fprintf(stderr, "Got a SIGUSR1!\n");
}

void handle_sigsegv(int signo){
    assert(signo == SIGSEGV);
    fprintf(stderr, "Got a SIGSEGV!\n");
}

void handle_sigfpe(int signo) {
    assert(signo == SIGFPE);
    fprintf(stderr, "Got a SIGFPE!\n");
}
void handle_sigill(int signo, siginfo_t*, void* ucontextv) {
    assert(signo == SIGILL);
    raise(SIGUSR1);
    fprintf(stderr, "Got a SIGILL!\n");

    const auto uctxt = (ucontext_t*) ucontextv;
	const auto gregs = uctxt->uc_mcontext.gregs;
    gregs[REG_RIP] += 2;
}

__attribute__((destructor))
static void pre_destructor() {
    fprintf(stderr, "cleanup fully done!\n");

}

__attribute__((constructor))
static void constructor() {
    fprintf(stderr, "getting ready to start!\n");

}

void cleanup(){
    fprintf(stderr, "cleanup half done!\n");
}

void cleanup2(int, void*){
    fprintf(stderr, "cleanup half done22!\n");
}


#include <linux/perf_event.h>    /* Definition of PERF_* constants */
#include <linux/hw_breakpoint.h> /* Definition of HW_* constants */
int set_hbreakpoint(char *addr, int tid){
	struct perf_event_attr attr = { .size = 0, };
	int fd;

	attr.type = PERF_TYPE_BREAKPOINT;
	attr.size = sizeof(attr);
	attr.inherit = 1;
	attr.exclude_kernel = 1;
	attr.exclude_hv = 1;
	attr.bp_addr = (unsigned long)addr;
	attr.bp_type = HW_BREAKPOINT_X;
	attr.bp_len = sizeof(long);
    
    attr.sigtrap = 1;
    attr.sig_data = -1;
    attr.remove_on_exec = 1;
    attr.sample_period = 1;

	fd = inline_syscall6(__NR_perf_event_open, &attr, tid, -1, -1, PERF_FLAG_FD_CLOEXEC, 0);
    nolibc_assert(fd>0);
    return fd;
}

void handle_sigtrap(int signo) {
    fprintf(stderr, "Got a SIGTRAP!\n");
}

void* thread_start(void*) {
    for (int i = 0; i < 5; i++) {
        fprintf(stderr, "Hello from thread!\n");
    }
    return NULL;
}


int main() {
    fprintf(stderr, "starting main!\n");

    fprintf(stderr, "starting threads!\n");
    pthread_t thread1;
    int r = pthread_create(&thread1, NULL, thread_start, NULL);
    if(r != 0){
        printf("cannot create thread1 %d [%d]\n", errno, r);
        asm("ud2");
    }

    printf("created thread1\n");
    pthread_t thread2;
    r = pthread_create(&thread2, NULL, thread_start, NULL);
    if(r != 0){
        printf("cannot create thread2 %d [%d]\n", errno, r);
        asm("ud2");
    }
    printf("created thread2\n");
    pthread_t thread3;
    r = pthread_create(&thread3, NULL, thread_start, NULL);
    if(r != 0){
        printf("cannot create thread3 %d [%d]\n", errno, r);
        asm("ud2");
    }
    printf("created thread3\n");
    pthread_t thread4;
    r = pthread_create(&thread4, NULL, thread_start, NULL);
    if(r != 0){
        printf("cannot create thread4 %d [%d]\n", errno, r);
        asm("ud2");
    }
    printf("created thread4\n");

    r = pthread_join(thread1, NULL);
    assert(r == 0);
    r = pthread_join(thread2, NULL);
    assert(r == 0);
    r = pthread_join(thread3, NULL);
    assert(r == 0);
    r = pthread_join(thread4, NULL);
    assert(r == 0);
    //return 0;
    //asm("int3");

    pthread_t thread5;
    r = pthread_create(&thread5, NULL, thread_start, NULL);
    if(r != 0){
        printf("cannot create thread5 %d [%d]\n", errno, r);
        asm("ud2");
    }
    printf("created thread5\n");
    r = pthread_join(thread5, NULL);
    assert(r == 0);


    fprintf(stderr, "executing command ls [%d]!\n\n\n\n\n", gettid());
    const char* command = "ls";
    system(command);  
    on_exit(cleanup2, NULL);
    atexit(cleanup);
    fprintf(stderr, "Hello world!\n");
    fprintf(stderr, "Hello world!\n");
    fprintf(stderr, "Hello world!\n");
    fprintf(stderr, "Hello world!\n");
    fprintf(stderr, "Bye bye now!\n");
    
    struct sigaction act = {};
    act.sa_handler = handle_sigfpe;

    assert(sigaction(SIGFPE, &act, NULL) == 0);

    struct sigaction act_alarm = {};
    act_alarm.sa_handler = handle_sigalarm;
    assert(sigaction(SIGALRM, &act_alarm, NULL) == 0);

    struct sigaction act_user1 = {};
    act_user1.sa_handler = handle_siguser1;
    act_user1.sa_flags |= SA_ONSTACK;
    assert(sigaction(SIGUSR1, &act_user1, NULL) == 0);

    sigset_t mask;
    assert(sigprocmask(SIG_SETMASK, NULL, &mask) == 0);
    assert(sigismember(&mask, SIGFPE) == 0);
    assert(sigismember(&mask, SIGALRM) == 0);
    assert(sigismember(&mask, SIGUSR1) == 0);

    stack_t* sig_stack = map_sig_stack();
    /*
    void* altstack_sp = ((char*)sig_stack->ss_sp+sig_stack->ss_size);
    if (sigaltstack(sig_stack, NULL)) {
        perror("sigaltstack");
        exit(-1);
    }
    fprintf(stderr, "altstack:%p\n", altstack_sp);
    */

    raise(SIGFPE);
    fprintf(stderr, "test\n");

    raise(SIGFPE);
    raise(SIGFPE);
    raise(SIGFPE);
    raise(SIGFPE);
    raise(SIGFPE);
    fprintf(stderr, "Good times!\n");
    // now trigger a signal without `raise`
    // so we can test how we enter the signal handling path from unprivileged code
    act = {};
    act.sa_sigaction = handle_sigill;
    act.sa_flags |= SA_SIGINFO|SA_ONSTACK;
    assert(sigemptyset(&act.sa_mask) == 0);
    assert(sigaction(SIGILL, &act, NULL) == 0);

    struct sigaction oldact = {};
    assert(sigaction(SIGILL, NULL, &oldact) == 0);
    assert(oldact.sa_sigaction == handle_sigill);
    asm("ud2");

    act = {};
    act.sa_handler = SIG_DFL;
    assert(sigaction(SIGILL, &act, NULL) == 0);
    assert(sigaction(SIGFPE, &act, NULL) == 0);

    // test vdso syscalls
    struct timespec t;
    assert(clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t) == 0);
    fprintf(stderr, "current thread time: %lus, %luns\n", t.tv_sec, t.tv_nsec);

    assert(clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t) == 0);
    fprintf(stderr, "current thread time: %lus, %luns\n", t.tv_sec, t.tv_nsec);

    assert(clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t) == 0);
    fprintf(stderr, "current thread time: %lus, %luns\n", t.tv_sec, t.tv_nsec);

    unsigned int cpu;
    unsigned int node;
    assert(syscall(__NR_getcpu, &cpu, &node, NULL) == 0);
    fprintf(stderr, "Current cpu: %d, current NUMA node: %d\n", cpu, node);

    fflush(stdout);
    fflush(stderr);
    
    /*
    if (pid_t child = fork()) {
        assert(child > 0);
        // parent process

        fprintf(stderr, "[%d] Parent going to sleep!\n", getpid());
        sleep(5);
        fprintf(stderr, "[%d] Parent woke up!\n", getpid());
    } else {
        // child process

        fprintf(stderr, "[%d] Child going to sleep!\n", getpid());
        sleep(10);
        fprintf(stderr, "[%d] Child woke up!\n", getpid());
        exit(0);
    }    
    */
    
    pthread_t thread;
    auto result = pthread_create(&thread, NULL, thread_start, NULL);
    assert(result == 0);
    result = pthread_join(thread, NULL);
    assert(result == 0);

    wait(NULL);

    fprintf(stderr, "the end!!\n");
    return 0;
}