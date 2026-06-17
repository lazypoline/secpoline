#include "signals.h"

#include "util.h"
#include "sud.h"
#include "secpoline.h"
#include "gsreldata.h"
#include "mpk_isolation.h"

#include <syscall.h>
#include <sys/signal.h>
#include <immintrin.h>
#include <string.h>

#include <errno.h>
#include <mutex>
#include <sys/mman.h>


#ifndef SA_UNSUPPORTED
#define SA_UNSUPPORTED	0x00000400
#endif

#ifndef SA_EXPOSE_TAGBITS
#define SA_EXPOSE_TAGBITS 0x00000800
#endif

#ifndef SIG_STACK_SIZE
#define SIG_STACK_SIZE 0x800000 //8Mb
#endif

// vIrTuAlIzE_sIgNaLs.cpp
int segfault_handler(int signo, siginfo_t* info, void* ucontextv);
extern "C" void call_app_handler(int signo, siginfo_t* info, void* ucontextv, void (*handler)(int, siginfo_t*, void*));

//global function pointer pointing to the signal handler entry point form the libsegfault_handler after it is loaded in
static void temp_func(int signo, siginfo_t* info, void* ucontextv) {assert(0&&signo&&info&&ucontextv);}
sighandler_type asm_signal_entry = temp_func;


void wrap_signal_handler(int signo, siginfo_t* info, void* ucontextv, char compartment_id_on_entry, char selector_on_entry) {
    // the signal handler might get called from within trusted code, or in untrusted code
    // either way, we have to grant syscall access here until we invoke the app-specific handler

    if(compartment_id_on_entry == TS_APPLICATION){
#if EXCLUSIVE_MPK_POLICY
        //copy the signal frame onto the untrusted stack
        char* old_untrusted_stack = (char*)gsreldata->secure_stack.sp; //during trusted code, this contains the untrusted stack
        char* untrusted_info = old_untrusted_stack - sizeof(siginfo_t);
        char* untrusted_ucontext = untrusted_info - sizeof(ucontext_t);
        gsreldata->secure_stack.sp = untrusted_ucontext; //update the "untruseted stack" to prevent overwrites
        memcpy_trusted_to_untrusted(untrusted_ucontext, ucontextv, sizeof(ucontext_t));
        memcpy_trusted_to_untrusted(untrusted_info, info, sizeof(siginfo_t));

        gsreldata->signal_handlers->invoke_app_specific_handler(signo, (siginfo_t*)untrusted_info, (void*)untrusted_ucontext);

        memcpy_untrusted_to_trusted(ucontextv, untrusted_ucontext, sizeof(ucontext_t));
        memcpy_untrusted_to_trusted(info, untrusted_info, sizeof(siginfo_t));
        gsreldata->secure_stack.sp = old_untrusted_stack;
#else
    gsreldata->signal_handlers->invoke_app_specific_handler(signo, info, ucontextv);
#endif
    }else{
#if EXCLUSIVE_MPK_POLICY
        //copy only siginfo to the untrusted stack because the ucontext belongs to the monitor and should not be modified by us
        //also don't copy it back to the trusted signal frame
        char* old_untrusted_stack = (char*)gsreldata->secure_stack.sp; //during trusted code, this contains the untrusted stack
        char* untrusted_info = old_untrusted_stack - sizeof(siginfo_t);
        gsreldata->secure_stack.sp = untrusted_info;
        memcpy_trusted_to_untrusted(untrusted_info, info, sizeof(siginfo_t));

        gsreldata->signal_handlers->invoke_app_specific_handler(signo, (siginfo_t*)untrusted_info, ucontextv);

        gsreldata->secure_stack.sp = old_untrusted_stack;
#else
    gsreldata->signal_handlers->invoke_app_specific_handler(signo, info, ucontextv);
#endif
    }
    // the signal handler is going to return here, and we will intercept the sigreturn (selector = off)
    // after we intercept the sigreturn, we will have to emulate it without interception, then re-enable the interception
    // we have to make sure that any sensitive data does not get overwritten by other threads while we go through the
    // trampoline here. That's why we push the privilege level to restore to an MPK-secured per-thread stack instead of
    // the thread's own stack (which is unprivileged). The trampoline will pop from there
    // the order is important here in the face of arbitrary signal delivery

    // always deprivilege here so we intercept the sigreturn, 
    // but the restore trampoline will restore the original privilege level to the selector_on_signal_entry
    return;
}

SignalHandlers::SignalHandlers() {
    // fill the array with all the SIG_DFL kernel_sigactions upfront
    for (int i = 0; i < _NSIG; i++) {
        if (i == SIGKILL)
            continue;

        struct kernel_sigaction dfl_act;
        auto result = nolibc_rt_sigaction(i, NULL, &dfl_act);
        if (result)
            continue;
        set_app_handler(i, dfl_act);
        if (dfl_act.k_sa_handler == SIG_DFL)
            dfl_handler() = dfl_act;
    }
}

SignalHandlers::SignalHandlers(const SignalHandlers& other) {
    std::lock_guard guard{other.mut};
    members = other.members;
}

/* needs syscall access to set signal masks etc. */
void SignalHandlers::invoke_app_specific_handler(int sig, siginfo_t *info, void *ucontextv) {
    //fprintf(stderr, ";Got signal %s [%d]\n", sig);

    mut.lock();
    auto app_handler = get_app_handler(sig);
    if(!app_handler.k_sa_handler || app_handler.k_sa_handler == SIG_DFL || app_handler.k_sa_handler == SIG_IGN){
        nolibc_print_str("segfault triggered and not handled");
        asm("ud2");
    }
    // we probably don't want to emulate SIG_DFLs
    assert(app_handler.k_sa_handler != SIG_DFL);
    assert(app_handler.k_sa_handler != SIG_IGN);

    if (app_handler.sa_flags & SA_RESETHAND) // reset to default disposition
		set_app_handler(sig, dfl_handler());
    mut.unlock();
    // app specific handler should have its syscalls intercepted

    // call app handler
    //((void (*)(int, siginfo_t*, void*)) app_handler.k_sa_handler)(sig, info, ucontextv);
    call_app_handler(sig, info, ucontextv, (void (*)(int, siginfo_t*, void*)) app_handler.k_sa_handler);
}

struct kernel_sigaction SignalHandlers::get_app_handler(int signo) {
    return app_handlers().at(signo);
}

struct kernel_sigaction SignalHandlers::set_app_handler(int signo, const struct kernel_sigaction &newact) {
    kernel_sigaction old = get_app_handler(signo);
    app_handlers().at(signo) = newact;
    return old;
}

long long SignalHandlers::handle_app_sigaction(int signo, struct kernel_sigaction *newact, struct kernel_sigaction *oldact) {
    assert(signo < 128 && signo > 0);
    // hold lock while operating on the app_handlers
    std::lock_guard guard{mut};

    struct kernel_sigaction trusted_newact;
    struct kernel_sigaction* trusted_newact_p = NULL;
    if(newact){
#if EXCLUSIVE_MPK_POLICY
        trusted_newact_p = (struct kernel_sigaction*)memcpy_untrusted_to_trusted(&trusted_newact, (struct kernel_sigaction *)newact, sizeof(trusted_newact)); //trusted_newact = *newact
#else
        trusted_newact_p = newact;
#endif
    }
    kernel_sigaction trusted_oldact;
    if (signo == SIGSYS) {
        // there seems to be an issue with a SUD SIGSYS being delivered while handling any other SIGSYS
        // e.g. executing any SUD-intercepted system call from any SIGSYS handler will terminate the program with SIGSYS
        // This should not be the kernel's behavior, but we also don't have to care: non-SUD SIGSYSes are generally non-recoverable anyway
        // note: non-SUD SIGSYSes _are_ nestable for some reason.
        // FIXME: right now we just ignore handler registration for SIGSYS, and always terminate the program on non-SUD SIGSYS
        if (trusted_newact_p) { // assert that the app doesn't ask for a bunch of info we don't provide
            assert(!(trusted_newact_p->sa_flags & SA_UNSUPPORTED)); // we don't support dynamically probing for flag bits
        }
        if (oldact){
            kernel_sigaction trusted_oldact = get_app_handler(SIGSYS);
            memcpy_trusted_to_untrusted(oldact, &trusted_oldact, sizeof(trusted_oldact));//*oldact = trusted_oldact
        }            
        return 0;
    }

    //SIGSEGV and SIGTRAP always need to be handled, so never allow the actual handler to be changed
    if(signo == SIGSEGV || signo == SIGTRAP){
        //nolibc_assert(trusted_newact_p->k_sa_handler != SIG_DFL);
        // if we don't change the newact
        if (!trusted_newact_p) {
            auto result = nolibc_rt_sigaction(signo, NULL, &trusted_oldact);
            if (result)
                return result;

            if (oldact){
                kernel_sigaction trusted_oldact = get_app_handler(signo);
                memcpy_trusted_to_untrusted(oldact, &trusted_oldact, sizeof(trusted_oldact));//*oldact = trusted_oldact
            }        
            return result;
        }

        trusted_newact_p->sa_flags &= ~SA_RESETHAND; // don't unset the sighandler ever
        //Keep the actual handler, and just update the apphander
        auto result = nolibc_rt_sigaction(signo, NULL, &trusted_oldact);
        if (result == 0) {
            auto old = set_app_handler(signo, *trusted_newact_p);
            if (oldact){
                memcpy_trusted_to_untrusted(oldact, &old, sizeof(old));//*oldact = old
            }
        }
    }



    // if we don't change the newact, or make it ignored
    if (!trusted_newact_p || trusted_newact_p->k_sa_handler == SIG_IGN) {
        auto result = nolibc_rt_sigaction(signo, trusted_newact_p, &trusted_oldact);
        if (result)
            return result;

        if (oldact){
            kernel_sigaction trusted_oldact = get_app_handler(signo);
            memcpy_trusted_to_untrusted(oldact, &trusted_oldact, sizeof(trusted_oldact));//*oldact = trusted_oldact
        }        

        if (trusted_newact_p)
            set_app_handler(signo, *trusted_newact_p);
            
        return result;
    }

    // unregister wrapper when we unregister the handler
    if (trusted_newact_p->k_sa_handler == SIG_DFL) {
        auto result = nolibc_rt_sigaction(signo, trusted_newact_p, &trusted_oldact);
        if (result == 0) {
            auto old = set_app_handler(signo, *trusted_newact_p);
            if (oldact){
                memcpy_trusted_to_untrusted(oldact, &old, sizeof(old));//*oldact = old
            }
        }
        return result;
    }

    struct kernel_sigaction newact_cpy = *trusted_newact_p;
    newact_cpy.sa_flags |= SA_SIGINFO|SA_ONSTACK|SA_NODEFER;
    
    newact_cpy.k_sa_handler = (decltype(newact_cpy.k_sa_handler)) asm_signal_entry;
    auto result = nolibc_rt_sigaction(signo, &newact_cpy, &trusted_oldact);
    if (result)
        return result;

    auto old = set_app_handler(signo, *trusted_newact_p);
    if (oldact){
        memcpy_trusted_to_untrusted(oldact, &old, sizeof(old));//*oldact = old
    }

    return result;
}

// defaults taken from https://man7.org/linux/man-pages/man7/signal.7.html
// deduplicated and unused sigs removed
SignalHandlers::SIGDISP_TYPE SignalHandlers::get_default_behavior(int signo) {
	switch (signo) {
		// ignored sigs
		case SIGCHLD:
		case SIGURG:
		case SIGWINCH:
			return SIGDISP_TYPE::IGN;

		// terminating sigs
		case SIGALRM:
		case SIGHUP:
		case SIGINT:
		case SIGIO:
		case SIGKILL:
		case SIGPIPE:
		case SIGPROF:
		case SIGPWR:
		case SIGSTKFLT:
		case SIGTERM:
		case SIGUSR1:
		case SIGUSR2:
		case SIGVTALRM:
			return SIGDISP_TYPE::TERM;

		// coredump sigs
		case SIGABRT:
		case SIGBUS:
		case SIGFPE:
		case SIGILL:
		case SIGQUIT:
		case SIGSEGV:
		case SIGSYS:
		case SIGTRAP:
		case SIGXCPU:
		case SIGXFSZ:
			return SIGDISP_TYPE::CORE;

		// stop sigs
		case SIGSTOP:
		case SIGTSTP:
		case SIGTTIN:
		case SIGTTOU:
			return SIGDISP_TYPE::STOP;

		// cont sigs
		case SIGCONT:
			return SIGDISP_TYPE::CONT;

		default:
			assert(!"Unknown signal!");
	}
}