#include <sys/signal.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include "gsreldata.h"
#include "sud.h"
#include "erim.h"
#include "util.h"
#include "nolibc_util.h"
#include "mpk_isolation.h"
#include "hardware_breakpoints.h"
#include <mutex>
#include <algorithm>
#include <unistd.h>
#include "segfault_handler.h"
#include "virt_page_manager.h"

#ifndef TRAP_PERF
    #define TRAP_PERF 6
#endif

static int secpoline_segfault_handler(siginfo_t* info, char compartment_id_on_entry);
static int secpoline_sigtrap_handler(siginfo_t* info, void* ucontextv, int compartment_id_on_entry);
extern "C" void asm_signal_entry(int signo, siginfo_t* info, void* ucontextv);
extern "C" void add_breakpoint_wrapper(struct unsafe_page* page, bool is_static);
void other_thread_add_breakpoint_wrapper();

extern virt_page_manager page_manager;

nolibc_lock segfault_handler_mutex;
nolibc_lock hbreakpoint_sync_mutex;
nolibc_lock waiting_thread_count_mutex;
nolibc_lock unsafe_page_mutex;
nolibc_lock trap_handler_mutex;
hbreakpoint_thread_synchronizer thread_synchronizer;
std::vector<char*> begnin_xrstors;
hbreakpoint_controller global_hbreakpoint_controller;

__attribute__((weak)) void wrap_signal_handler(int signo, siginfo_t* info, void* ucontextv, char compartment_id_on_entry, char selector_on_entry){nolibc_assert(0&&signo&&info&&ucontextv&&compartment_id_on_entry&&selector_on_entry);}
__attribute__((weak)) struct unsafe_page* erim_memScanRegion(char * start,unsigned long long length, unsigned long long * whitelist, unsigned int wlEntries, int perm, bool trusted_page, char** prev_page_ptr){nolibc_assert(0&&start&&length&&whitelist&&wlEntries&&perm&&trusted_page&&prev_page_ptr); return NULL;}
__attribute__((weak)) struct unsafe_page* add_unsafe_page(void* address, int current_perm, int desired_perm, bool trusted_page, std::vector<char*>* unsafe_instructions){nolibc_assert(0&&address&&current_perm&&desired_perm&&trusted_page&&unsafe_instructions); return NULL;}


unsafe_page_list* unsafe_pages_ptr = nullptr;
using sighandler_type = void(*)(int, siginfo_t*, void*);

//choose whether we should handler the signal or if the signal is for the application handler
extern "C" long long signal_handler_switch(int signo, siginfo_t* info, void* ucontextv){
    char compartment_id_on_entry = gsreldata->readable_data.compartment_id;
    char selector_on_entry = get_sud();
    gsreldata->readable_data.compartment_id = TS_MONITOR;


    //if the signal was a segfault, check if it should be handled by secpoline's segfault handler or the applications handler.
    //TODO move meta monitor to segfault handler so we can use it during the segfault handler
    set_sud_allow();

    //const auto uctxt = (ucontext_t*) ucontextv;
	//const auto gregs = uctxt->uc_mcontext.gregs;
    //nolibc_print_size_t("address", (size_t)info->si_addr);
    //nolibc_print_size_t("recieved signal", signo);
    int segfault_handler_res = -1;
#if SCAN_UNSAFE_INSTRUCTIONS
    if(signo == SIGSEGV){
        //nolibc_print_str("SEGFAULT");
        //nolibc_print_size_t("si code", info->si_code);
        //nolibc_print_size_t("address", (size_t)info->si_addr);
        //nolibc_print_size_t("ucontext address", (size_t)((ucontext_t*) ucontextv)->uc_mcontext.gregs[REG_RIP]);
        if(thread_synchronizer.controller_thread.load() != 0){
            //There is another thread trying to put breakpoints on a page, and this is a follower thread
            //Now there are three cases
            if(info->si_code==SI_USER || info->si_code==SI_TKILL){
                //This is the actual signal send by kill
                //nolibc_print_str("kill SEGV recieved");
                other_thread_add_breakpoint_wrapper();
                //nolibc_print_str("kill SEGV handled");
                segfault_handler_res = 0;
            }else if(__builtin_align_down(((char*)info->si_addr), PAGE_SIZE)==thread_synchronizer.segfault_page.load()->address){
                //This is a synchronous signal send for the same page as the controller tread
                //In this case everything is fine and this thread can behave like a follower thread
                //nolibc_print_str("segfault for existing controller thread");
                other_thread_add_breakpoint_wrapper();
                segfault_handler_res = 0;
            }else{
                //nolibc_print_str("segfault for non-existing controller thread");
                //This is a synchronous signal send for another page than the controller tread
                //In this case, complete the current page, and then start a new one
                other_thread_add_breakpoint_wrapper();
                segfault_handler_mutex.lock();
                segfault_handler_res = secpoline_segfault_handler(info, compartment_id_on_entry);
                segfault_handler_mutex.unlock();
            }
        }else if(info->si_code==SI_USER || info->si_code==SI_TKILL){//TODO, now the application cannot send SIGSEGV using KILL
            //nolibc_print_size_t("buffered SEGfault handled", nolibc_gettid());
            segfault_handler_res = 0;
        }else{
            //nolibc_print_size_t("claiming lock segfault", nolibc_gettid());
            while(!segfault_handler_mutex.try_lock()){
                if(thread_synchronizer.controller_thread.load() != 0){
                    //nolibc_print_size_t("redirected to follower thread instead", nolibc_gettid());
                    other_thread_add_breakpoint_wrapper();
                }
            }
            //nolibc_print_size_t("claimed lock segfault", nolibc_gettid());
            segfault_handler_res = secpoline_segfault_handler(info, compartment_id_on_entry);
            segfault_handler_mutex.unlock();
            //nolibc_print_size_t("lock segfault unlocked", nolibc_gettid());
        }
    }
#endif
    
    int trap_res = -1;
#if SCAN_UNSAFE_INSTRUCTIONS
    if(signo == SIGTRAP){
        trap_handler_mutex.lock();
        trap_res = secpoline_sigtrap_handler(info, ucontextv, compartment_id_on_entry);
        trap_handler_mutex.unlock();
    }
#endif

    //unblock all signals here, to prevent deadlocks we cannot unblock the signals untill after the secpoline segfault handler
    sigset_t empty_mask = {0};
    nolibc_assert(inline_syscall6(__NR_rt_sigprocmask, SIG_SETMASK, &empty_mask, 0, SIGSETSIZE, 0, 0) == 0);

    if(segfault_handler_res != 0 && trap_res != 0){
        set_sud_block();
        //TODO only try to call application handler for segfault and sigtrap if it exists
        //nolibc_assert(signo != SIGSEGV);
        wrap_signal_handler(signo, info, ucontextv, compartment_id_on_entry, selector_on_entry);
    }else{
        set_sud_block();
    }

    //nolibc_print_size_t("signal ended", nolibc_gettid());

    gsreldata->sigreturn_stack.current[0] = compartment_id_on_entry;
    gsreldata->sigreturn_stack.current++;    
    gsreldata->sigreturn_stack.current[0] = selector_on_entry;
    gsreldata->sigreturn_stack.current++;
    return compartment_id_on_entry;
}

//returns a non 0 value if the segfault was not handled here and should be handled by the application segfault handler
static int secpoline_segfault_handler(siginfo_t* info, char compartment_id_on_entry){
    //nolibc_print_size_t("got SIGSEGV", nolibc_gettid());
    nolibc_assert(info->si_code!=SI_USER && info->si_code!=SI_TKILL);
    nolibc_assert(info->si_code != SEGV_PKUERR);//never handle MPK fault as these are security violations

    if(info->si_code == SEGV_BNDERR || info->si_code == SEGV_MAPERR){
        return 1;
    }

    char* segfault_address = ((char*)info->si_addr);
    struct unsafe_page* segfault_page = find_unsafe_page(segfault_address);

    if(segfault_page==nullptr){
        return 2;
    }
    if(page_manager.lookup_addr((char*)segfault_page->address, compartment_id_on_entry)==NULL){
        return 3;
    }

    //someone tried to write to an executable page
    if(segfault_page->current_perm&PROT_EXEC){
        //this page has been made executable by another thread already
        if(!(segfault_page->desired_perm&PROT_WRITE))return 0;

        int new_prot = segfault_page->desired_perm & ~PROT_EXEC;
        nolibc_assert(secpoline_mprotect((char*)segfault_page->address, PAGE_SIZE, new_prot, compartment_id_on_entry, &page_manager)==0);
        segfault_page->current_perm = new_prot;
        return 0;
    }

    //someone is trying to executa a writable page
    else if(segfault_page->current_perm&PROT_WRITE){
        if(!(segfault_page->desired_perm&PROT_EXEC)) return 4;
        
        if(erim_memScanRegion((char*)segfault_page->address, PAGE_SIZE, nullptr, 0, segfault_page->desired_perm, segfault_page->desired_perm&~PROT_WRITE, segfault_page->trusted_page, NULL)){
            add_breakpoint_wrapper(segfault_page, false);
        }
        nolibc_assert(secpoline_mprotect((char*)segfault_page->address, PAGE_SIZE, PROT_READ|PROT_EXEC, compartment_id_on_entry, &page_manager)==0);
        segfault_page->current_perm = PROT_READ|PROT_EXEC;
        return 0;
    }

    //the page was read only, and now needs to be made executable
    else if(segfault_page->unsafe_instructions != nullptr){
        if(!(segfault_page->desired_perm&PROT_EXEC)){
            return 5;
        }
        add_breakpoint_wrapper(segfault_page, false);
        nolibc_assert(secpoline_mprotect((char*)segfault_page->address, PAGE_SIZE, PROT_READ|PROT_EXEC, compartment_id_on_entry, &page_manager)==0);
        segfault_page->current_perm = PROT_READ|PROT_EXEC;
        return 0;
    }

    //something wierd happend
    return 6;
}

static bool is_rewritten_xrstor(char* address){
    for(int i = 0; i < begnin_xrstors.size();i++){
        if(begnin_xrstors[i]==address)return true;
    }
    return false;
}

/*
static void rewrite_xrstor(char* trap_address, int compartment_id_on_entry){
    size_t page_pkey = -1;
    if(compartment_id_on_entry == TS_APPLICATION){
        //if we came from the unstrusted application, make sure the trap instruction belong to the untrusted applciation
        mpk_check_readonly(trap_address, GRANT_TRUSTED_PERMISSIONS);
        page_pkey = UNTRUSTED_MPKEY;
    }else{
        internal_wrpkru(GRANT_TRUSTED_PERMISSIONS);
        page_pkey = SECPOLINE_MPKEY;
    }

    int perms = PROT_READ|PROT_EXEC|PROT_WRITE;
    void* trap_page = __builtin_align_down(trap_address, PAGE_SIZE);
    nolibc_assert(inline_syscall6(__NR_mprotect, trap_page, 0x1000, perms, SECPOLINE_MPKEY, 0, 0) == 0);
    trap_address[0] = 0xCC; 
    trap_address[1] = 0xCC; 
    trap_address[2] = 0xCC; 
    nolibc_assert(inline_syscall6(__NR_mprotect, trap_page, 0x1000, PROT_READ, page_pkey, 0, 0) == 0);
}
*/

//For some reason, the hardware breakpoints set by perf_event seem to be synchronous(they get handled before the next instruction gets executed)
//but the program doesn't terminate when SIGTRAP is blocked, instead SIGTRAP gets delivered after it is unblocked
static int secpoline_sigtrap_handler(siginfo_t* info, void* ucontextv, int compartment_id_on_entry){

    const auto uctxt = (ucontext_t*) ucontextv;
	const auto gregs = uctxt->uc_mcontext.gregs;
    char* trap_address = (char*)gregs[REG_RIP];

    size_t rax = gregs[REG_RAX];
    //nolibc_print_size_t_hex("got SIGTRAP at", (size_t)trap_address);
    //nolibc_print_size_t("got SIGTRAP with si_code", info->si_code);

    if(info->si_code!=TRAP_PERF){
        //TODO this is a fix to get breakpoints working again for debuggers
        nolibc_assert(!"wrong sigtrap");
        //nolibc_print_size_t("non hardware breakpoint trap signal recieved", info->si_code);
        return 0;
    } 

    internal_wrpkru(GRANT_FULL_PERMISSIONS);
    if(erim_isXRSTOR(trap_address)){
        internal_wrpkru(GRANT_TRUSTED_PERMISSIONS);
        if(rax&(1<<9)){
            //nolibc_print_str("you hit a unsafe XRSOTR: exiting...");
            exit(1);
        }

        //nolibc_print_str("you hit a safe XRSOTR lets continue");
        gregs[REG_RIP] += 3;
        return 0;

        /*
        struct unsafe_page* trap_page = find_unsafe_page(trap_address);
        nolibc_assert(trap_page);

        //rewrite xrstor, add it to list of rewritten xrstors and rescan the page it is on
        //the breakpoints will be removed when new ones are placed, there is no reason to do that now
        rewrite_xrstor(trap_address, compartment_id_on_entry);
        begnin_xrstors.push_back((char*)trap_address);

            sigset_t empty_mask = {0};
        nolibc_assert(inline_syscall6(__NR_rt_sigprocmask, SIG_SETMASK, &empty_mask, 0, SIGSETSIZE, 0, 0) == 0);
        erim_memScanRegion((char*)trap_page->address, PAGE_SIZE, nullptr, 0, trap_page->desired_perm, trap_page->current_perm, trap_page->trusted_page, NULL);

        //TODO emulate xrstor here (update signal frame with relevant stuff)
        gregs[REG_RIP] += 3;
        return 0;
    }else if(is_rewritten_xrstor((char*)trap_address)){
        internal_wrpkru(GRANT_TRUSTED_PERMISSIONS);
        if(rax&(1<<9)){
            //nolibc_print_str("you hit a unsafe XRSOTR: exiting...");
            exit(1);
        }
        //TODO emulate xrstor here (update signal frame with relevant stuff)
        gregs[REG_RIP] += 3;
        return 0;
        */
    }

    internal_wrpkru(GRANT_FULL_PERMISSIONS);
    if(erim_isWRGSBASE32(trap_address)){
        //nolibc_print_str("you hit a unsafe WRGSBASE32: exiting...");
        exit(1);
    }else if(erim_isWRGSBASE64(trap_address)){
        //nolibc_print_str("you hit a unsafe WRGSBASE: exiting...");
        exit(1);
    }else if(erim_isWRPKRU(trap_address)){
        //nolibc_print_str("you hit a unsafe WRPKRU: exiting...");
        exit(1);
    }else{
        //nolibc_print_str("you hit a unsafe instruction: exiting...");
        asm("ud2");
        exit(1);   
    }
    nolibc_assert(0);
}

//set a page to non-executable by updating its permissions in the unsafe_page data structure and calling mprotect
//if the page is w&e then set it to writable, otherwise set it to readonly
void set_page_non_executable(void* address){
#if TRACK_MAPPINGS
    struct virt_page* pm_page = page_manager.lookup_addr((char*)address, -1);
    assert(pm_page != NULL);
    int cid = pm_page->Cid;
#else
    int cid = -1;
#endif

    struct unsafe_page* page = find_unsafe_page(address);
#if TRACK_MAPPINGS
    if(page->trusted_page) assert(pm_page->Cid==TS_MONITOR);
#endif
    if(!(page->current_perm&PROT_EXEC)){
        return;
    }
    unsafe_page_mutex.lock();
    nolibc_assert(page!=NULL);


    if(page->desired_perm&PROT_WRITE){
        nolibc_assert(page!=NULL);
        page->current_perm = PROT_READ|PROT_WRITE;
        nolibc_assert(secpoline_mprotect((char*)page->address, PAGE_SIZE, PROT_READ|PROT_WRITE, cid, &page_manager)==0);
        return;
    }
    page->current_perm = PROT_READ;
    nolibc_assert(secpoline_mprotect((char*)page->address, PAGE_SIZE, PROT_READ, cid, &page_manager)==0);
    unsafe_page_mutex.unlock();
    return;
}

//TODO also use erim.cpp mutex?
struct unsafe_page* find_unsafe_page(void* address){
    void* address_page = __builtin_align_down(address, PAGE_SIZE);
    for(int i = 0; i < unsafe_pages_ptr->size; i++) {
        if(unsafe_pages_ptr->list[i]->address==address_page){
            return unsafe_pages_ptr->list[i];
        }
    }
    return NULL;
}

void other_thread_add_breakpoint_wrapper(){
    //nolibc_print_str("waiting");
    while(!thread_synchronizer.waiting_thread_count.load());
    //nolibc_print_size_t_hex("DEBUG current segfault page", (size_t)thread_synchronizer.segfault_page.load());
    nolibc_assert(thread_synchronizer.segfault_page.load());
    //nolibc_print_size_t("placing breakpoints", nolibc_gettid());
    //nolibc_print_size_t("total follower threads", thread_synchronizer.active_thread_list_size-1);
    gsreldata->hardware_breakpoints->add_breakpoints((unsafe_page*)thread_synchronizer.segfault_page.load(), false);
    //nolibc_print_size_t("placing breakpoints done", nolibc_gettid());
    waiting_thread_count_mutex.lock();
    nolibc_assert(thread_synchronizer.waiting_thread_count>0);
    thread_synchronizer.waiting_thread_count--;
    waiting_thread_count_mutex.unlock();
    //nolibc_print_size_t("current waiting threads", thread_synchronizer.waiting_thread_count.load());
    while(thread_synchronizer.controller_thread.load()!=0);
    waiting_thread_count_mutex.lock();
    nolibc_assert(thread_synchronizer.waiting_thread_count>0);
    thread_synchronizer.waiting_thread_count--;
    //nolibc_print_size_t("new waiting threads count", thread_synchronizer.waiting_thread_count.load());
    waiting_thread_count_mutex.unlock();
    //nolibc_print_size_t("thread done waiting", nolibc_gettid());
    return;
}


extern "C" void add_breakpoint_wrapper(unsafe_page* page, bool is_static){
    //nolibc_print_str("claiming lock breakpoint");
    hbreakpoint_sync_mutex.lock();
    if(page->current_perm&PROT_EXEC){
        //This page was already updated, just return
        hbreakpoint_sync_mutex.unlock();
        //nolibc_print_str("page already executable, not claiming lock");
        return;
    }
    //nolibc_print_size_t("lock breakpoint claimed", nolibc_gettid());
    nolibc_assert(thread_synchronizer.controller_thread.load()==0);
    nolibc_assert(thread_synchronizer.waiting_thread_count.load()==0);
    nolibc_assert(thread_synchronizer.segfault_page.load()==nullptr);
    thread_synchronizer.controller_thread.store(nolibc_gettid());
    thread_synchronizer.segfault_page.store(page);
    //nolibc_print_size_t("controller thread", nolibc_gettid());
    //Start by synchronizing all threads to this points
    for(int tid_index = 0;tid_index<thread_synchronizer.active_thread_list_size;tid_index++){
        int tid = thread_synchronizer.active_thread_list[tid_index].tid;
        int pid = thread_synchronizer.active_thread_list[tid_index].pid;
        if(tid==nolibc_gettid())continue;
        //nolibc_print_size_t("sending signal to thread starting...", tid);
        //nolibc_print_size_t("sending signal to thread with pid", pid);
        nolibc_assert(!is_static);
        //nolibc_assert(inline_syscall6(__NR_tgkill, pid, tid, SIGSEGV, 0, 0, 0) == 0); //the signal wil have si_code SI_USER
        int ret = inline_syscall6(__NR_tgkill, pid, tid, SIGSEGV, 0, 0, 0);
        //nolibc_print_size_t("ret: ", -ret);
        nolibc_assert(ret == 0);
    }

    gsreldata->hardware_breakpoints->add_breakpoints(page, is_static);

    //Keep a global version of the set hbreakpoints, the fd's can be ignored, only the addresses are relevant when creating/unblocking new threads
    global_hbreakpoint_controller = *gsreldata->hardware_breakpoints;
    //nolibc_print_size_t("breakpoints added, controller thread", nolibc_gettid());

    waiting_thread_count_mutex.lock();
    thread_synchronizer.waiting_thread_count.store(thread_synchronizer.active_thread_list_size-1);
    waiting_thread_count_mutex.unlock();

    //now wait until all follower threads are done to prevent a follower thread from re following
    while(thread_synchronizer.waiting_thread_count.load(std::memory_order_acquire));

    thread_synchronizer.segfault_page.store(nullptr);
    //second sync fase to prevent a new controller thread from starting before all other threads are done waiting
    waiting_thread_count_mutex.lock();
    thread_synchronizer.waiting_thread_count.store(thread_synchronizer.active_thread_list_size-1);
    waiting_thread_count_mutex.unlock();
    thread_synchronizer.controller_thread.store(0);
    while(thread_synchronizer.waiting_thread_count.load(std::memory_order_acquire));

    hbreakpoint_sync_mutex.unlock();
    //nolibc_print_str("released lock breakpoint\n\n");
    return;
}

static void remove_element_active_thread_list(int tid){
    int i = 0;
    while((i<thread_synchronizer.active_thread_list_size-1) && (thread_synchronizer.active_thread_list[i].tid!=tid))i++;
    
    thread_synchronizer.active_thread_list_size--;
    //if it is the last element
    if(i==thread_synchronizer.active_thread_list_size){
        nolibc_assert(thread_synchronizer.active_thread_list[i].tid==tid);
        return;
    }
    //nolibc_assert(thread_synchronizer.active_thread_list[i-1].tid==tid);

    while(i<thread_synchronizer.active_thread_list_size){
        thread_synchronizer.active_thread_list[i] = thread_synchronizer.active_thread_list[i+1];
        i++;
    }

    nolibc_assert(i==thread_synchronizer.active_thread_list_size);
}

//can be used to add or remove a thread
//also initialises/frees the hbreakpoint controller
extern "C" void update_active_thread_list(bool remove_thread){
    set_sud_allow();

    //nolibc_print_str("claiming lock update list");
    while(!hbreakpoint_sync_mutex.try_lock()){
        if(thread_synchronizer.controller_thread.load() != 0 && (remove_thread==true)){
            //nolibc_print_size_t("redirected to follower thread before exiting", nolibc_gettid());
            other_thread_add_breakpoint_wrapper();
        }
    }
    //nolibc_print_size_t("lock update list claimed", nolibc_gettid());

    nolibc_assert(thread_synchronizer.controller_thread.load()==0);

    if(remove_thread){
        //we are removing the thread from the active thread list, so make sure we are not interupted anymore as it is no longer safe the untrusted application to gain control over this thread
        sigset_t mask;
        nolibc_sigfill_set_complete(&mask);
        nolibc_assert(inline_syscall6(__NR_rt_sigprocmask, SIG_SETMASK, &mask, 0, SIGSETSIZE, 0, 0) == 0);
        int old_size = thread_synchronizer.active_thread_list_size;
        remove_element_active_thread_list(nolibc_gettid());
        nolibc_assert(old_size == thread_synchronizer.active_thread_list_size+1);
        gsreldata->hardware_breakpoints->remove_all_hbreakpoints();
        free(gsreldata->hardware_breakpoints);
        hbreakpoint_sync_mutex.unlock();

        //nolibc_print_size_t("removed thread from active thread list", nolibc_gettid());
        return;
    }


    hbreakpoint_controller hardware_breakpoints;
    hardware_breakpoints = global_hbreakpoint_controller;
    nolibc_assert(hardware_breakpoints.used_breakpoints==global_hbreakpoint_controller.used_breakpoints);
    hardware_breakpoints.set_all_hbreakpoits();

    nolibc_assert(thread_synchronizer.active_thread_list_size<MAX_ACTIVE_THREAD);
    thread_synchronizer.active_thread_list[thread_synchronizer.active_thread_list_size].tid = nolibc_gettid();
    thread_synchronizer.active_thread_list[thread_synchronizer.active_thread_list_size].pid = nolibc_getpid();


    
    //nolibc_print_size_t("added thread with tid:", nolibc_gettid());
    //nolibc_print_size_t("added thread with pid:", nolibc_getpid());
    
    thread_synchronizer.active_thread_list_size++;
    
    gsreldata->hardware_breakpoints = &hardware_breakpoints;
    hbreakpoint_sync_mutex.unlock();
    //nolibc_print_str("released lock update list");

    set_sud_block();
    //TODO, this is a race condition. the local copy can changes after copying to the heap.
    gsreldata->hardware_breakpoints = new hbreakpoint_controller(hardware_breakpoints);
    return;
}

//only the calling thread exists in the child, so only this thread need to set breakpoints
extern "C" void add_breakpoints_after_fork_wrapper(void){
    //reset the current active threads, because the fork only kept the main thread
    thread_synchronizer.controller_thread.store(0, std::memory_order_relaxed);
    thread_synchronizer.waiting_thread_count.store(0, std::memory_order_relaxed);
    thread_synchronizer.segfault_page.store(nullptr, std::memory_order_relaxed);
    thread_synchronizer.active_thread_list_size = 1;
    thread_synchronizer.active_thread_list[0].tid = nolibc_gettid();
    thread_synchronizer.active_thread_list[0].pid = nolibc_getpid();

    gsreldata->hardware_breakpoints->set_all_hbreakpoits();
    return;
}

extern "C" void setup_segfault_handler(unsafe_page_list* unsafe_pages_address){
    unsafe_pages_ptr = unsafe_pages_address;
    return;
}