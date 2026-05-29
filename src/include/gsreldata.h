#pragma once

#include "config.h"

#define SUD_SELECTOR_OFFSET                 0
#define RIP_AFTER_SIGRETURN_HOLDER          8
#define COMPARTMENT_ID_OFFSET               16
#define PAGES_HEAD_OFFSET                   24
#define FS_BASE_OFFSET                      4104
#define CHILD_STACK_OFFSET                  4120
#define SIGNAL_HANDLER_LEVEL_OFFSET         4128
#define THREAD_CLEANUP_RSP_OFFSET           4136
#define SECURE_STACK_SP_OFFSET              4144
#define SIGRETURN_STACK_SP_OFFSET           4160
#define SIG_ALTSTACK_BASE_OFFSET            36936
#define SIG_ALTSTACK_SIZE_OFFSET            36952
#define RIP_AFTER_SYSCALL_STACK_SP_OFFSET   36960

#define XSAVE_AREA_STACK_SP_OFFSET          41088
/* https://www.moritz.systems/blog/how-debuggers-work-getting-and-setting-x86-registers-part-2/ */
#define XSAVE_EAX                           0b111   /* saves the x87 state, and XMM & YMM vector registers */
#define XSAVE_SIZE                          768     /* aligned to 64-byte boundary, so fine */

#define USED_KEY_MASK                    //used to disable access to all unused domains
#define SECPOLINE_MPKEY                 0
#define SECPOLINE_READONLY_MPKEY        1
#define UNTRUSTED_MPKEY                 2
#define NULL_PTR_MPKEY                  3
#define GRANT_FULL_PERMISSIONS          0b01111111111111111111111111000000  

#if EXCLUSIVE_MPK_POLICY
    #define GRANT_TRUSTED_PERMISSIONS       0b01111111111111111111111111110000
#else
    #define GRANT_TRUSTED_PERMISSIONS       0b01111111111111111111111111000000
#endif

#define REVOKE_PERMISSIONS              0b01111111111111111111111111001011   /* disable write and read for domain 1 and write for domain 2*/

#define SECURE_STACK_SIZE                   0x800000 //8Mb
#define PAGE_SIZE                           4096
#define SIGNAL_STACK_SIZE                   4096

//define program states
#define TS_MONITOR                          0
#define TS_APPLICATION                      1

#define RSP_OFFSET_UCONTEXT                 160

#define RSEQ_SIG                            0x53053053


#ifndef __ASSEMBLER__

__attribute__ ((visibility("hidden")))
extern "C" volatile long long cleanup_rsp;
extern "C" char* path_to_loader; 
extern "C" char* path_to_secpoline; 
extern char is_multithreaded;

class SignalHandlers;
class hbreakpoint_controller;

struct alignas(PAGE_SIZE) GSRelativeData {
    struct alignas(PAGE_SIZE) readableData {
        volatile char sud_selector = 0xFF;
        volatile long long rip_after_sigreturn_holder;
        volatile char compartment_id;
#if DEBUG
        volatile void* pages_head = nullptr;
#endif
    } readable_data;
    SignalHandlers* signal_handlers = nullptr;
    
    volatile void* fs_base = nullptr;
    
    volatile char fake_clone_flag = 0;
    volatile void* child_stack = nullptr; 
    volatile unsigned long long signal_handler_level = 0;
    volatile void* thread_cleanup_rsp = nullptr; 

    //secpoline stack (grows down)
    //during trusted code execution, sp contains the sp of the untrusted stack instead (base does not change)
    struct{
        void* sp = nullptr;
        void* base = nullptr;
    }secure_stack;

    struct {
        volatile long long* current = base;
        volatile long long base[0x1000];
    } sigreturn_stack;

    struct{
        void* sp;
        int flags;
        long long size;
    } altstack;

    struct { // stack of `rip_after_syscall`s for use during vfork handling
        volatile char* current = base;
        volatile char base[0x1000];
    } rip_after_syscall_stack;

    struct { // xsave area stack grows up
        volatile char* current = base;
        volatile char __attribute__((aligned(64))) base[XSAVE_SIZE * 6]; // 6 nesting levels ought to be fine
    } xsave_area_stack;

    hbreakpoint_controller* hardware_breakpoints;
    void* plugin_queue;
};

// GS-relative accessor
inline const auto gsreldata = (__seg_gs GSRelativeData*) 0x0;

// necessary to keep asm files in sync
static_assert(__builtin_offsetof(GSRelativeData, readable_data.sud_selector) == SUD_SELECTOR_OFFSET);
static_assert(__builtin_offsetof(GSRelativeData, readable_data.rip_after_sigreturn_holder) == RIP_AFTER_SIGRETURN_HOLDER);
static_assert(__builtin_offsetof(GSRelativeData, readable_data.compartment_id) == COMPARTMENT_ID_OFFSET);
#if DEBUG
static_assert(__builtin_offsetof(GSRelativeData, readable_data.pages_head) == PAGES_HEAD_OFFSET);
#endif
static_assert(__builtin_offsetof(GSRelativeData, secure_stack.sp) == SECURE_STACK_SP_OFFSET);
static_assert(__builtin_offsetof(GSRelativeData, fs_base) == FS_BASE_OFFSET);
static_assert(__builtin_offsetof(GSRelativeData, child_stack) == CHILD_STACK_OFFSET);
static_assert(__builtin_offsetof(GSRelativeData, signal_handler_level) == SIGNAL_HANDLER_LEVEL_OFFSET);
static_assert(__builtin_offsetof(GSRelativeData, thread_cleanup_rsp) == THREAD_CLEANUP_RSP_OFFSET);
static_assert(__builtin_offsetof(GSRelativeData, sigreturn_stack.current) == SIGRETURN_STACK_SP_OFFSET);
static_assert(__builtin_offsetof(GSRelativeData, altstack.sp) == SIG_ALTSTACK_BASE_OFFSET);
static_assert(__builtin_offsetof(GSRelativeData, altstack.size) == SIG_ALTSTACK_SIZE_OFFSET);
static_assert(__builtin_offsetof(GSRelativeData, rip_after_syscall_stack.current) == RIP_AFTER_SYSCALL_STACK_SP_OFFSET);
static_assert(__builtin_offsetof(GSRelativeData, xsave_area_stack.current) == XSAVE_AREA_STACK_SP_OFFSET);

static_assert(sizeof(GSRelativeData::readable_data)==PAGE_SIZE);

GSRelativeData* map_gsrel_region(void* secure_stack_base);
SignalHandlers* map_signal_handlers();
void enable_sud();
extern "C" void setup_new_thread(unsigned long long clone_flags, void* secure_stack_sp);
extern "C" void* teardown_thread_metadata();
extern "C" void init_tls_child();
extern "C" void cleanup_thread();
extern "C" void setup_restore_selector_trampoline(void* ucontextv, void* secure_stack_pointer);
void* setup_secure_stack();
void setup_altstack();

extern "C" long long meta_monitor_syscall(long long rdi, long long rsi, long long rdx, long long r10, long long r8, long long r9, long long rax);
extern "C" long long do_syscall_untrusted(long long rdi, long long rsi, long long rdx, long long r10, long long r8, long long r9, long long rax);
extern "C" void prepare_clone_vfork_parent(int flags);
extern "C" void restart_clone_vfork_parent(int flags);

#endif
