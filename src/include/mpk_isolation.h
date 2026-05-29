#pragma once
#include "types.h"
#include "gsreldata.h"
#include <immintrin.h>
#include "nolibc_util.h"
#include <sys/signal.h>
#include <asm/unistd.h>


using sighandler_type = void(*)(int, siginfo_t*, void*);

mmapped_list_s* get_mmappings();
void init_page_manager(mmapped_list_s* loader_mappings);
void* memcpy_untrusted_to_trusted(void* dest, void* src, int size);
void* memcpy_trusted_to_untrusted(void* dest, void* src, int size);
int get_pkey(int cid);
int get_cid(int key);

void nolibc_backtrace(size_t* base_ptr, int backtrace_size);

//access untrusted memory while enforcing the principle of least privileges
//rcx, rdx and rax can be clobbert
#if EXCLUSIVE_MPK_POLICY
#define ACCESS_UNTRUSTED_MEMORY(USER_CODE, OUTPUTS, INPUTS...)          \
    do {                                                                \
        asm volatile(                                                   \
            "xorl %%ecx, %%ecx\n"                                       \
            "xorl %%edx, %%edx\n"                                       \
            "movl %0, %%eax\n"                                          \
            "wrpkru\n"                                                  \
            "movb %%gs:%c2, %%dl\n"                                    \
            "cmpb %3, %%dl\n"  /*gsreldata->threadstate == TS_MONITOR*/\
            "je 1f\n"                                                   \
            "ud2\n"                                                     \
            "int3\n"                                                    \
            "1:\n"                                                      \
            USER_CODE                                                   \
            "xorl %%ecx, %%ecx\n"                                       \
            "xorl %%edx, %%edx\n"                                       \
            "movl %1, %%eax\n"                                          \
            "wrpkru\n"                                                  \
            "movb %%gs:%c2, %%dl\n"                                    \
            "cmpb %3, %%dl\n"  /*gsreldata->threadstate == TS_MONITOR*/\
            "je 1f\n"                                                   \
            "ud2\n"                                                     \
            "int3\n"                                                    \
            "1:\n"                                                      \
            :OUTPUTS                                                    \
            :"i"(REVOKE_PERMISSIONS), "i"(GRANT_TRUSTED_PERMISSIONS),   \
            "i"(COMPARTMENT_ID_OFFSET), "i"(TS_MONITOR), INPUTS         \
            : "rax", "rcx", "rdx"                                       \
        );                                                              \
    } while (0)


inline void internal_wrpkru(int pkru){
    asm volatile(
        "xorl %%ecx, %%ecx\n"
        "xorl %%edx, %%edx\n"
        "movl %[permissions], %%eax\n"
        "wrpkru\n"
        "movb %%gs:%c[compartment_id_offset], %%dl\n"
        "cmpb %[monitor_state], %%dl\n"
        "je 1f\n"
        "ud2\n"
        "int3\n"
        "1:\n"
        :
        :[permissions]"r"(pkru),
            [compartment_id_offset]"i"(COMPARTMENT_ID_OFFSET),
            [monitor_state]"i"(TS_MONITOR)
        : "rax", "rcx", "rdx"
    );   
}

#else
#define ACCESS_UNTRUSTED_MEMORY(USER_CODE, OUTPUTS, INPUTS...)          \
    do {                                                                \
        asm volatile(                                                   \
            USER_CODE                                                   \
            :OUTPUTS                                                    \
            :INPUTS                                                     \
            : "rax", "rcx", "rdx"                                       \
        );                                                              \
    } while (0)

    inline void internal_wrpkru([[maybe_unused]] int pkru){
        return;
    }
#endif

inline void mpk_check(void* address, int pkru_after){
    asm volatile(                                                   
        "xorl %%ecx, %%ecx\n"
        "xorl %%edx, %%edx\n"
        "movl %[untrusted_permission], %%eax\n"
        "wrpkru\n"
        "cmpl %[untrusted_permission], %%eax\n"
        "je 1f\n"
        "ud2\n"
        "int3\n"
        "1:\n"
        "movq (%[address]), %%rax\n"
        "movq %%rax, (%[address])\n"
        "xorl %%ecx, %%ecx\n"
        "xorl %%edx, %%edx\n"
        "movl %[permissions], %%eax\n"
        "wrpkru\n"
        "movb %%gs:%c[compartment_id_offset], %%dl\n"
        "cmpb %[monitor_state], %%dl\n"
        "je 1f\n"
        "ud2\n"
        "int3\n"
        "1:\n"
        :
        :[permissions]"r"(pkru_after),
            [untrusted_permission]"i"(REVOKE_PERMISSIONS),
            [compartment_id_offset]"i"(COMPARTMENT_ID_OFFSET),
            [monitor_state]"i"(TS_MONITOR),
            [address]"r"(address)
        : "rax", "rcx", "rdx"
    );   
}

inline void mpk_check_readonly(void* address, int pkru_after){
    asm volatile(                                                   
        "xorl %%ecx, %%ecx\n"
        "xorl %%edx, %%edx\n"
        "movl %[untrusted_permission], %%eax\n"
        "wrpkru\n"
        "cmpl %[untrusted_permission], %%eax\n"
        "je 1f\n"
        "ud2\n"
        "int3\n"
        "1:\n"
        "movq (%[address]), %%rax\n"
        "xorl %%ecx, %%ecx\n"
        "xorl %%edx, %%edx\n"
        "movl %[permissions], %%eax\n"
        "wrpkru\n"
        "movb %%gs:%c[compartment_id_offset], %%dl\n"
        "cmpb %[monitor_state], %%dl\n"
        "je 1f\n"
        "ud2\n"
        "int3\n"
        "1:\n"
        :
        :[permissions]"r"(pkru_after),
            [untrusted_permission]"i"(REVOKE_PERMISSIONS),
            [compartment_id_offset]"i"(COMPARTMENT_ID_OFFSET),
            [monitor_state]"i"(TS_MONITOR),
            [address]"r"(address)
        : "rax", "rcx", "rdx"
    );   
}

inline int rdpkru(){
    int ret;
    asm("rdpkru\n"
        "movl %%eax, %[ret]"
        :[ret]"=r"(ret)
        :"c"(0)
        :"rax", "rdx");
    return ret;
}

inline void nolibc_memcpy(long long* dest, long long* src, int size){
    nolibc_assert(size%8);
    for(int i = 0;i<size/8;i++){
        *(dest+i) = *(src+i);
    }
}