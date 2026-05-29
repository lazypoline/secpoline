#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <link.h>
#include <assert.h>
#include "types.h"
#include "secpoline.h"
#include "gsreldata.h"
#include <assert.h>
#include <pthread.h>
#include "nolibc_util.h"
#include <linux/unistd.h>
#include "erim.h"
#include <mutex>
#include <vector>
#include <sys/signal.h>
#include <dlfcn.h>
#include "signal_handlers.h"
#include <string>
#include "hardware_breakpoints.h"
#include "util.h"
#include <linux/rseq.h>
#include "virt_page_manager.h"




//global function pointer pointing to the signal handler entry point form the libsegfault_handler
extern std::vector<struct unsafe_page*> unsafe_pages;
using setup_type = void (*)(std::vector<struct unsafe_page*>*);

const int entry_amount = 4;
extern sighandler_type asm_signal_entry;
extern char* path_to_secpoline;
const char* libsegfault_file = "libsegfault_handler.so";
Page_group* vdso_pages;
void (*add_breakpoint_wrapper_func)(unsafe_page*, bool);
void (*add_breakpoints_after_fork_wrapper_func)(void);
void (*update_active_thread_list)(bool);

bool mapping_in_list(uint64_t mapping_address, mmapped_list_s* m_list);
static int is_buffer_untrusted(void* start, int size, int pkru_after, int readonly);
static void destroy_pkey_set();
static void get_allow_list(std::vector<unsigned long long>* allow_list);
void init_page_group(char* start, char* end, int prot, int is_segfault_handler, int cid, std::vector<unsigned long long>* allow_list);
void open_libsegfault_handler();
static void print_mmapped_list(mmapped_list_s*);
static void unset_rseq();
static size_t read_proc_maps(char* static_buf, size_t buf_size);

//TODO, these mappings are still file backed
void init_page_manager(mmapped_list_s* loader_mappings){
    //Setup phase
    vdso_pages = &loader_mappings->vdso;
    open_libsegfault_handler();
    destroy_pkey_set();
    std::vector<unsigned long long> allow_list;
    get_allow_list(&allow_list);

 
    //first load all of the current maps into a static buffer
    //then we can enable the meta-monitor to apply any rules to future mappings
    //lastly we need to apply those rules to the existing mappings from proc/self/maps
    const size_t static_buf_size = 16 * 1024 * 1024;
    char* static_buf = (char*)malloc(static_buf_size);
    size_t read_bytes = read_proc_maps(static_buf, static_buf_size);

    //do not enable sud until this point
    //any mappings made before this will be handled by the following code after being read in /proc/self/maps
    //so the meta monitor should not dubble the steps
    //however now we have all current mappigns, we need to interpose all future once
	enable_sud();

    //scan all executable pages
    //pkey_mprotect them with the correct pkey
    //add the group to the page_manager
    char *p = static_buf;
    char *end = static_buf + read_bytes;
    char* end_ptr = NULL;
    while (p < end) {
        char *line = p;

        // find end of line
        while (p < end && *p != '\n') p++;
        // terminate line in-place
        if (p < end) {
            *p = '\0';
            p++;
        }

        assert(strchr(line, '\0') != NULL);
        //fprintf(stderr, "%s\n", line);
        end_ptr = line;
        if (!*end_ptr)continue;
        if(strstr(line, "vdso")) continue;
        if(strstr(line, "vvar")) continue;
        //extract start and end adress of memory maping
        //star_adress-end_adress rwxp ....
        uint64_t mapping_start = strtoll(end_ptr, &end_ptr, 16);
        if(mapping_start>=0x7fffffffffffffff)continue; //ignore vsyscall pages
        assert(*end_ptr++ == '-');
        uint64_t mapping_end = strtoll(end_ptr, &end_ptr, 16);
        char* page_permissions = strchr(line, ' ')+1;
        int is_segfault_handler = (strstr(line, libsegfault_file) != NULL); //1 if the page group is part of the segfault handler
        
        int prot = 0;
        assert(*page_permissions=='r'||*page_permissions=='-');
        if(*(page_permissions)=='r')prot |= PROT_READ;
        if(*(page_permissions+1)=='w')prot |= PROT_WRITE;
        if(*(page_permissions+2)=='x')prot |= PROT_EXEC;
        
        int cid = mapping_in_list(mapping_start, loader_mappings) ? TS_APPLICATION : TS_MONITOR;

        init_page_group((char*)mapping_start, (char*)mapping_end, prot, is_segfault_handler, cid, &allow_list);
    }

    //tag vvar and vdso as trusted but readable by the untrusted applciation
    assert(page_manager.add_page((char*)loader_mappings->vdso.start_address, loader_mappings->vdso.size, loader_mappings->vdso.permissions, TS_MONITOR, false)==0);
    assert(inline_syscall6(__NR_pkey_mprotect, (void*)loader_mappings->vdso.start_address, loader_mappings->vdso.size, loader_mappings->vdso.permissions, SECPOLINE_READONLY_MPKEY, 0, 0)==0);
    assert(page_manager.add_page((char*)loader_mappings->vvar.start_address, loader_mappings->vvar.size, loader_mappings->vvar.permissions, TS_MONITOR, false)==0);
    assert(inline_syscall6(__NR_pkey_mprotect, (void*)loader_mappings->vvar.start_address, loader_mappings->vvar.size, loader_mappings->vvar.permissions, SECPOLINE_READONLY_MPKEY, 0, 0)==0);

    //need to retag gsreldata readable data
    assert(inline_syscall6(__NR_pkey_mprotect, (void*)_readgsbase_u64(), sizeof(GSRelativeData::readable_data), PROT_READ|PROT_WRITE, SECPOLINE_READONLY_MPKEY, 0, 0) == 0);

#if PREVENT_NULL_DEREF
    set_sud_allow();
    assert(inline_syscall6(__NR_pkey_mprotect, 0, PAGE_SIZE, PROT_EXEC, NULL_PTR_MPKEY, 0, 0) == 0);
    assert(page_manager.update_mprotect(0, PAGE_SIZE, PROT_EXEC, TS_MONITOR)==0);
    set_sud_block();
#endif
    free(static_buf);
}


void init_page_group(char* start, char* end, int prot, int is_segfault_handler, int cid, std::vector<unsigned long long>* allow_list){
    assert(allow_list != NULL);
    size_t size = end - start;

    if(is_segfault_handler){
        //these pages are for the segfault handler and should never be made non-executable, just mark them as unsafe
        assert(!(prot&PROT_EXEC && prot&PROT_WRITE));
        assert(cid == TS_MONITOR);
        if(prot&PROT_EXEC){
            for(char* address = (char *)start; address < end;address+=PAGE_SIZE){
                struct unsafe_page* page = erim_memScanRegion(address, PAGE_SIZE,  allow_list->data(), allow_list->size(), prot, prot, true, NULL);
                if(page != NULL){
                    //this page contains a unsafe instruction but it is part of the segfault handler code path, so dont make these pages non-executable
#if SCAN_UNSAFE_INSTRUCTIONS
                    add_breakpoint_wrapper_func(page, true);
#endif
                }
            }

        }
        //these can always be tagged as a full group, as no protections are changed here
        assert(page_manager.add_page(start, size, prot, TS_MONITOR, false)==0);
        assert(inline_syscall6(__NR_pkey_mprotect, start, size, prot, SECPOLINE_MPKEY, 0, 0) == 0);
        return;
    }

    //these pages should start as write only and be added as an unsafe page
    if(prot&PROT_EXEC && prot&PROT_WRITE){
        prot = prot&(~PROT_EXEC);
        for(char* address = start; address < end;address+=PAGE_SIZE){
            add_unsafe_page(address, prot, prot|PROT_EXEC, cid==TS_MONITOR, NULL);
        }
        assert(page_manager.add_page(start, size, prot, cid, false)==0);
        assert(inline_syscall6(__NR_pkey_mprotect, start, size, prot, get_pkey(cid), 0, 0) == 0);
        return;
    }

    //scan all executable pages for unsafe instructions
    //this also pkey_mprotects them and adds them to the page_manager
    if(prot&PROT_EXEC){
        scan_exec_mapping(start, size, prot, prot&~PROT_EXEC, false, cid, allow_list);
        return;
    }

    //the mmappings are not executable so just tage them and add them to the page manager
    assert(page_manager.add_page(start, size, prot, cid, false)==0);
    assert(inline_syscall6(__NR_pkey_mprotect, start, size, prot, get_pkey(cid), 0, 0) == 0);
    return;
}

static void get_allow_list(std::vector<unsigned long long>* allow_list){
    int i = 0;
    while(true){
        std::string result = "safe_wrpkru_entry_point" + std::to_string(i);
        unsigned long long entry_point = (unsigned long long)dlsym(RTLD_DEFAULT, result.c_str());
        if (dlerror()) {
            break;
        }      
        allow_list->push_back(entry_point);
        //printf("added entry point for %s at %llx\n", result.c_str(), (*allow_list)[i]);
        i++;
    }

    std::string result = "safe_wrpkru_entry_point_segfault" + std::to_string(0);
    unsigned long long enty_point = (unsigned long long)dlsym(RTLD_DEFAULT, result.c_str());
    //printf("added entry point for %s at %llx\n", result.c_str(), enty_point);
    assert(enty_point);
    allow_list->push_back(enty_point);
    if (!dlerror()) {
        i++;
    }  
    assert(i==entry_amount);
    assert(allow_list->size()==entry_amount);
}

//try to find the wrpkru instruction in pkey_set() and replace it with zeroes as this function should never be called anyway
static void destroy_pkey_set(){
    char* pkey_set_location = (char*) dlsym(RTLD_DEFAULT, "pkey_set");
    if(pkey_set_location==0)return;
    //TODO 256 is kinda arbitrary, find the end of pkey_set instead to determine the max seach lenght
    for(int i=0;i<256;i++){
        char* a = pkey_set_location+i;
        if(erim_isWRPKRU(a)){
            char* page = (char*)((size_t)a & ~(PAGE_SIZE - 1));
            mprotect(page, PAGE_SIZE, PROT_WRITE|PROT_READ);
            a[0] = 0;
            a[1] = 0;
            a[2] = 0;
            //printf("destroyed wrpku at location: %p\n", a);
            mprotect(page, PAGE_SIZE, PROT_READ|PROT_EXEC);
            return;
        }
    }
    return;
}

static size_t read_proc_maps(char* static_buf, size_t buf_size){
    int fd = inline_syscall6(__NR_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY, 0, 0, 0);
    assert(fd != 0);

    size_t off = 0;
    while (off < buf_size - 1) {
        ssize_t r = inline_syscall6(__NR_read, fd, (long)(static_buf + off), buf_size - 1 - off, 0, 0, 0);
        if (r < 0) {
            assert(0);
        }

        if (r == 0) {
            break; // EOF
        }

        off += r;
    }

    static_buf[off] = '\0';
    inline_syscall6(__NR_close, fd, 0, 0, 0, 0, 0);

    //printf("read %zu bytes\n", off);
    return off;
}

/*
static void unset_rseq(){
    int* libc_rseq_offset_p = (int*)dlsym(RTLD_NEXT, "__rseq_offset");
    char* fsbase;
    asm("rdfsbase %[ret]"
        :[ret]"=r"(fsbase));
    struct rseq* ptr =  (struct rseq*)(fsbase + *libc_rseq_offset_p);
    printf("rseq address: %p [offset=%d]\n", ptr, *libc_rseq_offset_p);
    //int ret = syscall(__NR_rseq, ptr, sizeof(*ptr), RSEQ_FLAG_UNREGISTER, RSEQ_SIG);
    //printf("unregister ret=%d\n", errno);
    //assert(ret == 0);
}
*/

void open_libsegfault_handler(){
    //TODO, find better way then requiring the same directory as secpoline
    char* end_of_dir = strrchr(path_to_secpoline, '/');
    int dir_size = end_of_dir-path_to_secpoline+1;
    int libsegfault_file_size = strlen(libsegfault_file);
    char* libsegfault_path = (char*) calloc(dir_size+libsegfault_file_size+1, 1);
    memcpy(libsegfault_path, path_to_secpoline, dir_size);
    memcpy(libsegfault_path+dir_size, libsegfault_file, libsegfault_file_size);

    void* handle = dlopen(libsegfault_path, RTLD_GLOBAL|RTLD_NOW);
    
    if (const char* error = dlerror()) {
        fprintf(stderr, "dlopen: %s\n", error);
        exit(-1);
    }  
    assert(handle);
    setup_type setup_func = (setup_type) dlsym(handle, "setup_segfault_handler");
    if (const char* error = dlerror()) {
        fprintf(stderr, "dlsym: %s\n", error);
        exit(-1);
    }  
    assert(setup_func);
    setup_func(&unsafe_pages);
    
    add_breakpoint_wrapper_func = (void(*)(unsafe_page*, bool)) dlsym(handle, "add_breakpoint_wrapper");
    if (const char* error = dlerror()) {
        fprintf(stderr, "dlsym: %s\n", error);
        exit(-1);
    }  
    assert(add_breakpoint_wrapper_func);

    add_breakpoints_after_fork_wrapper_func = (void(*)(void)) dlsym(handle, "add_breakpoints_after_fork_wrapper");
    if (const char* error = dlerror()) {
        fprintf(stderr, "dlsym: %s\n", error);
        exit(-1);
    }  
    assert(add_breakpoints_after_fork_wrapper_func);

    update_active_thread_list = (void(*)(bool)) dlsym(handle, "update_active_thread_list");
    if (const char* error = dlerror()) {
        fprintf(stderr, "dlsym: %s\n", error);
        exit(-1);
    }  
    assert(update_active_thread_list);
    update_active_thread_list(false); //initialise the main thread
    

    asm_signal_entry = (sighandler_type) dlsym(handle, "asm_signal_entry");
    if (const char* error = dlerror()) {
        fprintf(stderr, "dlsym: %s\n", error);
        exit(-1);
    }  
    assert(asm_signal_entry);
#if SCAN_UNSAFE_INSTRUCTIONS
    //set the segfault and trap handlers here
    struct sigaction act = {};
	act.sa_sigaction = asm_signal_entry;
	act.sa_flags = SA_SIGINFO|SA_ONSTACK|SA_NODEFER;
    assert(sigfillset(&act.sa_mask) == 0);
	assert(sigaction(SIGSEGV, &act, NULL) == 0);

    struct sigaction act_trap = {};
	act_trap.sa_sigaction = asm_signal_entry;
	act_trap.sa_flags = SA_SIGINFO|SA_ONSTACK|SA_NODEFER;
    assert(sigfillset(&act_trap.sa_mask) == 0);
	assert(sigaction(SIGTRAP, &act_trap, NULL) == 0);
#endif
}

int get_pkey(int cid){
    if(cid == TS_MONITOR) return SECPOLINE_MPKEY;
    if(cid == TS_APPLICATION) return UNTRUSTED_MPKEY;
    return -1;
}

int get_cid(int key){
    if((key == SECPOLINE_MPKEY) || (key == SECPOLINE_READONLY_MPKEY)) return TS_MONITOR;
    if(key == UNTRUSTED_MPKEY) return TS_APPLICATION;
    return -1;
}

bool mapping_in_list(uint64_t mapping_address, mmapped_list_s* m_list){
    for(int i=0; i<m_list->size;i++){
        if(mapping_address == m_list->list[i].start_address) return true;
    }
    return false;
}

static void print_mmapped_list(mmapped_list_s* m_list){
    for(int i=0; i<m_list->size;i++){
        printf("address:%p size:%d perm:%d\n", (void*)m_list->list[i].start_address, m_list->list[i].size, m_list->list[i].permissions);
    }
}

void* memcpy_untrusted_to_trusted(void* dest, void* src, int size){
#if EXCLUSIVE_MPK_POLICY
    assert(rdpkru()==GRANT_TRUSTED_PERMISSIONS); //don't call this when we already have full privileges
    //first make sure the untrusted src is actually untrusted memory
    assert(is_buffer_untrusted(src, size, GRANT_FULL_PERMISSIONS, 1));
    dest = memcpy(dest, src, size);
    internal_wrpkru(GRANT_TRUSTED_PERMISSIONS);
    return dest;
#else
    return memcpy(dest, src, size);
#endif
}

void* memcpy_trusted_to_untrusted(void* dest, void* src, int size){
#if EXCLUSIVE_MPK_POLICY
    assert(rdpkru()==GRANT_TRUSTED_PERMISSIONS); //don't call this when we already have full privileges
    //first make sure the untrusted src is actually untrusted memory
    assert(is_buffer_untrusted(dest, size, GRANT_FULL_PERMISSIONS, 0));
    dest = memcpy(dest, src, size);
    internal_wrpkru(GRANT_TRUSTED_PERMISSIONS);
    return dest;
#else
    return memcpy(dest, src, size);
#endif
}

static int is_buffer_untrusted(void* start, int size, int pkru_after, int readonly){
    size_t start_page = (size_t)__builtin_align_down(start, PAGE_SIZE);
    size_t end_page = (size_t)__builtin_align_down((void*)((size_t)start + size), PAGE_SIZE);
    if(readonly){
        if(start_page != end_page){
            //if the buffer lies on multiple pages, verify each one
            for(size_t address = start_page; address <= end_page; address+=PAGE_SIZE){
                mpk_check_readonly((void*)address, pkru_after);
            }
            return 1;
        }
        //this is the normal case where the buffer lies on a single page
        mpk_check_readonly((void*)start, pkru_after);
        return 1;
    }
    if(start_page != end_page){
        //if the buffer lies on multiple pages, verify each one
        for(size_t address = start_page; address <= end_page; address+=PAGE_SIZE){
            mpk_check((void*)address, pkru_after);
        }
        return 1;
    }
    //this is the normal case where the buffer lies on a single page
    mpk_check((void*)start, pkru_after);
    return 1;
}



void nolibc_backtrace(size_t* base_ptr, int backtrace_size){
    int pkru = rdpkru();
    internal_wrpkru(GRANT_FULL_PERMISSIONS);

    nolibc_print_str("backtrace:");
    for(int i = 0;i<backtrace_size;i++){
        size_t* ret_address = (size_t*)*(base_ptr + 1);
        nolibc_print_size_t_hex("#", (size_t)ret_address);
        base_ptr = (size_t*)base_ptr[0];
    }

    internal_wrpkru(pkru);
}