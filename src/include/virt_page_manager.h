#pragma once
#include <unordered_set>
#include <shared_mutex>
#include <mutex>
#include "nolibc_util.h"

#ifndef MREMAP_DONTUNMAP
    #define MREMAP_DONTUNMAP 4
#endif

struct virt_page{
    char* start;
    size_t size;
    int prot;
    int flags;
    int Cid; //compartment ID

    struct virt_page* next;
    char padding[24];
};

//all sizes are in bytes
class virt_page_manager{
    public:
        int add_page(char* start, size_t size, int prot, int flags, int cid, bool map_fixed);
        int remove_page(char* start, size_t size, int cid);
        int update_mprotect(char* start, size_t size, int prot, int cid);
        int update_size(char* start, size_t old_size, size_t new_size, int cid);
        struct virt_page* lookup_addr(char* addr, int cid);
        struct virt_page* lookup_range(char* start_addr, size_t size, int cid);
        int lookup_range_allow_gaps(char* start_addr, size_t size, int cid);

        void print_mappings();
        ~virt_page_manager();

        struct virt_page* pages = NULL;

    private:
        struct virt_page* free_pages = NULL;
        pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;

        int add_page_locked(char* start, size_t size, int prot, int flags, int cid, bool map_fixed, struct virt_page* p1);
        int remove_page_locked(char* start, size_t size, int cid);
        int remove_page_map_fixed_locked(char* start, size_t size, int cid);
        int update_mprotect_locked(char* start, size_t size, int prot, int cid);
        int update_size_locked(char* start, size_t old_size, size_t new_size, int cid);
        struct virt_page* lookup_addr_locked(char* addr, int cid);
        struct virt_page* lookup_range_locked(char* start_addr, size_t size, int cid);
        int lookup_range_allow_gaps_locked(char* start_addr, size_t size, int cid);

        struct virt_page* return_virt_page(struct virt_page* page_group, int cid);
        int virt_page_overlap(struct virt_page* page_group, char* start, size_t size);
        int virt_page_overlap_byte(struct virt_page* page_group, char* byte);
        struct virt_page* virt_page_get_prev_group(struct virt_page* page_group);

        void refill_free_list();
        void virt_page_free(struct virt_page* page_group);
        struct virt_page* virt_page_alloc();


};

extern virt_page_manager page_manager;


void scan_exec_mapping(char* start, size_t size, int prot, int unsafe_prot, int flags, int map_fixed, int cid, std::vector<unsigned long long>* allow_list);
void scan_exec_mapping_mprotect(char* start, size_t size, int prot, int unsafe_prot, int cid, std::vector<unsigned long long>* allow_list);
char* handle_mremap(char* start, size_t old_size, size_t new_size, int flags, char* new_start, int cid);
char* handle_mremap_exec(char* start, size_t old_size, size_t new_size, int flags, char* new_start, int prot, int cid);
size_t secpoline_mmap(size_t start, size_t size, size_t prot, size_t flags, int fd, size_t offset, int cid);
size_t map_file_baked(size_t start, size_t size, size_t prot, size_t flags, int fd, size_t offset, int cid);



inline int secpoline_mprotect(char* addr, size_t size, int prot, int cid, class virt_page_manager* pm){
    int ret = inline_syscall6(__NR_mprotect, addr, size, prot, 0, 0, 0);
    if(ret == 0){
        nolibc_assert(pm->update_mprotect(addr, size, prot, cid)==0);
    }
    return 0;
}
