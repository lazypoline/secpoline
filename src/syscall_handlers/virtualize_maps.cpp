#include <syscall.h>
#include <assert.h>
#include <sys/mman.h>
#include "erim.h"
#include "virt_page_manager.h"
#include "gsreldata.h"
#include "mpk_isolation.h"

//Do not call any outside code here as this code is shared between the meta monitor
size_t secpoline_mmap(size_t start, size_t size, size_t prot, size_t flags, int fd, size_t offset, int cid){
    int key = get_pkey(cid);
    if(cid==TS_MONITOR) nolibc_assert(gsreldata->readable_data.sud_selector==SYSCALL_DISPATCH_FILTER_ALLOW);
    if(key == -1) return -EINVAL;
    int is_exec = (!!(prot & PROT_EXEC));
    int is_write = (!!(prot & PROT_WRITE));
    int real_prot = prot;

    assert(!(flags&MAP_HUGETLB));

    if(size==0 || (start%PAGE_SIZE!=0)){
        return -EINVAL;
    }

#if PREVENT_MUTABLE_MAPS
    flags |= MAP_PRIVATE;
#endif

    if(flags&MAP_FIXED){
        if(is_multithreaded){
            if(page_manager.lookup_range((char*)start, size, cid) == NULL){
                return -EINVAL;
            }
        }else{
            if(page_manager.lookup_range_allow_gaps((char*)start, size, cid) == -1){
                return -EINVAL;
            }
        }
    }

    //executable pages need to be scanned for unsafe instructions first.
    //first map a read only page so we can scan it.
    if(is_exec && !is_write){
        assert(!(prot&PROT_WRITE));
        prot = PROT_READ;
    }

    //map these pages as writable, but mark it as porantially executable.
    if (is_exec && is_write)prot &=(~PROT_EXEC);

    //Map the actual pages
    int64_t result;
#if PREVENT_MUTABLE_MAPS
    if(fd != -1 && fd != 0){
        //prevent executable mappings from being file backed, as this allows attackers to insert wrpkru instruction through writes to the file
        result = map_file_baked(start, size, prot, flags, fd, offset, cid);
    }else{
        result = syscall_wrapper(__NR_mmap, start, size, prot, flags, -1, 0, cid);
    }
#else
    result = syscall_wrapper(__NR_mmap, start, size, prot, flags, fd, offset, cid);
#endif
    
    if(result <= 0){
        return result;
    }

    if(is_exec && !is_write){
        //this maps, pkey_mprotects and add the pages to the page manager
        if(cid == TS_MONITOR){
            set_sud_block();
        }
        scan_exec_mapping((char*)result, size, real_prot, real_prot&~PROT_EXEC, flags, flags&MAP_FIXED, cid, NULL);
        if(cid == TS_MONITOR){
            set_sud_allow();
        }
        return result;
    }


    assert(page_manager.add_page((char*)result, size, prot, flags, cid, flags&MAP_FIXED)==0);
    assert(syscall_wrapper(__NR_pkey_mprotect, (int64_t)result, size, prot, key, 0, 0, cid)==0);

    //if the pages can be executable, mark it as such so the segfault handler knows it.
    if(is_exec && is_write){
        if(cid == TS_MONITOR){
            set_sud_block();
        }
        for(char* address = (char *)result; address < (char*)result+size;address+=PAGE_SIZE){
            add_unsafe_page(address, prot, prot|PROT_EXEC, (cid==TS_MONITOR), NULL);
        }
        if(cid == TS_MONITOR){
            set_sud_allow();
        }
    }

    return result;
}

size_t map_file_baked(size_t start, size_t size, size_t prot, size_t flags, int fd, size_t offset, int cid){
    //first map the page as writable
    //TODO pkey_mprotect first in case key zero is not monitor owned
    int64_t result = syscall_wrapper(__NR_mmap, start, size, PROT_WRITE|PROT_READ, flags|MAP_ANONYMOUS, -1, 0, cid);
    if(result < 0) return result;


    size_t cur = syscall_wrapper(__NR_lseek, fd, 0, SEEK_CUR, 0, 0, 0, cid);
    if(cur < 0) return cur;

    size_t ret = syscall_wrapper(__NR_lseek, fd, offset, SEEK_SET, 0, 0, 0, cid);
    if(ret < 0) return ret;

    // Reading the file should be careful. You may need to read the file multiple times
    size_t readlen = 0;
    size_t curlen = 0;
    while(readlen < size) {
        curlen = inline_syscall6(__NR_read, fd, result+readlen, size - readlen, 0, 0, 0);
        assert(curlen >= 0);
        if(curlen == 0)
            break;
        readlen += curlen;
    }
    ret = syscall_wrapper(__NR_lseek, fd, cur, SEEK_SET, 0, 0, 0, cid);
    assert(ret >= 0);
    
    return result;
}

//scan the page for unsafe instructions and mprotect it with the correct key and protections
//also adds the group to the page_manager
void scan_exec_mapping(char* start, size_t size, int prot, int unsafe_prot, int flags, int map_fixed, int cid, std::vector<unsigned long long>* allow_list){
    //nolibc_print_size_t_hex("exec start", (size_t)start);
    //nolibc_print_size_t_hex("exec end", (size_t)start+size);
    int key = get_pkey(cid);
    if(key == -1) return;
#if !SCAN_UNSAFE_INSTRUCTIONS
        assert(page_manager.add_page(start, size, prot, flags, cid, map_fixed)==0);
        assert(inline_syscall6(__NR_pkey_mprotect, (int64_t)start, size, prot, key, 0, 0)==0);
        return;
#endif

    unsigned long long* allow_list_data = allow_list!=NULL ? allow_list->data() : NULL;
    unsigned long long allow_list_size = allow_list!=NULL ? allow_list->size() : 0;

    char* start_group = NULL;
    size_t group_size = 0; //the size of the current group in bytes
    char* prev_page = NULL;
    for(char* page = start; page < start+size;page+=PAGE_SIZE){
        //create a new group
        if(start_group==NULL){
            assert(group_size == 0);
            start_group=page;
        }
        
        //iterate over every page, if it contains an unsafe instruction, add every previous page to a group.
        //then mprotect the group and add it to the page mamager
        //unsafe pages are put in a seperate page manarger group
        unsafe_page* erim_ret = erim_memScanRegion(page, PAGE_SIZE, allow_list_data, allow_list_size, prot, prot&~PROT_EXEC, false, &prev_page);
        if((prev_page==(char*)-1)){
            //nolibc_print_size_t_hex("prev page", (size_t)page-PAGE_SIZE);
            //the previous page contains unsafe instructions, so reduce the current group by page_size
            //if group_size == PAGE_SIZE, then the last page was the only one in the group
            if(group_size != 0){
                group_size -= PAGE_SIZE;
                assert(page_manager.add_page((char*)page-PAGE_SIZE, PAGE_SIZE, unsafe_prot, flags, cid, map_fixed)==0);
                assert(inline_syscall6(__NR_pkey_mprotect, (int64_t)page-PAGE_SIZE, PAGE_SIZE, unsafe_prot, key, 0, 0)==0);
            }
        }

        if(erim_ret || (prev_page==(char*)-1)){
            if(group_size != 0){
                //now add all previous mappings to a group and mprotect them
                assert(page_manager.add_page((char*)start_group, group_size, prot, flags, cid, map_fixed)==0);
                assert(inline_syscall6(__NR_pkey_mprotect, (int64_t)start_group, group_size, prot, key, 0, 0)==0);

                //now we sperated the prev page, the group starts at this page
                group_size = 0;
                start_group = page;
            }
        }
        
        if(erim_ret){
            //and add the actual unsafe page
            assert(page_manager.add_page((char*)page, PAGE_SIZE, unsafe_prot, flags, cid, map_fixed)==0);
            assert(inline_syscall6(__NR_pkey_mprotect, (int64_t)page, PAGE_SIZE, unsafe_prot, key, 0, 0)==0);

            group_size = 0;
            start_group = NULL;
            
            prev_page = page;
            continue;
        }
        prev_page = page;
        group_size += PAGE_SIZE;
    }

    //now we have reached the end, mprotect the last group
    if(group_size == 0) return;

    assert(page_manager.add_page((char*)start_group, group_size, prot, flags, cid, map_fixed)==0);
    assert(inline_syscall6(__NR_pkey_mprotect, (int64_t)start_group, group_size, prot, key, 0, 0)==0);
    return;
}

//scan the page, mprotect it, and update its value in the page manager
void scan_exec_mapping_mprotect(char* start, size_t size, int prot, int unsafe_prot, int cid, std::vector<unsigned long long>* allow_list){
    int key = get_pkey(cid);
    if(key == -1) return;
#if !SCAN_UNSAFE_INSTRUCTIONS
        assert(syscall_wrapper(__NR_mprotect, (int64_t)start, size, prot, 0, 0,0, cid)==0); 
        assert(page_manager.update_mprotect(start, size, prot, cid)==0);
        return;
#endif

    unsigned long long* allow_list_data = allow_list!=NULL ? allow_list->data() : NULL;
    unsigned long long allow_list_size = allow_list!=NULL ? allow_list->size() : 0;

    char* start_group = NULL;
    char* prev_page = NULL;
    size_t group_size = 0; //the size of the current group in bytes
    for(char* page = start; page < start+size;page+=PAGE_SIZE){
        //create a new group
        if(start_group==NULL){
            assert(group_size == 0);
            start_group=page;
        }

        //iterate over every page, if it contains an unsafe instruction, add every previous page to a group.
        //then mprotect the group and add it to the page mamager
        //unsafe pages are put in a seperate page manarger group
        unsafe_page* erim_ret = erim_memScanRegion(page, PAGE_SIZE, allow_list_data, allow_list_size, prot, prot&~PROT_EXEC, false, &prev_page);
        if((prev_page==(char*)-1)){
            //the previous page contains unsafe instructions, so reduce the current group by page_size
            //if group_size == PAGE_SIZE, then the last page was the only one in the group
            if(group_size != 0){
                group_size -= PAGE_SIZE;
                assert(syscall_wrapper(__NR_mprotect, (int64_t)page-PAGE_SIZE, PAGE_SIZE, unsafe_prot, 0, 0, 0, cid)==0); 
                assert(page_manager.update_mprotect((char*)page-PAGE_SIZE, PAGE_SIZE, unsafe_prot, cid)==0);
            }
        }

        if(erim_ret || (prev_page==(char*)-1)){
            if(group_size != 0){
                //now add all previous mappings to a group and mprotect them
                assert(syscall_wrapper(__NR_mprotect, (int64_t)start_group, group_size, prot, 0, 0,0, cid)==0); 
                assert(page_manager.update_mprotect(start_group, group_size, prot, cid)==0);
            }
        }
        
        if(erim_ret){
            //and add the actual unsafe page
            assert(syscall_wrapper(__NR_mprotect, (int64_t)page, PAGE_SIZE, unsafe_prot, 0, 0, 0, cid)==0); 
            assert(page_manager.update_mprotect((char*)page, PAGE_SIZE, unsafe_prot, cid)==0);

            group_size = 0;
            start_group = NULL;
            
            prev_page = page;
            continue;
        }
        prev_page = page;
        group_size += PAGE_SIZE;
    }
        
    //now we have reached the end, mprotect the last group
    if(group_size == 0) return;

    assert(syscall_wrapper(__NR_mprotect, (int64_t)start_group, group_size, prot, 0, 0,0, cid)==0); 
    assert(page_manager.update_mprotect(start_group, group_size, prot, cid)==0);
    return;
}

char* handle_mremap_exec(char* start, size_t old_size, size_t new_size, int flags, char* new_start, int prot, int cid){
    //TODO, keep the desired mappings when remapping unsafe pages
    if(syscall_wrapper(__NR_mprotect, (size_t)start, old_size, PROT_READ, 0, 0, 0, cid)!=0) return (char*)-EINVAL;
    
    char* res = handle_mremap(start, old_size, new_size, flags, new_start, cid);
    assert(res > (char*)0); //to late to go back now

    if(!(flags&MREMAP_DONTUNMAP)){
        scan_exec_mapping_mprotect(res, new_size, prot, prot&~PROT_EXEC, cid, NULL);
        return res;
    }else{
        scan_exec_mapping_mprotect(start, old_size, prot, prot&~PROT_EXEC, cid, NULL);
        scan_exec_mapping_mprotect(res, new_size, prot, prot&~PROT_EXEC, cid, NULL);
        return res;
    }
    return (char*)-1;
}


char* handle_mremap(char* start, size_t old_size, size_t new_size, int flags, char* new_start, int cid){
    if(old_size == 0 || new_size == 0) return (char*)-EINVAL;
    if(((size_t)start%PAGE_SIZE != 0)) return (char*)-EINVAL;
    if((flags & MREMAP_FIXED) && ((size_t)new_start % PAGE_SIZE != 0)) return (char*)-EINVAL;
    if((old_size%PAGE_SIZE != 0) || (new_size%PAGE_SIZE != 0)) return (char*)-EINVAL;

    //first case, maymove is not set
    //this means that dontunmap and mapfixed are not allowed
    //so this just increases the size in place if possible
    //this is not dangerous as long as the mapping has the correct cid
    //so just try to increase its length
    if(!(flags&MREMAP_MAYMOVE)){
        if((flags&MREMAP_FIXED) || (flags&MREMAP_DONTUNMAP)) return (char*)-EINVAL;

        if(page_manager.update_size(start, old_size, new_size, cid)==0){
            assert(syscall_wrapper(__NR_mremap, (size_t)start, old_size, new_size, flags, 0, 0, cid) == (size_t)start);
            return start;
        }else{
            return (char*)-EFAULT;
        }
    }


    //second case, the mapping can be moved, but it is unmapped and not map fixed
    if(!(flags&MREMAP_FIXED)){
        int res = page_manager.update_size(start, old_size, new_size, cid);
        if(res==0){
            assert(syscall_wrapper(__NR_mremap, (size_t)start, old_size, new_size, flags, 0, 0, cid) == (size_t)start);
            return start;
        }else if(res == -2){
            struct virt_page* current_page = page_manager.lookup_addr(start, cid);
            if(current_page == NULL) return (char*)-EINVAL;
            int prot = current_page->prot;
            //the size increase failed, we need to move it somewhere else instead.
            //remove it first unless that is not needed
            if(!(flags&MREMAP_DONTUNMAP)){
                if(page_manager.remove_page(start, old_size, cid)!=0) return (char*)-EFAULT;
            }else{
                if(page_manager.lookup_range(start, old_size, cid)==NULL) return (char*)-EFAULT;
            }

            char* new_addr = (char*)syscall_wrapper(__NR_mremap, (size_t)start, old_size, new_size, flags, 0, 0, cid);
            assert(new_addr > (char*)0);
            
            //at this point the removal is done, so we cannot return if someting fails
            assert(page_manager.add_page(new_addr, new_size, prot, flags, cid, false)==0);
            return new_addr;

        }else{
            return (char*)-EFAULT;
        }
    }

    //map fixed, so it will always move
    struct virt_page* current_page = page_manager.lookup_addr(start, cid);
    if(current_page == NULL) return (char*)-EINVAL;
    int prot = current_page->prot;

    //make sure we are not overwriting anything in the wrong compartment
    if(page_manager.lookup_range(new_start, new_size, cid)!=NULL) return (char*)-EFAULT;
    //the size increase failed, we need to move it somewhere else instead.
    //remove it first unless that is not needed
    if(!(flags&MREMAP_DONTUNMAP)){
        if(page_manager.remove_page(start, old_size, cid)!=0) return (char*)-EFAULT;
    }else{
        if(page_manager.lookup_range(start, old_size, cid)==NULL) return (char*)-EFAULT;
    }

    char* new_addr = (char*)syscall_wrapper(__NR_mremap, (size_t)start, old_size, new_size, flags, (size_t)new_start, 0, cid);
    assert(new_addr > (char*)0);
    
    //at this point the removal is done, so we cannot return if someting fails
    assert(page_manager.add_page(new_addr, new_size, prot, cid, flags, false)==0);
    return new_addr;
}