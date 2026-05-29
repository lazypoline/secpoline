#include <syscall.h>
#include <sys/mman.h>
#include "erim.h"
#include "virt_page_manager.h"
#include "gsreldata.h"
#include "nolibc_util.h"
#include <stdio.h>
#include <unistd.h>
#include "mpk_isolation.h"

//TODO, potentially merge mappings with the same meta data, to make lookup faster

//Do not do syscalls here, we are under lock, so the meta monitor can easely enter deadlock
//We should only do futext for the locks and mmap for requesting new memory
//TODO just prevent map_fixed unless the entire range belongs to the cid, otherwise wierd race conditions can be forced
int virt_page_manager::add_page(char* start, size_t size, int prot, int cid, bool map_fixed){
#if TRACK_MAPPINGS
    char selector = get_sud();
    assert(pthread_rwlock_wrlock(&lock) == 0);
    set_sud_allow();
    struct virt_page* p1 = virt_page_alloc();
    int ret = add_page_locked(start, size, prot, cid, map_fixed, p1);
    if(ret == -1){
        virt_page_free(p1);
    }
    assert(pthread_rwlock_unlock(&lock)==0);
    (selector == SYSCALL_DISPATCH_FILTER_ALLOW) ? set_sud_allow() : set_sud_block();
    return ret;
#else 
    return 0;
#endif
}

//add a new page group, return -1 if it overlaps with an existing group
//TODO, when some checks fail after parts have been removed here with map fixed and add remove_page, we should be able to revert or look ahead
int virt_page_manager::add_page_locked(char* start, size_t size, int prot, int cid, bool map_fixed, struct virt_page* p1){
    size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    //nolibc_print_size_t_hex("adding page start", (size_t)start);
    //nolibc_print_size_t_hex("adding page end", (size_t)start + size);
    //nolibc_print_size_t_hex("adding page prot", prot);
    //nolibc_print_size_t_hex("cid", cid);
    //nolibc_print_size_t_hex("adding page map fixed?", (size_t)map_fixed);
    nolibc_assert(((size_t)start%PAGE_SIZE) == 0);
    //printf("[%d] adding new page: start %p end %p prot %d map_fixed %d\n", cid, start, start + size, prot, map_fixed);
    p1->start = start;
    p1->size = size;
    p1->prot = prot;
    p1->Cid = cid;
    p1->next = NULL;

    //if there are any pages with the correct cid in the range remove them when we use map_fixed
    if(map_fixed){
        //when there are more then one thread, do not allow gaps in the pages we are removing as this is a race condition
        if(is_multithreaded){
            if(remove_page_locked(start, size, cid) == -1){
                nolibc_print_str("removing failed");
                return -1;
            }
        }else{
            if(remove_page_map_fixed_locked(start, size, cid) == -1){
                nolibc_print_str("removing  fixed failed");
                return -1;
            } 
        }

    }
    
    if(pages == NULL){
        pages = p1;
        return 0;
    }

    char* end_addr = start + size;

    //the new page group should be at the start
    if(pages->start >= end_addr){
        struct virt_page* temp = pages;
        pages = p1;
        p1->next = temp;
        return 0;
    }

    struct virt_page* current_page = pages;
    for(;current_page->next != NULL;current_page = current_page->next){
        //if there is still overlap, something went wrong
        if(virt_page_overlap(current_page, start, size) > 0){
            nolibc_print_size_t_hex("overlap found with start", (size_t)current_page->start);
            nolibc_print_size_t_hex("overlap found with end", (size_t)current_page->start + current_page->size);
            asm("ud2");
            return -1;
        }
            
        if(start >= current_page->next->start) continue;

        //check for overlap with next page
        if(end_addr > current_page->next->start){
            nolibc_assert(!map_fixed);
            nolibc_print_str("future overlap failed");
            return -1;
        }
            
        //the new page is between current and next
        struct virt_page* next = current_page->next;
        current_page->next = p1;
        p1->next = next;
        return 0;
    }

    //check overlap with last page
    if(virt_page_overlap(current_page, start, size) > 0){
        nolibc_assert(!map_fixed);
        nolibc_print_str("final overlap failed");
        return -1;
    }
        
    current_page->next = p1;
    return 0;
}

int virt_page_manager::remove_page(char* start, size_t size, int cid){
#if TRACK_MAPPINGS
    char selector = get_sud();
    assert(pthread_rwlock_wrlock(&lock)==0);
    set_sud_allow();
    int ret = remove_page_locked(start, size, cid);
    assert(pthread_rwlock_unlock(&lock)==0);
    (selector == SYSCALL_DISPATCH_FILTER_ALLOW) ? set_sud_allow() : set_sud_block();
    return ret;
#else
    return 0;
#endif
}


int virt_page_manager::remove_page_locked(char* start, size_t size, int cid){
    //nolibc_print_size_t_hex("remove page start", (size_t)start);
    //nolibc_print_size_t_hex("remove page end", (size_t)start + size);
    //we can support removing part of the page group when there is only one, but his will never happen so lets not worry about it
    if(pages==NULL || pages->next==NULL)return -1;
    size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    nolibc_assert(((size_t)start%PAGE_SIZE) == 0);
    if(size == 0) return -1;

    char* end = start + size;


    struct virt_page* prev_page = NULL;
    struct virt_page* start_page = NULL;
    struct virt_page* end_page = NULL;

    //the first page in the list is already to high
    if((pages->start + pages->size) > start){
        nolibc_print_str("address to low");
        return -1;
    }

    //edge case, we start at the first page
    if(pages->next->start > start){
        start_page = pages;
        prev_page = NULL;
    }

    //iterate over every page, first make sure that there are not gaps and all pages between start and end have the correct cid
    //secondly, go from the start page to the end page and remove all of them (potentially only partially remove the first and last page)
    //we know that we do not start on the first page
    for(struct virt_page* current_page = pages;current_page->next!=NULL;current_page = current_page->next){
        struct virt_page* next_page = current_page->next;
        char* next_page_end = next_page->start+next_page->size;
        if(next_page == NULL){
            nolibc_print_str("idk idk?");
            return -1;
        }

        if(start_page == NULL && next_page->next == NULL){
            nolibc_print_str("something went wrong idk?");
            return -1;
        }
        //start lies somewhere on next_page
        if((start_page==NULL) && (next_page_end > start)){
            start_page = next_page;
            prev_page = current_page;
            if((start < start_page->start) || (start >= start_page->start + start_page->size)){
                nolibc_print_size_t_hex("first page but no overlap start", (size_t)start_page->start);
                nolibc_print_size_t_hex("first page but no overlap end", (size_t)start_page->start + start_page->size);
                asm("ud2");
                return -1;
            } 
        }

        //continue until the start is found
        if(start_page == NULL) continue;

        //once start page is found, make sure all future pages are continues and contain the correct cid
        if(next_page->Cid != cid){
            nolibc_print_str("removing wrong compartment");
            return -1;
        }
        //it is possible that this is still the same page group as the start page
        //end lies somewhere on next_page
        if(next_page_end >= end){
            if((end <= next_page->start) || (end > next_page_end)){
                nolibc_print_size_t_hex("last page but no overlap start", (size_t)start_page->start);
                nolibc_print_size_t_hex("last page but no overlap end", (size_t)start_page->start + start_page->size);
                return -1;
            }
            end_page = next_page;
            break;
        }

        //if this is not the final page, make sure the next next page has no gap
        if(next_page->next == NULL){
            nolibc_print_str("no next next page");
            return -1;
        }
        if(next_page_end != next_page->next->start){
            nolibc_print_str("beep boop, gap detected");
            return -1;
        }
    }
    //we did not find the end
    if(end_page == NULL){
        nolibc_print_str("final page not found");
        return -1;
    }
            
    //the entire range is valid
    //second step remove all pages from start to end (possibly start and end aswel)
    
    //common case: remove exactly one page group
    if(start_page == end_page){
        char* page_end = start_page->start+start_page->size;
        //there are four cases:
        //start and end match -> remove the entire group
        if((start_page->start == start) && (page_end == end)){
            if(prev_page == NULL){
                nolibc_assert(start_page == pages);
                pages = start_page->next;
                virt_page_free(start_page);
                return 0;
            }
            prev_page->next = start_page->next;
            virt_page_free(start_page);
            return 0;
        }

        //start matches and end does not -> move the start
        if(start_page->start == start){
            start_page->start = end;
            start_page->size = page_end-end;
            return 0;
        }

        //end matches and start does not -> reduce the size
        if(page_end == end){
            start_page->size = start-start_page->start;
            return 0;
        }

        //the removed pages are in the middle of the group -> split the group in two
        //the first group
        start_page->size = start - start_page->start;
        //the second group
        struct virt_page* new_group = virt_page_alloc();
        new_group->Cid = start_page->Cid;
        new_group->prot = start_page->prot;
        new_group->start = end;
        new_group->size = page_end-end;
        new_group->next = start_page->next;
        start_page->next = new_group;
        return 0;
    }

    //there are multiple groups in the range, first check if start needs to be fully removed or only reduced
    if(start == start_page->start){
        struct virt_page* temp = start_page;
        start_page = prev_page;
        if(prev_page == NULL){
            pages = temp->next;
        }else{
            prev_page->next = temp->next;
        }
        virt_page_free(temp);
    }else{
        start_page->size = start - start_page->start;
    }
    //at this point, start page is the last group before the removed section
    //go though all to be removed pages except the last one and remove them
    //it is possible that start_pages == NULL if it was the first page and removed fully
    //so handle that differently
    if(start_page == NULL){
        while(pages!=end_page){
            nolibc_assert(pages->next != NULL);
            struct virt_page* temp = pages;
            pages = temp->next;
            virt_page_free(temp);
        }
        nolibc_assert(pages == end_page);
        //check if the final page group need to be fulyl removed
        if(end == (end_page->start + end_page->size)){
            pages= end_page->next;
            virt_page_free(end_page);
            return 0;
        }else{
            end_page->size = (end_page->start+end_page->size)-end;
            end_page->start = end;
            return 0;
        }
    }else{
        while(start_page->next!=end_page){
            nolibc_assert(start_page->next->next != NULL);
            struct virt_page* temp = start_page->next;
            start_page->next = temp->next;
            virt_page_free(temp);
        }
        nolibc_assert(start_page->next == end_page);
        //check if the final page group need to be fulyl removed
        if(end == (end_page->start + end_page->size)){
            start_page->next = end_page->next;
            virt_page_free(end_page);
            return 0;
        }else{
            end_page->size = (end_page->start+end_page->size)-end;
            end_page->start = end;
            return 0;
        }
    }
    return -1;
}

//remove all pages in the range (making sure the cid is correct), but allow gaps between the groups
int virt_page_manager::remove_page_map_fixed_locked(char* start, size_t size, int cid){
    //we can support removing part of the page group when there is only one, but his will never happen so lets not worry about it
    size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    nolibc_assert(((size_t)start%PAGE_SIZE) == 0);
    if(size == 0) return -1;

    char* end = start + size;


    struct virt_page* prev_page = NULL;
    struct virt_page* current_page = pages;

    //iterate over all groups, if the group overlaps with the removal range, and remove it
    //if you tried to overwrite a group from another compartment just crash, don't try to revert everything
    while(current_page != NULL){
        char* current_end = current_page->start + current_page->size;

        //4 possiblities
        //no overlap
        if(current_end <= start){
            prev_page = current_page;
            current_page = current_page->next;
            continue;
        }

        //we found the end
        if(current_page->start >= end){
            break;
        }

        //so there is some overlap
        if(current_page->Cid != cid) assert(0);


        //the current page need to be fully removed
        if((start <= current_page->start) && (end >= current_end)){
            if(prev_page == NULL){
                nolibc_assert(current_page == pages);
                pages = current_page->next;
                virt_page_free(current_page);
                current_page = pages;
                continue;
            }

            prev_page->next = current_page->next;
            virt_page_free(current_page);
            current_page = prev_page->next;
            continue;
        }

        //this is the final page so just make it shorter
        if((start <= current_page->start) && (end < current_end)){
            current_page->start = end;
            current_page->size = current_end-end;
            return 0;
        }

        //this is the first page, so just make it a bit shorter
        if((end >= current_end) && (start > current_page->start)){
            current_page->size = start-current_page->start;
            prev_page = current_page;
            current_page = current_page->next;
            continue;
        }

        assert((start > current_page->start) && (end < current_end));

        //the removed pages are in the middle of the group -> split the group in two
        //the first group
        current_page->size = start - current_page->start;

        //the second group
        struct virt_page* new_group = virt_page_alloc();
        new_group->Cid = current_page->Cid;
        new_group->prot = current_page->prot;
        new_group->start = end;
        new_group->size = current_end-end;
        new_group->next = current_page->next;

        current_page->next = new_group;

        return 0;
    }

    return 0;
}


int virt_page_manager::update_mprotect(char* start, size_t size, int prot, int cid){
#if TRACK_MAPPINGS
    char selector = get_sud();
    assert(pthread_rwlock_wrlock(&lock)==0);
    set_sud_allow();
    int ret = update_mprotect_locked(start, size, prot, cid);
    assert(pthread_rwlock_unlock(&lock)==0);
    (selector == SYSCALL_DISPATCH_FILTER_ALLOW) ? set_sud_allow() : set_sud_block();
    return ret;
#else
    return 0;
#endif
}

int virt_page_manager::update_mprotect_locked(char* start, size_t size, int prot, int cid){
    //nolibc_print_size_t_hex("updating page start", (size_t)start);
    //nolibc_print_size_t_hex("updating page end", (size_t)start + size);
    //nolibc_print_size_t_hex("updating page prot", prot);
    if(pages == NULL) return -1;

    struct virt_page* start_page = lookup_addr_locked(start, cid);
    if(start_page == NULL) return -1;

    if(start_page->Cid != cid){
        return -1;
    }

    char* start_page_end = start_page->start+start_page->size;
    char* end = start + size;
    if(size == 0) return -1;
    if(end < start) return -1;
    
    if((start < start_page->start) || (start >= start_page_end)){
        return -1;
    }
    //first, lets look at the three most common cases and implement a faster call
    // 1) the range is the same as an existing page group
    if((start == start_page->start) && (end == start_page_end)){
        start_page->prot = prot;
        return 0;
    }

    // 2) the range is a subset of one group where the start or end overlap with that group
    if((start == start_page->start) && (end < start_page_end)){
        //split the group in two, update the originals protections
        struct virt_page* new_group = virt_page_alloc();
        new_group->prot = start_page->prot;
        new_group->Cid = cid;
        new_group->start = end;
        new_group->size = start_page_end - end;
        new_group->next = start_page->next;
        
        start_page->prot = prot;
        start_page->size = size;
        start_page->next = new_group;
        return 0;
    }

    if((start > start_page->start) && (end == start_page_end)){
        //split the group in two, set the protections of the new group
        struct virt_page* new_group = virt_page_alloc();
        new_group->prot = prot;
        new_group->Cid = cid;
        new_group->start = start;
        new_group->size = size;
        new_group->next = start_page->next;
        
        start_page->size = start - start_page->start;
        start_page->next = new_group;
        return 0;
    }

    // 3) the range is a subset in the middle of the group, so that group will be split in three
    if((start > start_page->start) && (end < start_page_end)){
        //split the group in three, -> start_group -> g1 -> g2 -> start_group.next
        struct virt_page* group1 = virt_page_alloc();
        struct virt_page* group2 = virt_page_alloc();
        

        group1->Cid = cid;
        group1->prot = prot;
        group1->size = size;
        group1->start = start;
        group1->next = group2;

        group2->Cid = cid;
        group2->prot = start_page->prot;
        group2->size = start_page_end - end;
        group2->start = end;
        group2->next = start_page->next;

        start_page->size = start - start_page->start;
        start_page->next = group1;
        return 0;
    }

    //the range covers multiple pages, lets remove everyting first, and then add the new page
    int ret = remove_page_locked(start, size, cid);
    if(ret == -1) return -1;

    //the pages where removed so now insert out new group
    for(struct virt_page* current_page = pages; current_page != NULL; current_page = current_page->next){
        char* current_end = current_page->start + current_page->size;
        if(start >= current_end){
            if(current_page->next == NULL){
                struct virt_page* new_group = virt_page_alloc();
                new_group->prot = prot;
                new_group->Cid = cid;
                new_group->start = start;
                new_group->size = size;
                new_group->next = NULL;
                
                current_page->next = new_group;
                return 0;
            }
            if(virt_page_overlap(current_page->next, start, size) != 0) assert(0); //we already removed stuff if we fail here we should undo that or just give up
            
            struct virt_page* new_group = virt_page_alloc();
            new_group->prot = prot;
            new_group->Cid = cid;
            new_group->start = start;
            new_group->size = size;
            new_group->next = current_page->next;
            
            current_page->next = new_group;
            return 0;
        }
    }
    assert(0); //We already removed stuff
    return -1;
}

int virt_page_manager::update_size(char* start, size_t old_size, size_t new_size, int cid){
#if TRACK_MAPPINGS
    char selector = get_sud();
    assert(pthread_rwlock_wrlock(&lock)==0);
    set_sud_allow();
    int ret = update_size_locked(start, old_size, new_size, cid);
    assert(pthread_rwlock_unlock(&lock)==0);
    (selector == SYSCALL_DISPATCH_FILTER_ALLOW) ? set_sud_allow() : set_sud_block();
    return ret;
#else
    return 0;
#endif
}

//TODO, groups can be merged allowing larger mapping to be remapped than allowed here
//TODO,reducing size also allows for multiple page groups
//returns -2 if its attempt to increase in size would cause overlap with an existing mapping
//otherwise return -1 for failure and 0 for success 
int virt_page_manager::update_size_locked(char* start, size_t old_size, size_t new_size, int cid){
    char* old_end = start + old_size;
    char* new_end = start + new_size;
    //check that the size of the group can change, then change it.
    struct virt_page* current_group = lookup_addr_locked(start, cid);
    if(current_group == NULL) return -1;
    if(old_size == new_size) return 0;
    //make sure the range is part of the same page group
    if(old_end > (current_group->start+current_group->size)) return -1;
    
    //two possible setups
    if(old_size < new_size){
        //increase the size
        size_t dsize = new_size - old_size;
        
        //you can only increase the size if the old range actually reaches the end of the group
        if((current_group->start + current_group->size) != old_end) return -2;  
        //there is overlap with the next group
        if((current_group->next) && (new_end > current_group->next->start)) return -2;

        current_group->size += dsize;
        return 0;

    }else{
        //decrease the size
        size_t dsize = old_size - new_size;

        //this can decrease the size of the group
        if(old_end == (current_group->start+current_group->size)){
            current_group->size -= dsize;
            return 0;
        }

        //or split it in two
        struct virt_page* new_group = virt_page_alloc();
        new_group->Cid = cid;
        new_group->prot = current_group->prot;
        new_group->next = current_group->next;
        new_group->start = old_end;
        new_group->size = (current_group->start + current_group->size) - old_end;
        
        current_group->size = new_end - current_group->start;
        current_group->next = new_group;
        return 0;
    }
    return -1;
}


struct virt_page* virt_page_manager::lookup_addr(char* addr, int cid){
#if TRACK_MAPPINGS
    char selector = get_sud();
    pthread_rwlock_rdlock(&lock);
    set_sud_allow();
    struct virt_page* ret = lookup_addr_locked(addr, cid);
    pthread_rwlock_unlock(&lock);
    (selector == SYSCALL_DISPATCH_FILTER_ALLOW) ? set_sud_allow() : set_sud_block();
    return ret;
#else
    return (struct virt_page*)-1;
#endif
}

struct virt_page* virt_page_manager::lookup_range(char* start_addr, size_t size, int cid){
#if TRACK_MAPPINGS
    char selector = get_sud();
    pthread_rwlock_rdlock(&lock);
    set_sud_allow();
    struct virt_page* ret = lookup_range_locked(start_addr, size, cid);
    pthread_rwlock_unlock(&lock);
    (selector == SYSCALL_DISPATCH_FILTER_ALLOW) ? set_sud_allow() : set_sud_block();
    return ret;
#else
    return (struct virt_page*)-1;
#endif
}

//make sure the address is in a valid page, return the page_group
//cid == -1 always returns the page group if it exists
struct virt_page* virt_page_manager::lookup_addr_locked(char* addr, int cid){
    if(pages == NULL) return NULL;
    
    for(struct virt_page* current_page = pages; current_page!=NULL; current_page = current_page->next){
        if(virt_page_overlap_byte(current_page, addr)){
            if(cid == -1 || current_page->Cid == cid){
                return current_page;
            }
        }
    }
    return NULL;
}

//make sure that every page in the range start_addr -> start_addr+size is in a valid page group with the correct cid
//returns the first group in the range
struct virt_page* virt_page_manager::lookup_range_locked(char* start_addr, size_t size, int cid){
    nolibc_assert(pages != NULL);

    char* end_addr = (start_addr + size);
    
    struct virt_page* start_range = NULL;
    for(struct virt_page* current_page = pages; current_page != NULL; current_page = current_page->next){
        //make sure the start addr is in the first page group to prevent gaps at the start
        if(virt_page_overlap_byte(current_page, start_addr)){
            start_range = current_page;
            break;
        }

    }

    if(start_range == NULL) return NULL;
    if(start_range->Cid != cid) return NULL;

    char* page_end = start_range->start + start_range->size;
    if(page_end >= end_addr){
        //the entire range fits in one page group
        return start_range;
    }

    for(struct virt_page* current_page = start_range; current_page != NULL; current_page = current_page->next){
        if(current_page->Cid != cid) return NULL;

        page_end = current_page->start + current_page->size;
        if(page_end >= end_addr){
            return start_range;
        }

        if(current_page->next == NULL) return NULL;
        if(current_page->next->start != page_end) return NULL;
    }

    return NULL;

}


int virt_page_manager::lookup_range_allow_gaps(char* start_addr, size_t size, int cid){
#if TRACK_MAPPINGS
    char selector = get_sud();
    pthread_rwlock_rdlock(&lock);
    set_sud_allow();
    int ret = lookup_range_allow_gaps_locked(start_addr, size, cid);
    pthread_rwlock_unlock(&lock);
    (selector == SYSCALL_DISPATCH_FILTER_ALLOW) ? set_sud_allow() : set_sud_block();
    return ret;
#else
    return 0;
#endif
}

// checks that every page group overlapping the range has the given cid
// gaps between page groups are allowed
// returns 0 on success and -1 on failure
int virt_page_manager::lookup_range_allow_gaps_locked(char* start_addr, size_t size, int cid){
    if(pages == NULL) return 0;

    char* end_addr = start_addr + size;

    for(struct virt_page* current_page = pages; current_page != NULL; current_page = current_page->next){
        char* page_start = current_page->start;
        char* page_end   = current_page->start + current_page->size;

        // no overlap
        if(page_end <= start_addr || page_start >= end_addr) continue;

        // overlapping page has wrong cid
        if(current_page->Cid != cid){
            return -1;
        }
    }

    //there are no overlapping pages
    return 0;
}


//returns the virt_page if it has the correct cid otherwise return NULL;
struct virt_page* virt_page_manager::return_virt_page(struct virt_page* page_group, int cid){
    if(page_group==NULL || cid == -1) return NULL;
    if(cid == page_group->Cid){
        return page_group;
    }else{
        return NULL;
    }
}

// return values:
// -1) error
// 0) start -> start + size does not overlap with the page_group
// 1) start -> start + size partially overlaps with the page_group
// 2) start -> start + size is the same as page_group
// 3) start -> start + size is a subset of page_group
// 4) start -> start + size is a superset of page_group
int virt_page_manager::virt_page_overlap(struct virt_page* page_group, char* start, size_t size){
    if(page_group == NULL) return -1;

    char* end = start + size;
    char* page_start = page_group->start;
    char* page_end = page_start + page_group->size;

    if(page_start >= end) return 0;
    if(page_end <= start) return 0;

    if(page_start == start && page_end == end) return 2;
    if(page_start <= start && page_end >= end) return 3;
    if(page_start > start && page_end < end) return 4;
    return 1;
}

// return values:
// -1) error
// 0) byte not in page_group
// 1) byte in page_group
int virt_page_manager::virt_page_overlap_byte(struct virt_page* page_group, char* byte){
    if(page_group == NULL) return -1;
    char* page_start = page_group->start;
    char* page_end = page_start + page_group->size;

    if(byte >= page_start && byte < page_end){
        return 1;
    }
    return 0;
}

struct virt_page* virt_page_manager::virt_page_get_prev_group(struct virt_page* page_group){
    nolibc_assert(pages != NULL);
    if(page_group == pages) return NULL;

    for(struct virt_page* current_page = pages; current_page->next!=NULL; current_page = current_page->next){
        if(current_page->next == page_group){
            return current_page;
        }
    }
    return NULL;
}


//map two new pages, and split it into a series of new virt_page nodes for the free list.
//use the first two to add this new page group to the manager
void virt_page_manager::refill_free_list(){
    nolibc_assert(PAGE_SIZE % sizeof(struct virt_page) == 0);

    //nolibc_print_str("free list empty\n");

    //NEW MMAP
#if DEBUG
    nolibc_assert(gsreldata->readable_data.sud_selector == SYSCALL_DISPATCH_FILTER_ALLOW);
#endif
    struct virt_page* new_pages = (struct virt_page*)inline_syscall6(__NR_mmap, 0, PAGE_SIZE*2, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    nolibc_assert(inline_syscall6(__NR_pkey_mprotect, new_pages, PAGE_SIZE*2, PROT_READ|PROT_WRITE, SECPOLINE_MPKEY, 0, 0)==0);
    nolibc_assert(new_pages != MAP_FAILED);

    struct virt_page* final_node = &new_pages[(PAGE_SIZE*2/sizeof(struct virt_page))-2];
    //chain the nodes on the new pages to form a linke list
    int node_index = 0;
    for(; node_index < ((PAGE_SIZE*2/sizeof(struct virt_page))-2); node_index++){
        new_pages[node_index].next = &new_pages[node_index+1];
    }
    nolibc_assert(new_pages[node_index-1].next == final_node);
    //add the list to the free list
    final_node->next = free_pages;
    free_pages = new_pages;

    //this will not require a second page as it does not use map_fixed
    struct virt_page* p1 = &new_pages[(PAGE_SIZE*2/sizeof(struct virt_page))-1];
    nolibc_assert(add_page_locked((char*)new_pages, PAGE_SIZE*2, PROT_READ|PROT_WRITE, TS_MONITOR, false, p1)==0);

    return;
}

//add the virt_page to the start of the free list
void virt_page_manager::virt_page_free(struct virt_page* page_group){
    page_group->next = free_pages;
    free_pages = page_group;
}

struct virt_page* virt_page_manager::virt_page_alloc(){
    if(free_pages == NULL){
        refill_free_list();
    }
    nolibc_assert(free_pages != NULL);
    struct virt_page* temp = free_pages;
    free_pages = free_pages->next;
    return temp;
}

virt_page_manager::~virt_page_manager(){
    //TODO maybe unmap all used pages by iterating over every used and free virt_page
}

void virt_page_manager::print_mappings(){
    //std::shared_lock<std::shared_mutex> lock(mtx);
    if(pages == NULL) return;

    for(struct virt_page* current_page = pages; current_page!=NULL; current_page = current_page->next){
        char* prot = (char*)malloc(4);
        prot[3] = '\0';
        prot[0] = (current_page->prot&PROT_READ) ? 'r' : '-';
        prot[1] = (current_page->prot&PROT_WRITE) ? 'w' : '-';
        prot[2] = (current_page->prot&PROT_EXEC) ? 'x' : '-';
        fprintf(stderr, "[%d] %p %p %s\n", current_page->Cid, current_page->start, current_page->start+current_page->size, prot);
        free(prot);
    }
}