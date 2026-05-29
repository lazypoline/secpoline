#include "hardware_breakpoints.h"
#include <linux/perf_event.h> //this header may not be up to date with the kernel and not include the sigtrap field, even when the kernel supports it.
#include <linux/hw_breakpoint.h>
#include <sys/syscall.h> 
#include <sys/ioctl.h>
#include <stdlib.h>
#include "nolibc_util.h"
#include "util.h"
#include "gsreldata.h"
#include "sud.h"
#include <errno.h>

hbreakpoint_controller::hbreakpoint_controller(){
#if SCAN_UNSAFE_INSTRUCTIONS
    max_dynamic_breakpoints = MAX_HBREAKPOINTS;
    test_remaining_breakpoints();
#else
    max_dynamic_breakpoints = 0;
#endif
}

void hbreakpoint_controller::add_breakpoints(unsafe_page* page, bool is_static){
#if SCAN_UNSAFE_INSTRUCTIONS
    int needed_breakpoints = page->unsafe_instructions_size;
    //static hbreakpoints cannot be moved as they are part of the critical segfault handler path
    if(is_static){
        nolibc_assert(static_hbreakpoints.size+needed_breakpoints <= MAX_HBREAKPOINTS);
        
        //if there are enough free breakpoints, just assign them
        if(used_breakpoints + needed_breakpoints <= MAX_HBREAKPOINTS){
            add_watched_page(page, true);
            return;
        }

        //there are not enough free breakpoints, so first get some back by removing them from the oldest page
        remove_dynamic_hbreakpoints(needed_breakpoints);
        add_watched_page(page, true);
        return;
    }

    nolibc_assert(needed_breakpoints <= max_dynamic_breakpoints);

    //if there are enough free breakpoints, just assign them
    if(used_breakpoints + needed_breakpoints <= MAX_HBREAKPOINTS){
        add_watched_page(page, false);
        return;
    }

    //there are not enough free breakpoints, so first get some back by removing them from the oldest page
    remove_dynamic_hbreakpoints(needed_breakpoints);
    add_watched_page(page, false);
    return;
#endif
}

void hbreakpoint_controller::add_watched_page(unsafe_page* page, bool is_static){
    std::vector<char*>* unsafe_instructions = page->unsafe_instructions;
    nolibc_assert(page->unsafe_instructions_size+used_breakpoints <= MAX_HBREAKPOINTS);
    watched_page* new_page;

    if(is_static){
        nolibc_assert(page->unsafe_instructions_size <= max_dynamic_breakpoints);
        new_page = &static_hbreakpoints.page_list[static_hbreakpoints.size];
        static_hbreakpoints.size++;
    }else{
        new_page = &dynamic_hbreakpoints.page_list[dynamic_hbreakpoints.size];
        dynamic_hbreakpoints.size++;
    }
 
    new_page->page_used_hbreakpoints = 0;
    //for every unsafe instruction on the page, set a breakpoint
    for(int i = 0;i<page->unsafe_instructions_size;i++){
        char* address = (*unsafe_instructions)[i];
        int fd = set_hbreakpoint(address);

        new_page->breakpoints[i].address = address;
        new_page->breakpoints[i].fd = fd;
        new_page->page_used_hbreakpoints++;

        used_breakpoints++;
        if(is_static){
            max_dynamic_breakpoints--;
        }
    }
    return;
}


//remove pages until there are n breakpoint available
void hbreakpoint_controller::remove_dynamic_hbreakpoints(int n){
    nolibc_assert(n <= max_dynamic_breakpoints);
    while(MAX_HBREAKPOINTS-used_breakpoints < n){
        remove_last_page();
    }
}

//remove breakpoints from the oldest page by ending its event and closing the file.
void hbreakpoint_controller::remove_last_page(){
    nolibc_assert(dynamic_hbreakpoints.size > 0);
    struct watched_page* oldest_page = &dynamic_hbreakpoints.page_list[0];

    //before removing the breakpoints set the page to non-executable again.
    nolibc_assert(oldest_page->page_used_hbreakpoints);
    set_page_non_executable(oldest_page->breakpoints[0].address);


    for(int i = 0;i < oldest_page->page_used_hbreakpoints;i++){
        int fd = oldest_page->breakpoints[i].fd;
        nolibc_assert(fd);
        
        //nolibc_assert(inline_syscall6(__NR_ioctl, fd, PERF_EVENT_IOC_DISABLE, 0, 0, 0, 0)==0);
        nolibc_assert(inline_syscall6(__NR_close, fd, 0, 0, 0, 0, 0)==0);

        used_breakpoints--;
    }
    
    //move all remaining watched pages one back
    dynamic_hbreakpoints.size--;
    for(int i = 0;i < dynamic_hbreakpoints.size;i++){
        nolibc_assert(i+1<=MAX_HBREAKPOINTS);
        dynamic_hbreakpoints.page_list[i] = dynamic_hbreakpoints.page_list[i+1];
    }
}

//place all hbreakpoints in the child process after a fork
void hbreakpoint_controller::set_all_hbreakpoits(){
#if SCAN_UNSAFE_INSTRUCTIONS
    int required_hbreakpoints = used_breakpoints;
    used_breakpoints = 0;
    int temp_max_dynamic_breakpoints = max_dynamic_breakpoints;
    max_dynamic_breakpoints = MAX_HBREAKPOINTS;
    test_remaining_breakpoints();
    
    for(int page_index=0;page_index<static_hbreakpoints.size;page_index++){
        watched_page* page = &static_hbreakpoints.page_list[page_index];
        for(int breakpoint_index=0;breakpoint_index<page->page_used_hbreakpoints;breakpoint_index++){
            char* addr = page->breakpoints[breakpoint_index].address;
            int fd = set_hbreakpoint(addr);
            page->breakpoints[breakpoint_index].fd = fd;
            used_breakpoints++;
            max_dynamic_breakpoints--;
        }
    }
    
    for(int page_index=0;page_index<dynamic_hbreakpoints.size;page_index++){
        watched_page* page = &dynamic_hbreakpoints.page_list[page_index];
        for(int breakpoint_index=0;breakpoint_index<page->page_used_hbreakpoints;breakpoint_index++){
            char* addr = page->breakpoints[breakpoint_index].address;
            int fd = set_hbreakpoint(addr);
            page->breakpoints[breakpoint_index].fd = fd;
            used_breakpoints++;
        }
    }

    nolibc_assert(used_breakpoints==required_hbreakpoints);
    nolibc_assert(max_dynamic_breakpoints==temp_max_dynamic_breakpoints);
#endif
}


//place all hbreakpoints in the child process after a fork
void hbreakpoint_controller::remove_all_hbreakpoints(){
#if SCAN_UNSAFE_INSTRUCTIONS
    for(int page_index=0;page_index<static_hbreakpoints.size;page_index++){
        watched_page* page = &static_hbreakpoints.page_list[page_index];
        for(int breakpoint_index=0;breakpoint_index<page->page_used_hbreakpoints;breakpoint_index++){
            int fd = page->breakpoints[breakpoint_index].fd;
            int res = inline_syscall6(__NR_close, fd, 0, 0, 0, 0, 0);
            if(res != 0){
                nolibc_print_size_t("close failed:", -res);
                nolibc_assert(0);
            }
        }
    }
    
    for(int page_index=0;page_index<dynamic_hbreakpoints.size;page_index++){
        watched_page* page = &dynamic_hbreakpoints.page_list[page_index];
        for(int breakpoint_index=0;breakpoint_index<page->page_used_hbreakpoints;breakpoint_index++){
            int fd = page->breakpoints[breakpoint_index].fd;
            int res = inline_syscall6(__NR_close, fd, 0, 0, 0, 0, 0);
            if(res != 0){
                nolibc_print_size_t("close failed:", -res);
                nolibc_assert(0);
            }
        }
    }
    used_breakpoints = 0;
    test_remaining_breakpoints();
#endif
}


int hbreakpoint_controller::set_hbreakpoint(char *addr){
#if !SCAN_UNSAFE_INSTRUCTIONS
    assert(0);
#endif

	struct perf_event_attr attr = { .size = 0, };
	int fd;

	attr.type = PERF_TYPE_BREAKPOINT;
	attr.size = sizeof(attr);
	attr.exclude_kernel = 1;
	attr.exclude_hv = 1;
	attr.inherit = 0;
	attr.inherit_thread = 0;
	attr.bp_addr = (unsigned long)addr;
	attr.bp_type = HW_BREAKPOINT_X;
	attr.bp_len = sizeof(long);
    
    attr.sigtrap = 1;
    attr.sig_data = -1;
    attr.remove_on_exec = 1;
    attr.sample_period = 1;

	fd = inline_syscall6(__NR_perf_event_open, &attr, 0, -1, -1, PERF_FLAG_FD_CLOEXEC, 0);
    if(fd < 0){
        nolibc_print_size_t("could not place breakpoints", fd);
        nolibc_assert(0);
    }
    //nolibc_print_size_t_hex("placing breakpoint", (size_t)addr);
    return fd;
}

/*
    Temporarily sets the remaining breakpoints on dummy addresses to 
    verify that there are really still as many available as we think.
    Unsets them again before returning. 
*/
void hbreakpoint_controller::test_remaining_breakpoints(){
#if DEBUG
    //make sure there are at least "max_breakpoints-used_breakpoints" hardware breakpoints available
    int remaining_breakpoints = MAX_HBREAKPOINTS - used_breakpoints;
    int fds[4];
    for(int i = 0; i < remaining_breakpoints; i++) {
        fds[i] = set_hbreakpoint((char*) (uintptr_t) i);
        nolibc_assert(fds[i] > 0);
    }

    for(int i=0;i<remaining_breakpoints;i++){
        nolibc_assert(inline_syscall6(__NR_close, fds[i], 0, 0, 0, 0, 0)==0);
    }
#endif
}
