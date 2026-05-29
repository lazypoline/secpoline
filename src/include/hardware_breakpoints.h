#pragma once

#include "erim.h"
#include <atomic>

#define MAX_HBREAKPOINTS 4
//hardware breakpoints are grouped by page
struct hbreakpoint{
    char* address;
    int fd;
};

struct watched_page{
    struct hbreakpoint breakpoints[MAX_HBREAKPOINTS];
    int page_used_hbreakpoints = 0;
};

struct hbreakpoint_list{
    watched_page page_list[MAX_HBREAKPOINTS];
    int size = 0;
};

class hbreakpoint_controller{
    public:
    int max_dynamic_breakpoints;

    hbreakpoint_controller();
    void add_breakpoints(unsafe_page* page, bool is_static);
    void set_all_hbreakpoits();
    void remove_all_hbreakpoints();
    int used_breakpoints = 0;

    private:
    struct hbreakpoint_list static_hbreakpoints; //breakpoints that cannot be moved
    struct hbreakpoint_list dynamic_hbreakpoints;

    int set_hbreakpoint(char* address);
    void add_watched_page(unsafe_page* page, bool is_static);
    void remove_dynamic_hbreakpoints(int n);
    void remove_last_page();
    void test_remaining_breakpoints();
};


struct active_thread{
};

#define MAX_ACTIVE_THREAD 4096

struct ptid{
    int tid;
    int pid;
};

struct hbreakpoint_thread_synchronizer{
    std::atomic<int> controller_thread{0};//set to the tid of the thread initialising breakpoint placement
    std::atomic<int> waiting_thread_count{0};
    std::atomic<unsafe_page*> segfault_page{nullptr};
    ptid active_thread_list[MAX_ACTIVE_THREAD]; //list of all threads in this process
    int active_thread_list_size = 0;
};
