#pragma once
#define MAX_MMAP_LIST_SIZE 256
struct Page_group{
    unsigned long long start_address;
    int size; //in bytes
    int permissions;
};
struct mmapped_list_s{
    struct Page_group list[MAX_MMAP_LIST_SIZE];
    int size;
    struct Page_group vvar;
    struct Page_group vdso;
};