#include "load_secpoline.h"
#include "ld_malloc.h"

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <link.h>
#include <assert.h>

struct mmapped_list_s* get_mappings(){
    struct mmapped_list_s mmapped_list;
    mmapped_list.size = 0;

    FILE *maps_file = fopen("/proc/self/maps", "r");

    if (maps_file == NULL) {
        fprintf(stderr, "could not open proc/self/maps\n");
        exit(1);
    }

    char* end_ptr;
    char line[256];
    while (fgets(line, sizeof(line), maps_file) != NULL) {

        //fprintf(stderr, "%s", line);
        end_ptr = line;
        if (!*end_ptr) continue;
        //extract start and end adress of memory maping
        //star_adress-end_adress rwxp ....
        uint64_t mapping_start = strtoll(end_ptr, &end_ptr, 16);
        if(mapping_start>=0x7fffffffffffffff)continue; //ignore vsyscall pages
        assert(*end_ptr++ == '-');
        uint64_t mapping_end = strtoll(end_ptr, &end_ptr, 16);
        char* page_permissions = strchr(line, ' ');

        if(strstr(line, "[vvar]")){
            mmapped_list.vvar.permissions = PROT_READ;
            mmapped_list.vvar.start_address = mapping_start;
            mmapped_list.vvar.size = mapping_end-mapping_start;
            continue;
        }

        if(strstr(line, "[vdso]")){
            mmapped_list.vdso.permissions = PROT_EXEC;
            mmapped_list.vdso.start_address = mapping_start;
            mmapped_list.vdso.size = mapping_end-mapping_start;
            continue;
        }

        mmapped_list.list[mmapped_list.size].size = 0;
        assert(mmapped_list.size<MAX_MMAP_LIST_SIZE);
        mmapped_list.list[mmapped_list.size].start_address = mapping_start;
        mmapped_list.list[mmapped_list.size].size = mapping_end-mapping_start;

        int perm = 0;
        page_permissions++;
        assert(*page_permissions=='r'||*page_permissions=='-');
        if(*(page_permissions)=='r')perm |= PROT_READ;
        if(*(page_permissions+1)=='w')perm |= PROT_WRITE;
        if(*(page_permissions+2)=='x')perm |= PROT_EXEC;
        mmapped_list.list[mmapped_list.size].permissions = perm;

        mmapped_list.size++;
        
    }

    //do not close proc/self/maps as this unmaps a page which causes wrong results in the mmapped list
    //fclose(maps_file);
    ld_malloc_reset(); //restart malloc so secpoline part of the laoder uses different pages

    struct mmapped_list_s* mmapped_list_p = (struct mmapped_list_s*) ld_malloc(sizeof(struct mmapped_list_s));
    memcpy(mmapped_list_p, &mmapped_list, sizeof(struct mmapped_list_s));
    return mmapped_list_p;
}

