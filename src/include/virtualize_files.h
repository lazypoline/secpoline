#include "gsreldata.h"
#include <cstdlib>
#include <cstring>
#include <assert.h>
#include <stdio.h>
#include <dirent.h>
#include <shared_mutex>
#include <unistd.h>
#include <mutex>
//bitmap that store the used fd
class fd_bitmap{
private:
    char* map = nullptr;
    size_t size; //size in bytes

public:
    mutable std::shared_mutex mtx; //read/write lock
    fd_bitmap(){
        map = (char*)calloc(sizeof(size_t), 1);
        size = 1;
        //parse proc/self/fd to get active fd's, it is a directory with a file for each fd
        DIR *d = opendir("/proc/self/fd");
        struct dirent *ent;
        assert(d);

        while ((ent = readdir(d)) != NULL) {
            if(ent->d_name[0] == '.') continue;
            int int_fd = atoi(ent->d_name); //returns 0 if conversion not valid but also for
            set_bit(int_fd);
        }
        closedir(d);
    }

    ~fd_bitmap() {
        free(map);
    }

    void set_bit(size_t index){
        std::unique_lock<std::shared_mutex> lock(mtx);
        size_t byte_index = index/8;

        if(byte_index >= size){
            size_t new_size = ((byte_index/8)+1)*8;

            map = (char*)realloc(map, new_size);
            assert(map);

            memset(map + size, 0, new_size - size);
            size = new_size;
        }

        assert(size > byte_index);
        map[byte_index] |= (1 << (index % 8));
        return;
    }

    int unset_bit(size_t index){

        size_t byte_index = index/8;

        if(byte_index >= size){
            return 0;
        }

        map[byte_index] &= ~(1 << (index % 8));
        return 0;
    }

    int read_bit(size_t index){
        std::shared_lock<std::shared_mutex> lock(mtx);
        size_t byte_index = index/8;

        if(byte_index >= size){
            return 0;
        }
        return (map[byte_index] >> (index % 8)) & 1;
    }
};

extern fd_bitmap untrusted_fd_bitmap;
