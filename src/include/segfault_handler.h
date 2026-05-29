#include <sys/signal.h>
#include <atomic>
#include "nolibc_util.h"

//The segfault handler is a seperate Shared Object so we can keep track of its pages and never make them non-executable, instead keep a hardware breakpoint on all unsafe instructions
void setup_segfault_handler(void);

class nolibc_lock{
    public:
    inline void lock(){
        while(flag.test_and_set(std::memory_order_acquire));
    }

    inline void unlock(){
        flag.clear(std::memory_order_release);
    }

    inline bool try_lock(){
        return !flag.test_and_set(std::memory_order_acquire);
    }

    inline void print_flag(){
        bool f = flag.test_and_set(std::memory_order_acquire);
        if(f==false){
            flag.clear(std::memory_order_release);
        }
        nolibc_print_size_t("flag:", f);
    }
    private:
    std::atomic_flag flag = ATOMIC_FLAG_INIT;
};
