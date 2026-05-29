#include <queue>
#include <mutex>
#include <condition_variable>
#include <stdint.h>
#include <string>

namespace falco {
namespace app {
bool run(int argc, char** argv, bool& restart, std::string& errstr);
}
}

static inline uint64_t read_gs_base() {
    uint64_t value;

    asm volatile (
        "rdgsbase %0"
        : "=r"(value)
    );

    return value;
}

struct syscall_t{
    int syscall_num;
    size_t arg1;
    size_t arg2;
    size_t arg3;
    size_t arg4;
    size_t arg5;
    size_t arg6;
};

class ThreadSafeQueue {
public:
    bool active = false;
    int push(syscall_t* value){
        std::lock_guard<std::mutex> lock(mutex_);

        if(!active) return -1;

        queue_.push(std::move(value));
        cond_.notify_one();
        return 0;
    }

    int pop(syscall_t** syscall_elements) {
        std::unique_lock<std::mutex> lock(mutex_);

        cond_.wait(lock, [this]{
            return !active || !queue_.empty();
        });

        if(!active && queue_.empty())
            return -1;

        *syscall_elements = std::move(queue_.front());
        queue_.pop();

        return 0;
    }

    bool empty() {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }

    void activate(){
        {
            std::lock_guard<std::mutex> lock(mutex_);
            active = true;
        }

        cond_.notify_all();
    }

    void deactivate(){
        {
            std::lock_guard<std::mutex> lock(mutex_);
            active = false;
        }

        cond_.notify_all();
    }

    void wait_active(){
        std::unique_lock<std::mutex> lock(mutex_);

        cond_.wait(lock, [this]{
            return active;
        });
    }

private:

    mutable std::mutex mutex_;
    std::condition_variable cond_;
    std::queue<syscall_t*> queue_;
};


extern ThreadSafeQueue plugin_queue;

int falco_entry(int argc, char **argv);
void* shim_start(void* args);

int send_syscall(int syscall_num, size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t arg5, size_t arg6);